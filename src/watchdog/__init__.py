#!/usr/bin/env python
#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import errno
import json
import logging
import logging.handlers
import os
import subprocess
import sys
import time

from collections import namedtuple
from logging.handlers import RotatingFileHandler
from signal import SIGTERM

try:
    import ConfigParser
except ImportError:
    from configparser import ConfigParser

VERSION = '1.7'

CONFIG_FILE = '/etc/amazon/efs/efs-utils.conf'
CONFIG_SECTION = 'mount-watchdog'

LOG_DIR = '/var/log/amazon/efs'
LOG_FILE = 'mount-watchdog.log'

STATE_FILE_DIR = '/var/run/efs'

Mount = namedtuple('Mount', ['server', 'mountpoint', 'type', 'options', 'freq', 'passno'])


def fatal_error(user_message, log_message=None):
    if log_message is None:
        log_message = user_message

    sys.stderr.write('%s\n' % user_message)
    logging.error(log_message)
    sys.exit(1)


def bootstrap_logging(config, log_dir=LOG_DIR):
    raw_level = config.get(CONFIG_SECTION, 'logging_level')
    levels = {
        'debug': logging.DEBUG,
        'info': logging.INFO,
        'warning': logging.WARNING,
        'error': logging.ERROR,
        'critical': logging.CRITICAL
    }
    level = levels.get(raw_level.lower())
    level_error = False

    if not level:
        # delay logging error about malformed log level until after logging is configured
        level_error = True
        level = logging.INFO

    max_bytes = config.getint(CONFIG_SECTION, 'logging_max_bytes')
    file_count = config.getint(CONFIG_SECTION, 'logging_file_count')

    handler = RotatingFileHandler(os.path.join(log_dir, LOG_FILE), maxBytes=max_bytes, backupCount=file_count)
    handler.setFormatter(logging.Formatter(fmt='%(asctime)s - %(levelname)s - %(message)s'))

    logger = logging.getLogger()
    logger.setLevel(level)
    logger.addHandler(handler)

    if level_error:
        logging.error('Malformed logging level "%s", setting logging level to %s', raw_level, level)


def parse_options(options):
    opts = {}
    for o in options.split(','):
        if '=' in o:
            k, v = o.split('=')
            opts[k] = v
        else:
            opts[o] = None
    return opts


def get_file_safe_mountpoint(mount):
    mountpoint = os.path.abspath(mount.mountpoint).replace(os.sep, '.')
    if mountpoint.startswith('.'):
        mountpoint = mountpoint[1:]

    opts = parse_options(mount.options)
    if 'port' not in opts:
        # some other localhost nfs mount not running over stunnel
        return None
    return mountpoint + '.' + opts['port']


def get_current_local_nfs_mounts(mount_file='/proc/mounts'):
    """
    Return a dict of the current NFS mounts for servers running on localhost, keyed by the mountpoint and port as it
    appears in EFS watchdog state files.
    """
    mounts = []

    with open(mount_file) as f:
        for mount in f:
            mounts.append(Mount._make(mount.strip().split()))

    mounts = [m for m in mounts if m.server.startswith('127.0.0.1') and 'nfs' in m.type]

    mount_dict = {}
    for m in mounts:
        safe_mnt = get_file_safe_mountpoint(m)
        if safe_mnt:
            mount_dict[safe_mnt] = m

    return mount_dict


def get_state_files(state_file_dir):
    """
    Return a dict of the absolute path of state files in state_file_dir, keyed by the mountpoint and port portion of the filename.
    """
    state_files = {}

    if os.path.isdir(state_file_dir):
        for sf in os.listdir(state_file_dir):
            if not sf.startswith('fs-'):
                continue

            # This translates the state file name "fs-deadbeaf.home.user.mnt.12345"
            # into file-safe mountpoint "home.user.mnt.12345"
            first_period = sf.find('.')
            mount_point_and_port = sf[first_period + 1:]
            logging.debug('Translating "%s" into mount point and port "%s"', sf, mount_point_and_port)
            state_files[mount_point_and_port] = sf

    return state_files


def is_pid_running(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def start_tls_tunnel(child_procs, state_file, command):
    # launch the tunnel in a process group so if it has any child processes, they can be killed easily
    logging.info('Starting TLS tunnel: "%s"', ' '.join(command))
    tunnel = subprocess.Popen(command, preexec_fn=os.setsid, close_fds=True)

    if not is_pid_running(tunnel.pid):
        fatal_error('Failed to initialize TLS tunnel for %s' % state_file, 'Failed to start TLS tunnel.')

    logging.info('Started TLS tunnel, pid: %d', tunnel.pid)

    child_procs.append(tunnel)
    return tunnel.pid


def clean_up_mount_state(state_file_dir, state_file, pid, is_running):
    if is_running:
        process_group = os.getpgid(pid)
        logging.info('Terminating running TLS tunnel - PID: %d, group ID: %s', pid, process_group)
        os.killpg(process_group, SIGTERM)

    if is_pid_running(pid):
        logging.info('TLS tunnel: %d is still running, will retry termination', pid)
    else:
        logging.info('TLS tunnel: %d is no longer running, cleaning up state', pid)
        state_file_path = os.path.join(state_file_dir, state_file)
        with open(state_file_path) as f:
            state = json.load(f)

        for f in state.get('files', list()):
            logging.debug('Deleting %s', f)
            try:
                os.remove(f)
            except OSError as e:
                if e.errno != errno.ENOENT:
                    raise

        os.remove(state_file_path)


def rewrite_state_file(state, state_file_dir, state_file):
    tmp_state_file = os.path.join(state_file_dir, '~%s' % state_file)
    with open(tmp_state_file, 'w') as f:
        json.dump(state, f)

    os.rename(tmp_state_file, os.path.join(state_file_dir, state_file))


def mark_as_unmounted(state, state_file_dir, state_file, current_time):
    logging.debug('Marking %s as unmounted at %d', state_file, current_time)
    state['unmount_time'] = current_time

    rewrite_state_file(state, state_file_dir, state_file)

    return state


def restart_tls_tunnel(child_procs, state, state_file_dir, state_file):
    new_tunnel_pid = start_tls_tunnel(child_procs, state_file, state['cmd'])
    state['pid'] = new_tunnel_pid

    logging.debug('Rewriting %s with new pid: %d', state_file, new_tunnel_pid)
    rewrite_state_file(state, state_file_dir, state_file)


def check_efs_mounts(child_procs, unmount_grace_period_sec, state_file_dir=STATE_FILE_DIR):
    nfs_mounts = get_current_local_nfs_mounts()
    logging.debug('Current local NFS mounts: %s', list(nfs_mounts.values()))

    state_files = get_state_files(state_file_dir)
    logging.debug('Current state files in "%s": %s', state_file_dir, list(state_files.values()))

    for mount, state_file in state_files.items():
        state_file_path = os.path.join(state_file_dir, state_file)
        with open(state_file_path) as f:
            try:
                state = json.load(f)
            except ValueError:
                logging.exception('Unable to parse json in %s', state_file_path)
                continue

        is_running = is_pid_running(state['pid'])

        current_time = time.time()
        if 'unmount_time' in state:
            if state['unmount_time'] + unmount_grace_period_sec < current_time:
                logging.info('Unmount grace period expired for %s', state_file)
                clean_up_mount_state(state_file_dir, state_file, state['pid'], is_running)

        elif mount not in nfs_mounts:
            logging.info('No mount found for "%s"', state_file)
            state = mark_as_unmounted(state, state_file_dir, state_file, current_time)

        else:
            if is_running:
                logging.debug('TLS tunnel for %s is running', state_file)
            else:
                logging.warn('TLS tunnel for %s is not running', state_file)
                restart_tls_tunnel(child_procs, state, state_file_dir, state_file)


def check_child_procs(child_procs):
    for proc in child_procs:
        proc.poll()
        if proc.returncode is not None:
            logging.warn('Child TLS tunnel process %d has exited, returncode=%d', proc.pid, proc.returncode)
            child_procs.remove(proc)


def parse_arguments(args=None):
    if args is None:
        args = sys.argv

    if '-h' in args[1:] or '--help' in args[1:]:
        sys.stdout.write('Usage: %s [--version] [-h|--help]\n' % args[0])
        sys.exit(0)

    if '--version' in args[1:]:
        sys.stdout.write('%s Version: %s\n' % (args[0], VERSION))
        sys.exit(0)


def assert_root():
    if os.geteuid() != 0:
        sys.stderr.write('only root can run amazon-efs-mount-watchdog\n')
        sys.exit(1)


def read_config(config_file=CONFIG_FILE):
    p = ConfigParser.SafeConfigParser()
    p.read(config_file)
    return p


def main():
    parse_arguments()
    assert_root()

    config = read_config()
    bootstrap_logging(config)

    child_procs = []

    if config.getboolean(CONFIG_SECTION, 'enabled'):
        poll_interval_sec = config.getint(CONFIG_SECTION, 'poll_interval_sec')
        unmount_grace_period_sec = config.getint(CONFIG_SECTION, 'unmount_grace_period_sec')

        while True:
            check_efs_mounts(child_procs, unmount_grace_period_sec)
            check_child_procs(child_procs)

            time.sleep(poll_interval_sec)
    else:
        logging.info('amazon-efs-mount-watchdog is not enabled')


if '__main__' == __name__:
    main()
