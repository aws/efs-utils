#!/usr/bin/env python
#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#
#
# Copy this script to /sbin/mount.efs and make sure it is executable.
#
# You will be able to mount an EFS file system by its short name, by adding it
# to /etc/fstab. The syntax of an fstab entry is:
#
# [Device] [Mount Point] [File System Type] [Options] [Dump] [Pass]
#
# Add an entry like this:
#
#   fs-deadbeef     /mount_point    efs     _netdev         0   0
#
# Using the 'efs' type will cause '/sbin/mount.efs' to be called by 'mount -a'
# for this file system. The '_netdev' option tells the init system that the
# 'efs' type is a networked file system type. This has been tested with systemd
# (Amazon Linux 2, CentOS 7, RHEL 7, Debian 9, and Ubuntu 16.04), and upstart
# (Amazon Linux 2017.09).
#
# Once there is an entry in fstab, the file system can be mounted with:
#
#   sudo mount /mount_point
#
# The script will add recommended mount options, if not provided in fstab.

import json
import logging
import os
import random
import re
import socket
import subprocess
import sys
import threading

from contextlib import contextmanager
from logging.handlers import RotatingFileHandler

try:
    import ConfigParser
except ImportError:
    from configparser import ConfigParser

try:
    from urllib2 import urlopen, URLError
except ImportError:
    from urllib.error import URLError
    from urllib.request import urlopen

VERSION = '1.11'

CONFIG_FILE = '/etc/amazon/efs/efs-utils.conf'
CONFIG_SECTION = 'mount'

LOG_DIR = '/var/log/amazon/efs'
LOG_FILE = 'mount.log'

STATE_FILE_DIR = '/var/run/efs'

FS_ID_RE = re.compile('^(?P<fs_id>fs-[0-9a-f]+)$')
EFS_FQDN_RE = re.compile('^(?P<fs_id>fs-[0-9a-f]+)\.efs\.(?P<region>[a-z0-9-]+)\.amazonaws.com$')

INSTANCE_METADATA_SERVICE_URL = 'http://169.254.169.254/latest/dynamic/instance-identity/document/'

DEFAULT_STUNNEL_VERIFY_LEVEL = 2
DEFAULT_STUNNEL_CAFILE = '/etc/amazon/efs/efs-utils.crt'

EFS_ONLY_OPTIONS = [
    'tls',
    'tlsport',
    'verify',
    'ocsp',
    'noocsp'
]

UNSUPPORTED_OPTIONS = [
    'cafile',
    'capath',
]

STUNNEL_GLOBAL_CONFIG = {
    'fips': 'no',
    'foreground': 'yes',
    'socket': [
        'l:SO_REUSEADDR=yes',
        'a:SO_BINDTODEVICE=lo',
    ],
}

STUNNEL_EFS_CONFIG = {
    'client': 'yes',
    'accept': '127.0.0.1:%s',
    'connect': '%s:2049',
    'sslVersion': 'TLSv1.2',
    'renegotiation': 'no',
    'TIMEOUTbusy': '20',
    'TIMEOUTclose': '0',
    'delay': 'yes',
}

WATCHDOG_SERVICE = 'amazon-efs-mount-watchdog'
SYSTEM_RELEASE_PATH = '/etc/system-release'
RHEL8_RELEASE_NAME = 'Red Hat Enterprise Linux release 8'


def fatal_error(user_message, log_message=None, exit_code=1):
    if log_message is None:
        log_message = user_message

    sys.stderr.write('%s\n' % user_message)
    logging.error(log_message)
    sys.exit(exit_code)


def get_region():
    """Return this instance's region via the instance metadata service."""
    def _fatal_error(message):
        fatal_error('Error retrieving region', message)

    try:
        resource = urlopen(INSTANCE_METADATA_SERVICE_URL, timeout=1)

        if resource.getcode() != 200:
            _fatal_error('Unable to reach instance metadata service at %s: status=%d'
                         % (INSTANCE_METADATA_SERVICE_URL, resource.getcode()))

        data = resource.read()
        if type(data) is str:
            instance_identity = json.loads(data)
        else:
            instance_identity = json.loads(data.decode(resource.headers.get_content_charset() or 'us-ascii'))

        return instance_identity['region']
    except URLError as e:
        _fatal_error('Unable to reach the instance metadata service at %s. If this is an on-premises instance, replace '
                     '"{region}" in the "dns_name_format" option in %s with the region of the EFS file system you are mounting.\n'
                     'See %s for more detail. %s'
                     % (INSTANCE_METADATA_SERVICE_URL, CONFIG_FILE, 'https://docs.aws.amazon.com/console/efs/direct-connect', e))
    except ValueError as e:
        _fatal_error('Error parsing json: %s' % (e,))
    except KeyError as e:
        _fatal_error('Region not present in %s: %s' % (instance_identity, e))


def parse_options(options):
    opts = {}
    for o in options.split(','):
        if '=' in o:
            k, v = o.split('=')
            opts[k] = v
        else:
            opts[o] = None
    return opts


def get_tls_port_range(config):
    lower_bound = config.getint(CONFIG_SECTION, 'port_range_lower_bound')
    upper_bound = config.getint(CONFIG_SECTION, 'port_range_upper_bound')

    if lower_bound >= upper_bound:
        fatal_error('Configuration option "port_range_upper_bound" defined as %d '
                    'must be strictly greater than "port_range_lower_bound" defined as %d.'
                    % (upper_bound, lower_bound))

    return lower_bound, upper_bound


def choose_tls_port(config, options):
    if 'tlsport' in options:
        try:
            ports_to_try = [int(options['tlsport'])]
        except ValueError:
            fatal_error('tlsport option [%s] is not an integer' % options['tlsport'])
    else:
        lower_bound, upper_bound = get_tls_port_range(config)

        tls_ports = list(range(lower_bound, upper_bound))

        # Choose a random midpoint, and then try ports in-order from there
        mid = random.randrange(len(tls_ports))

        ports_to_try = tls_ports[mid:] + tls_ports[:mid]
        assert len(tls_ports) == len(ports_to_try)

    sock = socket.socket()
    for tls_port in ports_to_try:
        try:
            sock.bind(('localhost', tls_port))
            sock.close()
            return tls_port
        except socket.error:
            continue

    sock.close()

    if 'tlsport' in options:
        fatal_error('Specified port [%s] is unavailable. Try selecting a different port.' % options['tlsport'])
    else:
        fatal_error('Failed to locate an available port in the range [%d, %d], try specifying a different port range in %s'
                    % (lower_bound, upper_bound, CONFIG_FILE))


def is_ocsp_enabled(config, options):
    if 'ocsp' in options and 'noocsp' in options:
        fatal_error('The "ocsp" and "noocsp" options are mutually exclusive')
    elif 'ocsp' in options:
        return True
    elif 'noocsp' in options:
        return False
    else:
        return config.getboolean(CONFIG_SECTION, 'stunnel_check_cert_validity')


def get_mount_specific_filename(fs_id, mountpoint, tls_port):
    return '%s.%s.%d' % (fs_id, os.path.abspath(mountpoint).replace(os.sep, '.').lstrip('.'), tls_port)


def serialize_stunnel_config(config, header=None):
    lines = []

    if header:
        lines.append('[%s]' % header)

    for k, v in config.items():
        if type(v) is list:
            for item in v:
                lines.append('%s = %s' % (k, item))
        else:
            lines.append('%s = %s' % (k, v))

    return lines


def add_stunnel_ca_options(efs_config, stunnel_cafile=DEFAULT_STUNNEL_CAFILE):
    if not os.path.exists(stunnel_cafile):
        fatal_error('Failed to find the EFS certificate authority file for verification',
                    'Failed to find the EFS CAfile "%s"' % stunnel_cafile)
    efs_config['CAfile'] = stunnel_cafile


def is_stunnel_option_supported(stunnel_output, stunnel_option_name):
    supported = False
    for line in stunnel_output:
        if line.startswith(stunnel_option_name):
            supported = True
            break

    if not supported:
        logging.warn('stunnel does not support "%s"', stunnel_option_name)

    return supported


def get_version_specific_stunnel_options(config):
    proc = subprocess.Popen(['stunnel', '-help'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
    proc.wait()
    _, err = proc.communicate()

    stunnel_output = err.splitlines()

    check_host_supported = is_stunnel_option_supported(stunnel_output, 'checkHost')
    ocsp_aia_supported = is_stunnel_option_supported(stunnel_output, 'OCSPaia')

    return check_host_supported, ocsp_aia_supported


def get_system_release_version():
    system_release_version = 'unknown'
    try:
        with open(SYSTEM_RELEASE_PATH) as f:
            system_release_version = f.read().strip()
    except IOError:
        logging.debug('Unable to read %s', SYSTEM_RELEASE_PATH)

    return system_release_version


def write_stunnel_config_file(config, state_file_dir, fs_id, mountpoint, tls_port, dns_name, verify_level, ocsp_enabled,
                              log_dir=LOG_DIR):
    """
    Serializes stunnel configuration to a file. Unfortunately this does not conform to Python's config file format, so we have to
    hand-serialize it.
    """

    mount_filename = get_mount_specific_filename(fs_id, mountpoint, tls_port)

    global_config = dict(STUNNEL_GLOBAL_CONFIG)
    if config.getboolean(CONFIG_SECTION, 'stunnel_debug_enabled'):
        global_config['debug'] = 'debug'
        global_config['output'] = os.path.join(log_dir, '%s.stunnel.log' % mount_filename)

    efs_config = dict(STUNNEL_EFS_CONFIG)
    efs_config['accept'] = efs_config['accept'] % tls_port
    efs_config['connect'] = efs_config['connect'] % dns_name
    efs_config['verify'] = verify_level
    if verify_level > 0:
        add_stunnel_ca_options(efs_config)

    check_host_supported, ocsp_aia_supported = get_version_specific_stunnel_options(config)

    tls_controls_message = 'WARNING: Your client lacks sufficient controls to properly enforce TLS. Please upgrade stunnel, ' \
        'or disable "%%s" in %s.\nSee %s for more detail.' % (CONFIG_FILE,
                                                              'https://docs.aws.amazon.com/console/efs/troubleshooting-tls')

    if config.getboolean(CONFIG_SECTION, 'stunnel_check_cert_hostname'):
        if check_host_supported:
            efs_config['checkHost'] = dns_name
        else:
            fatal_error(tls_controls_message % 'stunnel_check_cert_hostname')

    # Only use the config setting if the override is not set
    if ocsp_enabled:
        if ocsp_aia_supported:
            efs_config['OCSPaia'] = 'yes'
        else:
            fatal_error(tls_controls_message % 'stunnel_check_cert_validity')

    if RHEL8_RELEASE_NAME not in get_system_release_version():
        efs_config['libwrap'] = 'no'

    stunnel_config = '\n'.join(serialize_stunnel_config(global_config) + serialize_stunnel_config(efs_config, 'efs'))
    logging.debug('Writing stunnel configuration:\n%s', stunnel_config)

    stunnel_config_file = os.path.join(state_file_dir, 'stunnel-config.%s' % mount_filename)

    with open(stunnel_config_file, 'w') as f:
        f.write(stunnel_config)

    return stunnel_config_file


def write_tls_tunnel_state_file(fs_id, mountpoint, tls_port, tunnel_pid, command, files, state_file_dir):
    """
    Return the name of the temporary file containing TLS tunnel state, prefixed with a '~'. This file needs to be renamed to a
    non-temporary version following a successful mount.
    """
    state_file = '~' + get_mount_specific_filename(fs_id, mountpoint, tls_port)

    state = {
        'pid': tunnel_pid,
        'cmd': command,
        'files': files,
    }

    with open(os.path.join(state_file_dir, state_file), 'w') as f:
        json.dump(state, f)

    return state_file


def test_tunnel_process(tunnel_proc, fs_id):
    tunnel_proc.poll()
    if tunnel_proc.returncode is not None:
        out, err = tunnel_proc.communicate()
        fatal_error('Failed to initialize TLS tunnel for %s' % fs_id,
                    'Failed to start TLS tunnel (errno=%d). stdout="%s" stderr="%s"'
                    % (tunnel_proc.returncode, out.strip(), err.strip()))


def poll_tunnel_process(tunnel_proc, fs_id, mount_completed):
    """
    poll the tunnel process health every .5s during the mount attempt to fail fast if the tunnel dies - since this is not called
    from the main thread, if the tunnel fails, exit uncleanly with os._exit
    """
    while not mount_completed.is_set():
        try:
            test_tunnel_process(tunnel_proc, fs_id)
        except SystemExit as e:
            os._exit(e.code)
        mount_completed.wait(.5)


def get_init_system(comm_file='/proc/1/comm'):
    init_system = 'unknown'
    try:
        with open(comm_file) as f:
            init_system = f.read().strip()
    except IOError:
        logging.warning('Unable to read %s', comm_file)

    logging.debug('Identified init system: %s', init_system)
    return init_system


def check_network_status(fs_id, init_system):
    if init_system != 'systemd':
        logging.debug('Not testing network on non-systemd init systems')
        return

    with open(os.devnull, 'w') as devnull:
        rc = subprocess.call(['systemctl', 'status', 'network.target'], stdout=devnull, stderr=devnull, close_fds=True)

    if rc != 0:
        fatal_error('Failed to mount %s because the network was not yet available, add "_netdev" to your mount options' % fs_id,
                    exit_code=0)


def start_watchdog(init_system):
    if init_system == 'init':
        proc = subprocess.Popen(
                ['/sbin/status', WATCHDOG_SERVICE], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        status, _ = proc.communicate()
        if 'stop' in status:
            with open(os.devnull, 'w') as devnull:
                subprocess.Popen(['/sbin/start', WATCHDOG_SERVICE], stdout=devnull, stderr=devnull, close_fds=True)
        elif 'start' in status:
            logging.debug('%s is already running', WATCHDOG_SERVICE)

    elif init_system == 'systemd':
        rc = subprocess.call(['systemctl', 'is-active', '--quiet', WATCHDOG_SERVICE], close_fds=True)
        if rc != 0:
            with open(os.devnull, 'w') as devnull:
                subprocess.Popen(['systemctl', 'start', WATCHDOG_SERVICE], stdout=devnull, stderr=devnull, close_fds=True)
        else:
            logging.debug('%s is already running', WATCHDOG_SERVICE)

    else:
        error_message = 'Could not start %s, unrecognized init system "%s"' % (WATCHDOG_SERVICE, init_system)
        sys.stderr.write('%s\n' % error_message)
        logging.warning(error_message)


def create_state_file_dir(config, state_file_dir):
    mode = 0o750
    try:
        mode_str = config.get(CONFIG_SECTION, 'state_file_dir_mode')
        try:
            mode = int(mode_str, 8)
        except ValueError:
            logging.warn('Bad state_file_dir_mode "%s" in config file "%s"', mode_str, CONFIG_FILE)
    except ConfigParser.NoOptionError:
        pass

    os.makedirs(state_file_dir, mode)


@contextmanager
def bootstrap_tls(config, init_system, dns_name, fs_id, mountpoint, options, state_file_dir=STATE_FILE_DIR):
    start_watchdog(init_system)

    if not os.path.exists(state_file_dir):
        create_state_file_dir(config, state_file_dir)

    tls_port = choose_tls_port(config, options)

    # override the tlsport option so that we can later override the port the NFS client uses to connect to stunnel.
    # if the user has specified tlsport=X at the command line this will just re-set tlsport to X.
    options['tlsport'] = tls_port

    verify_level = int(options.get('verify', DEFAULT_STUNNEL_VERIFY_LEVEL))
    ocsp_enabled = is_ocsp_enabled(config, options)

    stunnel_config_file = write_stunnel_config_file(config, state_file_dir, fs_id, mountpoint, tls_port, dns_name, verify_level,
                                                    ocsp_enabled)

    tunnel_args = ['stunnel', stunnel_config_file]

    # launch the tunnel in a process group so if it has any child processes, they can be killed easily by the mount watchdog
    logging.info('Starting TLS tunnel: "%s"', ' '.join(tunnel_args))
    tunnel_proc = subprocess.Popen(
            tunnel_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid, close_fds=True)
    logging.info('Started TLS tunnel, pid: %d', tunnel_proc.pid)

    temp_tls_state_file = write_tls_tunnel_state_file(fs_id, mountpoint, tls_port, tunnel_proc.pid, tunnel_args,
                                                      [stunnel_config_file], state_file_dir)

    try:
        yield tunnel_proc
    finally:
        os.rename(os.path.join(state_file_dir, temp_tls_state_file), os.path.join(state_file_dir, temp_tls_state_file[1:]))


def get_nfs_mount_options(options):
    # If you change these options, update the man page as well at man/mount.efs.8
    if 'nfsvers' not in options and 'vers' not in options:
        options['nfsvers'] = '4.1'
    if 'rsize' not in options:
        options['rsize'] = '1048576'
    if 'wsize' not in options:
        options['wsize'] = '1048576'
    if 'soft' not in options and 'hard' not in options:
        options['hard'] = None
    if 'timeo' not in options:
        options['timeo'] = '600'
    if 'retrans' not in options:
        options['retrans'] = '2'
    if 'noresvport' not in options:
        options['noresvport'] = None

    if 'tls' in options:
        if 'port' in options:
            fatal_error('The "port" and "tls" options are mutually exclusive')
        options['port'] = options['tlsport']

    def to_nfs_option(k, v):
        if v is None:
            return k
        return '%s=%s' % (str(k), str(v))

    nfs_options = [to_nfs_option(k, v) for k, v in options.items() if k not in EFS_ONLY_OPTIONS]

    return ','.join(nfs_options)


def mount_nfs(dns_name, path, mountpoint, options):
    if 'tls' in options:
        mount_path = '127.0.0.1:%s' % path
    else:
        mount_path = '%s:%s' % (dns_name, path)

    command = ['/sbin/mount.nfs4', mount_path, mountpoint, '-o', get_nfs_mount_options(options)]

    logging.info('Executing: "%s"', ' '.join(command))

    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
    out, err = proc.communicate()

    if proc.returncode == 0:
        logging.info('Successfully mounted %s at %s', dns_name, mountpoint)
    else:
        message = 'Failed to mount %s at %s: returncode=%d, stderr="%s"' % (dns_name, mountpoint, proc.returncode, err.strip())
        fatal_error(err.strip(), message, proc.returncode)


def usage(out, exit_code=1):
    out.write('Usage: mount.efs [--version] [-h|--help] <fsname> <mountpoint> [-o <options>]\n')
    sys.exit(exit_code)


def parse_arguments_early_exit(args=None):
    """Parse arguments, checking for early exit conditions only"""
    if args is None:
        args = sys.argv

    if '-h' in args[1:] or '--help' in args[1:]:
        usage(out=sys.stdout, exit_code=0)

    if '--version' in args[1:]:
        sys.stdout.write('%s Version: %s\n' % (args[0], VERSION))
        sys.exit(0)


def parse_arguments(config, args=None):
    """Parse arguments, return (fsid, path, mountpoint, options)"""
    if args is None:
        args = sys.argv

    fsname = None
    mountpoint = None
    options = {}

    if len(args) > 1:
        fsname = args[1]
    if len(args) > 2:
        mountpoint = args[2]
    if len(args) > 4 and '-o' in args[:-1]:
        options_index = args.index('-o') + 1
        options = parse_options(args[options_index])

    if not fsname or not mountpoint:
        usage(out=sys.stderr)

    fs_id, path = match_device(config, fsname)

    return fs_id, path, mountpoint, options


def assert_root():
    if os.geteuid() != 0:
        sys.stderr.write('only root can run mount.efs\n')
        sys.exit(1)


def read_config(config_file=CONFIG_FILE):
    p = ConfigParser.SafeConfigParser()
    p.read(config_file)
    return p


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


def get_dns_name(config, fs_id):
    def _validate_replacement_field_count(format_str, expected_ct):
        if format_str.count('{') != expected_ct or format_str.count('}') != expected_ct:
            raise ValueError('DNS name format has an incorrect number of replacement fields')

    dns_name_format = config.get(CONFIG_SECTION, 'dns_name_format')

    if '{fs_id}' not in dns_name_format:
        raise ValueError('DNS name format must include {fs_id}')

    format_args = {'fs_id': fs_id}

    if '{region}' in dns_name_format:
        _validate_replacement_field_count(dns_name_format, 2)
        format_args['region'] = get_region()
    else:
        _validate_replacement_field_count(dns_name_format, 1)

    dns_name = dns_name_format.format(**format_args)

    try:
        socket.gethostbyname(dns_name)
    except socket.gaierror:
        fatal_error('Failed to resolve "%s" - check that your file system ID is correct.\nSee %s for more detail.'
                    % (dns_name, 'https://docs.aws.amazon.com/console/efs/mount-dns-name'),
                    'Failed to resolve "%s"' % dns_name)

    return dns_name


def match_device(config, device):
    """Return the EFS id and the remote path to mount"""

    try:
        remote, path = device.split(':', 1)
    except ValueError:
        remote = device
        path = '/'

    if FS_ID_RE.match(remote):
        return remote, path

    try:
        primary, secondaries, _ = socket.gethostbyname_ex(remote)
        hostnames = filter(lambda e: e is not None, [primary] + secondaries)
    except socket.gaierror:
        fatal_error(
            'Failed to resolve "%s" - check that the specified DNS name is a CNAME record resolving to a valid EFS DNS '
            'name' % remote,
            'Failed to resolve "%s"' % remote
        )

    if not hostnames:
        fatal_error(
            'The specified domain name "%s" did not resolve to an EFS mount target' % remote
        )

    for hostname in hostnames:
        efs_fqdn_match = EFS_FQDN_RE.match(hostname)

        if efs_fqdn_match:
            fs_id = efs_fqdn_match.group('fs_id')
            expected_dns_name = get_dns_name(config, fs_id)

            # check that the DNS name of the mount target matches exactly the DNS name the CNAME resolves to
            if hostname == expected_dns_name:
                return fs_id, path
    else:
        fatal_error('The specified CNAME "%s" did not resolve to a valid DNS name for an EFS mount target. '
                    'Please refer to the EFS documentation for mounting with DNS names for examples: %s'
                    % (remote, 'https://docs.aws.amazon.com/efs/latest/ug/mounting-fs-mount-cmd-dns-name.html'))


def mount_tls(config, init_system, dns_name, path, fs_id, mountpoint, options):
    with bootstrap_tls(config, init_system, dns_name, fs_id, mountpoint, options) as tunnel_proc:
        mount_completed = threading.Event()
        t = threading.Thread(target=poll_tunnel_process, args=(tunnel_proc, fs_id, mount_completed))
        t.start()
        mount_nfs(dns_name, path, mountpoint, options)
        mount_completed.set()
        t.join()


def check_unsupported_options(options):
    for unsupported_option in UNSUPPORTED_OPTIONS:
        if unsupported_option in options:
            warn_message = 'The "%s" option is not supported and has been ignored, as amazon-efs-utils relies on a built-in ' \
                           'trust store.' % unsupported_option
            sys.stderr.write('WARN: %s\n' % warn_message)
            logging.warn(warn_message)
            del options[unsupported_option]


def main():
    parse_arguments_early_exit()

    assert_root()

    config = read_config()
    bootstrap_logging(config)

    fs_id, path, mountpoint, options = parse_arguments(config)

    logging.info('version=%s options=%s', VERSION, options)
    check_unsupported_options(options)

    init_system = get_init_system()
    check_network_status(fs_id, init_system)

    dns_name = get_dns_name(config, fs_id)

    if 'tls' in options:
        mount_tls(config, init_system, dns_name, path, fs_id, mountpoint, options)
    else:
        mount_nfs(dns_name, path, mountpoint, options)


if '__main__' == __name__:
    main()
