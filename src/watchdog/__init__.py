#!/usr/bin/env python
#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import base64
import errno
import hashlib
import hmac
import json
import logging
import logging.handlers
import os
import pwd
import re
import shutil
import subprocess
import sys
import time

from collections import namedtuple
from contextlib import contextmanager
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler
from signal import SIGTERM, SIGHUP

try:
    import ConfigParser
    from ConfigParser import NoOptionError, NoSectionError
except ImportError:
    from configparser import ConfigParser, NoOptionError, NoSectionError

try:
    from urllib.parse import quote_plus
except ImportError:
    from urllib import quote_plus

try:
    from urllib2 import urlopen, URLError
except ImportError:
    from urllib.error import URLError
    from urllib.request import urlopen

VERSION = '1.21'
SERVICE = 'elasticfilesystem'

CONFIG_FILE = '/etc/amazon/efs/efs-utils.conf'
CONFIG_SECTION = 'mount-watchdog'

LOG_DIR = '/var/log/amazon/efs'
LOG_FILE = 'mount-watchdog.log'

STATE_FILE_DIR = '/var/run/efs'

PRIVATE_KEY_FILE = '/etc/amazon/efs/privateKey.pem'
REFRESH_SELF_SIGNED_CERT_INTERVAL_SEC = 60 * 60
NOT_BEFORE_MINS = 15
NOT_AFTER_HOURS = 3
DATE_ONLY_FORMAT = '%Y%m%d'
SIGV4_DATETIME_FORMAT = '%Y%m%dT%H%M%SZ'
CERT_DATETIME_FORMAT = '%y%m%d%H%M%SZ'

AWS_CREDENTIALS_FILES = {
    'credentials': os.path.expanduser(os.path.join('~' + pwd.getpwuid(os.getuid()).pw_name, '.aws', 'credentials')),
    'config': os.path.expanduser(os.path.join('~' + pwd.getpwuid(os.getuid()).pw_name, '.aws', 'config')),
}

CA_CONFIG_BODY = """dir = %s
RANDFILE = $dir/database/.rand

[ ca ]
default_ca = local_ca

[ local_ca ]
database = $dir/database/index.txt
serial = $dir/database/serial
private_key = %s
cert = $dir/certificate.pem
new_certs_dir = $dir/certs
default_md = sha256
preserve = no
policy = efsPolicy
x509_extensions = v3_ca

[ efsPolicy ]
CN = supplied

[ req ]
prompt = no
distinguished_name = req_distinguished_name

[ req_distinguished_name ]
CN = %s

%s

%s
"""

# SigV4 Auth
ALGORITHM = 'AWS4-HMAC-SHA256'
AWS4_REQUEST = 'aws4_request'

HTTP_REQUEST_METHOD = 'GET'
CANONICAL_URI = '/'
CANONICAL_HEADERS_DICT = {
    'host': '%s'
}
CANONICAL_HEADERS = '\n'.join(['%s:%s' % (k, v) for k, v in sorted(CANONICAL_HEADERS_DICT.items())])
SIGNED_HEADERS = ';'.join(CANONICAL_HEADERS_DICT.keys())
REQUEST_PAYLOAD = ''

AP_ID_RE = re.compile('^fsap-[0-9a-f]{17}$')

ECS_TASK_METADATA_API = '169.254.170.2'
INSTANCE_IAM_URL = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'
SECURITY_CREDS_ECS_URI_HELP_URL = 'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html'
SECURITY_CREDS_IAM_ROLE_HELP_URL = 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html'

Mount = namedtuple('Mount', ['server', 'mountpoint', 'type', 'options', 'freq', 'passno'])


def fatal_error(user_message, log_message=None):
    if log_message is None:
        log_message = user_message

    sys.stderr.write('%s\n' % user_message)
    logging.error(log_message)
    sys.exit(1)


def get_aws_security_credentials(credentials_source):
    """
    Lookup AWS security credentials (access key ID and secret access key). Adapted credentials provider chain from:
    https://boto3.amazonaws.com/v1/documentation/api/latest/guide/configuration.html and
    https://docs.aws.amazon.com/sdk-for-java/v1/developer-guide/credentials.html
    """
    method, value = credentials_source.split(':', 1)

    if method == 'credentials':
        return get_aws_security_credentials_from_file('credentials', value)
    elif method == 'config':
        return get_aws_security_credentials_from_file('config', value)
    elif method == 'ecs':
        return get_aws_security_credentials_from_ecs(value)
    elif method == 'metadata':
        return get_aws_security_credentials_from_instance_metadata()
    else:
        logging.error('Improper credentials source string "%s" found from mount state file', credentials_source)
        return None


def get_aws_security_credentials_from_file(file_name, awsprofile):
    # attempt to lookup AWS security credentials in AWS credentials file (~/.aws/credentials) and configs file (~/.aws/config)
    file_path = AWS_CREDENTIALS_FILES.get(file_name)
    if file_path and os.path.exists(file_path):
        credentials = credentials_file_helper(file_path, awsprofile)
        if credentials['AccessKeyId']:
            return credentials

    logging.error('AWS security credentials not found in %s under named profile [%s]', file_path, awsprofile)
    return None


def get_aws_security_credentials_from_ecs(uri):
    # through ECS security credentials uri found in AWS_CONTAINER_CREDENTIALS_RELATIVE_URI environment variable
    dict_keys = ['AccessKeyId', 'SecretAccessKey', 'Token']
    ecs_uri = ECS_TASK_METADATA_API + uri
    ecs_unsuccessful_resp = 'Unsuccessful retrieval of AWS security credentials at %s.' % ecs_uri
    ecs_url_error_msg = 'Unable to reach %s to retrieve AWS security credentials. See %s for more info.', ecs_uri, \
                        SECURITY_CREDS_ECS_URI_HELP_URL
    ecs_security_dict = url_request_helper(ecs_uri, ecs_unsuccessful_resp, ecs_url_error_msg)

    if ecs_security_dict and all(k in ecs_security_dict for k in dict_keys):
        return ecs_security_dict

    return None


def get_aws_security_credentials_from_instance_metadata():
    # through IAM role name security credentials lookup uri (after lookup for IAM role name attached to instance)
    dict_keys = ['AccessKeyId', 'SecretAccessKey', 'Token']
    iam_role_unsuccessful_resp = 'Unsuccessful retrieval of IAM role name at %s.' % INSTANCE_IAM_URL
    iam_role_url_error_msg = 'Unable to reach %s to retrieve IAM role name. See %s for more info.', INSTANCE_IAM_URL, \
                             SECURITY_CREDS_IAM_ROLE_HELP_URL
    iam_role_name = url_request_helper(INSTANCE_IAM_URL, iam_role_unsuccessful_resp, iam_role_url_error_msg)
    if iam_role_name:
        security_creds_lookup_url = INSTANCE_IAM_URL + str(iam_role_name)
        unsuccessful_resp = 'Unsuccessful retrieval of AWS security credentials at %s.' % security_creds_lookup_url
        url_error_msg = 'Unable to reach %s to retrieve AWS security credentials. See %s for more info.', \
                        security_creds_lookup_url, SECURITY_CREDS_IAM_ROLE_HELP_URL
        iam_security_dict = url_request_helper(security_creds_lookup_url, unsuccessful_resp, url_error_msg)

        if iam_security_dict and all(k in iam_security_dict for k in dict_keys):
            return iam_security_dict

    return None


def credentials_file_helper(file_path, awsprofile):
    aws_credentials_configs = read_config(file_path)
    credentials = {'AccessKeyId': None, 'SecretAccessKey': None, 'Token': None}

    try:
        aws_access_key_id = aws_credentials_configs.get(awsprofile, 'aws_access_key_id')
        secret_access_key = aws_credentials_configs.get(awsprofile, 'aws_secret_access_key')
        session_token = aws_credentials_configs.get(awsprofile, 'aws_session_token')

        credentials['AccessKeyId'] = aws_access_key_id
        credentials['SecretAccessKey'] = secret_access_key
        credentials['Token'] = session_token
    except NoOptionError as e:
        if 'aws_access_key_id' in str(e) or 'aws_secret_access_key' in str(e):
            logging.debug('aws_access_key_id or aws_secret_access_key not found in %s under named profile [%s]', file_path,
                          awsprofile)
        if 'aws_session_token' in str(e):
            logging.debug('aws_session_token not found in %s', file_path)
            credentials['AccessKeyId'] = aws_credentials_configs.get(awsprofile, 'aws_access_key_id')
            credentials['SecretAccessKey'] = aws_credentials_configs.get(awsprofile, 'aws_secret_access_key')
    except NoSectionError:
        logging.debug('No [%s] section found in config file %s', awsprofile, file_path)

    return credentials


def url_request_helper(url, unsuccessful_resp, url_error_msg):
    try:
        request_resp = urlopen(url, timeout=1)

        if request_resp.getcode() != 200:
            logging.debug(unsuccessful_resp + ' %s: ResponseCode=%d', url, request_resp.getcode())
            return None

        resp_body = request_resp.read()
        try:
            if type(resp_body) is str:
                resp_dict = json.loads(resp_body)
            else:
                resp_dict = json.loads(resp_body.decode(request_resp.headers.get_content_charset() or 'us-ascii'))

            return resp_dict
        except ValueError as e:
            logging.debug('Error parsing json: %s, returning raw response body: %s' % (e, str(resp_body)))
            return resp_body

    except URLError as e:
        logging.debug('%s %s', url_error_msg, e)
        return None


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
            if not sf.startswith('fs-') or os.path.isdir(os.path.join(state_file_dir, sf)):
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


def clean_up_mount_state(state_file_dir, state_file, pid, is_running, mount_state_dir=None):
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
                logging.debug('Deleted %s', f)
            except OSError as e:
                if e.errno != errno.ENOENT:
                    raise

        os.remove(state_file_path)

        if mount_state_dir is not None:
            mount_state_dir_abs_path = os.path.join(state_file_dir, mount_state_dir)
            if os.path.isdir(mount_state_dir_abs_path):
                shutil.rmtree(mount_state_dir_abs_path)
            else:
                logging.debug('Attempt to remove mount state directory %s failed. Directory is not present.',
                              mount_state_dir_abs_path)


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
    if 'certificate' in state and not os.path.exists(state['certificate']):
        logging.error('Cannot restart stunnel because self-signed certificate at %s is missing' % state['certificate'])
        return

    new_tunnel_pid = start_tls_tunnel(child_procs, state_file, state['cmd'])
    state['pid'] = new_tunnel_pid

    logging.debug('Rewriting %s with new pid: %d', state_file, new_tunnel_pid)
    rewrite_state_file(state, state_file_dir, state_file)


def check_efs_mounts(config, child_procs, unmount_grace_period_sec, state_file_dir=STATE_FILE_DIR):
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
                clean_up_mount_state(state_file_dir, state_file, state['pid'], is_running, state.get('mountStateDir'))

        elif mount not in nfs_mounts:
            logging.info('No mount found for "%s"', state_file)
            state = mark_as_unmounted(state, state_file_dir, state_file, current_time)

        else:
            if 'certificate' in state:
                check_certificate(config, state, state_file_dir, state_file)

            if is_running:
                logging.debug('TLS tunnel for %s is running', state_file)
            else:
                logging.warning('TLS tunnel for %s is not running', state_file)
                restart_tls_tunnel(child_procs, state, state_file_dir, state_file)


def check_child_procs(child_procs):
    for proc in child_procs:
        proc.poll()
        if proc.returncode is not None:
            logging.warning('Child TLS tunnel process %d has exited, returncode=%d', proc.pid, proc.returncode)
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
    try:
        p = ConfigParser.SafeConfigParser()
    except AttributeError:
        p = ConfigParser()
    p.read(config_file)
    return p


def check_certificate(config, state, state_file_dir, state_file, base_path=STATE_FILE_DIR):
    certificate_creation_time = datetime.strptime(state['certificateCreationTime'], CERT_DATETIME_FORMAT)
    certificate_exists = os.path.isfile(state['certificate'])
    # creation instead of NOT_BEFORE datetime is used for refresh of cert because NOT_BEFORE derives from creation datetime
    should_refresh_cert = (get_utc_now() - certificate_creation_time).total_seconds() > REFRESH_SELF_SIGNED_CERT_INTERVAL_SEC

    if certificate_exists and not should_refresh_cert:
        return

    ap_state = state.get('accessPoint')
    if ap_state and not AP_ID_RE.match(ap_state):
        logging.error('Access Point ID "%s" has been changed in the state file to a malformed format' % ap_state)
        return

    if not certificate_exists:
        logging.debug('Certificate (at %s) is missing. Recreating self-signed certificate' % state['certificate'])
    else:
        logging.debug('Refreshing self-signed certificate (at %s)' % state['certificate'])

    credentials_source = state.get('awsCredentialsMethod')
    updated_certificate_creation_time = recreate_certificate(config, state['mountStateDir'], state['commonName'], state['fsId'],
                                                             credentials_source, ap_state, state['region'], base_path=base_path)
    if updated_certificate_creation_time:
        state['certificateCreationTime'] = updated_certificate_creation_time
        rewrite_state_file(state, state_file_dir, state_file)

        # send SIGHUP to force a reload of the configuration file to trigger the stunnel process to notice the new certificate
        if is_pid_running(state['pid']):
            process_group = os.getpgid(state['pid'])
            logging.info('SIGHUP signal to stunnel. PID: %d, group ID: %s', state['pid'], process_group)
            os.killpg(process_group, SIGHUP)

        if not is_pid_running(state['pid']):
            logging.warning('TLS tunnel is not running for %s', state_file)


def create_required_directory(config, directory):
    mode = 0o750
    try:
        mode_str = config.get(CONFIG_SECTION, 'state_file_dir_mode')
        try:
            mode = int(mode_str, 8)
        except ValueError:
            logging.warning('Bad state_file_dir_mode "%s" in config file "%s"', mode_str, CONFIG_FILE)
    except NoOptionError:
        pass

    try:
        os.makedirs(directory, mode)
        logging.debug('Expected %s not found, recreating asset', directory)
    except OSError as e:
        if errno.EEXIST != e.errno or not os.path.isdir(directory):
            raise


def recreate_certificate(config, mount_name, common_name, fs_id, credentials_source, ap_id, region,
                         base_path=STATE_FILE_DIR):
    current_time = get_utc_now()
    tls_paths = tls_paths_dictionary(mount_name, base_path)

    certificate_config = os.path.join(tls_paths['mount_dir'], 'config.conf')
    certificate_signing_request = os.path.join(tls_paths['mount_dir'], 'request.csr')
    certificate = os.path.join(tls_paths['mount_dir'], 'certificate.pem')

    ca_dirs_check(config, tls_paths['database_dir'], tls_paths['certs_dir'])
    ca_supporting_files_check(tls_paths['index'], tls_paths['index_attr'], tls_paths['serial'], tls_paths['rand'])

    private_key = check_and_create_private_key(base_path)

    if credentials_source:
        public_key = os.path.join(tls_paths['mount_dir'], 'publicKey.pem')
        create_public_key(private_key, public_key)

    config_body = create_ca_conf(certificate_config, common_name, tls_paths['mount_dir'], private_key, current_time, region,
                                 fs_id, credentials_source, ap_id=ap_id)

    if not config_body:
        logging.error('Cannot recreate self-signed certificate')
        return None

    create_certificate_signing_request(certificate_config, private_key, certificate_signing_request)

    not_before = get_certificate_timestamp(current_time, minutes=-NOT_BEFORE_MINS)
    not_after = get_certificate_timestamp(current_time, hours=NOT_AFTER_HOURS)

    cmd = 'openssl ca -startdate %s -enddate %s -selfsign -batch -notext -config %s -in %s -out %s' % \
          (not_before, not_after, certificate_config, certificate_signing_request, certificate)
    subprocess_call(cmd, 'Failed to create self-signed client-side certificate')
    return current_time.strftime(CERT_DATETIME_FORMAT)


def get_private_key_path():
    """Wrapped for mocking purposes in unit tests"""
    return PRIVATE_KEY_FILE


def check_and_create_private_key(base_path=STATE_FILE_DIR):
    # Creating RSA private keys is slow, so we will create one private key and allow mounts to share it.
    # This means, however, that we have to include a locking mechanism to ensure that the private key is
    # atomically created, as mounts occurring in parallel may try to create the key simultaneously.
    # The key should have been created during mounting, but the watchdog will recreate the private key if
    # it is missing.
    key = get_private_key_path()

    @contextmanager
    def open_lock_file():
        lock_file = os.path.join(base_path, 'efs-utils-lock')
        f = os.open(lock_file, os.O_CREAT | os.O_DSYNC | os.O_EXCL | os.O_RDWR)
        try:
            lock_file_contents = 'PID: %s' % os.getpid()
            os.write(f, lock_file_contents.encode('utf-8'))
            yield f
        finally:
            os.close(f)
            os.remove(lock_file)

    def do_with_lock(function):
        while True:
            try:
                with open_lock_file():
                    return function()
            except OSError as e:
                if e.errno == errno.EEXIST:
                    logging.info('Failed to take out private key creation lock, sleeping 50 ms')
                    time.sleep(0.05)
                else:
                    raise

    def generate_key():
        if os.path.isfile(key):
            return

        cmd = 'openssl genpkey -algorithm RSA -out %s -pkeyopt rsa_keygen_bits:3072' % key
        subprocess_call(cmd, 'Failed to create private key')
        read_only_mode = 0o400
        os.chmod(key, read_only_mode)

    do_with_lock(generate_key)
    return key


def create_certificate_signing_request(config_path, key_path, csr_path):
    cmd = 'openssl req -new -config %s -key %s -out %s' % (config_path, key_path, csr_path)
    subprocess_call(cmd, 'Failed to create certificate signing request (csr)')


def create_ca_conf(config_path, common_name, directory, private_key, date, region, fs_id, credentials_source,
                   ap_id=None):
    """Populate ca/req configuration file with fresh configurations at every mount since SigV4 signature can change"""
    public_key_path = os.path.join(directory, 'publicKey.pem')
    security_credentials = get_aws_security_credentials(credentials_source) if credentials_source else ''

    if credentials_source and security_credentials is None:
        logging.error('Failed to retrieve AWS security credentials using lookup method: %s', credentials_source)
        return None

    ca_extension_body = ca_extension_builder(ap_id, security_credentials, fs_id)
    efs_client_auth_body = efs_client_auth_builder(public_key_path, security_credentials['AccessKeyId'],
                                                   security_credentials['SecretAccessKey'], date, region, fs_id,
                                                   security_credentials['Token']) if credentials_source else ''

    if credentials_source and not efs_client_auth_body:
        logging.error('Failed to create AWS SigV4 signature section for OpenSSL config. Public Key path: %s', public_key_path)
        return None

    full_config_body = CA_CONFIG_BODY % (directory, private_key, common_name, ca_extension_body, efs_client_auth_body)

    with open(config_path, 'w') as f:
        f.write(full_config_body)

    return full_config_body


def ca_extension_builder(ap_id, security_credentials, fs_id):
    ca_extension_str = '[ v3_ca ]\nsubjectKeyIdentifier = hash'
    if ap_id:
        ca_extension_str += '\n1.3.6.1.4.1.4843.7.1 = ASN1:UTF8String:' + ap_id
    if security_credentials:
        ca_extension_str += '\n1.3.6.1.4.1.4843.7.2 = ASN1:SEQUENCE:efs_client_auth'

    ca_extension_str += '\n1.3.6.1.4.1.4843.7.3 = ASN1:UTF8String:' + fs_id

    return ca_extension_str


def efs_client_auth_builder(public_key_path, access_key_id, secret_access_key, date, region, fs_id, session_token=None):
    public_key_hash = get_public_key_sha1(public_key_path)

    if not public_key_hash:
        return None

    canonical_request = create_canonical_request(public_key_hash, date, access_key_id, region, fs_id, session_token)
    string_to_sign = create_string_to_sign(canonical_request, date, region)
    signature = calculate_signature(string_to_sign, date, secret_access_key, region)
    efs_client_auth_str = '[ efs_client_auth ]'
    efs_client_auth_str += '\naccessKeyId = UTF8String:' + access_key_id
    efs_client_auth_str += '\nsignature = OCTETSTRING:' + signature
    efs_client_auth_str += '\nsigv4DateTime = UTCTIME:' + date.strftime(CERT_DATETIME_FORMAT)

    if session_token:
        efs_client_auth_str += '\nsessionToken = EXPLICIT:0,UTF8String:' + session_token

    return efs_client_auth_str


def create_public_key(private_key, public_key):
    cmd = 'openssl rsa -in %s -outform PEM -pubout -out %s' % (private_key, public_key)
    subprocess_call(cmd, 'Failed to create public key')


def subprocess_call(cmd, error_message):
    """Helper method to run shell openssl command and to handle response error messages"""
    process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
    (output, err) = process.communicate()
    rc = process.poll()
    if rc != 0:
        logging.debug('%s. Command %s failed, rc=%s, stdout="%s", stderr="%s"', error_message, cmd, rc, output, err)
    else:
        return output, err


def ca_dirs_check(config, database_dir, certs_dir):
    """Check if mount's database and certs directories exist and if not, create directories (also create all intermediate
    directories if they don't exist)."""
    if not os.path.exists(database_dir):
        create_required_directory(config, database_dir)
    if not os.path.exists(certs_dir):
        create_required_directory(config, certs_dir)


def ca_supporting_files_check(index_path, index_attr_path, serial_path, rand_path):
    """Create all supporting openssl ca and req files if they're not present in their respective directories"""
    def _recreate_file_warning(path):
        logging.warning('Expected %s not found, recreating file', path)

    if not os.path.isfile(index_path):
        open(index_path, 'w').close()
        _recreate_file_warning(index_path)
    if not os.path.isfile(index_attr_path):
        with open(index_attr_path, 'w+') as f:
            f.write('unique_subject = no')
        _recreate_file_warning(index_attr_path)
    if not os.path.isfile(serial_path):
        with open(serial_path, 'w+') as f:
            f.write('00')
        _recreate_file_warning(serial_path)
    if not os.path.isfile(rand_path):
        open(rand_path, 'w').close()
        _recreate_file_warning(rand_path)


def tls_paths_dictionary(mount_name, base_path=STATE_FILE_DIR):
    tls_dict = {
        'mount_dir': os.path.join(base_path, mount_name),
        'database_dir': os.path.join(base_path, mount_name, 'database'),
        'certs_dir': os.path.join(base_path, mount_name, 'certs'),
        'index': os.path.join(base_path, mount_name, 'database/index.txt'),
        'index_attr': os.path.join(base_path, mount_name, 'database/index.txt.attr'),
        'serial': os.path.join(base_path, mount_name, 'database/serial'),
        'rand': os.path.join(base_path, mount_name, 'database/.rand')
    }

    return tls_dict


def get_public_key_sha1(public_key):
    # truncating public key to remove the header and footer '-----(BEGIN|END) PUBLIC KEY-----'
    with open(public_key, 'r') as f:
        lines = f.readlines()
        lines = lines[1:-1]

    key = ''.join(lines)
    key = bytearray(base64.b64decode(key))

    # Parse the public key to pull out the actual key material by looking for the key BIT STRING
    # Example:
    #     0:d=0  hl=4 l= 418 cons: SEQUENCE
    #     4:d=1  hl=2 l=  13 cons: SEQUENCE
    #     6:d=2  hl=2 l=   9 prim: OBJECT            :rsaEncryption
    #    17:d=2  hl=2 l=   0 prim: NULL
    #    19:d=1  hl=4 l= 399 prim: BIT STRING
    cmd = 'openssl asn1parse -inform PEM -in %s' % public_key
    output, err = subprocess_call(cmd, 'Unable to ASN1 parse public key file, %s, correctly' % public_key)

    key_line = ''
    for line in output.splitlines():
        if 'BIT STRING' in line.decode('utf-8'):
            key_line = line.decode('utf-8')

    if not key_line:
        logging.error('Public key file, %s, is incorrectly formatted', public_key)
        return None

    key_line = key_line.replace(' ', '')

    # DER encoding TLV (Tag, Length, Value)
    # - the first octet (byte) is the tag (type)
    # - the next octets are the length - "definite form"
    #   - the first octet always has the high order bit (8) set to 1
    #   - the remaining 127 bits are used to encode the number of octets that follow
    #   - the following octets encode, as big-endian, the length (which may be 0) as a number of octets
    # - the remaining octets are the "value" aka content
    #
    # For a BIT STRING, the first octet of the value is used to signify the number of unused bits that exist in the last
    # content byte. Note that this is explicitly excluded from the SubjectKeyIdentifier hash, per
    # https://tools.ietf.org/html/rfc5280#section-4.2.1.2
    #
    # Example:
    #   0382018f00...<subjectPublicKey>
    #   - 03 - BIT STRING tag
    #   - 82 - 2 length octets to follow (ignore high order bit)
    #   - 018f - length of 399
    #   - 00 - no unused bits in the last content byte
    offset = int(key_line.split(':')[0])
    key = key[offset:]

    num_length_octets = key[1] & 0b01111111

    # Exclude the tag (1), length (1 + num_length_octets), and number of unused bits (1)
    offset = 1 + 1 + num_length_octets + 1
    key = key[offset:]

    sha1 = hashlib.sha1()
    sha1.update(key)

    return sha1.hexdigest()


def create_canonical_request(public_key_hash, date, access_key, region, fs_id, session_token=None):
    """
    Create a Canonical Request - https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
    """
    formatted_datetime = date.strftime(SIGV4_DATETIME_FORMAT)
    credential = quote_plus(access_key + '/' + get_credential_scope(date, region))

    request = HTTP_REQUEST_METHOD + '\n'
    request += CANONICAL_URI + '\n'
    request += create_canonical_query_string(public_key_hash, credential, formatted_datetime, session_token) + '\n'
    request += CANONICAL_HEADERS % fs_id + '\n'
    request += SIGNED_HEADERS + '\n'

    sha256 = hashlib.sha256()
    sha256.update(REQUEST_PAYLOAD.encode())
    request += sha256.hexdigest()

    return request


def create_canonical_query_string(public_key_hash, credential, formatted_datetime, session_token=None):
    canonical_query_params = {
        'Action': 'Connect',
        # Public key hash is included in canonical request to tie the signature to a specific key pair to avoid replay attacks
        'PublicKeyHash': quote_plus(public_key_hash),
        'X-Amz-Algorithm': ALGORITHM,
        'X-Amz-Credential': credential,
        'X-Amz-Date': quote_plus(formatted_datetime),
        'X-Amz-Expires': 86400,
        'X-Amz-SignedHeaders': SIGNED_HEADERS,
    }

    if session_token:
        canonical_query_params['X-Amz-Security-Token'] = quote_plus(session_token)

    # Cannot use urllib.urlencode because it replaces the %s's
    return '&'.join(['%s=%s' % (k, v) for k, v in sorted(canonical_query_params.items())])


def create_string_to_sign(canonical_request, date, region):
    """
    Create a String to Sign - https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
    """
    string_to_sign = ALGORITHM + '\n'
    string_to_sign += date.strftime(SIGV4_DATETIME_FORMAT) + '\n'
    string_to_sign += get_credential_scope(date, region) + '\n'

    sha256 = hashlib.sha256()
    sha256.update(canonical_request.encode())
    string_to_sign += sha256.hexdigest()

    return string_to_sign


def calculate_signature(string_to_sign, date, secret_access_key, region):
    """
    Calculate the Signature - https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
    """
    def _sign(key, msg):
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256)

    key_date = _sign(('AWS4' + secret_access_key).encode('utf-8'), date.strftime(DATE_ONLY_FORMAT)).digest()
    add_region = _sign(key_date, region).digest()
    add_service = _sign(add_region, SERVICE).digest()
    signing_key = _sign(add_service, 'aws4_request').digest()

    return _sign(signing_key, string_to_sign).hexdigest()


def get_credential_scope(date, region):
    return '/'.join([date.strftime(DATE_ONLY_FORMAT), region, SERVICE, AWS4_REQUEST])


def get_certificate_timestamp(current_time, **kwargs):
    updated_time = current_time + timedelta(**kwargs)
    return updated_time.strftime(CERT_DATETIME_FORMAT)


def get_utc_now():
    """
    Wrapped for patching purposes in unit tests
    """
    return datetime.utcnow()


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
            check_efs_mounts(config, child_procs, unmount_grace_period_sec)
            check_child_procs(child_procs)

            time.sleep(poll_interval_sec)
    else:
        logging.info('amazon-efs-mount-watchdog is not enabled')


if '__main__' == __name__:
    main()
