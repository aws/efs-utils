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

import base64
import errno
import hashlib
import hmac
import json
import logging
import os
import pwd
import random
import re
import socket
import subprocess
import sys
import threading
import time

from contextlib import contextmanager
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler

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
    from urllib2 import URLError, HTTPError, build_opener, urlopen, Request, HTTPHandler
    from urllib import urlencode
except ImportError:
    from urllib.request import urlopen, Request
    from urllib.error import URLError, HTTPError
    from urllib.parse import urlencode

try:
    import botocore.session
    from botocore.exceptions import ClientError, NoCredentialsError, EndpointConnectionError
    BOTOCORE_PRESENT = True
except ImportError:
    BOTOCORE_PRESENT = False


VERSION = '1.28.2'
SERVICE = 'elasticfilesystem'

CONFIG_FILE = '/etc/amazon/efs/efs-utils.conf'
CONFIG_SECTION = 'mount'
CLIENT_INFO_SECTION = 'client-info'
CLIENT_SOURCE_STR_LEN_LIMIT = 100

CLOUDWATCH_LOG_SECTION = 'cloudwatch-log'
DEFAULT_CLOUDWATCH_LOG_GROUP = '/aws/efs/utils'
DEFAULT_RETENTION_DAYS = 14
# Cloudwatchlog agent dict includes cloudwatchlog botocore client, cloudwatchlog group name, cloudwatchlog stream name
CLOUDWATCHLOG_AGENT = None

LOG_DIR = '/var/log/amazon/efs'
LOG_FILE = 'mount.log'

STATE_FILE_DIR = '/var/run/efs'

PRIVATE_KEY_FILE = '/etc/amazon/efs/privateKey.pem'
DATE_ONLY_FORMAT = '%Y%m%d'
SIGV4_DATETIME_FORMAT = '%Y%m%dT%H%M%SZ'
CERT_DATETIME_FORMAT = '%y%m%d%H%M%SZ'

AWS_CREDENTIALS_FILE = os.path.expanduser(os.path.join('~' + pwd.getpwuid(os.getuid()).pw_name, '.aws', 'credentials'))
AWS_CONFIG_FILE = os.path.expanduser(os.path.join('~' + pwd.getpwuid(os.getuid()).pw_name, '.aws', 'config'))

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

FS_ID_RE = re.compile('^(?P<fs_id>fs-[0-9a-f]+)$')
EFS_FQDN_RE = re.compile(r'^(?P<fs_id>fs-[0-9a-f]+)\.efs\.(?P<region>[a-z0-9-]+)\.(?P<dns_name_suffix>[a-z0-9.]+)$')
AP_ID_RE = re.compile('^fsap-[0-9a-f]{17}$')

CREDENTIALS_KEYS = ['AccessKeyId', 'SecretAccessKey', 'Token']
ECS_URI_ENV = 'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI'
ECS_TASK_METADATA_API = 'http://169.254.170.2'
WEB_IDENTITY_ROLE_ARN_ENV = 'AWS_ROLE_ARN'
WEB_IDENTITY_TOKEN_FILE_ENV = 'AWS_WEB_IDENTITY_TOKEN_FILE'
STS_ENDPOINT_URL = 'https://sts.amazonaws.com/'
INSTANCE_METADATA_TOKEN_URL = 'http://169.254.169.254/latest/api/token'
INSTANCE_METADATA_SERVICE_URL = 'http://169.254.169.254/latest/dynamic/instance-identity/document/'
INSTANCE_IAM_URL = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'
SECURITY_CREDS_ECS_URI_HELP_URL = 'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html'
SECURITY_CREDS_WEBIDENTITY_HELP_URL = 'https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html'
SECURITY_CREDS_IAM_ROLE_HELP_URL = 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html'

DEFAULT_STUNNEL_VERIFY_LEVEL = 2
DEFAULT_STUNNEL_CAFILE = '/etc/amazon/efs/efs-utils.crt'

NOT_BEFORE_MINS = 15
NOT_AFTER_HOURS = 3

EFS_ONLY_OPTIONS = [
    'accesspoint',
    'awscredsuri',
    'awsprofile',
    'cafile',
    'iam',
    'netns',
    'noocsp',
    'ocsp',
    'tls',
    'tlsport',
    'verify'
]

UNSUPPORTED_OPTIONS = [
    'capath'
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
    'TIMEOUTidle': '70',
    'delay': 'yes',
}

WATCHDOG_SERVICE = 'amazon-efs-mount-watchdog'
SYSTEM_RELEASE_PATH = '/etc/system-release'
OS_RELEASE_PATH = '/etc/os-release'
RHEL8_RELEASE_NAME = 'Red Hat Enterprise Linux release 8'
CENTOS8_RELEASE_NAME = 'CentOS Linux release 8'
FEDORA_RELEASE_NAME = 'Fedora release'
SUSE_RELEASE_NAME = 'openSUSE Leap'
SKIP_NO_LIBWRAP_RELEASES = [RHEL8_RELEASE_NAME, CENTOS8_RELEASE_NAME, FEDORA_RELEASE_NAME, SUSE_RELEASE_NAME]


def fatal_error(user_message, log_message=None, exit_code=1):
    if log_message is None:
        log_message = user_message

    sys.stderr.write('%s\n' % user_message)
    logging.error(log_message)
    publish_cloudwatch_log(CLOUDWATCHLOG_AGENT, 'Mount failed, %s' % log_message)
    sys.exit(exit_code)


def get_target_region(config):
    def _fatal_error(message):
        fatal_error('Error retrieving region. Please set the "region" parameter in the efs-utils configuration file.', message)

    metadata_exception = 'Unknown error'
    try:
        return config.get(CONFIG_SECTION, 'region')
    except NoOptionError:
        pass

    try:
        return get_region_from_instance_metadata()
    except Exception as e:
        metadata_exception = e
        logging.warning('Region not found in config file and metadata service call failed, falling back '
                        'to legacy "dns_name_format" check')

    try:
        region = get_region_from_legacy_dns_format(config)
        sys.stdout.write('Warning: region obtained from "dns_name_format" field. Please set the "region" '
                         'parameter in the efs-utils configuration file.')
        return region
    except Exception:
        logging.warning('Legacy check for region in "dns_name_format" failed')

    _fatal_error(metadata_exception)


def get_region_from_instance_metadata():
    instance_identity = get_instance_identity_info_from_instance_metadata('region')

    if not instance_identity:
        raise Exception("Cannot retrieve region from instance_metadata")

    return instance_identity


def get_instance_identity_info_from_instance_metadata(property):
    ec2_metadata_unsuccessful_resp = 'Unsuccessful retrieval of EC2 metadata at %s.' % INSTANCE_METADATA_SERVICE_URL
    ec2_metadata_url_error_msg = 'Unable to reach %s to retrieve EC2 instance metadata.' % INSTANCE_METADATA_SERVICE_URL
    instance_identity = url_request_helper(INSTANCE_METADATA_SERVICE_URL, ec2_metadata_unsuccessful_resp,
                                           ec2_metadata_url_error_msg, retry_with_new_header_token=True)
    if instance_identity:
        try:
            return instance_identity[property]
        except KeyError as e:
            logging.warning('%s not present in %s: %s' % (property, instance_identity, e))
        except TypeError as e:
            logging.warning('response %s is not a json object: %s' % (instance_identity, e))

    return None


def get_region_from_legacy_dns_format(config):
    """
    For backwards compatibility check dns_name_format to obtain the target region. This functionality
    should only be used if region is not present in the config file and metadata calls fail.
    """
    dns_name_format = config.get(CONFIG_SECTION, 'dns_name_format')
    if '{region}' not in dns_name_format:
        split_dns_name_format = dns_name_format.split('.')
        if '{dns_name_suffix}' in dns_name_format:
            return split_dns_name_format[-2]
        elif 'amazonaws.com' in dns_name_format:
            return split_dns_name_format[-3]
    raise Exception('Region not found in dns_name_format')


def get_aws_ec2_metadata_token():
    try:
        opener = build_opener(HTTPHandler)
        request = Request(INSTANCE_METADATA_TOKEN_URL)
        request.add_header('X-aws-ec2-metadata-token-ttl-seconds', 21600)
        request.get_method = lambda: 'PUT'
        res = opener.open(request)
        return res.read()
    except NameError:
        headers = {'X-aws-ec2-metadata-token-ttl-seconds': 21600}
        req = Request(INSTANCE_METADATA_TOKEN_URL, headers=headers, method='PUT')
        res = urlopen(req)
        return res.read()


def get_aws_security_credentials(use_iam, awsprofile=None, aws_creds_uri=None):
    """
    Lookup AWS security credentials (access key ID and secret access key). Adapted credentials provider chain from:
    https://boto3.amazonaws.com/v1/documentation/api/latest/guide/configuration.html and
    https://docs.aws.amazon.com/sdk-for-java/v1/developer-guide/credentials.html
    """
    if not use_iam:
        return None, None

    # attempt to lookup AWS security credentials through the credentials URI the ECS agent generated
    if aws_creds_uri:
        return get_aws_security_credentials_from_ecs(aws_creds_uri, True)

    # attempt to lookup AWS security credentials in AWS credentials file (~/.aws/credentials)
    # and configs file (~/.aws/config) with given awsprofile
    if awsprofile:
        return get_aws_security_credentials_from_awsprofile(awsprofile, True)

    # attempt to lookup AWS security credentials through AWS_CONTAINER_CREDENTIALS_RELATIVE_URI environment variable
    if ECS_URI_ENV in os.environ:
        credentials, credentials_source = get_aws_security_credentials_from_ecs(os.environ[ECS_URI_ENV], False)
        if credentials and credentials_source:
            return credentials, credentials_source

    # attempt to lookup AWS security credentials through AssumeRoleWithWebIdentity
    # (e.g. for IAM Role for Service Accounts (IRSA) approach on EKS)
    if WEB_IDENTITY_ROLE_ARN_ENV in os.environ and WEB_IDENTITY_TOKEN_FILE_ENV in os.environ:
        credentials, credentials_source = get_aws_security_credentials_from_webidentity(
            os.environ[WEB_IDENTITY_ROLE_ARN_ENV],
            os.environ[WEB_IDENTITY_TOKEN_FILE_ENV],
            False
        )
        if credentials and credentials_source:
            return credentials, credentials_source

    # attempt to lookup AWS security credentials with IAM role name attached to instance
    # through IAM role name security credentials lookup uri
    iam_role_name = get_iam_role_name()
    if iam_role_name:
        credentials, credentials_source = get_aws_security_credentials_from_instance_metadata(iam_role_name)
        if credentials and credentials_source:
            return credentials, credentials_source

    error_msg = 'AWS Access Key ID and Secret Access Key are not found in AWS credentials file (%s), config file (%s), ' \
                'from ECS credentials relative uri, or from the instance security credentials service' % \
                (AWS_CREDENTIALS_FILE, AWS_CONFIG_FILE)
    fatal_error(error_msg, error_msg)


def get_aws_security_credentials_from_awsprofile(awsprofile, is_fatal=False):
    for file_path in [AWS_CREDENTIALS_FILE, AWS_CONFIG_FILE]:
        if os.path.exists(file_path):
            credentials = credentials_file_helper(file_path, awsprofile)
            if credentials['AccessKeyId']:
                return credentials, os.path.basename(file_path) + ':' + awsprofile

    # Fail if credentials cannot be fetched from the given awsprofile
    if is_fatal:
        log_message = 'AWS security credentials not found in %s or %s under named profile [%s]' % \
                    (AWS_CREDENTIALS_FILE, AWS_CONFIG_FILE, awsprofile)
        fatal_error(log_message)
    else:
        return None, None


def get_aws_security_credentials_from_ecs(aws_creds_uri, is_fatal=False):
    ecs_uri = ECS_TASK_METADATA_API + aws_creds_uri
    ecs_unsuccessful_resp = 'Unsuccessful retrieval of AWS security credentials at %s.' % ecs_uri
    ecs_url_error_msg = 'Unable to reach %s to retrieve AWS security credentials. See %s for more info.' \
                        % (ecs_uri, SECURITY_CREDS_ECS_URI_HELP_URL)
    ecs_security_dict = url_request_helper(ecs_uri, ecs_unsuccessful_resp, ecs_url_error_msg)

    if ecs_security_dict and all(k in ecs_security_dict for k in CREDENTIALS_KEYS):
        return ecs_security_dict, 'ecs:' + aws_creds_uri

    # Fail if credentials cannot be fetched from the given aws_creds_uri
    if is_fatal:
        fatal_error(ecs_unsuccessful_resp, ecs_unsuccessful_resp)
    else:
        return None, None


def get_aws_security_credentials_from_webidentity(role_arn, token_file, is_fatal=False):
    try:
        with open(token_file, 'r') as f:
            token = f.read()
    except Exception as e:
        if is_fatal:
            unsuccessful_resp = 'Error reading token file %s: %s' % (token_file, e)
            fatal_error(unsuccessful_resp, unsuccessful_resp)
        else:
            return None, None

    webidentity_url = STS_ENDPOINT_URL + '?' + urlencode({
        'Version': '2011-06-15',
        'Action': 'AssumeRoleWithWebIdentity',
        'RoleArn': role_arn,
        'RoleSessionName': 'efs-mount-helper',
        'WebIdentityToken': token
    })

    unsuccessful_resp = 'Unsuccessful retrieval of AWS security credentials at %s.' % STS_ENDPOINT_URL
    url_error_msg = 'Unable to reach %s to retrieve AWS security credentials. See %s for more info.' % \
                    (STS_ENDPOINT_URL, SECURITY_CREDS_WEBIDENTITY_HELP_URL)
    resp = url_request_helper(webidentity_url, unsuccessful_resp, url_error_msg, headers={'Accept': 'application/json'})

    if resp:
        creds = resp \
                .get('AssumeRoleWithWebIdentityResponse', {}) \
                .get('AssumeRoleWithWebIdentityResult', {}) \
                .get('Credentials', {})
        if all(k in creds for k in ['AccessKeyId', 'SecretAccessKey', 'SessionToken']):
            return {
                'AccessKeyId': creds['AccessKeyId'],
                'SecretAccessKey': creds['SecretAccessKey'],
                'Token': creds['SessionToken']
            }, 'webidentity:' + ','.join([role_arn, token_file])

    # Fail if credentials cannot be fetched from the given aws_creds_uri
    if is_fatal:
        fatal_error(unsuccessful_resp, unsuccessful_resp)
    else:
        return None, None


def get_aws_security_credentials_from_instance_metadata(iam_role_name):
    security_creds_lookup_url = INSTANCE_IAM_URL + iam_role_name
    unsuccessful_resp = 'Unsuccessful retrieval of AWS security credentials at %s.' % security_creds_lookup_url
    url_error_msg = 'Unable to reach %s to retrieve AWS security credentials. See %s for more info.' % \
                    (security_creds_lookup_url, SECURITY_CREDS_IAM_ROLE_HELP_URL)
    iam_security_dict = url_request_helper(security_creds_lookup_url, unsuccessful_resp,
                                           url_error_msg, retry_with_new_header_token=True)

    if iam_security_dict and all(k in iam_security_dict for k in CREDENTIALS_KEYS):
        return iam_security_dict, 'metadata:'
    else:
        return None, None


def get_iam_role_name():
    iam_role_unsuccessful_resp = 'Unsuccessful retrieval of IAM role name at %s.' % INSTANCE_IAM_URL
    iam_role_url_error_msg = 'Unable to reach %s to retrieve IAM role name. See %s for more info.' % \
                             (INSTANCE_IAM_URL, SECURITY_CREDS_IAM_ROLE_HELP_URL)
    iam_role_name = url_request_helper(INSTANCE_IAM_URL, iam_role_unsuccessful_resp,
                                       iam_role_url_error_msg, retry_with_new_header_token=True)
    return iam_role_name


def credentials_file_helper(file_path, awsprofile):
    aws_credentials_configs = read_config(file_path)
    credentials = {'AccessKeyId': None, 'SecretAccessKey': None, 'Token': None}

    try:
        access_key = aws_credentials_configs.get(awsprofile, 'aws_access_key_id')
        secret_key = aws_credentials_configs.get(awsprofile, 'aws_secret_access_key')
        session_token = aws_credentials_configs.get(awsprofile, 'aws_session_token')

        credentials['AccessKeyId'] = access_key
        credentials['SecretAccessKey'] = secret_key
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


def get_aws_profile(options, use_iam):
    awsprofile = options.get('awsprofile')
    if not awsprofile and use_iam:
        for file_path in [AWS_CREDENTIALS_FILE, AWS_CONFIG_FILE]:
            aws_credentials_configs = read_config(file_path)
            # check if aws access key id is found under [default] section in current file and return 'default' if so
            try:
                access_key = aws_credentials_configs.get('default', 'aws_access_key_id')
                if access_key is not None:
                    return 'default'
            except (NoSectionError, NoOptionError):
                continue

    return awsprofile


def url_request_helper(url, unsuccessful_resp, url_error_msg, headers={}, retry_with_new_header_token=False):
    try:
        req = Request(url)
        for k, v in headers.items():
            req.add_header(k, v)
        request_resp = urlopen(req, timeout=1)

        return get_resp_obj(request_resp, url, unsuccessful_resp)
    except HTTPError as e:
        # For instance enable with IMDSv2, Unauthorized 401 error will be thrown,
        # to retrieve metadata, the header should embeded with metadata token
        if e.code == 401 and retry_with_new_header_token:
            token = get_aws_ec2_metadata_token()
            req.add_header('X-aws-ec2-metadata-token', token)
            request_resp = urlopen(req, timeout=1)
            return get_resp_obj(request_resp, url, unsuccessful_resp)
        err_msg = 'Unable to reach the url at %s: status=%d, reason is %s' % (url, e.code, e.reason)
    except URLError as e:
        err_msg = 'Unable to reach the url at %s, reason is %s' % (url, e.reason)

    if err_msg:
        logging.debug('%s %s', url_error_msg, err_msg)
    return None


def get_resp_obj(request_resp, url, unsuccessful_resp):
    if request_resp.getcode() != 200:
        logging.debug(unsuccessful_resp + ' %s: ResponseCode=%d', url, request_resp.getcode())
        return None

    resp_body = request_resp.read()
    resp_body_type = type(resp_body)
    try:
        if resp_body_type is str:
            resp_dict = json.loads(resp_body)
        else:
            resp_dict = json.loads(resp_body.decode(request_resp.headers.get_content_charset() or 'us-ascii'))

        return resp_dict
    except ValueError as e:
        logging.info('ValueError parsing "%s" into json: %s. Returning response body.' % (str(resp_body), e))
        return resp_body if resp_body_type is str else resp_body.decode('utf-8')


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
        ports_to_try = [int(options['tlsport'])]
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
    if 'ocsp' in options:
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


def add_stunnel_ca_options(efs_config, config, options):
    if 'cafile' in options:
        stunnel_cafile = options['cafile']
    else:
        try:
            stunnel_cafile = config.get(CONFIG_SECTION, 'stunnel_cafile')
        except NoOptionError:
            logging.debug('No CA file configured, using default CA file %s', DEFAULT_STUNNEL_CAFILE)
            stunnel_cafile = DEFAULT_STUNNEL_CAFILE

    if not os.path.exists(stunnel_cafile):
        fatal_error('Failed to find certificate authority file for verification',
                    'Failed to find CAfile "%s"' % stunnel_cafile)

    efs_config['CAfile'] = stunnel_cafile


def is_stunnel_option_supported(stunnel_output, stunnel_option_name):
    supported = False
    for line in stunnel_output:
        if line.startswith(stunnel_option_name):
            supported = True
            break

    if not supported:
        logging.warning('stunnel does not support "%s"', stunnel_option_name)

    return supported


def get_version_specific_stunnel_options():
    stunnel_command = [_stunnel_bin(), '-help']
    proc = subprocess.Popen(stunnel_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
    proc.wait()
    _, err = proc.communicate()

    stunnel_output = err.splitlines()

    check_host_supported = is_stunnel_option_supported(stunnel_output, b'checkHost')
    ocsp_aia_supported = is_stunnel_option_supported(stunnel_output, b'OCSPaia')

    return check_host_supported, ocsp_aia_supported


def _stunnel_bin():
    return find_command_path('stunnel',
                             'Please install it following the instructions at '
                             'https://docs.aws.amazon.com/efs/latest/ug/using-amazon-efs-utils.html#upgrading-stunnel')


def find_command_path(command, install_method):
    try:
        env_path = '/sbin:/usr/sbin:/usr/local/sbin:/root/bin:/usr/local/bin:/usr/bin:/bin'
        os.putenv('PATH', env_path)
        path = subprocess.check_output(['which', command])
    except subprocess.CalledProcessError as e:
        fatal_error('Failed to locate %s in %s - %s' % (command, env_path, install_method), e)
    return path.strip().decode()


def get_system_release_version():
    try:
        with open(SYSTEM_RELEASE_PATH) as f:
            return f.read().strip()
    except IOError:
        logging.debug('Unable to read %s', SYSTEM_RELEASE_PATH)

    try:
        with open(OS_RELEASE_PATH) as f:
            for line in f:
                if 'PRETTY_NAME' in line:
                    return line.split('=')[1].strip()
    except IOError:
        logging.debug('Unable to read %s', OS_RELEASE_PATH)

    return 'unknown'


def write_stunnel_config_file(config, state_file_dir, fs_id, mountpoint, tls_port, dns_name, verify_level, ocsp_enabled,
                              options, log_dir=LOG_DIR, cert_details=None):
    """
    Serializes stunnel configuration to a file. Unfortunately this does not conform to Python's config file format, so we have to
    hand-serialize it.
    """

    mount_filename = get_mount_specific_filename(fs_id, mountpoint, tls_port)

    global_config = dict(STUNNEL_GLOBAL_CONFIG)
    if config.getboolean(CONFIG_SECTION, 'stunnel_debug_enabled'):
        global_config['debug'] = 'debug'

        if config.has_option(CONFIG_SECTION, 'stunnel_logs_file'):
            global_config['output'] = config.get(CONFIG_SECTION, 'stunnel_logs_file').replace('{fs_id}', fs_id)
        else:
            global_config['output'] = os.path.join(log_dir, '%s.stunnel.log' % mount_filename)

    efs_config = dict(STUNNEL_EFS_CONFIG)
    efs_config['accept'] = efs_config['accept'] % tls_port
    efs_config['connect'] = efs_config['connect'] % dns_name
    efs_config['verify'] = verify_level
    if verify_level > 0:
        add_stunnel_ca_options(efs_config, config, options)

    if cert_details:
        efs_config['cert'] = cert_details['certificate']
        efs_config['key'] = cert_details['privateKey']

    check_host_supported, ocsp_aia_supported = get_version_specific_stunnel_options()

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

    system_release_version = get_system_release_version()
    if not any(release in system_release_version for release in SKIP_NO_LIBWRAP_RELEASES):
        efs_config['libwrap'] = 'no'

    stunnel_config = '\n'.join(serialize_stunnel_config(global_config) + serialize_stunnel_config(efs_config, 'efs'))
    logging.debug('Writing stunnel configuration:\n%s', stunnel_config)

    stunnel_config_file = os.path.join(state_file_dir, 'stunnel-config.%s' % mount_filename)

    with open(stunnel_config_file, 'w') as f:
        f.write(stunnel_config)

    return stunnel_config_file


def write_tls_tunnel_state_file(fs_id, mountpoint, tls_port, tunnel_pid, command, files, state_file_dir, cert_details=None):
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

    if cert_details:
        state.update(cert_details)

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


def check_network_target(fs_id):
    with open(os.devnull, 'w') as devnull:
        rc = subprocess.call(['systemctl', 'status', 'network.target'], stdout=devnull, stderr=devnull, close_fds=True)

    if rc != 0:
        fatal_error('Failed to mount %s because the network was not yet available, add "_netdev" to your mount options' % fs_id,
                    exit_code=0)


def check_network_status(fs_id, init_system):
    if init_system != 'systemd':
        logging.debug('Not testing network on non-systemd init systems')
        return

    check_network_target(fs_id)


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
    except OSError as e:
        if errno.EEXIST != e.errno or not os.path.isdir(directory):
            raise


@contextmanager
def bootstrap_tls(config, init_system, dns_name, fs_id, mountpoint, options, state_file_dir=STATE_FILE_DIR):
    tls_port = choose_tls_port(config, options)
    # override the tlsport option so that we can later override the port the NFS client uses to connect to stunnel.
    # if the user has specified tlsport=X at the command line this will just re-set tlsport to X.
    options['tlsport'] = tls_port

    use_iam = 'iam' in options
    ap_id = options.get('accesspoint')
    cert_details = {}
    security_credentials = None
    client_info = get_client_info(config)

    if use_iam:
        aws_creds_uri = options.get('awscredsuri')
        if aws_creds_uri:
            kwargs = {'aws_creds_uri': aws_creds_uri}
        else:
            kwargs = {'awsprofile': get_aws_profile(options, use_iam)}

        security_credentials, credentials_source = get_aws_security_credentials(use_iam, **kwargs)

        if credentials_source:
            cert_details['awsCredentialsMethod'] = credentials_source

    if ap_id:
        cert_details['accessPoint'] = ap_id

    # additional symbol appended to avoid naming collisions
    cert_details['mountStateDir'] = get_mount_specific_filename(fs_id, mountpoint, tls_port) + '+'
    # common name for certificate signing request is max 64 characters
    cert_details['commonName'] = socket.gethostname()[0:64]
    cert_details['region'] = get_target_region(config)
    cert_details['certificateCreationTime'] = create_certificate(config, cert_details['mountStateDir'],
                                                                 cert_details['commonName'], cert_details['region'], fs_id,
                                                                 security_credentials, ap_id, client_info,
                                                                 base_path=state_file_dir)
    cert_details['certificate'] = os.path.join(state_file_dir, cert_details['mountStateDir'], 'certificate.pem')
    cert_details['privateKey'] = get_private_key_path()
    cert_details['fsId'] = fs_id

    start_watchdog(init_system)

    if not os.path.exists(state_file_dir):
        create_required_directory(config, state_file_dir)

    verify_level = int(options.get('verify', DEFAULT_STUNNEL_VERIFY_LEVEL))
    ocsp_enabled = is_ocsp_enabled(config, options)

    stunnel_config_file = write_stunnel_config_file(config, state_file_dir, fs_id, mountpoint, tls_port, dns_name, verify_level,
                                                    ocsp_enabled, options, cert_details=cert_details)
    tunnel_args = [_stunnel_bin(), stunnel_config_file]
    if 'netns' in options:
        tunnel_args = ['nsenter', '--net=' + options['netns']] + tunnel_args

    # launch the tunnel in a process group so if it has any child processes, they can be killed easily by the mount watchdog
    logging.info('Starting TLS tunnel: "%s"', ' '.join(tunnel_args))
    tunnel_proc = subprocess.Popen(
        tunnel_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid, close_fds=True)
    logging.info('Started TLS tunnel, pid: %d', tunnel_proc.pid)

    temp_tls_state_file = write_tls_tunnel_state_file(fs_id, mountpoint, tls_port, tunnel_proc.pid, tunnel_args,
                                                      [stunnel_config_file], state_file_dir, cert_details=cert_details)

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

    if 'netns' in options:
        command = ['nsenter', '--net=' + options['netns']] + command

    logging.info('Executing: "%s"', ' '.join(command))

    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
    out, err = proc.communicate()

    if proc.returncode == 0:
        message = 'Successfully mounted %s at %s' % (dns_name, mountpoint)
        logging.info(message)
        publish_cloudwatch_log(CLOUDWATCHLOG_AGENT, message)
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


def get_client_info(config):
    client_info = {}

    # source key/value pair in config file
    if config.has_option(CLIENT_INFO_SECTION, 'source'):
        client_source = config.get(CLIENT_INFO_SECTION, 'source')
        if 0 < len(client_source) <= CLIENT_SOURCE_STR_LEN_LIMIT:
            client_info['source'] = client_source

    return client_info


def create_certificate(config, mount_name, common_name, region, fs_id, security_credentials, ap_id, client_info,
                       base_path=STATE_FILE_DIR):
    current_time = get_utc_now()
    tls_paths = tls_paths_dictionary(mount_name, base_path)

    certificate_config = os.path.join(tls_paths['mount_dir'], 'config.conf')
    certificate_signing_request = os.path.join(tls_paths['mount_dir'], 'request.csr')
    certificate = os.path.join(tls_paths['mount_dir'], 'certificate.pem')

    ca_dirs_check(config, tls_paths['database_dir'], tls_paths['certs_dir'])
    ca_supporting_files_check(tls_paths['index'], tls_paths['index_attr'], tls_paths['serial'], tls_paths['rand'])

    private_key = check_and_create_private_key(base_path)

    if security_credentials:
        public_key = os.path.join(tls_paths['mount_dir'], 'publicKey.pem')
        create_public_key(private_key, public_key)

    create_ca_conf(certificate_config, common_name, tls_paths['mount_dir'], private_key, current_time, region, fs_id,
                   security_credentials, ap_id, client_info)
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


def create_certificate_signing_request(config_path, private_key, csr_path):
    cmd = 'openssl req -new -config %s -key %s -out %s' % (config_path, private_key, csr_path)
    subprocess_call(cmd, 'Failed to create certificate signing request (csr)')


def create_ca_conf(config_path, common_name, directory, private_key, date,
                   region, fs_id, security_credentials, ap_id, client_info):
    """Populate ca/req configuration file with fresh configurations at every mount since SigV4 signature can change"""
    public_key_path = os.path.join(directory, 'publicKey.pem')
    ca_extension_body = ca_extension_builder(ap_id, security_credentials, fs_id, client_info)
    efs_client_auth_body = efs_client_auth_builder(public_key_path, security_credentials['AccessKeyId'],
                                                   security_credentials['SecretAccessKey'], date, region, fs_id,
                                                   security_credentials['Token']) if security_credentials else ''
    efs_client_info_body = efs_client_info_builder(client_info) if client_info else ''
    full_config_body = CA_CONFIG_BODY % (directory, private_key, common_name, ca_extension_body,
                                         efs_client_auth_body, efs_client_info_body)

    with open(config_path, 'w') as f:
        f.write(full_config_body)

    return full_config_body


def ca_extension_builder(ap_id, security_credentials, fs_id, client_info):
    ca_extension_str = '[ v3_ca ]\nsubjectKeyIdentifier = hash'
    if ap_id:
        ca_extension_str += '\n1.3.6.1.4.1.4843.7.1 = ASN1:UTF8String:' + ap_id
    if security_credentials:
        ca_extension_str += '\n1.3.6.1.4.1.4843.7.2 = ASN1:SEQUENCE:efs_client_auth'

    ca_extension_str += '\n1.3.6.1.4.1.4843.7.3 = ASN1:UTF8String:' + fs_id

    if client_info:
        ca_extension_str += '\n1.3.6.1.4.1.4843.7.4 = ASN1:SEQUENCE:efs_client_info'

    return ca_extension_str


def efs_client_auth_builder(public_key_path, access_key_id, secret_access_key, date, region, fs_id, session_token=None):
    public_key_hash = get_public_key_sha1(public_key_path)
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


def efs_client_info_builder(client_info):
    efs_client_info_str = '[ efs_client_info ]'
    for key, value in client_info.items():
        efs_client_info_str += '\n%s = UTF8String:%s' % (key, value)
    return efs_client_info_str


def create_public_key(private_key, public_key):
    cmd = 'openssl rsa -in %s -outform PEM -pubout -out %s' % (private_key, public_key)
    subprocess_call(cmd, 'Failed to create public key')


def subprocess_call(cmd, error_message):
    """Helper method to run shell openssl command and to handle response error messages"""
    retry_times = 3
    for retry in range(retry_times):
        process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        (output, err) = process.communicate()
        rc = process.poll()
        if rc != 0:
            logging.error('Command %s failed, rc=%s, stdout="%s", stderr="%s"' % (cmd, rc, output, err), exc_info=True)
            try:
                process.kill()
            except OSError:
                # Silently fail if the subprocess has exited already
                pass
        else:
            return output, err
    error_message = '%s, error is: %s' % (error_message, err)
    fatal_error(error_message, error_message)


def ca_dirs_check(config, database_dir, certs_dir):
    """Check if mount's database and certs directories exist and if not, create directories (also create all intermediate
    directories if they don't exist)."""
    if not os.path.exists(database_dir):
        create_required_directory(config, database_dir)
    if not os.path.exists(certs_dir):
        create_required_directory(config, certs_dir)


def ca_supporting_files_check(index_path, index_attr_path, serial_path, rand_path):
    """Recreate all supporting openssl ca and req files if they're not present in their respective directories"""
    if not os.path.isfile(index_path):
        open(index_path, 'w').close()
    if not os.path.isfile(index_attr_path):
        with open(index_attr_path, 'w+') as f:
            f.write('unique_subject = no')
    if not os.path.isfile(serial_path):
        with open(serial_path, 'w+') as f:
            f.write('00')
    if not os.path.isfile(rand_path):
        open(rand_path, 'w').close()


def get_certificate_timestamp(current_time, **kwargs):
    updated_time = current_time + timedelta(**kwargs)
    return updated_time.strftime(CERT_DATETIME_FORMAT)


def get_utc_now():
    """
    Wrapped for patching purposes in unit tests
    """
    return datetime.utcnow()


def assert_root():
    if os.geteuid() != 0:
        sys.stderr.write('only root can run mount.efs\n')
        sys.exit(1)


def read_config(config_file=CONFIG_FILE):
    try:
        p = ConfigParser.SafeConfigParser()
    except AttributeError:
        p = ConfigParser()
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

    expected_replacement_field_ct = 1

    if '{region}' in dns_name_format:
        expected_replacement_field_ct += 1
        format_args['region'] = get_target_region(config)

    if '{dns_name_suffix}' in dns_name_format:
        expected_replacement_field_ct += 1
        config_section = CONFIG_SECTION
        region = format_args.get('region')

        if region:
            region_specific_config_section = '%s.%s' % (CONFIG_SECTION, region)
            if config.has_section(region_specific_config_section):
                config_section = region_specific_config_section

        format_args['dns_name_suffix'] = config.get(config_section, 'dns_name_suffix')

        logging.debug("Using dns_name_suffix %s in config section [%s]", format_args.get('dns_name_suffix'), config_section)

    _validate_replacement_field_count(dns_name_format, expected_replacement_field_ct)

    dns_name = dns_name_format.format(**format_args)

    try:
        socket.gethostbyname(dns_name)
    except socket.gaierror:
        fatal_error('Failed to resolve "%s" - check that your file system ID is correct.\nSee %s for more detail.'
                    % (dns_name, 'https://docs.aws.amazon.com/console/efs/mount-dns-name'),
                    'Failed to resolve "%s"' % dns_name)

    return dns_name


def tls_paths_dictionary(mount_name, base_path=STATE_FILE_DIR):
    tls_dict = {
        'mount_dir': os.path.join(base_path, mount_name),
        # every mount will have its own ca mode assets due to lack of multi-threading support in openssl
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
        err_msg = 'Public key file, %s, is incorrectly formatted' % public_key
        fatal_error(err_msg, err_msg)

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
        hostnames = list(filter(lambda e: e is not None, [primary] + secondaries))
    except socket.gaierror:
        create_default_cloudwatchlog_agent_if_not_exist(config)
        fatal_error(
            'Failed to resolve "%s" - check that the specified DNS name is a CNAME record resolving to a valid EFS DNS '
            'name' % remote,
            'Failed to resolve "%s"' % remote
        )

    if not hostnames:
        create_default_cloudwatchlog_agent_if_not_exist(config)
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
        create_default_cloudwatchlog_agent_if_not_exist(config)
        fatal_error('The specified CNAME "%s" did not resolve to a valid DNS name for an EFS mount target. '
                    'Please refer to the EFS documentation for mounting with DNS names for examples: %s'
                    % (remote, 'https://docs.aws.amazon.com/efs/latest/ug/mounting-fs-mount-cmd-dns-name.html'))


def is_nfs_mount(mountpoint):
    cmd = ['stat', '-f', '-L', '-c', '%T', mountpoint]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
    output, _ = p.communicate()
    return output and 'nfs' in str(output)


def mount_tls(config, init_system, dns_name, path, fs_id, mountpoint, options):
    if os.path.ismount(mountpoint) and is_nfs_mount(mountpoint):
        sys.stdout.write("%s is already mounted, please run 'mount' command to verify\n" % mountpoint)
        logging.warning("%s is already mounted, mount aborted" % mountpoint)
        return

    with bootstrap_tls(config, init_system, dns_name, fs_id, mountpoint, options) as tunnel_proc:
        mount_completed = threading.Event()
        t = threading.Thread(target=poll_tunnel_process, args=(tunnel_proc, fs_id, mount_completed))
        t.daemon = True
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
            logging.warning(warn_message)
            del options[unsupported_option]


def check_options_validity(options):
    if 'tls' in options:
        if 'port' in options:
            fatal_error('The "port" and "tls" options are mutually exclusive')

        if 'tlsport' in options:
            try:
                int(options['tlsport'])
            except ValueError:
                fatal_error('tlsport option [%s] is not an integer' % options['tlsport'])

        if 'ocsp' in options and 'noocsp' in options:
            fatal_error('The "ocsp" and "noocsp" options are mutually exclusive')

    if 'accesspoint' in options:
        if 'tls' not in options:
            fatal_error('The "tls" option is required when mounting via "accesspoint"')
        if not AP_ID_RE.match(options['accesspoint']):
            fatal_error('Access Point ID %s is malformed' % options['accesspoint'])

    if 'iam' in options and 'tls' not in options:
        fatal_error('The "tls" option is required when mounting via "iam"')

    if 'awsprofile' in options and 'iam' not in options:
        fatal_error('The "iam" option is required when mounting with named profile option, "awsprofile"')

    if 'awscredsuri' in options and 'iam' not in options:
        fatal_error('The "iam" option is required when mounting with "awscredsuri"')

    if 'awscredsuri' in options and 'awsprofile' in options:
        fatal_error('The "awscredsuri" and "awsprofile" options are mutually exclusive')


def bootstrap_cloudwatch_logging(config, fs_id=None):
    if not check_if_cloudwatch_log_enabled(config):
        return None

    cloudwatchlog_client = get_botocore_client(config, 'logs')

    if not cloudwatchlog_client:
        return None

    cloudwatchlog_config = get_cloudwatchlog_config(config, fs_id)
    log_group_name = cloudwatchlog_config.get('log_group_name')
    log_stream_name = cloudwatchlog_config.get('log_stream_name')
    retention_days = cloudwatchlog_config.get('retention_days')

    group_creation_completed = create_cloudwatch_log_group(cloudwatchlog_client, log_group_name)

    if not group_creation_completed:
        return None

    put_retention_policy_completed = put_cloudwatch_log_retention_policy(cloudwatchlog_client, log_group_name, retention_days)

    if not put_retention_policy_completed:
        return None

    stream_creation_completed = create_cloudwatch_log_stream(cloudwatchlog_client, log_group_name, log_stream_name)

    if not stream_creation_completed:
        return None

    return {
        'client': cloudwatchlog_client,
        'log_group_name': log_group_name,
        'log_stream_name': log_stream_name
    }


def create_default_cloudwatchlog_agent_if_not_exist(config):
    if not check_if_cloudwatch_log_enabled(config):
        return None
    global CLOUDWATCHLOG_AGENT
    if not CLOUDWATCHLOG_AGENT:
        CLOUDWATCHLOG_AGENT = bootstrap_cloudwatch_logging(config)


def get_botocore_client(config, service):
    if not BOTOCORE_PRESENT:
        logging.error('Failed to import botocore, please install botocore first.')
        return None

    session = botocore.session.get_session()
    region = get_target_region(config)

    iam_role_name = get_iam_role_name()
    if iam_role_name:
        credentials, _ = get_aws_security_credentials_from_instance_metadata(iam_role_name)
        if credentials:
            return session.create_client(service, aws_access_key_id=credentials['AccessKeyId'],
                                         aws_secret_access_key=credentials['SecretAccessKey'],
                                         aws_session_token=credentials['Token'], region_name=region)
    return session.create_client(service, region_name=region)


def get_cloudwatchlog_config(config, fs_id=None):
    log_group_name = DEFAULT_CLOUDWATCH_LOG_GROUP
    if config.has_option(CLOUDWATCH_LOG_SECTION, 'log_group_name'):
        log_group_name = config.get(CLOUDWATCH_LOG_SECTION, 'log_group_name')

    retention_days = DEFAULT_RETENTION_DAYS
    if config.has_option(CLOUDWATCH_LOG_SECTION, 'retention_in_days'):
        retention_days = config.get(CLOUDWATCH_LOG_SECTION, 'retention_in_days')

    log_stream_name = get_cloudwatch_log_stream_name(fs_id)

    return {
        'log_group_name': log_group_name,
        'retention_days': int(retention_days),
        'log_stream_name': log_stream_name
    }


def get_cloudwatch_log_stream_name(fs_id=None):
    instance_id = get_instance_identity_info_from_instance_metadata('instanceId')
    if instance_id and fs_id:
        log_stream_name = '%s - %s - mount.log' % (fs_id, instance_id)
    elif instance_id:
        log_stream_name = '%s - mount.log' % (instance_id)
    elif fs_id:
        log_stream_name = '%s - mount.log' % (fs_id)
    else:
        log_stream_name = 'default - mount.log'

    return log_stream_name


def check_if_cloudwatch_log_enabled(config):
    if config.has_option(CLOUDWATCH_LOG_SECTION, 'enabled'):
        return config.getboolean(CLOUDWATCH_LOG_SECTION, 'enabled')
    return False


def cloudwatch_create_log_group_helper(cloudwatchlog_client, log_group_name):
    cloudwatchlog_client.create_log_group(
        logGroupName=log_group_name
    )
    logging.info('Created cloudwatch log group %s' % log_group_name)


def create_cloudwatch_log_group(cloudwatchlog_client, log_group_name):
    try:
        cloudwatch_create_log_group_helper(cloudwatchlog_client, log_group_name)
    except ClientError as e:
        exception = e.response['Error']['Code']

        if exception == 'ResourceAlreadyExistsException':
            logging.debug('Log group %s already exist, %s' % (log_group_name, e.response))
            return True
        elif exception == 'LimitExceededException':
            logging.error('Reached the maximum number of log groups that can be created, %s' % e.response)
            return False
        elif exception == 'OperationAbortedException':
            logging.debug('Multiple requests to update the same log group %s were in conflict, %s' % (log_group_name, e.response))
            return False
        elif exception == 'InvalidParameterException':
            logging.error('Log group name %s is specified incorrectly, %s' % (log_group_name, e.response))
            return False
        else:
            handle_general_botocore_exceptions(e)
            return False
    except NoCredentialsError as e:
        logging.warning('Credentials are not properly configured, %s' % e)
        return False
    except EndpointConnectionError as e:
        logging.warning('Could not connect to the endpoint, %s' % e)
        return False
    except Exception as e:
        logging.warning('Unknown error, %s.' % e)
        return False
    return True


def cloudwatch_put_retention_policy_helper(cloudwatchlog_client, log_group_name, retention_days):
    cloudwatchlog_client.put_retention_policy(
        logGroupName=log_group_name,
        retentionInDays=retention_days
    )
    logging.debug('Set cloudwatch log group retention days to %s' % retention_days)


def put_cloudwatch_log_retention_policy(cloudwatchlog_client, log_group_name, retention_days):
    try:
        cloudwatch_put_retention_policy_helper(cloudwatchlog_client, log_group_name, retention_days)
    except ClientError as e:
        exception = e.response['Error']['Code']

        if exception == 'ResourceNotFoundException':
            logging.error('Log group %s does not exist, %s' % (log_group_name, e.response))
            return False
        elif exception == 'OperationAbortedException':
            logging.debug('Multiple requests to update the same log group %s were in conflict, %s' % (log_group_name, e.response))
            return False
        elif exception == 'InvalidParameterException':
            logging.error('Either parameter log group name %s or retention in days %s is specified incorrectly, %s'
                          % (log_group_name, retention_days, e.response))
            return False
        else:
            handle_general_botocore_exceptions(e)
            return False
    except NoCredentialsError as e:
        logging.warning('Credentials are not properly configured, %s' % e)
        return False
    except EndpointConnectionError as e:
        logging.warning('Could not connect to the endpoint, %s' % e)
        return False
    except Exception as e:
        logging.warning('Unknown error, %s.' % e)
        return False
    return True


def cloudwatch_create_log_stream_helper(cloudwatchlog_client, log_group_name, log_stream_name):
    cloudwatchlog_client.create_log_stream(
        logGroupName=log_group_name,
        logStreamName=log_stream_name
    )
    logging.info('Created cloudwatch log stream %s in log group %s' % (log_stream_name, log_group_name))


def create_cloudwatch_log_stream(cloudwatchlog_client, log_group_name, log_stream_name):
    try:
        cloudwatch_create_log_stream_helper(cloudwatchlog_client, log_group_name, log_stream_name)
    except ClientError as e:
        exception = e.response['Error']['Code']

        if exception == 'ResourceAlreadyExistsException':
            logging.debug('Log stream %s already exist in log group %s, %s' % (log_stream_name, log_group_name, e.response))
            return True
        elif exception == 'InvalidParameterException':
            logging.error('Either parameter log group name %s or log stream name %s is specified incorrectly, %s'
                          % (log_group_name, log_stream_name, e.response))
            return False
        elif exception == 'ResourceNotFoundException':
            logging.error('Log group %s does not exist, %s' % (log_group_name, e.response))
            return False
        else:
            handle_general_botocore_exceptions(e)
            return False
    except NoCredentialsError as e:
        logging.warning('Credentials are not properly configured, %s' % e)
        return False
    except EndpointConnectionError as e:
        logging.warning('Could not connect to the endpoint, %s' % e)
        return False
    except Exception as e:
        logging.warning('Unknown error, %s.' % e)
        return False
    return True


def cloudwatch_put_log_events_helper(cloudwatchlog_agent, message, token=None):
    kwargs = {
        'logGroupName': cloudwatchlog_agent.get('log_group_name'),
        'logStreamName': cloudwatchlog_agent.get('log_stream_name'),
        'logEvents': [
            {
                'timestamp': int(round(time.time() * 1000)),
                'message': message
            }
        ]
    }
    if token:
        kwargs['sequenceToken'] = token
    cloudwatchlog_agent.get('client').put_log_events(**kwargs)


def publish_cloudwatch_log(cloudwatchlog_agent, message):
    if not cloudwatchlog_agent or not cloudwatchlog_agent.get('client'):
        return False

    token = get_log_stream_next_token(cloudwatchlog_agent)

    try:
        cloudwatch_put_log_events_helper(cloudwatchlog_agent, message, token)
    except ClientError as e:
        exception = e.response['Error']['Code']

        if exception == 'InvalidSequenceTokenException':
            logging.debug('The sequence token is not valid, %s' % e.response)
            return False
        elif exception == 'InvalidParameterException':
            logging.debug('One of the parameter to put log events is not valid, %s' % e.response)
            return False
        elif exception == 'DataAlreadyAcceptedException':
            logging.debug('The event %s was already logged, %s' % (message, e.response))
            return False
        elif exception == 'UnrecognizedClientException':
            logging.debug('The most likely cause is an invalid AWS access key ID or secret Key, %s' % e.response)
            return False
        elif exception == 'ResourceNotFoundException':
            logging.error('Either log group %s or log stream %s does not exist, %s'
                          % (cloudwatchlog_agent.get('log_group_name'), cloudwatchlog_agent.get('log_stream_name'), e.response))
            return False
        else:
            logging.debug('Unexpected error: %s' % e)
            return False
    except NoCredentialsError as e:
        logging.warning('Credentials are not properly configured, %s' % e)
        return False
    except EndpointConnectionError as e:
        logging.warning('Could not connect to the endpoint, %s' % e)
        return False
    except Exception as e:
        logging.warning('Unknown error, %s.' % e)
        return False
    return True


def cloudwatch_describe_log_streams_helper(cloudwatchlog_agent):
    return cloudwatchlog_agent.get('client').describe_log_streams(
        logGroupName=cloudwatchlog_agent.get('log_group_name'),
        logStreamNamePrefix=cloudwatchlog_agent.get('log_stream_name')
    )


def get_log_stream_next_token(cloudwatchlog_agent):
    try:
        response = cloudwatch_describe_log_streams_helper(cloudwatchlog_agent)
    except ClientError as e:
        exception = e.response['Error']['Code']

        if exception == 'InvalidParameterException':
            logging.debug('Either parameter log group name %s or log stream name %s is specified incorrectly, %s'
                          % (cloudwatchlog_agent.get('log_group_name'), cloudwatchlog_agent.get('log_stream_name'), e.response))
        elif exception == 'ResourceNotFoundException':
            logging.debug('Either log group %s or log stream %s does not exist, %s'
                          % (cloudwatchlog_agent.get('log_group_name'), cloudwatchlog_agent.get('log_stream_name'), e.response))
        else:
            handle_general_botocore_exceptions(e)
        return None
    except NoCredentialsError as e:
        logging.warning('Credentials are not properly configured, %s' % e)
        return None
    except EndpointConnectionError as e:
        logging.warning('Could not connect to the endpoint, %s' % e)
        return None
    except Exception as e:
        logging.warning('Unknown error, %s' % e)
        return None

    try:
        log_stream = response['logStreams'][0]
        return log_stream.get('uploadSequenceToken')
    except (IndexError, TypeError, KeyError):
        pass

    return None


def handle_general_botocore_exceptions(error):
    exception = error.response['Error']['Code']

    if exception == 'ServiceUnavailableException':
        logging.debug('The service cannot complete the request, %s' % error.response)
    elif exception == 'AccessDeniedException':
        logging.debug('User is not authorized to perform the action, %s' % error.response)
    else:
        logging.debug('Unexpected error: %s' % error)


def main():
    parse_arguments_early_exit()

    assert_root()

    config = read_config()
    bootstrap_logging(config)

    fs_id, path, mountpoint, options = parse_arguments(config)

    logging.info('version=%s options=%s', VERSION, options)

    global CLOUDWATCHLOG_AGENT
    CLOUDWATCHLOG_AGENT = bootstrap_cloudwatch_logging(config, fs_id)

    check_unsupported_options(options)
    check_options_validity(options)

    init_system = get_init_system()
    check_network_status(fs_id, init_system)

    dns_name = get_dns_name(config, fs_id)

    if 'tls' in options:
        mount_tls(config, init_system, dns_name, path, fs_id, mountpoint, options)
    else:
        mount_nfs(dns_name, path, mountpoint, options)


if '__main__' == __name__:
    main()
