#!/usr/bin/env python3
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
import platform
import pwd
import re
import shutil
import socket
import subprocess
import sys
import time
from collections import namedtuple
from contextlib import contextmanager
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler
from signal import SIGHUP, SIGKILL, SIGTERM

try:
    from configparser import ConfigParser, NoOptionError, NoSectionError
except ImportError:
    import ConfigParser
    from ConfigParser import NoOptionError, NoSectionError

try:
    from urllib.parse import quote_plus
except ImportError:
    from urllib import quote_plus

try:
    from urllib.error import HTTPError, URLError
    from urllib.parse import urlencode
    from urllib.request import Request, urlopen
except ImportError:
    from urllib import urlencode

    from urllib2 import HTTPError, HTTPHandler, Request, URLError, build_opener, urlopen


AMAZON_LINUX_2_RELEASE_ID = "Amazon Linux release 2 (Karoo)"
AMAZON_LINUX_2_PRETTY_NAME = "Amazon Linux 2"
AMAZON_LINUX_2_RELEASE_VERSIONS = [
    AMAZON_LINUX_2_RELEASE_ID,
    AMAZON_LINUX_2_PRETTY_NAME,
]
VERSION = "1.34.4"
SERVICE = "elasticfilesystem"

CONFIG_FILE = "/etc/amazon/efs/efs-utils.conf"
CONFIG_SECTION = "mount-watchdog"
MOUNT_CONFIG_SECTION = "mount"
CLIENT_INFO_SECTION = "client-info"
CLIENT_SOURCE_STR_LEN_LIMIT = 100
DISABLE_FETCH_EC2_METADATA_TOKEN_ITEM = "disable_fetch_ec2_metadata_token"
DEFAULT_UNKNOWN_VALUE = "unknown"
DEFAULT_MACOS_VALUE = "macos"
# 50ms
DEFAULT_TIMEOUT = 0.05

LOG_DIR = "/var/log/amazon/efs"
LOG_FILE = "mount-watchdog.log"

STATE_FILE_DIR = "/var/run/efs"
STUNNEL_PID_FILE = "stunnel.pid"

DEFAULT_NFS_PORT = "2049"
PRIVATE_KEY_FILE = "/etc/amazon/efs/privateKey.pem"
DEFAULT_REFRESH_SELF_SIGNED_CERT_INTERVAL_MIN = 60
DEFAULT_STUNNEL_HEALTH_CHECK_INTERVAL_MIN = 5
DEFAULT_STUNNEL_HEALTH_CHECK_TIMEOUT_SEC = 30
NOT_BEFORE_MINS = 15
NOT_AFTER_HOURS = 3
DATE_ONLY_FORMAT = "%Y%m%d"
SIGV4_DATETIME_FORMAT = "%Y%m%dT%H%M%SZ"
CERT_DATETIME_FORMAT = "%y%m%d%H%M%SZ"

AWS_CREDENTIALS_FILES = {
    "credentials": os.path.expanduser(
        os.path.join("~" + pwd.getpwuid(os.getuid()).pw_name, ".aws", "credentials")
    ),
    "config": os.path.expanduser(
        os.path.join("~" + pwd.getpwuid(os.getuid()).pw_name, ".aws", "config")
    ),
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

%s
"""

# SigV4 Auth
ALGORITHM = "AWS4-HMAC-SHA256"
AWS4_REQUEST = "aws4_request"

HTTP_REQUEST_METHOD = "GET"
CANONICAL_URI = "/"
CANONICAL_HEADERS_DICT = {"host": "%s"}
CANONICAL_HEADERS = "\n".join(
    ["%s:%s" % (k, v) for k, v in sorted(CANONICAL_HEADERS_DICT.items())]
)
SIGNED_HEADERS = ";".join(CANONICAL_HEADERS_DICT.keys())
REQUEST_PAYLOAD = ""

AP_ID_RE = re.compile("^fsap-[0-9a-f]{17}$")

ECS_TASK_METADATA_API = "http://169.254.170.2"
STS_ENDPOINT_URL_FORMAT = "https://sts.{}.amazonaws.com/"
INSTANCE_IAM_URL = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
INSTANCE_METADATA_TOKEN_URL = "http://169.254.169.254/latest/api/token"
SECURITY_CREDS_ECS_URI_HELP_URL = (
    "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html"
)
SECURITY_CREDS_WEBIDENTITY_HELP_URL = "https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html"
SECURITY_CREDS_IAM_ROLE_HELP_URL = (
    "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html"
)
NAMED_PROFILE_HELP_URL = (
    "https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-profiles.html"
)
CONFIG_FILE_SETTINGS_HELP_URL = (
    "https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html"
    "#cli-configure-files-settings"
)

Mount = namedtuple(
    "Mount", ["server", "mountpoint", "type", "options", "freq", "passno"]
)

NFSSTAT_TIMEOUT = 5

# Unmount difference time in seconds
UNMOUNT_DIFF_TIME = 30

# Default unmount count for consistency
DEFAULT_UNMOUNT_COUNT_FOR_CONSISTENCY = 5

MAC_OS_PLATFORM_LIST = ["darwin"]
SYSTEM_RELEASE_PATH = "/etc/system-release"
OS_RELEASE_PATH = "/etc/os-release"
STUNNEL_INSTALLATION_MESSAGE = "Please install it following the instructions at: https://docs.aws.amazon.com/efs/latest/ug/using-amazon-efs-utils.html#upgrading-stunnel"


def fatal_error(user_message, log_message=None):
    if log_message is None:
        log_message = user_message

    sys.stderr.write("%s\n" % user_message)
    logging.error(log_message)
    sys.exit(1)


def get_aws_security_credentials(config, credentials_source, region):
    """
    Lookup AWS security credentials (access key ID and secret access key). Adapted credentials provider chain from:
    https://boto3.amazonaws.com/v1/documentation/api/latest/guide/configuration.html and
    https://docs.aws.amazon.com/sdk-for-java/v1/developer-guide/credentials.html
    """
    method, value = credentials_source.split(":", 1)

    if method == "credentials":
        return get_aws_security_credentials_from_file("credentials", value)
    elif method == "named_profile":
        return get_aws_security_credentials_from_assumed_profile(value)
    elif method == "config":
        return get_aws_security_credentials_from_file("config", value)
    elif method == "ecs":
        return get_aws_security_credentials_from_ecs(config, value)
    elif method == "webidentity":
        return get_aws_security_credentials_from_webidentity(
            config, *(value.split(",")), region=region
        )
    elif method == "metadata":
        return get_aws_security_credentials_from_instance_metadata(config)
    else:
        logging.error(
            'Improper credentials source string "%s" found from mount state file',
            credentials_source,
        )
        return None


def get_boolean_config_item_value(
    config, config_section, config_item, default_value, emit_warning_message=False
):
    warning_message = None
    if not config.has_section(config_section):
        warning_message = (
            "Warning: config file does not have section %s." % config_section
        )
    elif not config.has_option(config_section, config_item):
        warning_message = (
            "Warning: config file does not have %s item in section %s."
            % (config_item, config_section)
        )

    if warning_message:
        if emit_warning_message:
            sys.stdout.write(
                "%s. You should be able to find a new config file in the same folder as current config file %s. "
                "Consider update the new config file to latest config file. Use the default value [%s = %s]."
                % (warning_message, CONFIG_FILE, config_item, default_value)
            )
        return default_value
    return config.getboolean(config_section, config_item)


def fetch_ec2_metadata_token_disabled(config):
    return get_boolean_config_item_value(
        config,
        MOUNT_CONFIG_SECTION,
        DISABLE_FETCH_EC2_METADATA_TOKEN_ITEM,
        default_value=False,
    )


def get_aws_ec2_metadata_token(timeout=DEFAULT_TIMEOUT):
    # Normally the session token is fetched within 10ms, setting a timeout of 50ms here to abort the request
    # and return None if the token has not returned within 50ms
    try:
        opener = build_opener(HTTPHandler)
        request = Request(INSTANCE_METADATA_TOKEN_URL)
        request.add_header("X-aws-ec2-metadata-token-ttl-seconds", "21600")
        request.get_method = lambda: "PUT"
        try:
            res = opener.open(request, timeout=timeout)
            return res.read()
        except socket.timeout:
            exception_message = "Timeout when getting the aws ec2 metadata token"
        except HTTPError as e:
            exception_message = "Failed to fetch token due to %s" % e
        except Exception as e:
            exception_message = (
                "Unknown error when fetching aws ec2 metadata token, %s" % e
            )
        logging.debug(exception_message)
        return None
    except NameError:
        headers = {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}
        req = Request(INSTANCE_METADATA_TOKEN_URL, headers=headers, method="PUT")
        try:
            res = urlopen(req, timeout=timeout)
            return res.read()
        except socket.timeout:
            exception_message = "Timeout when getting the aws ec2 metadata token"
        except HTTPError as e:
            exception_message = "Failed to fetch token due to %s" % e
        except Exception as e:
            exception_message = (
                "Unknown error when fetching aws ec2 metadata token, %s" % e
            )
        logging.debug(exception_message)
        return None


def get_aws_security_credentials_from_file(file_name, awsprofile):
    # attempt to lookup AWS security credentials in AWS credentials file (~/.aws/credentials) and configs file (~/.aws/config)
    file_path = AWS_CREDENTIALS_FILES.get(file_name)
    if file_path and os.path.exists(file_path):
        credentials = credentials_file_helper(file_path, awsprofile)
        if credentials["AccessKeyId"]:
            return credentials

    logging.error(
        "AWS security credentials not found in %s under named profile [%s]",
        file_path,
        awsprofile,
    )
    return None


def get_aws_security_credentials_from_assumed_profile(awsprofile):
    credentials = botocore_credentials_helper(awsprofile)
    if credentials["AccessKeyId"]:
        return credentials

    logging.error(
        "AWS security credentials not found via assuming named profile [%s] using botocore",
        awsprofile,
    )
    return None


def botocore_credentials_helper(awsprofile):
    credentials = {"AccessKeyId": None, "SecretAccessKey": None, "Token": None}

    try:
        import botocore.session
        from botocore.exceptions import ProfileNotFound
    except ImportError:
        logging.error(
            "Named profile credentials cannot be retrieved without botocore, please install botocore first."
        )
        return credentials

    session = botocore.session.get_session()
    session.set_config_variable("profile", awsprofile)

    try:
        frozen_credentials = session.get_credentials().get_frozen_credentials()
    except ProfileNotFound as e:
        logging.error(
            "%s, please add the [profile %s] section in the aws config file following %s and %s."
            % (e, awsprofile, NAMED_PROFILE_HELP_URL, CONFIG_FILE_SETTINGS_HELP_URL)
        )
        return credentials

    credentials["AccessKeyId"] = frozen_credentials.access_key
    credentials["SecretAccessKey"] = frozen_credentials.secret_key
    credentials["Token"] = frozen_credentials.token
    return credentials


def get_aws_security_credentials_from_ecs(config, uri):
    # through ECS security credentials uri found in AWS_CONTAINER_CREDENTIALS_RELATIVE_URI environment variable
    dict_keys = ["AccessKeyId", "SecretAccessKey", "Token"]
    ecs_uri = ECS_TASK_METADATA_API + uri
    ecs_unsuccessful_resp = (
        "Unsuccessful retrieval of AWS security credentials at %s." % ecs_uri
    )
    ecs_url_error_msg = (
        "Unable to reach %s to retrieve AWS security credentials. See %s for more info."
        % (ecs_uri, SECURITY_CREDS_ECS_URI_HELP_URL)
    )
    ecs_security_dict = url_request_helper(
        config, ecs_uri, ecs_unsuccessful_resp, ecs_url_error_msg
    )

    if ecs_security_dict and all(k in ecs_security_dict for k in dict_keys):
        return ecs_security_dict

    return None


def get_aws_security_credentials_from_webidentity(config, role_arn, token_file, region):
    try:
        with open(token_file, "r") as f:
            token = f.read()
    except Exception as e:
        logging.error("Error reading token file %s: %s", token_file, e)
        return None

    STS_ENDPOINT_URL = STS_ENDPOINT_URL_FORMAT.format(region)
    webidentity_url = (
        STS_ENDPOINT_URL
        + "?"
        + urlencode(
            {
                "Version": "2011-06-15",
                "Action": "AssumeRoleWithWebIdentity",
                "RoleArn": role_arn,
                "RoleSessionName": "efs-mount-helper",
                "WebIdentityToken": token,
            }
        )
    )

    unsuccessful_resp = (
        "Unsuccessful retrieval of AWS security credentials at %s." % STS_ENDPOINT_URL
    )
    url_error_msg = (
        "Unable to reach %s to retrieve AWS security credentials. See %s for more info."
        % (STS_ENDPOINT_URL, SECURITY_CREDS_WEBIDENTITY_HELP_URL)
    )
    resp = url_request_helper(
        config,
        webidentity_url,
        unsuccessful_resp,
        url_error_msg,
        headers={"Accept": "application/json"},
    )

    if resp:
        creds = (
            resp.get("AssumeRoleWithWebIdentityResponse", {})
            .get("AssumeRoleWithWebIdentityResult", {})
            .get("Credentials", {})
        )
        if all(k in creds for k in ["AccessKeyId", "SecretAccessKey", "SessionToken"]):
            return {
                "AccessKeyId": creds["AccessKeyId"],
                "SecretAccessKey": creds["SecretAccessKey"],
                "Token": creds["SessionToken"],
            }

    return None


def get_aws_security_credentials_from_instance_metadata(config):
    # through IAM role name security credentials lookup uri (after lookup for IAM role name attached to instance)
    dict_keys = ["AccessKeyId", "SecretAccessKey", "Token"]
    iam_role_unsuccessful_resp = (
        "Unsuccessful retrieval of IAM role name at %s." % INSTANCE_IAM_URL
    )
    iam_role_url_error_msg = (
        "Unable to reach %s to retrieve IAM role name. See %s for more info."
        % (INSTANCE_IAM_URL, SECURITY_CREDS_IAM_ROLE_HELP_URL)
    )
    iam_role_name = url_request_helper(
        config, INSTANCE_IAM_URL, iam_role_unsuccessful_resp, iam_role_url_error_msg
    )
    if iam_role_name:
        security_creds_lookup_url = INSTANCE_IAM_URL + iam_role_name
        unsuccessful_resp = (
            "Unsuccessful retrieval of AWS security credentials at %s."
            % security_creds_lookup_url
        )
        url_error_msg = (
            "Unable to reach %s to retrieve AWS security credentials. See %s for more info."
            % (security_creds_lookup_url, SECURITY_CREDS_IAM_ROLE_HELP_URL)
        )
        iam_security_dict = url_request_helper(
            config, security_creds_lookup_url, unsuccessful_resp, url_error_msg
        )

        if iam_security_dict and all(k in iam_security_dict for k in dict_keys):
            return iam_security_dict

    return None


def credentials_file_helper(file_path, awsprofile):
    aws_credentials_configs = read_config(file_path)
    credentials = {"AccessKeyId": None, "SecretAccessKey": None, "Token": None}

    try:
        aws_access_key_id = aws_credentials_configs.get(awsprofile, "aws_access_key_id")
        secret_access_key = aws_credentials_configs.get(
            awsprofile, "aws_secret_access_key"
        )
        session_token = aws_credentials_configs.get(awsprofile, "aws_session_token")

        credentials["AccessKeyId"] = aws_access_key_id
        credentials["SecretAccessKey"] = secret_access_key
        credentials["Token"] = session_token
    except NoOptionError as e:
        if "aws_access_key_id" in str(e) or "aws_secret_access_key" in str(e):
            logging.debug(
                "aws_access_key_id or aws_secret_access_key not found in %s under named profile [%s]",
                file_path,
                awsprofile,
            )
        if "aws_session_token" in str(e):
            logging.debug("aws_session_token not found in %s", file_path)
            credentials["AccessKeyId"] = aws_credentials_configs.get(
                awsprofile, "aws_access_key_id"
            )
            credentials["SecretAccessKey"] = aws_credentials_configs.get(
                awsprofile, "aws_secret_access_key"
            )
    except NoSectionError:
        logging.debug("No [%s] section found in config file %s", awsprofile, file_path)

    return credentials


def is_instance_metadata_url(url):
    return url.startswith("http://169.254.169.254")


def url_request_helper(config, url, unsuccessful_resp, url_error_msg, headers={}):
    try:
        req = Request(url)
        for k, v in headers.items():
            req.add_header(k, v)

        if not fetch_ec2_metadata_token_disabled(config) and is_instance_metadata_url(
            url
        ):
            # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
            # IMDSv1 is a request/response method to access instance metadata
            # IMDSv2 is a session-oriented method to access instance metadata
            # We expect the token retrieve will fail in bridge networking environment (e.g. container) since the default hop
            # limit for getting the token is 1. If the token retrieve does timeout, we fallback to use IMDSv1 instead
            token = get_aws_ec2_metadata_token()
            if token:
                req.add_header("X-aws-ec2-metadata-token", token)

        request_resp = urlopen(req, timeout=1)

        return get_resp_obj(request_resp, url, unsuccessful_resp)
    except socket.timeout:
        err_msg = "Request timeout"
    except HTTPError as e:
        # For instance enable with IMDSv2 and fetch token disabled, Unauthorized 401 error will be thrown
        if (
            e.code == 401
            and fetch_ec2_metadata_token_disabled(config)
            and is_instance_metadata_url(url)
        ):
            logging.warning(
                "Unauthorized request to instance metadata url %s, IMDSv2 is enabled on the instance, while fetching "
                "ec2 metadata token is disabled. Please set the value of config item "
                '"%s" to "false" in config file %s.'
                % (url, DISABLE_FETCH_EC2_METADATA_TOKEN_ITEM, CONFIG_FILE)
            )
        err_msg = "Unable to reach the url at %s: status=%d, reason is %s" % (
            url,
            e.code,
            e.reason,
        )
    except URLError as e:
        err_msg = "Unable to reach the url at %s, reason is %s" % (url, e.reason)

    if err_msg:
        logging.debug("%s %s", url_error_msg, err_msg)
    return None


def get_resp_obj(request_resp, url, unsuccessful_resp):
    if request_resp.getcode() != 200:
        logging.debug(
            unsuccessful_resp + " %s: ResponseCode=%d", url, request_resp.getcode()
        )
        return None

    resp_body = request_resp.read()
    resp_body_type = type(resp_body)
    try:
        if resp_body_type is str:
            resp_dict = json.loads(resp_body)
        else:
            resp_dict = json.loads(
                resp_body.decode(
                    request_resp.headers.get_content_charset() or "us-ascii"
                )
            )

        return resp_dict
    except ValueError:
        return resp_body if resp_body_type is str else resp_body.decode("utf-8")


def bootstrap_logging(config, log_dir=LOG_DIR):
    raw_level = config.get(CONFIG_SECTION, "logging_level")
    levels = {
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "warning": logging.WARNING,
        "error": logging.ERROR,
        "critical": logging.CRITICAL,
    }
    level = levels.get(raw_level.lower())
    level_error = False

    if not level:
        # delay logging error about malformed log level until after logging is configured
        level_error = True
        level = logging.INFO

    max_bytes = config.getint(CONFIG_SECTION, "logging_max_bytes")
    file_count = config.getint(CONFIG_SECTION, "logging_file_count")

    handler = RotatingFileHandler(
        os.path.join(log_dir, LOG_FILE), maxBytes=max_bytes, backupCount=file_count
    )
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S %Z",
        )
    )

    logger = logging.getLogger()
    logger.setLevel(level)
    logger.addHandler(handler)

    if level_error:
        logging.error(
            'Malformed logging level "%s", setting logging level to %s',
            raw_level,
            level,
        )


def parse_options(options):
    opts = {}
    for o in options.split(","):
        if "=" in o:
            k, v = o.split("=")
            opts[k] = v
        else:
            opts[o] = None
    return opts


def get_file_safe_mountpoint(mount):
    mountpoint = os.path.abspath(mount.mountpoint).replace(os.sep, ".")
    if mountpoint.startswith("."):
        mountpoint = mountpoint[1:]

    opts = parse_options(mount.options)
    if "port" not in opts:
        if not check_if_running_on_macos():
            # /proc/mounts provides a list of all mounts in use by the system (including the mount options used).
            # In the case of tls mount: stunnel establishes a localhost port connection in order to listen on the requests,
            # and then send packets further to the server:2049. If the port is 2049 which is the default nfs port,
            # /proc/mounts will not display the port number in the options information, thus watchdog process will not treat
            # the mount as EFS mount and won't restart the killed stunnel which cause the mount hang.
            # So, tlsport=2049 is being added here by appending with the mountpoint.
            # Putting a default port 2049 to fix the Stunnel process being killed issue.
            opts["port"] = DEFAULT_NFS_PORT
        # some other localhost nfs mount not running over stunnel.
        # For MacOS, we ignore the port if the port is missing in mount options.
        else:
            return mountpoint
    return mountpoint + "." + opts["port"]


def get_current_local_nfs_mounts(mount_file="/proc/mounts"):
    """
    Return a dict of the current NFS mounts for servers running on localhost, keyed by the mountpoint and port as it
    appears in EFS watchdog state files.
    """
    mounts = []

    if not check_if_running_on_macos():
        with open(mount_file) as f:
            for mount in f:
                mounts.append(Mount._make(mount.strip().split()))
    else:
        # stat command on MacOS does not have '--file-system' option to verify the filesystem type of a mount point,
        # traverse all the mounts, and find if current mount point is already mounted
        process = subprocess.run(
            ["mount", "-t", "nfs"],
            check=True,
            stdout=subprocess.PIPE,
            universal_newlines=True,
        )
        stdout = process.stdout
        if stdout:
            output = stdout.split("\n")
            for mount in output:
                _mount = mount.split()
                if len(_mount) >= 4:
                    mount_ops = get_nfs_mount_options_on_macos(_mount[2], _mount[0])
                    # Sample output: 127.0.0.1:/ on /Users/ec2-user/efs (nfs)
                    mounts.append(
                        Mount._make(
                            [
                                _mount[0],
                                _mount[2],
                                _mount[3],
                                mount_ops if mount_ops else "",
                                0,
                                0,
                            ]
                        )
                    )
        else:
            logging.warning("No nfs mounts found")

    mounts = [m for m in mounts if m.server.startswith("127.0.0.1") and "nfs" in m.type]

    mount_dict = {}
    for m in mounts:
        safe_mnt = get_file_safe_mountpoint(m)
        if safe_mnt:
            mount_dict[safe_mnt] = m

    return mount_dict


def get_nfs_mount_options_on_macos(mount_point, mount_server="127.0.0.1:/"):

    if not mount_point:
        logging.warning("Unable to get local mount options with empty mount point")
        return None

    try:
        process = subprocess.run(
            ["nfsstat", "-f", "JSON", "-m", mount_point],
            check=True,
            stdout=subprocess.PIPE,
            universal_newlines=True,
            timeout=NFSSTAT_TIMEOUT,
        )
        stdout = process.stdout
        if not stdout:
            logging.warning(
                "Unable to get local mount options with mount point: %s", mount_point
            )
            return None
        try:
            state_json = json.loads(stdout)
        except ValueError:
            logging.exception("Unable to parse json of %s", stdout)
            return None
        try:
            return ",".join(
                state_json.get(mount_server)
                .get("Original mount options")
                .get("NFS parameters")
            )
        except AttributeError:
            logging.exception("Unable to get object in %s", state_json)
            return None
    except subprocess.TimeoutExpired:
        logging.warning(
            "Fetching nfs mount parameters timed out for mount point %s. Ignoring port option.",
            mount_point,
        )
        return None


def get_state_files(state_file_dir):
    """
    Return a dict of the absolute path of state files in state_file_dir,
    keyed by the mountpoint and port portion of the filename.
    """
    state_files = {}

    if os.path.isdir(state_file_dir):
        for sf in os.listdir(state_file_dir):
            if not sf.startswith("fs-") or os.path.isdir(
                os.path.join(state_file_dir, sf)
            ):
                continue

            # This translates the state file name "fs-deadbeaf.home.user.mnt.12345"
            # into file-safe mountpoint "home.user.mnt.12345"
            first_period = sf.find(".")
            mount_point_and_port = sf[first_period + 1 :]
            logging.debug(
                'Translating "%s" into mount point and port "%s"',
                sf,
                mount_point_and_port,
            )
            state_files[mount_point_and_port] = sf

    return state_files


def get_pid_in_state_dir(state_file, state_file_dir):
    """
    :param state_file: The state file path, e.g. fs-deadbeef.mnt.20560.
    :param state_file_dir: The state file dir path, e.g. /var/run/efs.
    """
    state_dir_pid_path = os.path.join(
        state_file_dir, state_file + "+", STUNNEL_PID_FILE
    )
    if os.path.exists(state_dir_pid_path):
        with open(state_dir_pid_path) as f:
            return f.read()
    return None


def is_mount_stunnel_proc_running(state_pid, state_file, state_file_dir):
    """
    Check whether a given stunnel process id in state file is running for the mount. To avoid we incorrectly checking
    processes running by other applications and send signal further, the stunnel process in state file is counted as
    running iff:
    1. The pid in state file is not None.
    2. The process running with the pid is a stunnel process. This is validated through process command name.
    3. The process can be reached via os.kill(pid, 0).
    4. Every launched stunnel process will write its process id to the pid file in the mount state_file_dir, and only
       when the stunnel is terminated this pid file can be removed. Check whether the stunnel pid file exists and its
       value is equal to the pid documented in state file. This step is to make sure we don't send signal later to any
       stunnel process that is not owned by the mount.

    :param state_pid: The pid in state file.
    :param state_file: The state file path, e.g. fs-deadbeef.mnt.20560.
    :param state_file_dir: The state file dir path, e.g. /var/run/efs.
    """
    if not state_pid:
        logging.debug("State pid is None for %s", state_file)
        return False

    process_name = check_process_name(state_pid)
    if not process_name or "stunnel" not in str(process_name):
        logging.debug(
            "Process running on %s is not a stunnel process, full command: %s.",
            state_pid,
            str(process_name) if process_name else "",
        )
        return False

    if not is_pid_running(state_pid):
        logging.debug(
            "Stunnel process with pid %s is not running anymore for %s.",
            state_pid,
            state_file,
        )
        return False

    pid_in_stunnel_pid_file = get_pid_in_state_dir(state_file, state_file_dir)
    # efs-utils versions older than 1.32.2 does not create a pid file in state dir
    # To avoid the healthy stunnel established by those version to be treated as not running due to the missing pid file, which can result in stunnel being constantly restarted,
    # assuming the stunnel is still running even if the stunnel pid file does not exist.
    if not pid_in_stunnel_pid_file:
        logging.debug(
            "Pid file of stunnel does not exist for %s. It is possible that the stunnel is no longer running or the mount was mounted using an older version efs-utils (<1.32.2). Assuming the stunnel with pid %s is still running.",
            state_file,
            state_pid,
        )

    elif int(state_pid) != int(pid_in_stunnel_pid_file):
        logging.warning(
            "Stunnel pid mismatch in state file (pid = %s) and stunnel pid file (pid = %s). Assuming the "
            "stunnel is not running.",
            int(state_pid),
            int(pid_in_stunnel_pid_file),
        )
        return False

    logging.debug("TLS tunnel for %s is running with pid %s", state_file, state_pid)
    return True


def is_pid_running(pid):
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def check_if_platform_is_mac():
    return sys.platform in MAC_OS_PLATFORM_LIST


def get_system_release_version():
    # MacOS does not maintain paths /etc/os-release and /etc/sys-release
    if check_if_platform_is_mac():
        return platform.platform()

    try:
        with open(SYSTEM_RELEASE_PATH) as f:
            return f.read().strip()
    except IOError:
        logging.debug("Unable to read %s", SYSTEM_RELEASE_PATH)

    try:
        with open(OS_RELEASE_PATH) as f:
            for line in f:
                if "PRETTY_NAME" in line:
                    return line.split("=")[1].strip()
    except IOError:
        logging.debug("Unable to read %s", OS_RELEASE_PATH)

    return DEFAULT_UNKNOWN_VALUE


def find_command_path(command, install_method):
    # If not running on macOS, use linux paths
    if not check_if_platform_is_mac():
        env_path = (
            "/sbin:/usr/sbin:/usr/local/sbin:/root/bin:/usr/local/bin:/usr/bin:/bin"
        )
    # Homebrew on x86 macOS uses /usr/local/bin; Homebrew on Apple Silicon macOS uses /opt/homebrew/bin since v3.0.0
    # For more information, see https://brew.sh/2021/02/05/homebrew-3.0.0/
    else:
        env_path = "/opt/homebrew/bin:/usr/local/bin"
    os.putenv("PATH", env_path)

    try:
        path = subprocess.check_output(["which", command])
        return path.strip().decode()
    except subprocess.CalledProcessError as e:
        fatal_error(
            "Failed to locate %s in %s - %s" % (command, env_path, install_method), e
        )


# In ECS amazon linux 2, we start stunnel using `nsenter` which will run as a subprocess of bash, utilizes the `setns`
# system call to join an existing namespace and then executes the specified program using `exec`. Any exception won't
# be caught properly by subprocess.
# As a precaution on ECS AL2 that stunnel bin is removed after installing new efs-utils, and watchdog cannot launch
# stunnel for previous old mount, we do a replacement of stunnel path in the command to the stunnel5 path.
#
def update_stunnel_command_for_ecs_amazon_linux_2(
    command, state, state_file_dir, state_file
):
    if (
        "nsenter" in command
        and "stunnel5" not in " ".join(command)
        and get_system_release_version() in AMAZON_LINUX_2_RELEASE_VERSIONS
    ):
        for i in range(len(command)):
            if "stunnel" in command[i] and "stunnel-config" not in command[i]:
                command[i] = find_command_path("stunnel5", STUNNEL_INSTALLATION_MESSAGE)
                break
        logging.info(
            "Rewriting %s with new stunnel cmd: %s for ECS Amazon Linux 2 platform.",
            state_file,
            " ".join(state["cmd"]),
        )
        rewrite_state_file(state, state_file_dir, state_file)
    return command


def start_tls_tunnel(child_procs, state, state_file_dir, state_file):
    # launch the tunnel in a process group so if it has any child processes, they can be killed easily
    command = state["cmd"]
    logging.info('Starting TLS tunnel: "%s"', " ".join(command))

    command = update_stunnel_command_for_ecs_amazon_linux_2(
        command, state, state_file_dir, state_file
    )
    tunnel = None
    try:
        tunnel = subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid,
            close_fds=True,
        )
    except FileNotFoundError as e:
        logging.warning("Watchdog failed to start stunnel due to %s", e)

        # https://github.com/kubernetes-sigs/aws-efs-csi-driver/issues/812 It is possible that the stunnel is not
        # present anymore and replaced by stunnel5 on AL2, meanwhile watchdog is attempting to restart stunnel for
        # mount using old efs-utils based on old state file generated during previous mount, which has stale command
        # using stunnel bin. Update the state file if the stunnel does not exist anymore, and use stunnel5 on Al2.
        #
        if get_system_release_version() in AMAZON_LINUX_2_RELEASE_VERSIONS:
            for i in range(len(command)):
                if "stunnel" in command[i] and "stunnel-config" not in command[i]:
                    command[i] = find_command_path(
                        "stunnel5", STUNNEL_INSTALLATION_MESSAGE
                    )
                    break

            tunnel = subprocess.Popen(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid,
                close_fds=True,
            )

            state["cmd"] = command
            logging.info(
                "Rewriting %s with new stunnel cmd: %s for Amazon Linux 2 platform.",
                state_file,
                " ".join(state["cmd"]),
            )
            rewrite_state_file(state, state_file_dir, state_file)

    if tunnel is None or not is_pid_running(tunnel.pid):
        fatal_error(
            "Failed to initialize TLS tunnel for %s" % state_file,
            "Failed to start TLS tunnel.",
        )

    logging.info("Started TLS tunnel, pid: %d", tunnel.pid)

    child_procs.append(tunnel)
    return tunnel.pid


def clean_up_mount_state(state_file_dir, state_file, pid, mount_state_dir=None):
    send_signal_to_running_stunnel_process_group(
        pid, state_file, state_file_dir, SIGTERM
    )
    cleanup_mount_state_if_stunnel_not_running(
        pid, state_file, state_file_dir, mount_state_dir
    )


def cleanup_mount_state_if_stunnel_not_running(
    pid, state_file, state_file_dir, mount_state_dir
):
    if is_mount_stunnel_proc_running(pid, state_file, state_file_dir):
        logging.info("TLS tunnel: %d is still running, will retry termination", pid)
    else:
        if not pid:
            logging.info("TLS tunnel has been killed, cleaning up state")
        else:
            logging.info("TLS tunnel: %d is no longer running, cleaning up state", pid)
        state_file_path = os.path.join(state_file_dir, state_file)
        with open(state_file_path) as f:
            state = json.load(f)

        for f in state.get("files", list()):
            logging.debug("Deleting %s", f)
            try:
                os.remove(f)
                logging.debug("Deleted %s", f)
            except OSError as e:
                if e.errno != errno.ENOENT:
                    raise

        os.remove(state_file_path)

        if mount_state_dir is not None:
            mount_state_dir_abs_path = os.path.join(state_file_dir, mount_state_dir)
            if os.path.isdir(mount_state_dir_abs_path):
                shutil.rmtree(mount_state_dir_abs_path)
            else:
                logging.debug(
                    "Attempt to remove mount state directory %s failed. Directory is not present.",
                    mount_state_dir_abs_path,
                )


def rewrite_state_file(state, state_file_dir, state_file):
    tmp_state_file = os.path.join(state_file_dir, "~%s" % state_file)
    with open(tmp_state_file, "w") as f:
        json.dump(state, f)

    os.rename(tmp_state_file, os.path.join(state_file_dir, state_file))


def mark_as_unmounted(state, state_file_dir, state_file, current_time):
    logging.debug("Marking %s as unmounted at %d", state_file, current_time)
    state["unmount_time"] = current_time

    rewrite_state_file(state, state_file_dir, state_file)

    return state


def restart_tls_tunnel(child_procs, state, state_file_dir, state_file):
    if "certificate" in state and not os.path.exists(state["certificate"]):
        logging.error(
            "Cannot restart stunnel because self-signed certificate at %s is missing"
            % state["certificate"]
        )
        return

    new_tunnel_pid = start_tls_tunnel(child_procs, state, state_file_dir, state_file)
    state["pid"] = new_tunnel_pid

    logging.debug("Rewriting %s with new pid: %d", state_file, new_tunnel_pid)
    rewrite_state_file(state, state_file_dir, state_file)


def check_efs_mounts(
    config,
    child_procs,
    unmount_grace_period_sec,
    unmount_count_for_consistency,
    state_file_dir=STATE_FILE_DIR,
):
    nfs_mounts = get_current_local_nfs_mounts()
    logging.debug("Current local NFS mounts: %s", list(nfs_mounts.values()))

    state_files = get_state_files(state_file_dir)
    logging.debug(
        'Current state files in "%s": %s', state_file_dir, list(state_files.values())
    )

    for mount, state_file in state_files.items():
        state_file_path = os.path.join(state_file_dir, state_file)
        with open(state_file_path) as f:
            try:
                state = json.load(f)
            except ValueError:
                logging.exception("Unable to parse json in %s", state_file_path)
                continue

        current_time = time.time()
        if "unmount_time" in state:
            if state["unmount_time"] + unmount_grace_period_sec < current_time:
                logging.info("Unmount grace period expired for %s", state_file)
                clean_up_mount_state(
                    state_file_dir,
                    state_file,
                    state.get("pid"),
                    state.get("mountStateDir"),
                )
        # For MacOS, if we don't have port from previous system call (nfsstat -F JSON -m mount_point), we ignore the port
        elif mount not in nfs_mounts and (
            not check_if_running_on_macos()
            or mount[: mount.rindex(".")] not in nfs_mounts
        ):
            # Wait 30 seconds before deciding mount no longer exists to prevent race condition
            # of watchdog's reads of nfs mounts and state files.
            if current_time - state.get("mount_time", 0) > UNMOUNT_DIFF_TIME:
                # Ensure we have consistent unmount reads for at least 5 times by default.
                if state.get("unmount_count", 0) > unmount_count_for_consistency:
                    logging.info('No mount found for "%s"', state_file)
                    state = mark_as_unmounted(
                        state, state_file_dir, state_file, current_time
                    )
                else:
                    state["unmount_count"] = state.get("unmount_count", 0) + 1
                    rewrite_state_file(state, state_file_dir, state_file)

        else:
            # Set unmount count to 0 if there were inconsistent reads
            state["unmount_count"] = 0
            rewrite_state_file(state, state_file_dir, state_file)
            if "certificate" in state:
                check_certificate(config, state, state_file_dir, state_file)

            if is_mount_stunnel_proc_running(
                state.get("pid"), state_file, state_file_dir
            ):
                # https://github.com/kubernetes-sigs/aws-efs-csi-driver/issues/616 We have seen EFS hanging issue caused
                # by stuck stunnel (version: 4.56) process. Apart from checking whether stunnel is running or not, we
                # need to check whether the stunnel connection established is healthy periodically.
                #
                # The way to check the stunnel health is by `df` the mountpoint, i.e. check the file system information,
                # which will trigger a remote GETATTR on the root of the file system. Normally the command will finish
                # in 10 milliseconds, thus if the command hang for certain period (defined as 30 sec as of now), the
                # stunnel connection is likely to be unhealthy. Watchdog will kill the old stunnel process and restart
                # a new one for the unhealthy mount. The health check will run every 5 min since mount.
                #
                # Both the command hang timeout and health check interval are configurable in efs-utils config file.
                #
                check_stunnel_health(
                    config, state, state_file_dir, state_file, child_procs, nfs_mounts
                )
            else:
                logging.warning("TLS tunnel for %s is not running", state_file)
                restart_tls_tunnel(child_procs, state, state_file_dir, state_file)


def check_stunnel_health(
    config, state, state_file_dir, state_file, child_procs, nfs_mounts
):
    if not get_boolean_config_item_value(
        config, CONFIG_SECTION, "stunnel_health_check_enabled", default_value=True
    ):
        return

    check_interval_min = get_int_value_from_config_file(
        config,
        "stunnel_health_check_interval_min",
        DEFAULT_STUNNEL_HEALTH_CHECK_INTERVAL_MIN,
    )

    current_time = time.time()

    # The mount_time info in the state file is added in version 1.31.3. It is possible for existing mounts, there are
    # no mount_time in state file, which will cause watchdog to crash. If the information does not exist, we just take
    # current time as the initial mount time of the mount.
    #
    if "mount_time" not in state:
        state["mount_time"] = current_time
        rewrite_state_file(state, state_file_dir, state_file)
        return

    # Only start to perform the stunnel health check after the check interval passed.
    if current_time - state["mount_time"] < check_interval_min * 60:
        return

    last_stunnel_check_time = (
        state["last_stunnel_check_time"] if "last_stunnel_check_time" in state else 0
    )
    if (
        last_stunnel_check_time != 0
        and current_time - last_stunnel_check_time < check_interval_min * 60
    ):
        return

    # We add this mountpoint info in the state file along with this change. It is possible for existing mounts, there
    # are no mountpoint in state file, which will cause watchdog to crash. To handle that case, we need to extract the
    # mountpoint from the state file name, and write that information to state file.
    #
    if "mountpoint" in state:
        mountpoint = state["mountpoint"]
    else:
        mountpoint = get_mountpoint_from_nfs_mounts(state_file, nfs_mounts)
        state["mountpoint"] = mountpoint
        rewrite_state_file(state, state_file_dir, state_file)

    stunnel_pid = state["pid"]
    process = subprocess.Popen(
        ["df", mountpoint],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
    )

    command_timeout_sec = get_int_value_from_config_file(
        config,
        "stunnel_health_check_command_timeout_sec",
        DEFAULT_STUNNEL_HEALTH_CHECK_TIMEOUT_SEC,
    )
    try:
        state["last_stunnel_check_time"] = current_time
        process.communicate(timeout=command_timeout_sec)
        logging.debug(
            "Stunnel [PID: %d] running for tls mount on %s passed health check.",
            stunnel_pid,
            mountpoint,
        )
        rewrite_state_file(state, state_file_dir, state_file)
    except subprocess.TimeoutExpired:
        if send_signal_to_running_stunnel_process_group(
            stunnel_pid, state_file, state_file_dir, SIGKILL
        ):
            logging.warning(
                "Connection timeout for %s after %d sec, SIGKILL has been sent to the potential unhealthy stunnel %s, "
                "restarting a new stunnel process.",
                mountpoint,
                command_timeout_sec,
                stunnel_pid,
            )
            restart_tls_tunnel(child_procs, state, state_file_dir, state_file)
        else:
            logging.warning(
                "Stunnel health check timed out for %s, stunnel [PID: %d] is not running anymore.",
                mountpoint,
                stunnel_pid,
            )
        # The child process is not killed if the timeout expires, so in order to cleanup properly, kill the child
        # process after the timeout.
        #
        process.kill()


# Retrieve the nfs mountpoint with the port information in the mount option
def get_mountpoint_from_nfs_mounts(state_file, nfs_mounts):
    search_pattern = "port={port}".format(
        port=os.path.basename(state_file).split(".")[-1]
    )
    for mount in nfs_mounts.values():
        if search_pattern in mount[3]:
            return mount[1]


def get_int_value_from_config_file(config, config_name, default_config_value):
    val = default_config_value
    try:
        value_from_config = config.get(CONFIG_SECTION, config_name)
        try:
            if int(value_from_config) > 0:
                val = int(value_from_config)
            else:
                logging.debug(
                    '%s value in config file "%s" is lower than 1. Defaulting to %d.',
                    config_name,
                    CONFIG_FILE,
                    default_config_value,
                )
        except ValueError:
            logging.debug(
                'Bad %s, "%s", in config file "%s". Defaulting to %d.',
                config_name,
                value_from_config,
                CONFIG_FILE,
                default_config_value,
            )
    except NoOptionError:
        logging.debug(
            'No %s value in config file "%s". Defaulting to %d.',
            config_name,
            CONFIG_FILE,
            default_config_value,
        )

    return val


def check_child_procs(child_procs):
    for proc in child_procs:
        proc.poll()
        if proc.returncode is not None:
            logging.warning(
                "Child TLS tunnel process %d has exited, returncode=%d",
                proc.pid,
                proc.returncode,
            )
            child_procs.remove(proc)


def parse_arguments(args=None):
    if args is None:
        args = sys.argv

    if "-h" in args[1:] or "--help" in args[1:]:
        sys.stdout.write("Usage: %s [--version] [-h|--help]\n" % args[0])
        sys.exit(0)

    if "--version" in args[1:]:
        sys.stdout.write("%s Version: %s\n" % (args[0], VERSION))
        sys.exit(0)


def assert_root():
    if os.geteuid() != 0:
        sys.stderr.write("only root can run amazon-efs-mount-watchdog\n")
        sys.exit(1)


def read_config(config_file=CONFIG_FILE):
    try:
        p = ConfigParser.SafeConfigParser()
    except AttributeError:
        p = ConfigParser()
    p.read(config_file)
    return p


def check_certificate(
    config, state, state_file_dir, state_file, base_path=STATE_FILE_DIR
):
    certificate_creation_time = datetime.strptime(
        state["certificateCreationTime"], CERT_DATETIME_FORMAT
    )
    certificate_exists = os.path.isfile(state["certificate"])
    certificate_renewal_interval_secs = (
        get_certificate_renewal_interval_mins(config) * 60
    )
    # creation instead of NOT_BEFORE datetime is used for refresh of cert because NOT_BEFORE derives from creation datetime
    should_refresh_cert = (
        get_utc_now() - certificate_creation_time
    ).total_seconds() > certificate_renewal_interval_secs

    if certificate_exists and not should_refresh_cert:
        return

    ap_state = state.get("accessPoint")
    if ap_state and not AP_ID_RE.match(ap_state):
        logging.error(
            'Access Point ID "%s" has been changed in the state file to a malformed format'
            % ap_state
        )
        return

    if not certificate_exists:
        logging.debug(
            "Certificate (at %s) is missing. Recreating self-signed certificate"
            % state["certificate"]
        )
    else:
        logging.debug(
            "Refreshing self-signed certificate (at %s)" % state["certificate"]
        )

    credentials_source = state.get("awsCredentialsMethod")
    updated_certificate_creation_time = recreate_certificate(
        config,
        state["mountStateDir"],
        state["commonName"],
        state["fsId"],
        credentials_source,
        ap_state,
        state["region"],
        base_path=base_path,
    )
    if updated_certificate_creation_time:
        state["certificateCreationTime"] = updated_certificate_creation_time
        rewrite_state_file(state, state_file_dir, state_file)

        # send SIGHUP to force a reload of the configuration file to trigger the stunnel process to notice the new certificate
        send_signal_to_running_stunnel_process_group(
            state.get("pid"), state_file, state_file_dir, SIGHUP
        )


def send_signal_to_running_stunnel_process_group(
    stunnel_pid, state_file, state_file_dir, signal
):
    """
    Send a signal to the given stunnel_pid if the process running with the pid is the mount stunnel process.

    :param stunnel_pid: The pid in state file.
    :param state_file: The state file path, e.g. fs-deadbeef.mnt.20560.
    :param state_file_dir: The state file dir path, e.g. /var/run/efs.
    :param signal: OS signal send to stunnel process group, e.g. SIGHUP, SIGKILL, SIGTERM.
    """
    if is_mount_stunnel_proc_running(stunnel_pid, state_file, state_file_dir):
        process_group = os.getpgid(stunnel_pid)
        try:
            logging.info(
                "Sending signal %s(%d) to stunnel. PID: %d, group ID: %s",
                signal.name,
                signal.value,
                stunnel_pid,
                process_group,
            )
        except AttributeError:
            # In python3.4, the signal is a int object, so it does not have name and value property
            logging.info(
                "Sending signal(%s) to stunnel. PID: %d, group ID: %s",
                signal,
                stunnel_pid,
                process_group,
            )
        os.killpg(process_group, signal)
        return True
    else:
        logging.warning("TLS tunnel is not running for %s", state_file)
        return False


def create_required_directory(config, directory):
    mode = 0o750
    try:
        mode_str = config.get(CONFIG_SECTION, "state_file_dir_mode")
        try:
            mode = int(mode_str, 8)
        except ValueError:
            logging.warning(
                'Bad state_file_dir_mode "%s" in config file "%s"',
                mode_str,
                CONFIG_FILE,
            )
    except NoOptionError:
        pass

    try:
        os.makedirs(directory, mode)
        logging.debug("Expected %s not found, recreating asset", directory)
    except OSError as e:
        if errno.EEXIST != e.errno or not os.path.isdir(directory):
            raise


def get_client_info(config):
    client_info = {}

    # source key/value pair in config file
    if config.has_option(CLIENT_INFO_SECTION, "source"):
        client_source = config.get(CLIENT_INFO_SECTION, "source")
        if 0 < len(client_source) <= CLIENT_SOURCE_STR_LEN_LIMIT:
            client_info["source"] = client_source
    if not client_info.get("source"):
        if check_if_running_on_macos():
            client_info["source"] = DEFAULT_MACOS_VALUE
        else:
            client_info["source"] = DEFAULT_UNKNOWN_VALUE

    client_info["efs_utils_version"] = VERSION

    return client_info


def recreate_certificate(
    config,
    mount_name,
    common_name,
    fs_id,
    credentials_source,
    ap_id,
    region,
    base_path=STATE_FILE_DIR,
):
    current_time = get_utc_now()
    tls_paths = tls_paths_dictionary(mount_name, base_path)

    certificate_config = os.path.join(tls_paths["mount_dir"], "config.conf")
    certificate_signing_request = os.path.join(tls_paths["mount_dir"], "request.csr")
    certificate = os.path.join(tls_paths["mount_dir"], "certificate.pem")

    ca_dirs_check(config, tls_paths["database_dir"], tls_paths["certs_dir"])
    ca_supporting_files_check(
        tls_paths["index"],
        tls_paths["index_attr"],
        tls_paths["serial"],
        tls_paths["rand"],
    )

    private_key = check_and_create_private_key(base_path)

    if credentials_source:
        public_key = os.path.join(tls_paths["mount_dir"], "publicKey.pem")
        create_public_key(private_key, public_key)

    client_info = get_client_info(config)
    config_body = create_ca_conf(
        config,
        certificate_config,
        common_name,
        tls_paths["mount_dir"],
        private_key,
        current_time,
        region,
        fs_id,
        credentials_source,
        ap_id=ap_id,
        client_info=client_info,
    )

    if not config_body:
        logging.error("Cannot recreate self-signed certificate")
        return None

    create_certificate_signing_request(
        certificate_config, private_key, certificate_signing_request
    )

    not_before = get_certificate_timestamp(current_time, minutes=-NOT_BEFORE_MINS)
    not_after = get_certificate_timestamp(current_time, hours=NOT_AFTER_HOURS)

    cmd = "openssl ca -startdate %s -enddate %s -selfsign -batch -notext -config %s -in %s -out %s" % (
        not_before,
        not_after,
        certificate_config,
        certificate_signing_request,
        certificate,
    )
    subprocess_call(cmd, "Failed to create self-signed client-side certificate")
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
        lock_file = os.path.join(base_path, "efs-utils-lock")
        f = os.open(lock_file, os.O_CREAT | os.O_DSYNC | os.O_EXCL | os.O_RDWR)
        try:
            lock_file_contents = "PID: %s" % os.getpid()
            os.write(f, lock_file_contents.encode("utf-8"))
            yield f
        finally:
            check_and_remove_lock_file(lock_file, f)

    def do_with_lock(function):
        while True:
            try:
                with open_lock_file():
                    return function()
            except OSError as e:
                if e.errno == errno.EEXIST:
                    logging.info(
                        "Failed to take out private key creation lock, sleeping %s (s)"
                        % DEFAULT_TIMEOUT
                    )
                    time.sleep(DEFAULT_TIMEOUT)
                else:
                    # errno.ENOENT: No such file or directory, errno.EBADF: Bad file descriptor
                    if e.errno == errno.ENOENT or e.errno == errno.EBADF:
                        logging.debug(
                            "lock file does not exist or Bad file descriptor, The file is already removed nothing to do."
                        )
                    else:
                        raise Exception(
                            "Could not remove lock file unexpected exception: %s", e
                        )

    def generate_key():
        if os.path.isfile(key):
            return

        cmd = (
            "openssl genpkey -algorithm RSA -out %s -pkeyopt rsa_keygen_bits:3072" % key
        )
        subprocess_call(cmd, "Failed to create private key")
        read_only_mode = 0o400
        os.chmod(key, read_only_mode)

    do_with_lock(generate_key)
    return key


def create_certificate_signing_request(config_path, key_path, csr_path):
    cmd = "openssl req -new -config %s -key %s -out %s" % (
        config_path,
        key_path,
        csr_path,
    )
    subprocess_call(cmd, "Failed to create certificate signing request (csr)")


def create_ca_conf(
    config,
    config_path,
    common_name,
    directory,
    private_key,
    date,
    region,
    fs_id,
    credentials_source,
    ap_id=None,
    client_info=None,
):
    """Populate ca/req configuration file with fresh configurations at every mount since SigV4 signature can change"""
    public_key_path = os.path.join(directory, "publicKey.pem")
    security_credentials = (
        get_aws_security_credentials(config, credentials_source, region)
        if credentials_source
        else ""
    )

    if credentials_source and security_credentials is None:
        logging.error(
            "Failed to retrieve AWS security credentials using lookup method: %s",
            credentials_source,
        )
        return None

    ca_extension_body = ca_extension_builder(
        ap_id, security_credentials, fs_id, client_info
    )
    efs_client_auth_body = (
        efs_client_auth_builder(
            public_key_path,
            security_credentials["AccessKeyId"],
            security_credentials["SecretAccessKey"],
            date,
            region,
            fs_id,
            security_credentials["Token"],
        )
        if credentials_source
        else ""
    )
    if credentials_source and not efs_client_auth_body:
        logging.error(
            "Failed to create AWS SigV4 signature section for OpenSSL config. Public Key path: %s",
            public_key_path,
        )
        return None
    efs_client_info_body = efs_client_info_builder(client_info) if client_info else ""
    full_config_body = CA_CONFIG_BODY % (
        directory,
        private_key,
        common_name,
        ca_extension_body,
        efs_client_auth_body,
        efs_client_info_body,
    )

    with open(config_path, "w") as f:
        f.write(full_config_body)

    return full_config_body


def ca_extension_builder(ap_id, security_credentials, fs_id, client_info):
    ca_extension_str = "[ v3_ca ]\nsubjectKeyIdentifier = hash"
    if ap_id:
        ca_extension_str += "\n1.3.6.1.4.1.4843.7.1 = ASN1:UTF8String:" + ap_id
    if security_credentials:
        ca_extension_str += "\n1.3.6.1.4.1.4843.7.2 = ASN1:SEQUENCE:efs_client_auth"

    ca_extension_str += "\n1.3.6.1.4.1.4843.7.3 = ASN1:UTF8String:" + fs_id
    if client_info:
        ca_extension_str += "\n1.3.6.1.4.1.4843.7.4 = ASN1:SEQUENCE:efs_client_info"

    return ca_extension_str


def efs_client_auth_builder(
    public_key_path,
    access_key_id,
    secret_access_key,
    date,
    region,
    fs_id,
    session_token=None,
):
    public_key_hash = get_public_key_sha1(public_key_path)

    if not public_key_hash:
        return None

    canonical_request = create_canonical_request(
        public_key_hash, date, access_key_id, region, fs_id, session_token
    )
    string_to_sign = create_string_to_sign(canonical_request, date, region)
    signature = calculate_signature(string_to_sign, date, secret_access_key, region)
    efs_client_auth_str = "[ efs_client_auth ]"
    efs_client_auth_str += "\naccessKeyId = UTF8String:" + access_key_id
    efs_client_auth_str += "\nsignature = OCTETSTRING:" + signature
    efs_client_auth_str += "\nsigv4DateTime = UTCTIME:" + date.strftime(
        CERT_DATETIME_FORMAT
    )

    if session_token:
        efs_client_auth_str += "\nsessionToken = EXPLICIT:0,UTF8String:" + session_token

    return efs_client_auth_str


def efs_client_info_builder(client_info):
    efs_client_info_str = "[ efs_client_info ]"
    for key, value in client_info.items():
        efs_client_info_str += "\n%s = UTF8String: %s" % (key, value)
    return efs_client_info_str


def create_public_key(private_key, public_key):
    cmd = "openssl rsa -in %s -outform PEM -pubout -out %s" % (private_key, public_key)
    subprocess_call(cmd, "Failed to create public key")


def subprocess_call(cmd, error_message):
    """Helper method to run shell openssl command and to handle response error messages"""
    process = subprocess.Popen(
        cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True
    )
    (output, err) = process.communicate()
    rc = process.poll()
    if rc != 0:
        logging.debug(
            '%s. Command %s failed, rc=%s, stdout="%s", stderr="%s"',
            error_message,
            cmd,
            rc,
            output,
            err,
        )
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
        logging.warning("Expected %s not found, recreating file", path)

    if not os.path.isfile(index_path):
        open(index_path, "w").close()
        _recreate_file_warning(index_path)
    if not os.path.isfile(index_attr_path):
        with open(index_attr_path, "w+") as f:
            f.write("unique_subject = no")
        _recreate_file_warning(index_attr_path)
    if not os.path.isfile(serial_path):
        with open(serial_path, "w+") as f:
            f.write("00")
        _recreate_file_warning(serial_path)
    if not os.path.isfile(rand_path):
        open(rand_path, "w").close()
        _recreate_file_warning(rand_path)


def tls_paths_dictionary(mount_name, base_path=STATE_FILE_DIR):
    tls_dict = {
        "mount_dir": os.path.join(base_path, mount_name),
        "database_dir": os.path.join(base_path, mount_name, "database"),
        "certs_dir": os.path.join(base_path, mount_name, "certs"),
        "index": os.path.join(base_path, mount_name, "database/index.txt"),
        "index_attr": os.path.join(base_path, mount_name, "database/index.txt.attr"),
        "serial": os.path.join(base_path, mount_name, "database/serial"),
        "rand": os.path.join(base_path, mount_name, "database/.rand"),
    }

    return tls_dict


def get_public_key_sha1(public_key):
    # truncating public key to remove the header and footer '-----(BEGIN|END) PUBLIC KEY-----'
    with open(public_key, "r") as f:
        lines = f.readlines()
        lines = lines[1:-1]

    key = "".join(lines)
    key = bytearray(base64.b64decode(key))

    # Parse the public key to pull out the actual key material by looking for the key BIT STRING
    # Example:
    #     0:d=0  hl=4 l= 418 cons: SEQUENCE
    #     4:d=1  hl=2 l=  13 cons: SEQUENCE
    #     6:d=2  hl=2 l=   9 prim: OBJECT            :rsaEncryption
    #    17:d=2  hl=2 l=   0 prim: NULL
    #    19:d=1  hl=4 l= 399 prim: BIT STRING
    cmd = "openssl asn1parse -inform PEM -in %s" % public_key
    output, err = subprocess_call(
        cmd, "Unable to ASN1 parse public key file, %s, correctly" % public_key
    )

    key_line = ""
    for line in output.splitlines():
        if "BIT STRING" in line.decode("utf-8"):
            key_line = line.decode("utf-8")

    if not key_line:
        logging.error("Public key file, %s, is incorrectly formatted", public_key)
        return None

    key_line = key_line.replace(" ", "")

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
    offset = int(key_line.split(":")[0])
    key = key[offset:]

    num_length_octets = key[1] & 0b01111111

    # Exclude the tag (1), length (1 + num_length_octets), and number of unused bits (1)
    offset = 1 + 1 + num_length_octets + 1
    key = key[offset:]

    sha1 = hashlib.sha1()
    sha1.update(key)

    return sha1.hexdigest()


def create_canonical_request(
    public_key_hash, date, access_key, region, fs_id, session_token=None
):
    """
    Create a Canonical Request - https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
    """
    formatted_datetime = date.strftime(SIGV4_DATETIME_FORMAT)
    credential = quote_plus(access_key + "/" + get_credential_scope(date, region))

    request = HTTP_REQUEST_METHOD + "\n"
    request += CANONICAL_URI + "\n"
    request += (
        create_canonical_query_string(
            public_key_hash, credential, formatted_datetime, session_token
        )
        + "\n"
    )
    request += CANONICAL_HEADERS % fs_id + "\n"
    request += SIGNED_HEADERS + "\n"

    sha256 = hashlib.sha256()
    sha256.update(REQUEST_PAYLOAD.encode())
    request += sha256.hexdigest()

    return request


def create_canonical_query_string(
    public_key_hash, credential, formatted_datetime, session_token=None
):
    canonical_query_params = {
        "Action": "Connect",
        # Public key hash is included in canonical request to tie the signature to a specific key pair to avoid replay attacks
        "PublicKeyHash": quote_plus(public_key_hash),
        "X-Amz-Algorithm": ALGORITHM,
        "X-Amz-Credential": credential,
        "X-Amz-Date": quote_plus(formatted_datetime),
        "X-Amz-Expires": 86400,
        "X-Amz-SignedHeaders": SIGNED_HEADERS,
    }

    if session_token:
        canonical_query_params["X-Amz-Security-Token"] = quote_plus(session_token)

    # Cannot use urllib.urlencode because it replaces the %s's
    return "&".join(
        ["%s=%s" % (k, v) for k, v in sorted(canonical_query_params.items())]
    )


def create_string_to_sign(canonical_request, date, region):
    """
    Create a String to Sign - https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
    """
    string_to_sign = ALGORITHM + "\n"
    string_to_sign += date.strftime(SIGV4_DATETIME_FORMAT) + "\n"
    string_to_sign += get_credential_scope(date, region) + "\n"

    sha256 = hashlib.sha256()
    sha256.update(canonical_request.encode())
    string_to_sign += sha256.hexdigest()

    return string_to_sign


def calculate_signature(string_to_sign, date, secret_access_key, region):
    """
    Calculate the Signature - https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
    """

    def _sign(key, msg):
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256)

    key_date = _sign(
        ("AWS4" + secret_access_key).encode("utf-8"), date.strftime(DATE_ONLY_FORMAT)
    ).digest()
    add_region = _sign(key_date, region).digest()
    add_service = _sign(add_region, SERVICE).digest()
    signing_key = _sign(add_service, "aws4_request").digest()

    return _sign(signing_key, string_to_sign).hexdigest()


def get_certificate_renewal_interval_mins(config):
    interval = DEFAULT_REFRESH_SELF_SIGNED_CERT_INTERVAL_MIN
    try:
        mins_from_config = config.get(CONFIG_SECTION, "tls_cert_renewal_interval_min")
        try:
            if int(mins_from_config) > 0:
                interval = int(mins_from_config)
            else:
                logging.warning(
                    'tls_cert_renewal_interval_min value in config file "%s" is lower than 1 minute. Defaulting '
                    "to %d minutes.",
                    CONFIG_FILE,
                    DEFAULT_REFRESH_SELF_SIGNED_CERT_INTERVAL_MIN,
                )
        except ValueError:
            logging.warning(
                'Bad tls_cert_renewal_interval_min value, "%s", in config file "%s". Defaulting to %d minutes.',
                mins_from_config,
                CONFIG_FILE,
                DEFAULT_REFRESH_SELF_SIGNED_CERT_INTERVAL_MIN,
            )
    except NoOptionError:
        logging.warning(
            'No tls_cert_renewal_interval_min value in config file "%s". Defaulting to %d minutes.',
            CONFIG_FILE,
            DEFAULT_REFRESH_SELF_SIGNED_CERT_INTERVAL_MIN,
        )

    return interval


def get_credential_scope(date, region):
    return "/".join([date.strftime(DATE_ONLY_FORMAT), region, SERVICE, AWS4_REQUEST])


def get_certificate_timestamp(current_time, **kwargs):
    updated_time = current_time + timedelta(**kwargs)
    return updated_time.strftime(CERT_DATETIME_FORMAT)


def get_utc_now():
    """
    Wrapped for patching purposes in unit tests
    """
    return datetime.utcnow()


def check_process_name(pid):
    if not check_if_running_on_macos():
        cmd = ["cat", "/proc/{pid}/cmdline".format(pid=pid)]
    else:
        cmd = ["ps", "-p", str(pid), "-o", "command="]

    p = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True
    )
    return p.communicate()[0]


def check_if_running_on_macos():
    return sys.platform == "darwin"


def check_and_remove_file(path):
    try:
        os.remove(path)
        logging.debug("Removed %s successfully", path)
    except OSError as e:
        if e.errno != errno.ENOENT:
            logging.debug("Could not remove %s. Unexpected exception: %s", path, e)
        else:
            logging.debug("%s does not exist, nothing to do", path)


def check_and_remove_lock_file(path, file):
    """
    There is a possibility of having a race condition as the lock file is getting deleted in both mount_efs and watchdog,
    so creating a function in order to check whether the path exist or not before removing the lock file.
    """
    try:
        os.close(file)
        os.remove(path)
        logging.debug("Removed %s successfully", path)
    except OSError as e:
        if not (e.errno == errno.ENOENT or e.errno == errno.EBADF):
            raise Exception("Could not remove %s. Unexpected exception: %s", path, e)
        else:
            logging.debug(
                "%s does not exist, The file is already removed nothing to do", path
            )


def clean_up_certificate_lock_file(state_file_dir=STATE_FILE_DIR):
    """
    Cleans up private key lock file 'efs-utils-lock' left behind by a previous process attempting to create private key
    and efs-csi-driver is restarted. Once driver restarts, a new mount/watchdog process will fail to create private key
    since contents of `STATE_FILE_DIR` is persisted on a node across driver pod restarts.
    """
    lock_file = os.path.join(state_file_dir, "efs-utils-lock")
    logging.debug("Removing private key file")
    check_and_remove_file(lock_file)


def clean_up_previous_stunnel_pids(state_file_dir=STATE_FILE_DIR):
    """
    Cleans up stunnel pids created by mount watchdog spawned by a previous efs-csi-driver pod after driver restart, upgrade
    or crash. This method attempts to clean PIDs from persisted state files after efs-csi-driver restart to
    ensure watchdog creates a new stunnel.
    """
    state_files = get_state_files(state_file_dir)
    logging.debug(
        'Persisted state files in "%s": %s', state_file_dir, list(state_files.values())
    )

    for state_file in state_files.values():
        state_file_path = os.path.join(state_file_dir, state_file)
        with open(state_file_path) as f:
            try:
                state = json.load(f)
            except ValueError:
                logging.exception("Unable to parse json in %s", state_file_path)
                continue

            try:
                pid = state["pid"]
            except KeyError:
                logging.debug("No PID found in state file %s", state_file)
                continue

            out = check_process_name(pid)

            if out and "stunnel" in str(out):
                logging.debug(
                    "PID %s in state file %s is active. Skipping clean up",
                    pid,
                    state_file,
                )
                continue

            state.pop("pid")
            logging.debug("Cleaning up pid %s in state file %s", pid, state_file)

            rewrite_state_file(state, state_file_dir, state_file)


def main():
    parse_arguments()
    assert_root()

    config = read_config()
    bootstrap_logging(config)

    child_procs = []

    if get_boolean_config_item_value(
        config, CONFIG_SECTION, "enabled", default_value=True, emit_warning_message=True
    ):
        logging.info(
            "amazon-efs-mount-watchdog, version %s, is enabled and started", VERSION
        )
        poll_interval_sec = config.getint(CONFIG_SECTION, "poll_interval_sec")

        if config.has_option(CONFIG_SECTION, "unmount_count_for_consistency"):
            unmount_count_for_consistency = config.getint(
                CONFIG_SECTION, "unmount_count_for_consistency"
            )
        else:
            unmount_count_for_consistency = DEFAULT_UNMOUNT_COUNT_FOR_CONSISTENCY

        unmount_grace_period_sec = config.getint(
            CONFIG_SECTION, "unmount_grace_period_sec"
        )

        clean_up_previous_stunnel_pids()
        clean_up_certificate_lock_file()

        while True:
            config = read_config()

            check_efs_mounts(
                config,
                child_procs,
                unmount_grace_period_sec,
                unmount_count_for_consistency,
            )
            check_child_procs(child_procs)

            time.sleep(poll_interval_sec)
    else:
        logging.info("amazon-efs-mount-watchdog is not enabled")


if "__main__" == __name__:
    main()
