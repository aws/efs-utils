#!/usr/bin/env python3
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
import platform
import pwd
import random
import re
import socket
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from logging.handlers import RotatingFileHandler

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

try:
    import botocore.config
    import botocore.session
    from botocore.exceptions import (
        ClientError,
        EndpointConnectionError,
        NoCredentialsError,
        ProfileNotFound,
    )

    BOTOCORE_PRESENT = True
except ImportError:
    BOTOCORE_PRESENT = False


VERSION = "2.1.0"
SERVICE = "elasticfilesystem"

AMAZON_LINUX_2_RELEASE_ID = "Amazon Linux release 2 (Karoo)"
AMAZON_LINUX_2_PRETTY_NAME = "Amazon Linux 2"
AMAZON_LINUX_2_RELEASE_VERSIONS = [
    AMAZON_LINUX_2_RELEASE_ID,
    AMAZON_LINUX_2_PRETTY_NAME,
]

CLONE_NEWNET = 0x40000000
CONFIG_FILE = "/etc/amazon/efs/efs-utils.conf"
CONFIG_SECTION = "mount"
CLIENT_INFO_SECTION = "client-info"
CLIENT_SOURCE_STR_LEN_LIMIT = 100
# Cloudwatchlog agent dict includes cloudwatchlog botocore client, cloudwatchlog group name, cloudwatchlog stream name
CLOUDWATCHLOG_AGENT = None
CLOUDWATCH_LOG_SECTION = "cloudwatch-log"
DEFAULT_CLOUDWATCH_LOG_GROUP = "/aws/efs/utils"
DEFAULT_FALLBACK_ENABLED = True
DEFAULT_RETENTION_DAYS = 14
DEFAULT_UNKNOWN_VALUE = "unknown"
# 50ms
DEFAULT_TIMEOUT = 0.05
DEFAULT_MACOS_VALUE = "macos"
DEFAULT_GET_AWS_EC2_METADATA_TOKEN_RETRY_COUNT = 3
DEFAULT_NFS_MOUNT_COMMAND_RETRY_COUNT = 3
DEFAULT_NFS_MOUNT_COMMAND_TIMEOUT_SEC = 15
DISABLE_FETCH_EC2_METADATA_TOKEN_ITEM = "disable_fetch_ec2_metadata_token"
FALLBACK_TO_MOUNT_TARGET_IP_ADDRESS_ITEM = (
    "fall_back_to_mount_target_ip_address_enabled"
)
INSTANCE_IDENTITY = None
INSTANCE_AZ_ID_METADATA = None
RETRYABLE_ERRORS = ["reset by peer"]
OPTIMIZE_READAHEAD_ITEM = "optimize_readahead"

LOG_DIR = "/var/log/amazon/efs"
LOG_FILE = "mount.log"

STATE_FILE_DIR = "/var/run/efs"

PRIVATE_KEY_FILE = "/etc/amazon/efs/privateKey.pem"
DATE_ONLY_FORMAT = "%Y%m%d"
SIGV4_DATETIME_FORMAT = "%Y%m%dT%H%M%SZ"
CERT_DATETIME_FORMAT = "%y%m%d%H%M%SZ"

AWS_CREDENTIALS_FILE = os.path.expanduser(
    os.path.join("~" + pwd.getpwuid(os.getuid()).pw_name, ".aws", "credentials")
)
AWS_CONFIG_FILE = os.path.expanduser(
    os.path.join("~" + pwd.getpwuid(os.getuid()).pw_name, ".aws", "config")
)

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

FS_ID_RE = re.compile("^(?P<fs_id>fs-[0-9a-f]+)$")
EFS_FQDN_RE = re.compile(
    r"^((?P<az>[a-z0-9-]+)\.)?(?P<fs_id>fs-[0-9a-f]+)\.efs\."
    r"(?P<region>[a-z0-9-]+)\.(?P<dns_name_suffix>[a-z0-9.]+)$"
)
AP_ID_RE = re.compile("^fsap-[0-9a-f]{17}$")

CREDENTIALS_KEYS = ["AccessKeyId", "SecretAccessKey", "Token"]
ECS_TASK_METADATA_API = "http://169.254.170.2"
STS_ENDPOINT_URL_FORMAT = "https://sts.{}.{}/"
INSTANCE_METADATA_TOKEN_URL = "http://169.254.169.254/latest/api/token"
INSTANCE_METADATA_SERVICE_URL = (
    "http://169.254.169.254/latest/dynamic/instance-identity/document/"
)
INSTANCE_METADATA_SERVICE_AZ_ID_URL = (
    "http://169.254.169.254/latest/meta-data/placement/availability-zone-id"
)
INSTANCE_IAM_URL = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
NAMED_PROFILE_HELP_URL = (
    "https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-profiles.html"
)
CONFIG_FILE_SETTINGS_HELP_URL = (
    "https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html"
    "#cli-configure-files-settings"
)

SECURITY_CREDS_ECS_URI_HELP_URL = (
    "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html"
)
SECURITY_CREDS_WEBIDENTITY_HELP_URL = "https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html"
SECURITY_CREDS_IAM_ROLE_HELP_URL = (
    "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html"
)

DEFAULT_STUNNEL_VERIFY_LEVEL = 2
DEFAULT_STUNNEL_CAFILE = "/etc/amazon/efs/efs-utils.crt"

LEGACY_STUNNEL_MOUNT_OPTION = "stunnel"

NOT_BEFORE_MINS = 15
NOT_AFTER_HOURS = 3

EFS_PROXY_TLS_OPTION = "--tls"

EFS_ONLY_OPTIONS = [
    "accesspoint",
    "awscredsuri",
    "awsprofile",
    "az",
    "cafile",
    "iam",
    "mounttargetip",
    "netns",
    "noocsp",
    "notls",
    "ocsp",
    "region",
    "tls",
    "tlsport",
    "verify",
    "rolearn",
    "jwtpath",
    "fsap",
    "crossaccount",
    LEGACY_STUNNEL_MOUNT_OPTION,
]

UNSUPPORTED_OPTIONS = ["capath"]

STUNNEL_GLOBAL_CONFIG = {
    "fips": "no",
    "foreground": "yes",
    "socket": [
        "l:SO_REUSEADDR=yes",
        "a:SO_BINDTODEVICE=lo",
    ],
}

STUNNEL_EFS_CONFIG = {
    "client": "yes",
    "accept": "127.0.0.1:%s",
    "connect": "%s:2049",
    "sslVersion": "TLSv1.2",
    "renegotiation": "no",
    "TIMEOUTbusy": "20",
    "TIMEOUTclose": "0",
    "TIMEOUTidle": "70",
    "delay": "yes",
}

WATCHDOG_SERVICE = "amazon-efs-mount-watchdog"
# MacOS instances use plist files. This files needs to be loaded on launchctl (init system of MacOS)
WATCHDOG_SERVICE_PLIST_PATH = "/Library/LaunchAgents/amazon-efs-mount-watchdog.plist"
SYSTEM_RELEASE_PATH = "/etc/system-release"
OS_RELEASE_PATH = "/etc/os-release"
MACOS_BIG_SUR_RELEASE = "macOS-11"
MACOS_MONTEREY_RELEASE = "macOS-12"
MACOS_VENTURA_RELEASE = "macOS-13"
MACOS_SONOMA_RELEASE = "macOS-14"


# Multiplier for max read ahead buffer size
# Set default as 15 aligning with prior linux kernel 5.4
DEFAULT_NFS_MAX_READAHEAD_MULTIPLIER = 15
NFS_READAHEAD_CONFIG_PATH_FORMAT = "/sys/class/bdi/%s:%s/read_ahead_kb"
NFS_READAHEAD_OPTIMIZE_LINUX_KERNEL_MIN_VERSION = [5, 4]

# MacOS does not support the property of Socket SO_BINDTODEVICE in stunnel configuration
SKIP_NO_SO_BINDTODEVICE_RELEASES = [
    MACOS_BIG_SUR_RELEASE,
    MACOS_MONTEREY_RELEASE,
    MACOS_VENTURA_RELEASE,
    MACOS_SONOMA_RELEASE,
]

MAC_OS_PLATFORM_LIST = ["darwin"]
# MacOS Versions : Sonoma - 23.*, Ventura - 22.*, Monterey - 21.*, Big Sur - 20.*, Catalina - 19.*, Mojave - 18.*. Catalina and Mojave are not supported for now
MAC_OS_SUPPORTED_VERSION_LIST = ["20", "21", "22", "23"]

AWS_FIPS_ENDPOINT_CONFIG_ENV = "AWS_USE_FIPS_ENDPOINT"
ECS_URI_ENV = "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"
WEB_IDENTITY_ROLE_ARN_ENV = "AWS_ROLE_ARN"
WEB_IDENTITY_TOKEN_FILE_ENV = "AWS_WEB_IDENTITY_TOKEN_FILE"

ECS_FARGATE_TASK_METADATA_ENDPOINT_ENV = "ECS_CONTAINER_METADATA_URI_V4"
ECS_FARGATE_TASK_METADATA_ENDPOINT_URL_EXTENSION = "/task"
ECS_FARGATE_CLIENT_IDENTIFIER = "ecs.fargate"


def errcheck(ret, func, args):
    from ctypes import get_errno

    if ret == -1:
        e = get_errno()
        raise OSError(e, os.strerror(e))


def setns(fd, nstype):
    from ctypes import CDLL

    libc = CDLL("libc.so.6", use_errno=True)
    libc.setns.errcheck = errcheck
    if hasattr(fd, "fileno"):
        fd = fd.fileno()
    return libc.setns(fd, nstype)


class NetNS(object):
    # Open sockets from given network namespace: stackoverflow.com/questions/28846059
    def __init__(self, nspath):
        self.original_nspath = "/proc/%d/ns/net" % os.getpid()
        self.target_nspath = nspath

    def __enter__(self):
        self.original_namespace = open(self.original_nspath)
        with open(self.target_nspath) as fd:
            setns(fd, CLONE_NEWNET)

    def __exit__(self, *args):
        setns(self.original_namespace, CLONE_NEWNET)
        self.original_namespace.close()


class FallbackException(Exception):
    """Exception raised for errors happens when dns resolve and fallback to mount target ip address attempt both fail

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message):
        self.message = message
        super().__init__(self.message)


def fatal_error(user_message, log_message=None, exit_code=1):
    if log_message is None:
        log_message = user_message

    sys.stderr.write("%s\n" % user_message)
    logging.error(log_message)
    publish_cloudwatch_log(CLOUDWATCHLOG_AGENT, "Mount failed, %s" % log_message)
    sys.exit(exit_code)


def get_target_region(config, options):
    def _fatal_error(message):
        fatal_error(
            'Error retrieving region. Please set the "region" parameter '
            "in the efs-utils configuration file or specify it as a "
            "mount option.",
            message,
        )

    if "region" in options:
        return options.get("region")

    try:
        return config.get(CONFIG_SECTION, "region")
    except NoOptionError:
        pass

    try:
        return get_region_from_instance_metadata(config)
    except Exception as e:
        metadata_exception = e
        logging.warning(
            "Region not found in config file and metadata service call failed, falling back "
            'to legacy "dns_name_format" check'
        )

    try:
        region = get_region_from_legacy_dns_format(config)
        sys.stdout.write(
            'Warning: region obtained from "dns_name_format" field. Please set the "region" '
            "parameter in the efs-utils configuration file."
        )
        return region
    except Exception:
        logging.warning('Legacy check for region in "dns_name_format" failed')

    _fatal_error(metadata_exception)

def get_target_domain_suffix(config):
    def _fatal_error():
        fatal_error(
            'Error retrieving region. Please set the "dns_name_suffix" parameter '
            "in the efs-utils configuration file."
        )
    region = get_target_region(config)
    config_section = get_config_section(config, region)

    try:
        return config.get(config_section, "dns_name_suffix")
    except NoOptionError:
        pass

    _fatal_error()


def get_target_az(config, options):
    if "az" in options:
        return options.get("az")

    try:
        return get_az_from_instance_metadata(config)
    except Exception as e:
        logging.warning("Get AZ via metadata service call failed, %s", e)

    return None


def get_region_from_instance_metadata(config):
    instance_identity = get_instance_identity_info_from_instance_metadata(
        config, "region"
    )

    if not instance_identity:
        raise Exception(
            "Cannot retrieve region from instance_metadata. "
            "Please set the 'region' parameter in the efs-utils configuration file."
        )

    return instance_identity


def get_az_from_instance_metadata(config):
    instance_identity = get_instance_identity_info_from_instance_metadata(
        config, "availabilityZone"
    )

    if not instance_identity:
        raise Exception("Cannot retrieve az from instance_metadata")

    return instance_identity


def get_az_id_from_instance_metadata(config, options):
    az_id = get_az_id_info_from_instance_metadata(config, options)

    if not az_id:
        raise RuntimeError("Cannot retrieve az-id from instance_metadata")

    return az_id


def get_az_id_info_from_instance_metadata(config, options):
    logging.debug("Retrieve availability-zone-id from instance metadata")
    instance_az_id_url = get_instance_az_id_metadata_url(config)
    metadata_unsuccessful_resp = (
        "Unsuccessful retrieval of metadata at %s." % instance_az_id_url
    )
    metadata_url_error_msg = (
        "Unable to reach %s to retrieve instance metadata." % instance_az_id_url
    )

    global INSTANCE_AZ_ID_METADATA
    if INSTANCE_AZ_ID_METADATA:
        logging.debug(
            "Instance az_id already retrieved in previous call, use the cached values."
        )
        az_id_metadata = INSTANCE_AZ_ID_METADATA
    else:
        az_id_metadata = url_request_helper(
            config,
            instance_az_id_url,
            metadata_unsuccessful_resp,
            metadata_url_error_msg,
        )
        INSTANCE_AZ_ID_METADATA = az_id_metadata

    # ECS Fargate returns a json response with the AZ-name which we convert to AZ-ID
    if az_id_metadata and is_ecs_fargate_client(config):
        return get_az_id_from_ecs_fargate_response(config, options, az_id_metadata)
    elif az_id_metadata:
        return az_id_metadata

    return None


def get_instance_az_id_metadata_url(config):
    instance_az_id_url = INSTANCE_METADATA_SERVICE_AZ_ID_URL
    if is_ecs_fargate_client(config):
        # ECS-Fargate Metadata Endpoint must be used for ECS-Fargate clients.
        logging.debug("ECS-Fargate client detected, use ECS-Fargate Metadata Endpoint")
        try:
            instance_az_id_url = (
                os.getenv(ECS_FARGATE_TASK_METADATA_ENDPOINT_ENV)
                + ECS_FARGATE_TASK_METADATA_ENDPOINT_URL_EXTENSION
            )
        except Exception as e:
            logging.warning("Unable to parse ECS-Fargate Metadata Endpoint: %s", e)
            instance_az_id_url = None
    return instance_az_id_url


def is_ecs_fargate_client(config):
    client_info = get_client_info(config)
    if client_info and client_info.get("source") == ECS_FARGATE_CLIENT_IDENTIFIER:
        return True
    return False


def get_az_id_from_ecs_fargate_response(config, options, az_id_metadata):
    try:
        property = "AvailabilityZone"
        az_name = az_id_metadata[property]
        ec2_client = get_botocore_client(config, "ec2", options)
        az_id = get_az_id_by_az_name(ec2_client, az_name)
        return az_id
    except KeyError as e:
        logging.warning("%s not present in %s: %s" % (property, az_id_metadata, e))
    except TypeError as e:
        logging.warning("response %s is not a json object: %s" % (az_id_metadata, e))
    except FallbackException as e:
        fatal_error(e.message)
    return None


def get_instance_identity_info_from_instance_metadata(config, property):
    logging.debug("Retrieve property %s from instance metadata", property)
    ec2_metadata_unsuccessful_resp = (
        "Unsuccessful retrieval of EC2 metadata at %s." % INSTANCE_METADATA_SERVICE_URL
    )
    ec2_metadata_url_error_msg = (
        "Unable to reach %s to retrieve EC2 instance metadata."
        % INSTANCE_METADATA_SERVICE_URL
    )

    global INSTANCE_IDENTITY
    if INSTANCE_IDENTITY:
        logging.debug(
            "Instance metadata already retrieved in previous call, use the cached values."
        )
        instance_identity = INSTANCE_IDENTITY
    else:
        instance_identity = url_request_helper(
            config,
            INSTANCE_METADATA_SERVICE_URL,
            ec2_metadata_unsuccessful_resp,
            ec2_metadata_url_error_msg,
        )
        INSTANCE_IDENTITY = instance_identity

    if instance_identity:
        try:
            return instance_identity[property]
        except KeyError as e:
            logging.warning(
                "%s not present in %s: %s" % (property, instance_identity, e)
            )
        except TypeError as e:
            logging.warning(
                "response %s is not a json object: %s" % (instance_identity, e)
            )

    return None


def get_region_from_legacy_dns_format(config):
    """
    For backwards compatibility check dns_name_format to obtain the target region. This functionality
    should only be used if region is not present in the config file and metadata calls fail.
    """
    dns_name_format = config.get(CONFIG_SECTION, "dns_name_format")
    if "{region}" not in dns_name_format:
        split_dns_name_format = dns_name_format.split(".")
        if "{dns_name_suffix}" in dns_name_format:
            return split_dns_name_format[-2]
        elif "amazonaws.com" in dns_name_format:
            return split_dns_name_format[-3]
    raise Exception("Region not found in dns_name_format")


def get_boolean_config_item_value(
    config, config_section, config_item, default_value, emit_warning_message=True
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
        CONFIG_SECTION,
        DISABLE_FETCH_EC2_METADATA_TOKEN_ITEM,
        default_value=False,
    )


def get_aws_ec2_metadata_token(
    request_timeout=0.5,
    max_retries=DEFAULT_GET_AWS_EC2_METADATA_TOKEN_RETRY_COUNT,
    retry_delay=0.5,
):
    """
    Retrieves the AWS EC2 metadata token. Typically, the token is fetched
    within 10ms. We set a default timeout of 0.5 seconds to prevent mount
    failures caused by slow requests.

    Args:
        max_retries (int): The maximum number of retries.
        retry_delay (int): The delay in seconds between retries.

    Returns:
        The AWS EC2 metadata token str or None if it cannot be retrieved.
    """

    def get_token(timeout):
        try:
            opener = build_opener(HTTPHandler)
            request = Request(INSTANCE_METADATA_TOKEN_URL)
            request.add_header("X-aws-ec2-metadata-token-ttl-seconds", "21600")
            request.get_method = lambda: "PUT"
            try:
                response = opener.open(request, timeout=timeout)
                return response.read()
            finally:
                opener.close()

        except NameError:
            headers = {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}
            request = Request(
                INSTANCE_METADATA_TOKEN_URL, headers=headers, method="PUT"
            )
            response = urlopen(request, timeout=timeout)
            return response.read()

    retries = 0
    while retries < max_retries:
        try:
            return get_token(timeout=request_timeout)
        except socket.timeout:
            logging.debug(
                "Timeout when getting the aws ec2 metadata token. Attempt: %s/%s"
                % (retries + 1, max_retries)
            )
        except HTTPError as e:
            logging.debug(
                "Failed to fetch token due to %s. Attempt: %s/%s"
                % (e, retries + 1, max_retries)
            )
        except Exception as e:
            logging.debug(
                "Unknown error when fetching aws ec2 metadata token, %s. Attempt: %s/%s"
                % (e, retries + 1, max_retries)
            )

        retries += 1
        if retries < max_retries:
            logging.debug("Retrying in %s seconds", retry_delay)
            time.sleep(retry_delay)
        else:
            logging.debug(
                "Unable to retrieve AWS EC2 metadata token. Maximum number of retries reached."
            )
            return None


def get_aws_security_credentials(
    config,
    use_iam,
    region,
    dns_name_suffix,
    awsprofile=None,
    aws_creds_uri=None,
    jwt_path=None,
    role_arn=None,
):
    """
    Lookup AWS security credentials. Adapted credentials provider chain from:
    https://boto3.amazonaws.com/v1/documentation/api/latest/guide/configuration.html and
    https://docs.aws.amazon.com/sdk-for-java/v1/developer-guide/credentials.html

    If iam is enabled, this function will return two objects, credentials and credentials_source.
    credentials is a dictionary with three keys, "AccessKeyId", "SecretAccessKey", and "Token".
    credentials_source will be a string that describes the method by which the credentials were obtained.
    """

    if not use_iam:
        return None, None

    # attempt to lookup AWS security credentials through the credentials URI the ECS agent generated
    if aws_creds_uri:
        return get_aws_security_credentials_from_ecs(config, aws_creds_uri, True)

    # attempt to lookup AWS security credentials in AWS credentials file (~/.aws/credentials)
    # and configs file (~/.aws/config) with given awsprofile
    # if the credentials are not present in above filepath, and botocore is present, attempt to assume the given awsprofile
    if awsprofile:
        return get_aws_security_credentials_from_awsprofile(awsprofile, True)

    # attempt to lookup AWS security credentials through AWS_CONTAINER_CREDENTIALS_RELATIVE_URI environment variable
    if ECS_URI_ENV in os.environ:
        credentials, credentials_source = get_aws_security_credentials_from_ecs(
            config, os.environ[ECS_URI_ENV], False
        )
        if credentials and credentials_source:
            return credentials, credentials_source

    # attempt to lookup AWS security credentials through AssumeRoleWithWebIdentity
    # (e.g. for IAM Role for Service Accounts (IRSA) approach on EKS)
    if jwt_path and role_arn:
        credentials, credentials_source = get_aws_security_credentials_from_webidentity(
            config,
            role_arn,
            jwt_path,
            region,
            dns_name_suffix,
            False,
        )
        if credentials and credentials_source:
            return credentials, credentials_source

    if (
        WEB_IDENTITY_ROLE_ARN_ENV in os.environ
        and WEB_IDENTITY_TOKEN_FILE_ENV in os.environ
    ):
        credentials, credentials_source = get_aws_security_credentials_from_webidentity(
            config,
            os.environ[WEB_IDENTITY_ROLE_ARN_ENV],
            os.environ[WEB_IDENTITY_TOKEN_FILE_ENV],
            region,
            dns_name_suffix,
            False,
        )
        if credentials and credentials_source:
            return credentials, credentials_source

    # attempt to lookup AWS security credentials with IAM role name attached to instance
    # through IAM role name security credentials lookup uri
    iam_role_name = get_iam_role_name(config)
    if iam_role_name:
        (
            credentials,
            credentials_source,
        ) = get_aws_security_credentials_from_instance_metadata(config, iam_role_name)
        if credentials and credentials_source:
            return credentials, credentials_source

    error_msg = (
        "AWS Access Key ID and Secret Access Key are not found in AWS credentials file (%s), config file (%s), "
        "from ECS credentials relative uri, or from the instance security credentials service"
        % (AWS_CREDENTIALS_FILE, AWS_CONFIG_FILE)
    )
    fatal_error(error_msg, error_msg)


def get_aws_security_credentials_from_awsprofile(awsprofile, is_fatal=False):
    for file_path in [AWS_CREDENTIALS_FILE, AWS_CONFIG_FILE]:
        if os.path.exists(file_path):
            credentials = credentials_file_helper(file_path, awsprofile)
            if credentials["AccessKeyId"]:
                logging.debug("Retrieved credentials from %s" % file_path)
                return credentials, os.path.basename(file_path) + ":" + awsprofile

    # If credentials are not defined in the aws credentials and config file, attempt to assume the named profile
    credentials = botocore_credentials_helper(awsprofile)
    if credentials["AccessKeyId"]:
        logging.debug("Retrieved credentials from assumed profile %s" % awsprofile)
        return credentials, "named_profile:" + awsprofile

    # Fail if credentials cannot be fetched from the given awsprofile
    if is_fatal:
        log_message = (
            "AWS security credentials not found in %s or %s under named profile [%s]"
            % (AWS_CREDENTIALS_FILE, AWS_CONFIG_FILE, awsprofile)
        )
        fatal_error(log_message)
    else:
        return None, None


def get_aws_security_credentials_from_ecs(config, aws_creds_uri, is_fatal=False):
    ecs_uri = ECS_TASK_METADATA_API + aws_creds_uri
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

    if ecs_security_dict and all(k in ecs_security_dict for k in CREDENTIALS_KEYS):
        return ecs_security_dict, "ecs:" + aws_creds_uri

    # Fail if credentials cannot be fetched from the given aws_creds_uri
    if is_fatal:
        fatal_error(ecs_unsuccessful_resp, ecs_unsuccessful_resp)
    else:
        return None, None


def get_aws_security_credentials_from_webidentity(
    config, role_arn, token_file, region, dns_name_suffix, is_fatal=False
):
    try:
        with open(token_file, "r") as f:
            token = f.read()
    except Exception as e:
        if is_fatal:
            unsuccessful_resp = "Error reading token file %s: %s" % (token_file, e)
            fatal_error(unsuccessful_resp, unsuccessful_resp)
        else:
            return None, None

    STS_ENDPOINT_URL = STS_ENDPOINT_URL_FORMAT.format(region,dns_name_suffix)
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
            }, "webidentity:" + ",".join([role_arn, token_file])

    # Fail if credentials cannot be fetched from the given aws_creds_uri
    if is_fatal:
        fatal_error(unsuccessful_resp, unsuccessful_resp)
    else:
        return None, None


def get_aws_security_credentials_from_instance_metadata(config, iam_role_name):
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

    if iam_security_dict and all(k in iam_security_dict for k in CREDENTIALS_KEYS):
        return iam_security_dict, "metadata:"
    else:
        return None, None


def get_iam_role_name(config):
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
    return iam_role_name


def credentials_file_helper(file_path, awsprofile):
    aws_credentials_configs = read_config(file_path)
    credentials = {"AccessKeyId": None, "SecretAccessKey": None, "Token": None}

    try:
        access_key = aws_credentials_configs.get(awsprofile, "aws_access_key_id")
        secret_key = aws_credentials_configs.get(awsprofile, "aws_secret_access_key")
        session_token = aws_credentials_configs.get(awsprofile, "aws_session_token")

        credentials["AccessKeyId"] = access_key
        credentials["SecretAccessKey"] = secret_key
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


def botocore_credentials_helper(awsprofile):
    # This method retrieves credentials from aws named profile using botocore, botocore will then assume that named profile, get
    # and return the credentials
    credentials = {"AccessKeyId": None, "SecretAccessKey": None, "Token": None}
    if not BOTOCORE_PRESENT:
        logging.error(
            "Cannot find credentials for %s, to assume this profile, please install botocore first."
            % awsprofile
        )
        return credentials
    session = botocore.session.get_session()
    session.set_config_variable("profile", awsprofile)

    try:
        frozen_credentials = session.get_credentials().get_frozen_credentials()
    except ProfileNotFound as e:
        fatal_error(
            "%s, please add the [profile %s] section in the aws config file following %s and %s."
            % (e, awsprofile, NAMED_PROFILE_HELP_URL, CONFIG_FILE_SETTINGS_HELP_URL)
        )

    credentials["AccessKeyId"] = frozen_credentials.access_key
    credentials["SecretAccessKey"] = frozen_credentials.secret_key
    credentials["Token"] = frozen_credentials.token
    return credentials


def get_aws_profile(options, use_iam):
    awsprofile = options.get("awsprofile")
    if not awsprofile and use_iam:
        for file_path in [AWS_CREDENTIALS_FILE, AWS_CONFIG_FILE]:
            aws_credentials_configs = read_config(file_path)
            # check if aws access key id is found under [default] section in current file and return 'default' if so
            try:
                access_key = aws_credentials_configs.get("default", "aws_access_key_id")
                if access_key is not None:
                    return "default"
            except (NoSectionError, NoOptionError):
                continue

    return awsprofile


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
    """
    Parse the response of an url request

    :return: If the response result can be parsed into json object, return the json object parsed from the response.
             Otherwise return the response body in string format.
    """

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


def parse_options(options):
    """
    Parses a comma delineated string of key=value options (e.g. 'opt1,opt2=val').
    Returns a dictionary of key,value pairs, where value = None if
    it was not provided.
    """
    opts = {}
    for o in options.split(","):
        if "=" in o:
            k, v = o.split("=")
            opts[k] = v
        else:
            opts[o] = None
    return opts


def get_tls_port_range(config):
    lower_bound = config.getint(CONFIG_SECTION, "port_range_lower_bound")
    upper_bound = config.getint(CONFIG_SECTION, "port_range_upper_bound")

    if lower_bound >= upper_bound:
        fatal_error(
            'Configuration option "port_range_upper_bound" defined as %d '
            'must be strictly greater than "port_range_lower_bound" defined as %d.'
            % (upper_bound, lower_bound)
        )

    return lower_bound, upper_bound


def choose_tls_port_and_get_bind_sock(config, options, state_file_dir):
    if "tlsport" in options:
        ports_to_try = [int(options["tlsport"])]
    else:
        lower_bound, upper_bound = get_tls_port_range(config)

        ports_to_try = list(range(lower_bound, upper_bound))

        # shuffle the ports_to_try to reduce possibility of multiple mounts starting from same port range
        random.shuffle(ports_to_try)

    if "netns" not in options:
        tls_port_sock = find_tls_port_in_range_and_get_bind_sock(
            ports_to_try, state_file_dir
        )
    else:
        with NetNS(nspath=options["netns"]):
            tls_port_sock = find_tls_port_in_range_and_get_bind_sock(
                ports_to_try, state_file_dir
            )

    if tls_port_sock:
        return tls_port_sock

    if "tlsport" in options:
        fatal_error(
            "Specified port [%s] is unavailable. Try selecting a different port."
            % options["tlsport"]
        )
    else:
        fatal_error(
            "Failed to locate an available port in the range [%d, %d], try specifying a different port range in %s"
            % (lower_bound, upper_bound, CONFIG_FILE)
        )


def find_tls_port_in_range_and_get_bind_sock(ports_to_try, state_file_dir):
    sock = socket.socket()
    for tls_port in ports_to_try:
        mount = find_existing_mount_using_tls_port(state_file_dir, tls_port)
        if mount:
            logging.debug(
                "Skip binding TLS port %s as it is already assigned to %s",
                tls_port,
                mount,
            )
            continue
        try:
            logging.info("binding %s", tls_port)
            sock.bind(("localhost", tls_port))
            return sock
        except socket.error as e:
            logging.warning(e)
            continue
    sock.close()
    return None


def find_existing_mount_using_tls_port(state_file_dir, tls_port):
    if not os.path.exists(state_file_dir):
        logging.debug(
            "State file dir %s does not exist, assuming no existing mount using tls port %s",
            state_file_dir,
            tls_port,
        )
        return None

    for fname in os.listdir(state_file_dir):
        if fname.endswith(".%s" % tls_port):
            return fname

    return None


def is_ocsp_enabled(config, options):
    if "ocsp" in options:
        return True
    elif "noocsp" in options:
        return False
    else:
        return get_boolean_config_item_value(
            config, CONFIG_SECTION, "stunnel_check_cert_validity", default_value=False
        )


def get_mount_specific_filename(fs_id, mountpoint, tls_port):
    return "%s.%s.%d" % (
        fs_id,
        os.path.abspath(mountpoint).replace(os.sep, ".").lstrip("."),
        tls_port,
    )


def serialize_stunnel_config(config, header=None):
    lines = []

    if header:
        lines.append("[%s]" % header)

    for k, v in config.items():
        if type(v) is list:
            for item in v:
                lines.append("%s = %s" % (k, item))
        else:
            lines.append("%s = %s" % (k, v))

    return lines


# These options are used by both stunnel and efs-proxy for TLS mounts
def add_tunnel_ca_options(efs_config, config, options, region):
    if "cafile" in options:
        stunnel_cafile = options["cafile"]
    else:
        try:
            config_section = get_config_section(config, region)
            stunnel_cafile = config.get(config_section, "stunnel_cafile")
            logging.debug(
                "Using stunnel_cafile %s in config section [%s]",
                stunnel_cafile,
                config_section,
            )
        except NoOptionError:
            logging.debug(
                "No CA file configured, using default CA file %s",
                DEFAULT_STUNNEL_CAFILE,
            )
            stunnel_cafile = DEFAULT_STUNNEL_CAFILE

    if not os.path.exists(stunnel_cafile):
        fatal_error(
            "Failed to find certificate authority file for verification",
            'Failed to find CAfile "%s"' % stunnel_cafile,
        )

    efs_config["CAfile"] = stunnel_cafile


def get_config_section(config, region):
    region_specific_config_section = "%s.%s" % (CONFIG_SECTION, region)
    if config.has_section(region_specific_config_section):
        config_section = region_specific_config_section
    else:
        config_section = CONFIG_SECTION
    return config_section


def is_stunnel_option_supported(
    stunnel_output,
    stunnel_option_name,
    stunnel_option_value=None,
    emit_warning_log=True,
):
    supported = False
    for line in stunnel_output:
        if line.startswith(stunnel_option_name):
            if not stunnel_option_value:
                supported = True
                break
            elif stunnel_option_value and stunnel_option_value in line:
                supported = True
                break

    if not supported and emit_warning_log:
        if not stunnel_option_value:
            logging.warning('stunnel does not support "%s"', stunnel_option_name)
        else:
            logging.warning(
                'stunnel does not support "%s" as value of "%s"',
                stunnel_option_value,
                stunnel_option_name,
            )

    return supported


def get_stunnel_options():
    stunnel_command = [_stunnel_bin(), "-help"]
    proc = subprocess.Popen(
        stunnel_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True
    )
    proc.wait()
    _, err = proc.communicate()

    return err.splitlines()


def _stunnel_bin():
    installation_message = "Please install it following the instructions at: https://docs.aws.amazon.com/efs/latest/ug/using-amazon-efs-utils.html#upgrading-stunnel"
    if get_system_release_version() in AMAZON_LINUX_2_RELEASE_VERSIONS:
        return find_command_path("stunnel5", installation_message)
    else:
        return find_command_path("stunnel", installation_message)


def _efs_proxy_bin():
    error_message = "The efs-proxy binary is packaged with efs-utils. It was deleted or not installed correctly."
    return find_command_path("efs-proxy", error_message)


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


def write_stunnel_config_file(
    config,
    state_file_dir,
    fs_id,
    mountpoint,
    tls_port,
    dns_name,
    verify_level,
    ocsp_enabled,
    options,
    region,
    log_dir=LOG_DIR,
    cert_details=None,
    fallback_ip_address=None,
    efs_proxy_enabled=True,
):
    """
    Serializes stunnel configuration to a file. Unfortunately this does not conform to Python's config file format, so we have to
    hand-serialize it.
    """

    stunnel_options = get_stunnel_options()
    mount_filename = get_mount_specific_filename(fs_id, mountpoint, tls_port)

    system_release_version = get_system_release_version()
    global_config = dict(STUNNEL_GLOBAL_CONFIG)

    if not efs_proxy_enabled and is_stunnel_option_supported(
        stunnel_options, b"foreground", b"quiet", emit_warning_log=False
    ):
        # Do not log to stderr of subprocess in addition to the destinations specified with syslog and output.
        # Only support in stunnel version 5.25+.
        global_config["foreground"] = "quiet"

    if any(
        release in system_release_version
        for release in SKIP_NO_SO_BINDTODEVICE_RELEASES
    ):
        global_config["socket"].remove("a:SO_BINDTODEVICE=lo")

    if get_boolean_config_item_value(
        config, CONFIG_SECTION, "stunnel_debug_enabled", default_value=False
    ):
        global_config["debug"] = "debug"
        # If the stunnel debug is enabled, we also redirect stunnel log to stderr to capture any error while launching
        # the stunnel.
        global_config["foreground"] = "yes"
        if config.has_option(CONFIG_SECTION, "stunnel_logs_file"):
            global_config["output"] = config.get(
                CONFIG_SECTION, "stunnel_logs_file"
            ).replace("{fs_id}", fs_id)
        else:
            proxy_log_file = (
                "%s.efs-proxy.log" if efs_proxy_enabled else "%s.stunnel.log"
            )
            global_config["output"] = os.path.join(
                log_dir, proxy_log_file % mount_filename
            )

    global_config["pid"] = os.path.join(
        state_file_dir, mount_filename + "+", "stunnel.pid"
    )

    if get_fips_config(config):
        global_config["fips"] = "yes"

    efs_config = dict(STUNNEL_EFS_CONFIG)
    efs_config["accept"] = efs_config["accept"] % tls_port

    if fallback_ip_address:
        efs_config["connect"] = efs_config["connect"] % fallback_ip_address
    else:
        efs_config["connect"] = efs_config["connect"] % dns_name

    # Verify level is only valid for tls mounts
    if (verify_level is not None) and tls_enabled(options):
        efs_config["verify"] = verify_level
        if verify_level > 0:
            add_tunnel_ca_options(efs_config, config, options, region)

    if cert_details:
        efs_config["cert"] = cert_details["certificate"]
        efs_config["key"] = cert_details["privateKey"]

    tls_controls_message = (
        "WARNING: Your client lacks sufficient controls to properly enforce TLS. Please upgrade stunnel, "
        'or disable "%%s" in %s.\nSee %s for more detail.'
        % (CONFIG_FILE, "https://docs.aws.amazon.com/console/efs/troubleshooting-tls")
    )

    if tls_enabled(options):
        # These config options are not applicable to non-tls mounts with efs-proxy
        if get_boolean_config_item_value(
            config, CONFIG_SECTION, "stunnel_check_cert_hostname", default_value=True
        ):
            if (not efs_proxy_enabled) and (
                not is_stunnel_option_supported(stunnel_options, b"checkHost")
            ):
                fatal_error(tls_controls_message % "stunnel_check_cert_hostname")
            else:
                efs_config["checkHost"] = dns_name[dns_name.index(fs_id) :]

        # Only use the config setting if the override is not set
        if not efs_proxy_enabled and ocsp_enabled:
            if is_stunnel_option_supported(stunnel_options, b"OCSPaia"):
                efs_config["OCSPaia"] = "yes"
            else:
                fatal_error(tls_controls_message % "stunnel_check_cert_validity")

    # If the stunnel libwrap option is supported, we disable the usage of /etc/hosts.allow and /etc/hosts.deny by
    # setting the option to no
    if not efs_proxy_enabled and is_stunnel_option_supported(
        stunnel_options, b"libwrap"
    ):
        efs_config["libwrap"] = "no"

    stunnel_config = "\n".join(
        serialize_stunnel_config(global_config)
        + serialize_stunnel_config(efs_config, "efs")
    )
    logging.debug("Writing stunnel configuration:\n%s", stunnel_config)

    stunnel_config_file = os.path.join(
        state_file_dir, "stunnel-config.%s" % mount_filename
    )

    with open(stunnel_config_file, "w") as f:
        f.write(stunnel_config)

    return stunnel_config_file


def write_tunnel_state_file(
    fs_id,
    mountpoint,
    tls_port,
    tunnel_pid,
    command,
    files,
    state_file_dir,
    cert_details=None,
):
    """
    Return the name of the temporary file containing TLS tunnel state, prefixed with a '~'. This file needs to be renamed to a
    non-temporary version following a successful mount.

    The "tunnel" here refers to efs-proxy, or stunnel.
    """
    state_file = "~" + get_mount_specific_filename(fs_id, mountpoint, tls_port)

    state = {
        "pid": tunnel_pid,
        "cmd": command,
        "files": files,
        "mount_time": time.time(),
        "mountpoint": mountpoint,
    }

    if cert_details:
        state.update(cert_details)

    with open(os.path.join(state_file_dir, state_file), "w") as f:
        json.dump(state, f)

    return state_file


def rewrite_tunnel_state_file(state, state_file_dir, state_file):
    with open(os.path.join(state_file_dir, state_file), "w") as f:
        json.dump(state, f)
    return state_file


def update_tunnel_temp_state_file_with_tunnel_pid(
    temp_tls_state_file, state_file_dir, stunnel_pid
):
    with open(os.path.join(state_file_dir, temp_tls_state_file), "r") as f:
        state = json.load(f)
    state["pid"] = stunnel_pid
    temp_tls_state_file = rewrite_tunnel_state_file(
        state, state_file_dir, temp_tls_state_file
    )
    return temp_tls_state_file


def test_tunnel_process(tunnel_proc, fs_id):
    tunnel_proc.poll()
    if tunnel_proc.returncode is not None:
        _, err = tunnel_proc.communicate()
        fatal_error(
            "Failed to initialize tunnel for %s, please check mount.log for the failure reason."
            % fs_id,
            'Failed to start tunnel (errno=%d), stderr="%s". If the stderr is lacking enough details, please '
            "enable stunnel debug log in efs-utils config file and retry the mount to capture more info."
            % (tunnel_proc.returncode, err.strip()),
        )


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
        mount_completed.wait(0.5)


def get_init_system(comm_file="/proc/1/comm"):
    init_system = DEFAULT_UNKNOWN_VALUE
    if not check_if_platform_is_mac():
        try:
            with open(comm_file) as f:
                init_system = f.read().strip()
        except IOError:
            logging.warning("Unable to read %s", comm_file)
    else:
        init_system = "launchd"

    logging.debug("Identified init system: %s", init_system)
    return init_system


def check_network_target(fs_id):
    with open(os.devnull, "w") as devnull:
        rc = subprocess.call(
            ["systemctl", "is-active", "network.target"],
            stdout=devnull,
            stderr=devnull,
            close_fds=True,
        )

    if rc != 0:
        # For fstab mount, the exit code 0 below is to avoid non-zero exit status causing instance to fail the
        # local-fs.target boot up and then fail the network setup failure can result in the instance being unresponsive.
        # https://docs.amazonaws.cn/en_us/efs/latest/ug/troubleshooting-efs-mounting.html#automount-fails
        #
        fatal_error(
            'Failed to mount %s because the network was not yet available, add "_netdev" to your mount options'
            % fs_id,
            exit_code=0,
        )


# This network status check is necessary for the fstab automount use case and should not be removed.
# efs-utils relies on the network to retrieve the instance metadata and get information e.g. region, to further parse
# the DNS name of file system to mount target IP address, we need a way to inform users to add `_netdev` option to fstab
# entry if they haven't do so.
#
# However, network.target status itself cannot accurately reflect the status of network reachability.
# We will replace this check with other accurate way such that even network.target is turned off while network is
# reachable, the mount can still proceed.
#
def check_network_status(fs_id, init_system):
    if init_system != "systemd":
        logging.debug("Not testing network on non-systemd init systems")
        return

    check_network_target(fs_id)


def start_watchdog(init_system):
    if init_system == "init":
        proc = subprocess.Popen(
            ["/sbin/status", WATCHDOG_SERVICE],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
        )
        status, _ = proc.communicate()
        if "stop" in str(status):
            subprocess.Popen(
                ["/sbin/start", WATCHDOG_SERVICE],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
            )
        elif "start" in str(status):
            logging.debug("%s is already running", WATCHDOG_SERVICE)

    elif init_system == "systemd":
        rc = subprocess.call(
            ["systemctl", "is-active", "--quiet", WATCHDOG_SERVICE], close_fds=True
        )
        if rc != 0:
            subprocess.Popen(
                ["systemctl", "start", WATCHDOG_SERVICE],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
            )
        else:
            logging.debug("%s is already running", WATCHDOG_SERVICE)

    elif init_system == "launchd":
        rc = subprocess.Popen(
            ["sudo", "launchctl", "list", WATCHDOG_SERVICE],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
        )
        if rc != 0:
            if not os.path.exists(WATCHDOG_SERVICE_PLIST_PATH):
                fatal_error(
                    "Watchdog plist file missing. Copy the watchdog plist file in directory /Library/LaunchAgents"
                )
            subprocess.Popen(
                ["sudo", "launchctl", "load", WATCHDOG_SERVICE_PLIST_PATH],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
            )
        else:
            logging.debug("%s is already running", WATCHDOG_SERVICE)

    else:
        error_message = 'Could not start %s, unrecognized init system "%s"' % (
            WATCHDOG_SERVICE,
            init_system,
        )
        sys.stderr.write("%s\n" % error_message)
        logging.warning(error_message)


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
    except OSError as e:
        if errno.EEXIST != e.errno or not os.path.isdir(directory):
            raise


# Example of a localhost bind sock: sock.bind(('localhost',12345))
# sock.getsockname() -> ('127.0.0.1', 12345)
# This function returns the port of the bind socket, in the example is 12345
def get_tls_port_from_sock(tls_port_sock):
    return tls_port_sock.getsockname()[1]


def tls_enabled(options):
    return "tls" in options


@contextmanager
def bootstrap_proxy(
    config,
    init_system,
    dns_name,
    fs_id,
    mountpoint,
    options,
    state_file_dir=STATE_FILE_DIR,
    fallback_ip_address=None,
    efs_proxy_enabled=True,
):
    """
    Generates a TLS private key and client-side certificate, a stunnel configuration file, and a state file
    that is used to pass information to the Watchdog process.

    This function will spin up a stunnel or efs-proxy process, and pass it the stunnel configuration file.
    The client-side certificate generated by this function contains IAM information that can be used by the EFS backend to enforce
    file system policies.

    The state file passes information about the mount and the associated proxy process (whether that's stunnel or efs-proxy) to
    the Watchdog daemon service. This allows Watchdog to monitor the proxy process's health.

    This function will yield a handle on the proxy process, whether it's efs-proxy or stunnel.
    """

    proxy_listen_sock = choose_tls_port_and_get_bind_sock(
        config, options, state_file_dir
    )
    proxy_listen_port = get_tls_port_from_sock(proxy_listen_sock)

    try:
        # override the tlsport option so that we can later override the port the NFS client uses to connect to stunnel.
        # if the user has specified tlsport=X at the command line this will just re-set tlsport to X.
        options["tlsport"] = proxy_listen_port

        use_iam = "iam" in options
        ap_id = options.get("accesspoint")
        cert_details = None
        security_credentials = None
        client_info = get_client_info(config)
        region = get_target_region(config, options)
<<<<<<< HEAD
        dns_name_suffix = get_target_domain_suffix(config)
=======
>>>>>>> upstream/master

        if tls_enabled(options):
            cert_details = {}
            # IAM can only be used for tls mounts
            if use_iam:
                aws_creds_uri = options.get("awscredsuri")
                role_arn = options.get("rolearn")
                jwt_path = options.get("jwtpath")
                if aws_creds_uri:
                    kwargs = {"aws_creds_uri": aws_creds_uri}
                elif role_arn and jwt_path:
                    kwargs = {"role_arn": role_arn, "jwt_path": jwt_path}
                else:
                    kwargs = {"awsprofile": get_aws_profile(options, use_iam)}

                security_credentials, credentials_source = get_aws_security_credentials(
                    config, use_iam, region, dns_name_suffix, **kwargs
                )

                if credentials_source:
                    cert_details["awsCredentialsMethod"] = credentials_source
                    logging.debug(
                        "AWS credentials source used for IAM authentication: ",
                        credentials_source,
                    )

            # Access points must be mounted over TLS
            if ap_id:
                cert_details["accessPoint"] = ap_id

            # additional symbol appended to avoid naming collisions
            cert_details["mountStateDir"] = (
                get_mount_specific_filename(fs_id, mountpoint, proxy_listen_port) + "+"
            )
            # common name for certificate signing request is max 64 characters
            cert_details["commonName"] = socket.gethostname()[0:64]
            cert_details["region"] = region
            cert_details["certificateCreationTime"] = create_certificate(
                config,
                cert_details["mountStateDir"],
                cert_details["commonName"],
                cert_details["region"],
                fs_id,
                security_credentials,
                ap_id,
                client_info,
                base_path=state_file_dir,
            )
            cert_details["certificate"] = os.path.join(
                state_file_dir, cert_details["mountStateDir"], "certificate.pem"
            )
            cert_details["privateKey"] = get_private_key_path()
            cert_details["fsId"] = fs_id

        if not os.path.exists(state_file_dir):
            create_required_directory(config, state_file_dir)

        start_watchdog(init_system)

        verify_level = (
            int(options.get("verify", DEFAULT_STUNNEL_VERIFY_LEVEL))
            if tls_enabled(options)
            else None
        )

        ocsp_enabled = is_ocsp_enabled(config, options)
        if ocsp_enabled:
            assert (
                not efs_proxy_enabled
            ), "OCSP is not supported by efs-proxy, and efs-utils failed to revert to stunnel-mode."

        stunnel_config_file = write_stunnel_config_file(
            config,
            state_file_dir,
            fs_id,
            mountpoint,
            proxy_listen_port,
            dns_name,
            verify_level,
            ocsp_enabled,
            options,
            region,
            cert_details=cert_details,
            fallback_ip_address=fallback_ip_address,
            efs_proxy_enabled=efs_proxy_enabled,
        )
        if efs_proxy_enabled:
            if "tls" in options:
                tunnel_args = [
                    _efs_proxy_bin(),
                    stunnel_config_file,
                    EFS_PROXY_TLS_OPTION,
                ]
            else:
                tunnel_args = [
                    _efs_proxy_bin(),
                    stunnel_config_file,
                ]
        else:
            tunnel_args = [_stunnel_bin(), stunnel_config_file]

        if "netns" in options:
            tunnel_args = ["nsenter", "--net=" + options["netns"]] + tunnel_args

        # This temp state file is acting like a tlsport lock file, which is why pid =- 1
        temp_tls_state_file = write_tunnel_state_file(
            fs_id,
            mountpoint,
            proxy_listen_port,
            -1,
            tunnel_args,
            [stunnel_config_file],
            state_file_dir,
            cert_details=cert_details,
        )
    finally:
        # When choosing a TLS port for efs-proxy/stunnel to listen on, we open the port to ensure it is free.
        # However, we must free it again so efs-proxy/stunnel can bind to it. We make sure to only free it after
        # we write the temporary state file, which acts like a tlsport lock file. This ensures we don't encounter
        # any race conditions when choosing tls ports during concurrent mounts.
        logging.debug(
            "Closing socket used to choose proxy listen port %s.", proxy_listen_port
        )
        proxy_listen_sock.close()

    # launch the tunnel in a process group so if it has any child processes, they can be killed easily by the mount watchdog
    logging.info(
        'Starting %s: "%s"',
        "efs-proxy" if efs_proxy_enabled else "stunnel",
        " ".join(tunnel_args),
    )
    tunnel_proc = subprocess.Popen(
        tunnel_args,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        preexec_fn=os.setsid,
        close_fds=True,
    )
    logging.info(
        "Started %s, pid: %d",
        "efs-proxy" if efs_proxy_enabled else "stunnel",
        tunnel_proc.pid,
    )

    update_tunnel_temp_state_file_with_tunnel_pid(
        temp_tls_state_file, state_file_dir, tunnel_proc.pid
    )

    if "netns" not in options:
        test_tlsport(options["tlsport"])
    else:
        with NetNS(nspath=options["netns"]):
            test_tlsport(options["tlsport"])

    try:
        yield tunnel_proc
    finally:
        # The caller of this function should use this function in the context of a `with` statement
        # so that the state file is correctly renamed.
        os.rename(
            os.path.join(state_file_dir, temp_tls_state_file),
            os.path.join(state_file_dir, temp_tls_state_file[1:]),
        )


def test_tlsport(tlsport):
    retry_times = 5
    while not verify_tlsport_can_be_connected(tlsport) and retry_times > 0:
        logging.debug(
            "The tlsport %s cannot be connected yet, sleep %s(s), %s retry time(s) left",
            tlsport,
            DEFAULT_TIMEOUT,
            retry_times,
        )
        time.sleep(DEFAULT_TIMEOUT)
        retry_times -= 1


def check_if_nfsvers_is_compatible_with_macos(options):
    # MacOS does not support NFSv4.1
    if (
        ("nfsvers" in options and options["nfsvers"] == "4.1")
        or ("vers" in options and options["vers"] == "4.1")
        or ("minorversion" in options and options["minorversion"] == 1)
    ):
        fatal_error("NFSv4.1 is not supported on MacOS, please switch to NFSv4.0")


# Use stunnel instead of efs-proxy for tls mounts,
# and attach non-tls mounts directly to the mount target.
def legacy_stunnel_mode_enabled(options, config):
    return (
        LEGACY_STUNNEL_MOUNT_OPTION in options
        or check_if_platform_is_mac()
        or is_ocsp_enabled(config, options)
    )


def get_nfs_mount_options(options, config):
    # If you change these options, update the man page as well at man/mount.efs.8
    if "nfsvers" not in options and "vers" not in options:
        options["nfsvers"] = "4.1" if not check_if_platform_is_mac() else "4.0"

    if check_if_platform_is_mac():
        check_if_nfsvers_is_compatible_with_macos(options)

    if "rsize" not in options:
        options["rsize"] = "1048576"
    if "wsize" not in options:
        options["wsize"] = "1048576"
    if "soft" not in options and "hard" not in options:
        options["hard"] = None
    if "timeo" not in options:
        options["timeo"] = "600"
    if "retrans" not in options:
        options["retrans"] = "2"
    if "noresvport" not in options:
        options["noresvport"] = None

    # Set mountport to 2049 for MacOS
    if check_if_platform_is_mac():
        options["mountport"] = "2049"

    if legacy_stunnel_mode_enabled(options, config):
        # Non-tls mounts in stunnel mode should not re-map the port
        if "tls" in options:
            options["port"] = options["tlsport"]
    else:
        options["port"] = options["tlsport"]

    def to_nfs_option(k, v):
        if v is None:
            return k
        return "%s=%s" % (str(k), str(v))

    nfs_options = [
        to_nfs_option(k, v) for k, v in options.items() if k not in EFS_ONLY_OPTIONS
    ]

    return ",".join(nfs_options)


def mount_nfs(config, dns_name, path, mountpoint, options, fallback_ip_address=None):
    if legacy_stunnel_mode_enabled(options, config):
        if "tls" in options:
            mount_path = "127.0.0.1:%s" % path
        elif fallback_ip_address:
            mount_path = "%s:%s" % (fallback_ip_address, path)
        else:
            mount_path = "%s:%s" % (dns_name, path)
    else:
        mount_path = "127.0.0.1:%s" % path

    if not check_if_platform_is_mac():
        command = [
            "/sbin/mount.nfs4",
            mount_path,
            mountpoint,
            "-o",
            get_nfs_mount_options(options, config),
        ]
    else:
        command = [
            "/sbin/mount_nfs",
            "-o",
            get_nfs_mount_options(options, config),
            mount_path,
            mountpoint,
        ]

    if "netns" in options:
        command = ["nsenter", "--net=" + options["netns"]] + command

    if call_nfs_mount_command_with_retry_succeed(
        config, options, command, dns_name, mountpoint
    ):
        return

    logging.info('Executing: "%s"', " ".join(command))

    proc = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True
    )
    out, err = proc.communicate()

    if proc.returncode == 0:
        post_mount_nfs_success(config, options, dns_name, mountpoint)
    else:
        message = 'Failed to mount %s at %s: returncode=%d, stderr="%s"' % (
            dns_name,
            mountpoint,
            proc.returncode,
            err.strip(),
        )
        fatal_error(err.strip(), message, proc.returncode)


def post_mount_nfs_success(config, options, dns_name, mountpoint):
    message = "Successfully mounted %s at %s" % (dns_name, mountpoint)
    logging.info(message)
    publish_cloudwatch_log(CLOUDWATCHLOG_AGENT, message)

    # only perform readahead optimize after mount succeed
    optimize_readahead_window(mountpoint, options, config)


def call_nfs_mount_command_with_retry_succeed(
    config, options, command, dns_name, mountpoint
):
    def backoff_function(i):
        """Backoff exponentially and add a constant 0-1 second jitter"""
        return (1.5**i) + random.random()

    if not get_boolean_config_item_value(
        config, CONFIG_SECTION, "retry_nfs_mount_command", default_value=True
    ):
        logging.debug(
            "Configuration 'retry_nfs_mount_command' is not enabled, skip retrying mount.nfs command."
        )
        return

    retry_nfs_mount_command_timeout_sec = get_int_value_from_config_file(
        config,
        "retry_nfs_mount_command_timeout_sec",
        DEFAULT_NFS_MOUNT_COMMAND_TIMEOUT_SEC,
    )
    retry_count = get_int_value_from_config_file(
        config,
        "retry_nfs_mount_command_count",
        DEFAULT_NFS_MOUNT_COMMAND_RETRY_COUNT,
    )

    for retry in range(retry_count - 1):
        retry_sleep_time_sec = backoff_function(retry)
        err = "unknown error"
        logging.info(
            'Executing: "%s" with %s sec time limit.'
            % (" ".join(command), retry_nfs_mount_command_timeout_sec)
        )
        proc = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True
        )

        try:
            out, err = proc.communicate(timeout=retry_nfs_mount_command_timeout_sec)
            rc = proc.poll()
            if rc != 0:
                continue_retry = any(
                    error_string in str(err) for error_string in RETRYABLE_ERRORS
                )
                if continue_retry:
                    logging.error(
                        'Mounting %s to %s failed, return code=%s, stdout="%s", stderr="%s", mount attempt %d/%d, '
                        "wait %d sec before next attempt."
                        % (
                            dns_name,
                            mountpoint,
                            rc,
                            out,
                            err,
                            retry + 1,
                            retry_count,
                            retry_sleep_time_sec,
                        )
                    )
                else:
                    message = 'Failed to mount %s at %s: returncode=%d, stderr="%s"' % (
                        dns_name,
                        mountpoint,
                        proc.returncode,
                        err.strip(),
                    )
                    fatal_error(err.strip(), message, proc.returncode)
            else:
                post_mount_nfs_success(config, options, dns_name, mountpoint)
                return True
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except OSError:
                # Silently fail if the subprocess has exited already
                pass
            retry_sleep_time_sec = 0
            err = "timeout after %s sec" % retry_nfs_mount_command_timeout_sec
            logging.error(
                "Mounting %s to %s failed due to %s, mount attempt %d/%d, wait %d sec before next attempt."
                % (
                    dns_name,
                    mountpoint,
                    err,
                    retry + 1,
                    retry_count,
                    retry_sleep_time_sec,
                )
            )
        except Exception as e:
            message = 'Failed to mount %s at %s: returncode=%d, stderr="%s", %s' % (
                dns_name,
                mountpoint,
                proc.returncode,
                err.strip(),
                e,
            )
            fatal_error(err.strip(), message, proc.returncode)

        sys.stderr.write(
            "Mount attempt %d/%d failed due to %s, wait %d sec before next attempt.\n"
            % (retry + 1, retry_count, err, retry_sleep_time_sec)
        )
        time.sleep(retry_sleep_time_sec)

    return False


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


def usage(out, exit_code=1):
    out.write(
        "Usage: mount.efs [--version] [-h|--help] <fsname> <mountpoint> [-o <options>]\n"
    )
    sys.exit(exit_code)


def parse_arguments_early_exit(args=None):
    """Parse arguments, checking for early exit conditions only"""
    if args is None:
        args = sys.argv

    if "-h" in args[1:] or "--help" in args[1:]:
        usage(out=sys.stdout, exit_code=0)

    if "--version" in args[1:]:
        sys.stdout.write("%s Version: %s\n" % (args[0], VERSION))
        sys.exit(0)


def parse_arguments(config, args=None):
    """Parse arguments, return (fsid, path, mountpoint, options)"""
    if args is None:
        args = sys.argv

    fsname = None
    mountpoint = None
    options = {}

    if not check_if_platform_is_mac():
        if len(args) > 1:
            fsname = args[1]
        if len(args) > 2:
            mountpoint = args[2]
        if len(args) > 4 and "-o" in args[:-1]:
            options_index = args.index("-o") + 1
            options = parse_options(args[options_index])
    else:
        if len(args) > 1:
            fsname = args[-2]
        if len(args) > 2:
            mountpoint = args[-1]
        if len(args) > 4 and "-o" in args[:-2]:
            for arg in args[1:-2]:
                if arg != "-o":
                    options.update(parse_options(arg))

    if not fsname or not mountpoint:
        usage(out=sys.stderr)

    # We treat az as an option when customer is using dns name of az mount target to mount,
    # even if they don't provide az with option, we update the options with that info
    fs_id, path, az = match_device(config, fsname, options)

    return fs_id, path, mountpoint, add_field_in_options(options, "az", az)


def get_client_info(config):
    client_info = {}

    # source key/value pair in config file
    if config.has_option(CLIENT_INFO_SECTION, "source"):
        client_source = config.get(CLIENT_INFO_SECTION, "source")
        if 0 < len(client_source) <= CLIENT_SOURCE_STR_LEN_LIMIT:
            client_info["source"] = client_source
    if not client_info.get("source"):
        if check_if_platform_is_mac():
            client_info["source"] = DEFAULT_MACOS_VALUE
        else:
            client_info["source"] = DEFAULT_UNKNOWN_VALUE

    client_info["efs_utils_version"] = VERSION

    return client_info


def create_certificate(
    config,
    mount_name,
    common_name,
    region,
    fs_id,
    security_credentials,
    ap_id,
    client_info,
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

    if security_credentials:
        public_key = os.path.join(tls_paths["mount_dir"], "publicKey.pem")
        create_public_key(private_key, public_key)

    create_ca_conf(
        certificate_config,
        common_name,
        tls_paths["mount_dir"],
        private_key,
        current_time,
        region,
        fs_id,
        security_credentials,
        ap_id,
        client_info,
    )
    create_certificate_signing_request(
        certificate_config, private_key, certificate_signing_request
    )

    not_before = get_certificate_timestamp(current_time, minutes=-NOT_BEFORE_MINS)
    not_after = get_certificate_timestamp(current_time, hours=NOT_AFTER_HOURS)

    cmd = (
        "openssl ca -startdate %s -enddate %s -selfsign -batch -notext -config %s -in %s -out %s"
        % (
            not_before,
            not_after,
            certificate_config,
            certificate_signing_request,
            certificate,
        )
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
                        "Failed to take out private key creation lock, sleeping %s (s)",
                        DEFAULT_TIMEOUT,
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
            # If the openssl genpkey command is interrupted or isn't successful,
            # it will leave behind an empty file.
            if os.path.getsize(key) == 0:
                logging.warning("Purging empty private key file")
                os.remove(key)
            else:
                return

        cmd = (
            "openssl genpkey -algorithm RSA -out %s -pkeyopt rsa_keygen_bits:3072" % key
        )
        subprocess_call(cmd, "Failed to create private key")
        read_only_mode = 0o400
        os.chmod(key, read_only_mode)

    do_with_lock(generate_key)
    return key


def create_certificate_signing_request(config_path, private_key, csr_path):
    cmd = "openssl req -new -config %s -key %s -out %s" % (
        config_path,
        private_key,
        csr_path,
    )
    subprocess_call(cmd, "Failed to create certificate signing request (csr)")


def create_ca_conf(
    config_path,
    common_name,
    directory,
    private_key,
    date,
    region,
    fs_id,
    security_credentials,
    ap_id,
    client_info,
):
    """Populate ca/req configuration file with fresh configurations at every mount since SigV4 signature can change"""
    public_key_path = os.path.join(directory, "publicKey.pem")
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
        if security_credentials
        else ""
    )
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
        efs_client_info_str += "\n%s = UTF8String:%s" % (key, value)
    return efs_client_info_str


def create_public_key(private_key, public_key):
    cmd = "openssl rsa -in %s -outform PEM -pubout -out %s" % (private_key, public_key)
    subprocess_call(cmd, "Failed to create public key")


def subprocess_call(cmd, error_message):
    """Helper method to run shell openssl command and to handle response error messages"""
    retry_times = 3
    for retry in range(retry_times):
        process = subprocess.Popen(
            cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True
        )
        (output, err) = process.communicate()
        rc = process.poll()
        if rc != 0:
            logging.error(
                'Command %s failed, rc=%s, stdout="%s", stderr="%s"'
                % (cmd, rc, output, err),
                exc_info=True,
            )
            try:
                process.kill()
            except OSError:
                # Silently fail if the subprocess has exited already
                pass
        else:
            return output, err
    error_message = "%s, error is: %s" % (error_message, err)
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
        open(index_path, "w").close()
    if not os.path.isfile(index_attr_path):
        with open(index_attr_path, "w+") as f:
            f.write("unique_subject = no")
    if not os.path.isfile(serial_path):
        with open(serial_path, "w+") as f:
            f.write("00")
    if not os.path.isfile(rand_path):
        open(rand_path, "w").close()


def get_certificate_timestamp(current_time, **kwargs):
    updated_time = current_time + timedelta(**kwargs)
    return updated_time.strftime(CERT_DATETIME_FORMAT)


def get_utc_now():
    """
    Wrapped for patching purposes in unit tests
    """
    return datetime.now(timezone.utc)


def assert_root():
    if os.geteuid() != 0:
        sys.stderr.write("only root can run mount.efs\n")
        sys.exit(1)


def read_config(config_file=CONFIG_FILE):
    try:
        p = ConfigParser.SafeConfigParser()
    except AttributeError:
        p = ConfigParser()
    p.read(config_file)
    return p


# Retrieve and parse the logging level from the config file.
def get_log_level_from_config(config):
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

    return (level, raw_level, level_error)


# Convert the log level provided in the config into a log level string
# that is understandable by efs-proxy
def get_efs_proxy_log_level(config):
    level, raw_level, level_error = get_log_level_from_config(config)
    if level_error:
        return "info"

    # Efs-proxy does not have a CRITICAL log level
    if level == logging.CRITICAL:
        return "error"

    return raw_level.lower()


def bootstrap_logging(config, log_dir=LOG_DIR):
    level, raw_level, level_error = get_log_level_from_config(config)

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


def get_dns_name_and_fallback_mount_target_ip_address(config, fs_id, options):
    def _validate_replacement_field_count(format_str, expected_ct):
        if format_str.count("{") != expected_ct or format_str.count("}") != expected_ct:
            raise ValueError(
                "DNS name format has an incorrect number of replacement fields"
            )

    # mounts using crossaccount have a predetermined dns name format
    if options and "crossaccount" in options:
        try:
            az_id = get_az_id_from_instance_metadata(config, options)
<<<<<<< HEAD
            region = get_target_region(config)
            dns_name_suffix = get_target_domain_suffix(config)
            dns_name = "%s.%s.efs.%s.%s" % (az_id, fs_id, region, dns_name_suffix)
=======
            region = get_target_region(config, options)
            dns_name = "%s.%s.efs.%s.amazonaws.com" % (az_id, fs_id, region)
>>>>>>> upstream/master
        except RuntimeError:
            err_msg = "Cannot retrieve AZ-ID from metadata service. This is required for the crossaccount mount option."
            fatal_error(err_msg)
    else:
        dns_name_format = config.get(CONFIG_SECTION, "dns_name_format")

        if "{fs_id}" not in dns_name_format:
            raise ValueError("DNS name format must include {fs_id}")

        format_args = {"fs_id": fs_id}

        expected_replacement_field_ct = 1

        if "{az}" in dns_name_format:
            az = options.get("az")
            if az:
                expected_replacement_field_ct += 1
                format_args["az"] = az
            else:
                dns_name_format = dns_name_format.replace("{az}.", "")

        if "{region}" in dns_name_format:
            expected_replacement_field_ct += 1
            format_args["region"] = get_target_region(config, options)

        if "{dns_name_suffix}" in dns_name_format:
            expected_replacement_field_ct += 1
            config_section = CONFIG_SECTION
            region = format_args.get("region")

            if region:
                config_section = get_config_section(config, region)

            format_args["dns_name_suffix"] = config.get(
                config_section, "dns_name_suffix"
            )

            logging.debug(
                "Using dns_name_suffix %s in config section [%s]",
                format_args.get("dns_name_suffix"),
                config_section,
            )

        _validate_replacement_field_count(
            dns_name_format, expected_replacement_field_ct
        )
        dns_name = dns_name_format.format(**format_args)

    if "mounttargetip" in options:
        if "crossaccount" in options:
            fatal_error(
                "mounttargetip option is incompatible with crossaccount option."
            )
        ip_address = options.get("mounttargetip")
        logging.info(
            "Use the mount target ip address %s provided in the mount options to mount."
            % ip_address
        )
        try:
            mount_target_ip_address_can_be_resolved(
                ip_address,
                passed_via_options=True,
                network_namespace=options.get("netns") if "netns" in options else None,
            )
            return dns_name, options.get("mounttargetip")
        except FallbackException as e:
            fallback_message = e.message
            throw_ip_address_connect_failure_with_fallback_message(
                ip_address=ip_address, fallback_message=fallback_message
            )

    if dns_name_can_be_resolved(dns_name):
        return dns_name, None

    logging.info(
        "Failed to resolve %s, attempting to lookup mount target ip address using botocore.",
        dns_name,
    )

    try:
        fallback_mount_target_ip_address = get_fallback_mount_target_ip_address(
            config, options, fs_id, dns_name
        )
        logging.info(
            "Found fall back mount target ip address %s for file system %s",
            fallback_mount_target_ip_address,
            fs_id,
        )
        return dns_name, fallback_mount_target_ip_address
    except FallbackException as e:
        fallback_message = e.message

    throw_dns_resolve_failure_with_fallback_message(dns_name, fallback_message)


def get_fallback_mount_target_ip_address(config, options, fs_id, dns_name):
    if options and "crossaccount" in options:
        fallback_message = "Fallback to mount target ip address feature is not available when the crossaccount option is used."
        raise FallbackException(fallback_message)

    fall_back_to_ip_address_enabled = (
        check_if_fall_back_to_mount_target_ip_address_is_enabled(config)
    )

    if not fall_back_to_ip_address_enabled:
        fallback_message = (
            "Fallback to mount target ip address feature is not enabled in config file %s."
            % CONFIG_FILE
        )
        raise FallbackException(fallback_message)

    if not BOTOCORE_PRESENT:
        fallback_message = "Failed to import necessary dependency botocore, please install botocore first."
        raise FallbackException(fallback_message)

    mount_target_ip_address = None
    try:
        mount_target_ip_address = get_fallback_mount_target_ip_address_helper(
            config, options, fs_id
        )
        mount_target_ip_address_can_be_resolved(
            mount_target_ip_address,
            network_namespace=options.get("netns") if "netns" in options else None,
        )
        return mount_target_ip_address
    except FallbackException as e:
        throw_ip_address_connect_failure_with_fallback_message(
            dns_name, mount_target_ip_address, e.message
        )


def check_if_fall_back_to_mount_target_ip_address_is_enabled(config):
    return get_boolean_config_item_value(
        config,
        CONFIG_SECTION,
        FALLBACK_TO_MOUNT_TARGET_IP_ADDRESS_ITEM,
        default_value=DEFAULT_FALLBACK_ENABLED,
    )


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


def dns_name_can_be_resolved(dns_name):
    try:
        socket.gethostbyname(dns_name)
        return True
    except socket.gaierror:
        return False


def mount_target_ip_address_can_be_resolved(
    mount_target_ip_address, passed_via_options=False, network_namespace=None
):
    tries = 3
    for attempt in range(tries):
        try:
            # Open a socket connection to mount target nfs port to verify that the mount target can be connected
            if not network_namespace:
                s = socket.create_connection((mount_target_ip_address, 2049), timeout=2)
            else:
                with NetNS(nspath=network_namespace):
                    s = socket.create_connection(
                        (mount_target_ip_address, 2049), timeout=2
                    )
            s.close()
            return True
        except socket.timeout:
            if attempt < tries - 1:
                message = (
                    "The ip address %s cannot be connected yet, sleep 0.5s, %s retry time(s) left"
                    % (mount_target_ip_address, tries - attempt - 1)
                )
                logging.warning(message)
                time.sleep(0.5)
                continue
            else:
                raise FallbackException(
                    "Connection to the mount target IP address %s timeout. Please retry in 5 minutes if the "
                    "mount target is newly created. Otherwise check your VPC and security group "
                    "configuration to ensure your file system is reachable via TCP port 2049 from your "
                    "instance." % mount_target_ip_address
                )
        except Exception as e:
            hint_message = (
                " Please check if the mount target ip address passed via mount option is correct."
                if passed_via_options
                else ""
            )
            raise FallbackException(
                "Unknown error when connecting to mount target IP address %s, %s.%s"
                % (mount_target_ip_address, e, hint_message)
            )


def get_fallback_mount_target_ip_address_helper(config, options, fs_id):
    az_name = get_target_az(config, options)

    ec2_client = get_botocore_client(config, "ec2", options)
    efs_client = get_botocore_client(config, "efs", options)

    mount_target = get_mount_target_in_az(efs_client, ec2_client, fs_id, az_name)
    mount_target_ip = mount_target.get("IpAddress")
    logging.debug("Found mount target ip address %s in AZ %s", mount_target_ip, az_name)

    return mount_target_ip


def throw_dns_resolve_failure_with_fallback_message(dns_name, fallback_message=None):
    fallback_message = (
        "\nAttempting to lookup mount target ip address using botocore. %s"
        % fallback_message
        if fallback_message
        else ""
    )
    message = (
        'Failed to resolve "%s" - check that your file system ID is correct, and ensure that the VPC has an EFS mount '
        "target for this file system ID.\nSee %s for more detail.%s"
    ) % (
        dns_name,
        "https://docs.aws.amazon.com/console/efs/mount-dns-name",
        fallback_message,
    )
    fatal_error(message)


def throw_ip_address_connect_failure_with_fallback_message(
    dns_name=None, ip_address=None, fallback_message=None
):
    dns_message = 'Failed to resolve "%s". ' % dns_name if dns_name else ""
    if not ip_address:
        ip_address_message = (
            "The file system mount target ip address cannot be found, please pass mount target ip "
            "address via mount options. "
        )
    else:
        ip_address_message = (
            "Cannot connect to file system mount target ip address %s. " % ip_address
        )
    fallback_message = "\n%s" % fallback_message if fallback_message else ""
    fatal_error("%s%s%s" % (dns_message, ip_address_message, fallback_message))


def tls_paths_dictionary(mount_name, base_path=STATE_FILE_DIR):
    tls_dict = {
        "mount_dir": os.path.join(base_path, mount_name),
        # every mount will have its own ca mode assets due to lack of multi-threading support in openssl
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
        err_msg = "Public key file, %s, is incorrectly formatted" % public_key
        fatal_error(err_msg, err_msg)

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


def get_credential_scope(date, region):
    return "/".join([date.strftime(DATE_ONLY_FORMAT), region, SERVICE, AWS4_REQUEST])


def match_device(config, device, options):
    """Return the EFS id, the remote path, and the az to mount"""

    try:
        remote, path = device.split(":", 1)
    except ValueError:
        remote = device
        path = "/"

    if FS_ID_RE.match(remote):
        return remote, path, None

    try:
        primary, secondaries, _ = socket.gethostbyname_ex(remote)
        hostnames = list(filter(lambda e: e is not None, [primary] + secondaries))
    except socket.gaierror:
        create_default_cloudwatchlog_agent_if_not_exist(config, options)
        fatal_error(
            'Failed to resolve "%s" - check that the specified DNS name is a CNAME record resolving to a valid EFS DNS '
            "name" % remote,
            'Failed to resolve "%s"' % remote,
        )

    if not hostnames:
        create_default_cloudwatchlog_agent_if_not_exist(config, options)
        fatal_error(
            'The specified domain name "%s" did not resolve to an EFS mount target'
            % remote
        )

    for hostname in hostnames:
        efs_fqdn_match = EFS_FQDN_RE.match(hostname)

        if efs_fqdn_match:
            az = efs_fqdn_match.group("az")
            fs_id = efs_fqdn_match.group("fs_id")

            if az and "az" in options and az != options["az"]:
                fatal_error(
                    'The hostname "%s" resolved by the specified domain name "%s" does not match the az provided in the '
                    "mount options, expected = %s, given = %s"
                    % (hostname, remote, options["az"], az)
                )

            expected_dns_name, _ = get_dns_name_and_fallback_mount_target_ip_address(
                config, fs_id, add_field_in_options(options, "az", az)
            )

            # check that the DNS name of the mount target matches exactly the DNS name the CNAME resolves to
            if hostname == expected_dns_name:
                return fs_id, path, az
    else:
        create_default_cloudwatchlog_agent_if_not_exist(config, options)
        fatal_error(
            'The specified CNAME "%s" did not resolve to a valid DNS name for an EFS mount target. '
            "Please refer to the EFS documentation for mounting with DNS names for examples: %s"
            % (
                remote,
                "https://docs.aws.amazon.com/efs/latest/ug/mounting-fs-mount-cmd-dns-name.html",
            )
        )


def add_field_in_options(options, field_key, field_value):
    if field_value and field_key not in options:
        options[field_key] = field_value
    return options


def is_nfs_mount(mountpoint):
    if not check_if_platform_is_mac():
        cmd = ["stat", "-f", "-L", "-c", "%T", mountpoint]
        p = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True
        )
        output, _ = p.communicate()
        return output and "nfs" in str(output)
    else:
        process = subprocess.run(
            ["mount", "-t", "nfs"],
            check=True,
            stdout=subprocess.PIPE,
            universal_newlines=True,
        )
        stdout = process.stdout
        if not stdout:
            return False
        mounts = stdout.split("\n")
        for mount in mounts:
            _mount = mount.split()
            if len(_mount) >= 4 and _mount[2] == mountpoint and "nfs" in _mount[3]:
                return True
        return False


def mount_with_proxy(
    config,
    init_system,
    dns_name,
    path,
    fs_id,
    mountpoint,
    options,
    fallback_ip_address=None,
):
    """
    This function is responsible for launching a efs-proxy process and attaching a NFS mount to that process
    over the loopback interface. Efs-proxy is responsible for forwarding NFS operations to EFS.
    When the legacy 'stunnel' mount option is used, this function will launch a stunnel process instead of efs-proxy.
    """
    if os.path.ismount(mountpoint) and is_nfs_mount(mountpoint):
        sys.stdout.write(
            "%s is already mounted, please run 'mount' command to verify\n" % mountpoint
        )
        logging.warning("%s is already mounted, mount aborted" % mountpoint)
        return

    efs_proxy_enabled = not legacy_stunnel_mode_enabled(options, config)
    logging.debug("mount_with_proxy: efs_proxy_enabled = %s", efs_proxy_enabled)

    with bootstrap_proxy(
        config,
        init_system,
        dns_name,
        fs_id,
        mountpoint,
        options,
        fallback_ip_address=fallback_ip_address,
        efs_proxy_enabled=efs_proxy_enabled,
    ) as tunnel_proc:
        mount_completed = threading.Event()
        t = threading.Thread(
            target=poll_tunnel_process, args=(tunnel_proc, fs_id, mount_completed)
        )
        t.daemon = True
        t.start()
        mount_nfs(config, dns_name, path, mountpoint, options)
        mount_completed.set()
        t.join()


def verify_tlsport_can_be_connected(tlsport):
    try:
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    except Exception as e:
        logging.warning("Error opening a socket, %s", e)
        return False
    try:
        logging.debug("Trying to connect to 127.0.0.1: %s", tlsport)
        test_socket.connect(("127.0.0.1", tlsport))
        return True
    except ConnectionRefusedError:
        return False
    finally:
        test_socket.close()


def check_unsupported_options(options):
    for unsupported_option in UNSUPPORTED_OPTIONS:
        if unsupported_option in options:
            warn_message = (
                'The "%s" option is not supported and has been ignored, as amazon-efs-utils relies on a built-in '
                "trust store." % unsupported_option
            )
            sys.stderr.write("WARN: %s\n" % warn_message)
            logging.warning(warn_message)
            del options[unsupported_option]


def check_options_validity(options):
    if "tls" in options:
        if "port" in options:
            fatal_error('The "port" and "tls" options are mutually exclusive')

        if "tlsport" in options:
            try:
                int(options["tlsport"])
            except ValueError:
                fatal_error(
                    "tlsport option [%s] is not an integer" % options["tlsport"]
                )

        if "ocsp" in options and "noocsp" in options:
            fatal_error('The "ocsp" and "noocsp" options are mutually exclusive')

        if "notls" in options:
            fatal_error('The "tls" and "notls" options are mutually exclusive')

    if "accesspoint" in options:
        if "tls" not in options:
            fatal_error('The "tls" option is required when mounting via "accesspoint"')
        if not AP_ID_RE.match(options["accesspoint"]):
            fatal_error("Access Point ID %s is malformed" % options["accesspoint"])

    if "iam" in options and "tls" not in options:
        fatal_error('The "tls" option is required when mounting via "iam"')

    if "awsprofile" in options and "iam" not in options:
        fatal_error(
            'The "iam" option is required when mounting with named profile option, "awsprofile"'
        )

    if "awscredsuri" in options:
        if "iam" not in options:
            fatal_error('The "iam" option is required when mounting with "awscredsuri"')
        if "awsprofile" in options:
            fatal_error(
                'The "awscredsuri" and "awsprofile" options are mutually exclusive'
            )
        # The URI must start with slash symbol as it will be appended to the ECS task metadata endpoint
        if not options["awscredsuri"].startswith("/"):
            fatal_error("awscredsuri %s is malformed" % options["awscredsuri"])


def bootstrap_cloudwatch_logging(config, options, fs_id=None):
    if not check_if_cloudwatch_log_enabled(config):
        return None

    cloudwatchlog_client = get_botocore_client(config, "logs", options)

    if not cloudwatchlog_client:
        return None

    cloudwatchlog_config = get_cloudwatchlog_config(config, fs_id)

    log_group_name = cloudwatchlog_config.get("log_group_name")
    log_stream_name = cloudwatchlog_config.get("log_stream_name")
    retention_days = cloudwatchlog_config.get("retention_days")

    group_creation_completed = create_cloudwatch_log_group(
        cloudwatchlog_client, log_group_name
    )

    if not group_creation_completed:
        return None

    put_retention_policy_completed = put_cloudwatch_log_retention_policy(
        cloudwatchlog_client, log_group_name, retention_days
    )

    if not put_retention_policy_completed:
        return None

    stream_creation_completed = create_cloudwatch_log_stream(
        cloudwatchlog_client, log_group_name, log_stream_name
    )

    if not stream_creation_completed:
        return None

    return {
        "client": cloudwatchlog_client,
        "log_group_name": log_group_name,
        "log_stream_name": log_stream_name,
    }


def create_default_cloudwatchlog_agent_if_not_exist(config, options):
    if not check_if_cloudwatch_log_enabled(config):
        return None
    global CLOUDWATCHLOG_AGENT
    if not CLOUDWATCHLOG_AGENT:
        CLOUDWATCHLOG_AGENT = bootstrap_cloudwatch_logging(config, options)


def get_fips_config(config):
    """
    Check whether FIPS is enabled either by setting the `AWS_USE_FIPS_ENDPOINT`
    environmental variable, or through the efs-utils config file.

    Enabling FIPS means that both the Botocore client and stunnel will be configured
    to use FIPS.
    """

    return os.getenv(
        AWS_FIPS_ENDPOINT_CONFIG_ENV, "False"
    ).lower() == "true" or get_boolean_config_item_value(
        config, CONFIG_SECTION, "fips_mode_enabled", default_value=False
    )


def get_botocore_client(config, service, options):
    if not BOTOCORE_PRESENT:
        logging.error("Failed to import botocore, please install botocore first.")
        return None

    botocore_config = None
    if get_fips_config(config):
        botocore_config = botocore.config.Config(use_fips_endpoint=True)

    session = botocore.session.get_session()
    region = get_target_region(config, options)

    if options and options.get("awsprofile"):
        profile = options.get("awsprofile")
        session.set_config_variable("profile", profile)
        try:
            return session.create_client(
                service, region_name=region, config=botocore_config
            )
        except ProfileNotFound as e:
            fatal_error(
                "%s, please add the [profile %s] section in the aws config file following %s and %s."
                % (e, profile, NAMED_PROFILE_HELP_URL, CONFIG_FILE_SETTINGS_HELP_URL)
            )

    return session.create_client(service, region_name=region, config=botocore_config)


def get_cloudwatchlog_config(config, fs_id=None):
    log_group_name = DEFAULT_CLOUDWATCH_LOG_GROUP
    if config.has_option(CLOUDWATCH_LOG_SECTION, "log_group_name"):
        log_group_name = config.get(CLOUDWATCH_LOG_SECTION, "log_group_name")

        if "{fs_id}" in log_group_name:
            if fs_id:
                # Formatting the log_group_name with the fs_id.
                log_group_name = log_group_name.format(fs_id=fs_id)
            else:
                # If fs_id is None so putting the logs into the log-group by removing '/{fs_id}' in log_group_name.
                log_group_name = log_group_name.replace("/{fs_id}", "")
                logging.warning(
                    "Failed to load the File System ID, pushing logs to log group %s.",
                    log_group_name,
                )

    logging.debug("Pushing logs to log group named %s in Cloudwatch.", log_group_name)
    retention_days = DEFAULT_RETENTION_DAYS
    if config.has_option(CLOUDWATCH_LOG_SECTION, "retention_in_days"):
        retention_days = config.get(CLOUDWATCH_LOG_SECTION, "retention_in_days")

    log_stream_name = get_cloudwatch_log_stream_name(config, fs_id)

    return {
        "log_group_name": log_group_name,
        "retention_days": int(retention_days),
        "log_stream_name": log_stream_name,
    }


def get_cloudwatch_log_stream_name(config, fs_id=None):
    instance_id = get_instance_identity_info_from_instance_metadata(
        config, "instanceId"
    )
    if instance_id and fs_id:
        log_stream_name = "%s - %s - mount.log" % (fs_id, instance_id)
    elif instance_id:
        log_stream_name = "%s - mount.log" % (instance_id)
    elif fs_id:
        log_stream_name = "%s - mount.log" % (fs_id)
    else:
        log_stream_name = "default - mount.log"

    return log_stream_name


def check_if_platform_is_mac():
    return sys.platform in MAC_OS_PLATFORM_LIST


def check_if_mac_version_is_supported():
    return any(
        release in platform.release() for release in MAC_OS_SUPPORTED_VERSION_LIST
    )


def check_if_cloudwatch_log_enabled(config):
    # We don't emit warning message here as there will always no `enabled` config item even for a new config file. By default we
    # comment out the `enabled = true` in config file so that the cloudwatch log feature is disabled. This is not set as
    # `enabled = false` because we enable this feature by uncommenting this item for user who use System Manager Distributor
    # to install efs-utils. This gives user an opportunity to still disable the feature by setting `enabled = false`.
    return get_boolean_config_item_value(
        config,
        CLOUDWATCH_LOG_SECTION,
        "enabled",
        default_value=False,
        emit_warning_message=False,
    )


def cloudwatch_create_log_group_helper(cloudwatchlog_client, log_group_name):
    cloudwatchlog_client.create_log_group(logGroupName=log_group_name)
    logging.info("Created cloudwatch log group %s" % log_group_name)


def create_cloudwatch_log_group(cloudwatchlog_client, log_group_name):
    try:
        cloudwatch_create_log_group_helper(cloudwatchlog_client, log_group_name)
    except ClientError as e:
        exception = e.response["Error"]["Code"]

        if exception == "ResourceAlreadyExistsException":
            logging.debug(
                "Log group %s already exist, %s" % (log_group_name, e.response)
            )
            return True
        elif exception == "LimitExceededException":
            logging.error(
                "Reached the maximum number of log groups that can be created, %s"
                % e.response
            )
            return False
        elif exception == "OperationAbortedException":
            logging.debug(
                "Multiple requests to update the same log group %s were in conflict, %s"
                % (log_group_name, e.response)
            )
            return False
        elif exception == "InvalidParameterException":
            logging.error(
                "Log group name %s is specified incorrectly, %s"
                % (log_group_name, e.response)
            )
            return False
        else:
            handle_general_botocore_exceptions(e)
            return False
    except NoCredentialsError as e:
        logging.warning("Credentials are not properly configured, %s" % e)
        return False
    except EndpointConnectionError as e:
        logging.warning("Could not connect to the endpoint, %s" % e)
        return False
    except Exception as e:
        logging.warning("Unknown error, %s." % e)
        return False
    return True


def cloudwatch_put_retention_policy_helper(
    cloudwatchlog_client, log_group_name, retention_days
):
    cloudwatchlog_client.put_retention_policy(
        logGroupName=log_group_name, retentionInDays=retention_days
    )
    logging.debug("Set cloudwatch log group retention days to %s" % retention_days)


def put_cloudwatch_log_retention_policy(
    cloudwatchlog_client, log_group_name, retention_days
):
    try:
        cloudwatch_put_retention_policy_helper(
            cloudwatchlog_client, log_group_name, retention_days
        )
    except ClientError as e:
        exception = e.response["Error"]["Code"]

        if exception == "ResourceNotFoundException":
            logging.error(
                "Log group %s does not exist, %s" % (log_group_name, e.response)
            )
            return False
        elif exception == "OperationAbortedException":
            logging.debug(
                "Multiple requests to update the same log group %s were in conflict, %s"
                % (log_group_name, e.response)
            )
            return False
        elif exception == "InvalidParameterException":
            logging.error(
                "Either parameter log group name %s or retention in days %s is specified incorrectly, %s"
                % (log_group_name, retention_days, e.response)
            )
            return False
        else:
            handle_general_botocore_exceptions(e)
            return False
    except NoCredentialsError as e:
        logging.warning("Credentials are not properly configured, %s" % e)
        return False
    except EndpointConnectionError as e:
        logging.warning("Could not connect to the endpoint, %s" % e)
        return False
    except Exception as e:
        logging.warning("Unknown error, %s." % e)
        return False
    return True


def cloudwatch_create_log_stream_helper(
    cloudwatchlog_client, log_group_name, log_stream_name
):
    cloudwatchlog_client.create_log_stream(
        logGroupName=log_group_name, logStreamName=log_stream_name
    )
    logging.info(
        "Created cloudwatch log stream %s in log group %s"
        % (log_stream_name, log_group_name)
    )


def create_cloudwatch_log_stream(cloudwatchlog_client, log_group_name, log_stream_name):
    try:
        cloudwatch_create_log_stream_helper(
            cloudwatchlog_client, log_group_name, log_stream_name
        )
    except ClientError as e:
        exception = e.response["Error"]["Code"]

        if exception == "ResourceAlreadyExistsException":
            logging.debug(
                "Log stream %s already exist in log group %s, %s"
                % (log_stream_name, log_group_name, e.response)
            )
            return True
        elif exception == "InvalidParameterException":
            logging.error(
                "Either parameter log group name %s or log stream name %s is specified incorrectly, %s"
                % (log_group_name, log_stream_name, e.response)
            )
            return False
        elif exception == "ResourceNotFoundException":
            logging.error(
                "Log group %s does not exist, %s" % (log_group_name, e.response)
            )
            return False
        else:
            handle_general_botocore_exceptions(e)
            return False
    except NoCredentialsError as e:
        logging.warning("Credentials are not properly configured, %s" % e)
        return False
    except EndpointConnectionError as e:
        logging.warning("Could not connect to the endpoint, %s" % e)
        return False
    except Exception as e:
        logging.warning("Unknown error, %s." % e)
        return False
    return True


def cloudwatch_put_log_events_helper(cloudwatchlog_agent, message, token=None):
    kwargs = {
        "logGroupName": cloudwatchlog_agent.get("log_group_name"),
        "logStreamName": cloudwatchlog_agent.get("log_stream_name"),
        "logEvents": [
            {"timestamp": int(round(time.time() * 1000)), "message": message}
        ],
    }
    if token:
        kwargs["sequenceToken"] = token
    cloudwatchlog_agent.get("client").put_log_events(**kwargs)


def publish_cloudwatch_log(cloudwatchlog_agent, message):
    if not cloudwatchlog_agent or not cloudwatchlog_agent.get("client"):
        return False

    token = get_log_stream_next_token(cloudwatchlog_agent)

    try:
        cloudwatch_put_log_events_helper(cloudwatchlog_agent, message, token)
    except ClientError as e:
        exception = e.response["Error"]["Code"]

        if exception == "InvalidSequenceTokenException":
            logging.debug("The sequence token is not valid, %s" % e.response)
            return False
        elif exception == "InvalidParameterException":
            logging.debug(
                "One of the parameter to put log events is not valid, %s" % e.response
            )
            return False
        elif exception == "DataAlreadyAcceptedException":
            logging.debug("The event %s was already logged, %s" % (message, e.response))
            return False
        elif exception == "UnrecognizedClientException":
            logging.debug(
                "The most likely cause is an invalid AWS access key ID or secret Key, %s"
                % e.response
            )
            return False
        elif exception == "ResourceNotFoundException":
            logging.error(
                "Either log group %s or log stream %s does not exist, %s"
                % (
                    cloudwatchlog_agent.get("log_group_name"),
                    cloudwatchlog_agent.get("log_stream_name"),
                    e.response,
                )
            )
            return False
        else:
            logging.debug("Unexpected error: %s" % e)
            return False
    except NoCredentialsError as e:
        logging.warning("Credentials are not properly configured, %s" % e)
        return False
    except EndpointConnectionError as e:
        logging.warning("Could not connect to the endpoint, %s" % e)
        return False
    except Exception as e:
        logging.warning("Unknown error, %s." % e)
        return False
    return True


def cloudwatch_describe_log_streams_helper(cloudwatchlog_agent):
    return cloudwatchlog_agent.get("client").describe_log_streams(
        logGroupName=cloudwatchlog_agent.get("log_group_name"),
        logStreamNamePrefix=cloudwatchlog_agent.get("log_stream_name"),
    )


def get_log_stream_next_token(cloudwatchlog_agent):
    try:
        response = cloudwatch_describe_log_streams_helper(cloudwatchlog_agent)
    except ClientError as e:
        exception = e.response["Error"]["Code"]

        if exception == "InvalidParameterException":
            logging.debug(
                "Either parameter log group name %s or log stream name %s is specified incorrectly, %s"
                % (
                    cloudwatchlog_agent.get("log_group_name"),
                    cloudwatchlog_agent.get("log_stream_name"),
                    e.response,
                )
            )
        elif exception == "ResourceNotFoundException":
            logging.debug(
                "Either log group %s or log stream %s does not exist, %s"
                % (
                    cloudwatchlog_agent.get("log_group_name"),
                    cloudwatchlog_agent.get("log_stream_name"),
                    e.response,
                )
            )
        else:
            handle_general_botocore_exceptions(e)
        return None
    except NoCredentialsError as e:
        logging.warning("Credentials are not properly configured, %s" % e)
        return None
    except EndpointConnectionError as e:
        logging.warning("Could not connect to the endpoint, %s" % e)
        return None
    except Exception as e:
        logging.warning("Unknown error, %s" % e)
        return None

    try:
        log_stream = response["logStreams"][0]
        return log_stream.get("uploadSequenceToken")
    except (IndexError, TypeError, KeyError):
        pass

    return None


def ec2_describe_availability_zones_helper(ec2_client, kwargs):
    # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_availability_zones
    return ec2_client.describe_availability_zones(**kwargs)


def get_az_id_by_az_name_helper(ec2_client, az_name, dryrun=False):
    operation = "DescribeAvailabilityZones"
    kwargs = {"ZoneNames": [az_name]}
    if dryrun:
        kwargs["DryRun"] = True

    try:
        az_info = ec2_describe_availability_zones_helper(ec2_client, kwargs)
        logging.debug("Found the az information for %s: %s", az_name, az_info)
        return az_info
    except ClientError as e:
        exception = e.response["Error"]["Code"]
        exception_message = e.response["Error"]["Message"]

        if exception == "DryRunOperation":
            logging.debug("Describe availability zones dryrun succeed.")
            return
        elif exception == "UnauthorizedOperation":
            fallback_message = "Unauthorized to perform operation %s." % operation
        elif exception == "InvalidParameterValue":
            fallback_message = "Invalid availability zone %s" % az_name
        elif exception == "ServiceUnavailableException":
            fallback_message = (
                "The ec2 service cannot complete the request, %s" % exception_message
            )
        elif exception == "AccessDeniedException":
            fallback_message = exception_message
        else:
            fallback_message = "Unexpected error: %s" % exception_message
    except NoCredentialsError as e:
        fallback_message = (
            "%s when performing operation %s, please confirm your aws credentials are properly configured."
            % (e, operation)
        )
    except EndpointConnectionError as e:
        fallback_message = (
            "Could not connect to the endpoint when performing operation %s, %s"
            % (operation, e)
        )
    except Exception as e:
        fallback_message = "Unknown error when performing operation %s, %s." % (
            operation,
            e,
        )
    raise FallbackException(fallback_message)


def get_az_id_by_az_name(ec2_client, az_name):
    # Perform a dryrun api call first
    get_az_id_by_az_name_helper(ec2_client, az_name, dryrun=True)
    az_info = get_az_id_by_az_name_helper(ec2_client, az_name, dryrun=False)
    if az_info and az_info.get("AvailabilityZones"):
        az_id = az_info["AvailabilityZones"][0]["ZoneId"]
        logging.debug("Found AZ mapping [AZ name: %s, AZ ID: %s]", az_name, az_id)
        return az_id
    return None


def efs_describe_mount_targets_helper(efs_client, kwargs):
    # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/efs.html#EFS.Client.describe_mount_targets
    return efs_client.describe_mount_targets(**kwargs)


def get_mount_targets_info(efs_client, fs_id):
    operation = "DescribeMountTargets"
    kwargs = {"FileSystemId": fs_id}

    try:
        mount_targets_info = efs_describe_mount_targets_helper(efs_client, kwargs)
        logging.debug(
            "Found these mount targets for file system %s: %s",
            fs_id,
            mount_targets_info,
        )
        return mount_targets_info.get("MountTargets")
    except ClientError as e:
        exception = e.response["Error"]["Code"]
        exception_message = e.response["Error"]["Message"]

        if exception == "FileSystemNotFound":
            fallback_message = "The file system %s is not found" % fs_id
        elif exception == "ServiceUnavailableException":
            fallback_message = (
                "The elasticfilesystem service cannot complete the request, %s"
                % exception_message
            )
        elif exception == "AccessDeniedException":
            fallback_message = exception_message
        else:
            fallback_message = "Unexpected error: %s" % exception_message
    except NoCredentialsError as e:
        fallback_message = (
            "%s when performing operation %s, please confirm your aws credentials are properly configured."
            % (e, operation)
        )
    except EndpointConnectionError as e:
        fallback_message = (
            "Could not connect to the endpoint when performing operation %s, %s"
            % (operation, e)
        )
    except Exception as e:
        fallback_message = "Unknown error when performing operation %s, %s." % (
            operation,
            e,
        )

    raise FallbackException(fallback_message)


def get_mount_target_in_az(efs_client, ec2_client, fs_id, az_name=None):
    if not efs_client or not ec2_client:
        raise FallbackException("Boto client cannot be null")

    mount_targets = get_mount_targets_info(efs_client, fs_id)
    if not mount_targets:
        message = (
            "Cannot find mount target for the file system %s, please create a mount target in %s."
            % (fs_id, az_name if az_name else "any availability zone.")
        )
        raise FallbackException(message)

    available_mount_targets = [
        mount_target
        for mount_target in mount_targets
        if mount_target.get("LifeCycleState") == "available"
    ]
    if not available_mount_targets:
        message = (
            "No mount target created for the file system %s is in available state yet, please retry in 5 minutes."
            % fs_id
        )
        raise FallbackException(message)

    if az_name:
        az_id = get_az_id_by_az_name(ec2_client, az_name)
    else:
        # If the az_name is None, which means the IMDS instance identity retrieve failed,
        # in that case randomly pick one available mount target
        logging.info(
            "No az info passed via options, randomly pick one available mount target."
        )
        return random.choice(available_mount_targets)

    az_names_of_available_mount_targets = [
        mount_target.get("AvailabilityZoneName")
        for mount_target in available_mount_targets
    ]
    available_mount_targets_message = (
        "Available mount target(s) are in az %s" % az_names_of_available_mount_targets
    )

    if not az_id:
        message = (
            "No matching az id for the az %s. Please check the az option passed. %s"
            % (az_name, available_mount_targets_message)
        )
        raise FallbackException(message)

    for mount_target in mount_targets:
        if mount_target["AvailabilityZoneId"] == az_id:
            mount_target_state = mount_target.get("LifeCycleState")
            if mount_target_state != "available":
                message = "Unknown mount target state"
                if mount_target_state in ["creating", "updating", "error"]:
                    message = (
                        "Mount target in the az %s is %s, please retry in 5 minutes, or use the "
                        "mount target in the other az by passing the availability zone name option. %s"
                        % (az_name, mount_target_state, available_mount_targets_message)
                    )
                elif mount_target_state in ["deleted", "deleting"]:
                    message = (
                        "Mount target in the availability zone %s is %s, "
                        'please create a new one in %s, or use the " "mount target '
                        "in the other az by passing the availability zone name option. %s"
                    ) % (
                        az_name,
                        mount_target_state,
                        az_name,
                        available_mount_targets_message,
                    )
                raise FallbackException(message)
            return mount_target

    message = (
        "No matching mount target in the az %s. Please create one mount target in %s, or try the mount target in another "
        "AZ by passing the availability zone name option. %s"
        % (az_name, az_name, available_mount_targets_message)
    )
    raise FallbackException(message)


def handle_general_botocore_exceptions(error):
    exception = error.response["Error"]["Code"]

    if exception == "ServiceUnavailableException":
        logging.debug("The service cannot complete the request, %s" % error.response)
    elif exception == "AccessDeniedException":
        logging.debug(
            "User is not authorized to perform the action, %s" % error.response
        )
    else:
        logging.debug("Unexpected error: %s" % error)


# A change in the Linux kernel 5.4+ results a throughput regression on NFS client.
# With patch (https://bugzilla.kernel.org/show_bug.cgi?id=204939), starting from 5.4.*,
# Linux NFS client is using a fixed default value of 128K as read_ahead_kb.
# Before this patch, the read_ahead_kb equation is (NFS_MAX_READAHEAD) 15 * (client configured read size).
# Thus, with EFS recommendation of rsize (1MB) in mount option,
# NFS client might see a throughput drop in kernel 5.4+, especially for sequential read.
# To fix the issue, below function will modify read_ahead_kb to 15 * rsize (1MB by default) after mount.
def optimize_readahead_window(mountpoint, options, config):
    if not should_revise_readahead(config):
        return

    fixed_readahead_kb = int(
        DEFAULT_NFS_MAX_READAHEAD_MULTIPLIER * int(options["rsize"]) / 1024
    )

    try:
        major, minor = decode_device_number(os.stat(mountpoint).st_dev)
        # modify read_ahead_kb in /sys/class/bdi/<bdi>/read_ahead_kb
        # The bdi identifier is in the form of MAJOR:MINOR, which can be derived from device number
        #
        read_ahead_kb_config_file = NFS_READAHEAD_CONFIG_PATH_FORMAT % (major, minor)

        logging.debug(
            "Modifying value in %s to %s.",
            read_ahead_kb_config_file,
            str(fixed_readahead_kb),
        )
        p = subprocess.Popen(
            "echo %s > %s" % (fixed_readahead_kb, read_ahead_kb_config_file),
            shell=True,
            stderr=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
        )
        _, error = p.communicate()
        if p.returncode != 0:
            logging.warning(
                'Failed to modify read_ahead_kb: %s with returncode: %d, error: "%s".'
                % (fixed_readahead_kb, p.returncode, error.strip())
            )
    except Exception as e:
        logging.warning(
            'Failed to modify read_ahead_kb: %s with error: "%s".'
            % (fixed_readahead_kb, e)
        )


# https://github.com/torvalds/linux/blob/master/include/linux/kdev_t.h#L48-L49
def decode_device_number(device_number):
    major = (device_number & 0xFFF00) >> 8
    minor = (device_number & 0xFF) | ((device_number >> 12) & 0xFFF00)
    return major, minor


# Only modify read_ahead_kb iff
# 1. instance platform is linux
# 2. kernel version of instance is 5.4+
# 3. 'optimize_readahead' is set to true in efs-utils config file
def should_revise_readahead(config):
    if platform.system() != "Linux":
        return False

    if (
        get_linux_kernel_version(len(NFS_READAHEAD_OPTIMIZE_LINUX_KERNEL_MIN_VERSION))
        < NFS_READAHEAD_OPTIMIZE_LINUX_KERNEL_MIN_VERSION
    ):
        return False

    return get_boolean_config_item_value(
        config, CONFIG_SECTION, OPTIMIZE_READAHEAD_ITEM, default_value=False
    )


# Parse Linux kernel version from platform.release()
# Failback to 0.0.0... as invalid version
# Examples:
#             platform.release()                Parsed version with desired_length:2
# RHEL        3.10.0-1160.el7.x86_64            [3, 10]
# AL2         5.4.105-48.177.amzn2.x86_64       [5, 4]
# Ubuntu      5.4.0-1038-aws                    [5, 4]
# OpenSUSE    5.3.18-24.37-default              [5, 3]
def get_linux_kernel_version(desired_length):
    version = []
    try:
        version = [
            int(v)
            for v in platform.release().split("-", 1)[0].split(".")[:desired_length]
        ]
    except ValueError:
        logging.warning("Failed to retrieve linux kernel version")
    # filling 0 at the end
    for i in range(len(version), desired_length):
        version.append(0)
    return version


def main():
    parse_arguments_early_exit()

    assert_root()

    config = read_config()
    bootstrap_logging(config)

    if check_if_platform_is_mac() and not check_if_mac_version_is_supported():
        fatal_error(
            "We do not support EFS on MacOS Kernel version " + platform.release()
        )

    fs_id, path, mountpoint, options = parse_arguments(config)

    logging.info("version=%s options=%s", VERSION, options)

    global CLOUDWATCHLOG_AGENT
    CLOUDWATCHLOG_AGENT = bootstrap_cloudwatch_logging(config, options, fs_id)

    check_unsupported_options(options)
    check_options_validity(options)

    init_system = get_init_system()
    check_network_status(fs_id, init_system)

    dns_name, fallback_ip_address = get_dns_name_and_fallback_mount_target_ip_address(
        config, fs_id, options
    )

    if check_if_platform_is_mac() and "notls" not in options:
        options["tls"] = None

    if "tls" not in options and legacy_stunnel_mode_enabled(options, config):
        mount_nfs(
            config,
            dns_name,
            path,
            mountpoint,
            options,
            fallback_ip_address=fallback_ip_address,
        )
    else:
        mount_with_proxy(
            config,
            init_system,
            dns_name,
            path,
            fs_id,
            mountpoint,
            options,
            fallback_ip_address=fallback_ip_address,
        )


if "__main__" == __name__:
    main()
