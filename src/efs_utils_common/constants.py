#!/usr/bin/env python3
#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.


import os
import pwd
import re

VERSION = "3.0.1"

AMAZON_LINUX_2_RELEASE_ID = "Amazon Linux release 2 (Karoo)"
AMAZON_LINUX_2_PRETTY_NAME = "Amazon Linux 2"
AMAZON_LINUX_2_RELEASE_VERSIONS = [
    AMAZON_LINUX_2_RELEASE_ID,
    AMAZON_LINUX_2_PRETTY_NAME,
]

CLONE_NEWNET = 0x40000000
CONFIG_FILE = "/etc/amazon/efs/efs-utils.conf"
S3FILES_CONFIG_FILE = "/etc/amazon/efs/s3files-utils.conf"
CONFIG_SECTION = "mount"
PROXY_CONFIG_SECTION = "proxy"
DEFAULT_PROXY_LOGGING_LEVEL = "INFO"
DEFAULT_PROXY_LOGGING_MAX_BYTES = 1048576
DEFAULT_PROXY_LOGGING_FILE_COUNT = 10
CLIENT_INFO_SECTION = "client-info"
CLIENT_SOURCE_STR_LEN_LIMIT = 100
# Cloudwatchlog agent dict includes cloudwatchlog botocore client, cloudwatchlog group name, cloudwatchlog stream name
CLOUDWATCH_LOG_SECTION = "cloudwatch-log"
DEFAULT_CLOUDWATCH_LOG_GROUP = "/aws/efs/utils"
DEFAULT_FALLBACK_ENABLED = True
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
EFS_PROXY_NO_READ_BYPASS_OPTION = "--no-direct-s3-read"

NON_NFS_OPTIONS = [
    "accesspoint",
    "awscredsuri",
    "awsprofile",
    "az",
    "azid",
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
    "crossaccount",
    LEGACY_STUNNEL_MOUNT_OPTION,
    "nodirects3read",
    "nos3readcache",
]

UNSUPPORTED_OPTIONS = ["capath"]

WATCHDOG_SERVICE = "amazon-efs-mount-watchdog"
# MacOS instances use plist files. This files needs to be loaded on launchctl (init system of MacOS)
WATCHDOG_SERVICE_PLIST_PATH = "/Library/LaunchAgents/amazon-efs-mount-watchdog.plist"
SYSTEM_RELEASE_PATH = "/etc/system-release"
OS_RELEASE_PATH = "/etc/os-release"
MACOS_BIG_SUR_RELEASE = "macOS-11"
MACOS_MONTEREY_RELEASE = "macOS-12"
MACOS_VENTURA_RELEASE = "macOS-13"
MACOS_SONOMA_RELEASE = "macOS-14"
MACOS_SEQUOIA_RELEASE = "macOS-15"
MACOS_TAHOE_RELEASE = "macOS-26"


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
    MACOS_SEQUOIA_RELEASE,
    MACOS_TAHOE_RELEASE,
]

MAC_OS_PLATFORM_LIST = ["darwin"]
# MacOS Versions : Tahoe - 25.*, Sequoia - 24.*, Sonoma - 23.*, Ventura - 22.*, Monterey - 21.*, Big Sur - 20.*, Catalina - 19.*, Mojave - 18.*. Catalina and Mojave are not supported for now
MAC_OS_SUPPORTED_VERSION_LIST = ["20", "21", "22", "23", "24", "25"]

AWS_FIPS_ENDPOINT_CONFIG_ENV = "AWS_USE_FIPS_ENDPOINT"
ECS_URI_ENV = "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"
WEB_IDENTITY_ROLE_ARN_ENV = "AWS_ROLE_ARN"
WEB_IDENTITY_TOKEN_FILE_ENV = "AWS_WEB_IDENTITY_TOKEN_FILE"

ECS_FARGATE_TASK_METADATA_ENDPOINT_ENV = "ECS_CONTAINER_METADATA_URI_V4"
ECS_FARGATE_TASK_METADATA_ENDPOINT_URL_EXTENSION = "/task"
ECS_FARGATE_CLIENT_IDENTIFIER = "ecs.fargate"

AWS_CONTAINER_CREDS_FULL_URI_ENV = "AWS_CONTAINER_CREDENTIALS_FULL_URI"
AWS_CONTAINER_AUTH_TOKEN_FILE_ENV = "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"

UBUNTU_24_RELEASE = "Ubuntu 24"

MOUNT_TYPE_EFS = "EFS"
MOUNT_TYPE_S3FILES = "S3Files"
PROXY_MODE_EFS_PROXY = "efs-proxy"
PROXY_MODE_STUNNEL = "stunnel"

AP_REGEX_PATTERN = re.compile("^fsap-[0-9a-f]{17}$")
FS_ID_REGEX_PATTERN = re.compile("^(?P<fs_id>fs-[0-9a-f]+)$")

EFS_SERVICE_NAME = "elasticfilesystem"
S3FILES_SERVICE_NAME = "s3files"
