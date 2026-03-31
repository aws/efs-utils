#!/usr/bin/env python3
#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.


import ipaddress
import logging
import platform
import sys

from efs_utils_common.constants import (
    CLIENT_INFO_SECTION,
    CLIENT_SOURCE_STR_LEN_LIMIT,
    DEFAULT_MACOS_VALUE,
    DEFAULT_UNKNOWN_VALUE,
    MAC_OS_PLATFORM_LIST,
    MAC_OS_SUPPORTED_VERSION_LIST,
    OS_RELEASE_PATH,
    SYSTEM_RELEASE_PATH,
    VERSION,
)


def is_ipv6_address(ip_address):
    try:
        return isinstance(ipaddress.ip_address(ip_address), ipaddress.IPv6Address)
    except ValueError:
        return False


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


def check_if_platform_is_mac():
    return sys.platform in MAC_OS_PLATFORM_LIST


def check_if_mac_version_is_supported():
    return any(
        release in platform.release() for release in MAC_OS_SUPPORTED_VERSION_LIST
    )


# https://github.com/torvalds/linux/blob/master/include/linux/kdev_t.h#L48-L49
def decode_device_number(device_number):
    major = (device_number & 0xFFF00) >> 8
    minor = (device_number & 0xFF) | ((device_number >> 12) & 0xFFF00)
    return major, minor


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
