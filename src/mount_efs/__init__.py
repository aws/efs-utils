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


import logging
import platform
import re
import sys

from efs_utils_common.cloudwatch import bootstrap_cloudwatch_logging
from efs_utils_common.config_utils import (
    bootstrap_logging,
    is_ocsp_enabled,
    read_config,
)
from efs_utils_common.constants import (
    CONFIG_FILE,
    EFS_SERVICE_NAME,
    LEGACY_STUNNEL_MOUNT_OPTION,
    MOUNT_TYPE_EFS,
    PROXY_MODE_STUNNEL,
    VERSION,
)
from efs_utils_common.context import MountContext
from efs_utils_common.error_reporting import fatal_error
from efs_utils_common.file_utils import usage
from efs_utils_common.metadata import legacy_stunnel_mode_enabled
from efs_utils_common.mount_options import (
    check_options_validity,
    check_unsupported_options,
    parse_options,
)
from efs_utils_common.mount_utils import mount_nfs, mount_with_proxy
from efs_utils_common.network_utils import check_network_status
from efs_utils_common.platform_utils import (
    check_if_mac_version_is_supported,
    check_if_platform_is_mac,
)
from efs_utils_common.process_utils import add_field_in_options, assert_root
from efs_utils_common.proxy import get_init_system
from mount_efs.dns_resolver import (
    get_dns_name_and_fallback_mount_target_ip_address,
    match_device,
)

# Fully Qualified Domain Name
FQDN_REGEX_PATTERN = re.compile(
    r"^((?P<az>[a-z0-9-]+)\.)?(?P<fs_id>fs-[0-9a-f]+)\.(?:[a-z-]+\.)+"
    r"(?P<region>[a-z0-9-]+)\.(?P<dns_name_suffix>[a-z0-9.-]+)$"
)

# The azid is only used for S3Files DNS name resolution
MOUNT_TYPE_SPECIFIC_UNSUPPORTED_OPTIONS = ["azid"]


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


def main():
    context = MountContext()
    context.mount_type = MOUNT_TYPE_EFS

    parse_arguments_early_exit()

    assert_root()

    config = read_config(CONFIG_FILE)
    bootstrap_logging(config)

    if check_if_platform_is_mac() and not check_if_mac_version_is_supported():
        fatal_error(
            "We do not support EFS on MacOS Kernel version " + platform.release()
        )

    context.service = EFS_SERVICE_NAME
    context.fqdn_regex_pattern = FQDN_REGEX_PATTERN
    context.config_file_path = CONFIG_FILE
    context.unsupported_options = MOUNT_TYPE_SPECIFIC_UNSUPPORTED_OPTIONS

    fs_id, path, mountpoint, options = parse_arguments(config)

    # Use stunnel instead of efs-proxy for tls mounts,
    # and attach non-tls mounts directly to the mount target.
    if (
        LEGACY_STUNNEL_MOUNT_OPTION in options
        or check_if_platform_is_mac()
        or is_ocsp_enabled(config, options)
    ):
        context.proxy_mode = PROXY_MODE_STUNNEL

    logging.info("version=%s options=%s", VERSION, options)

    context.cloudwatch_agent = bootstrap_cloudwatch_logging(config, options, fs_id)

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


if __name__ == "__main__":
    main()
