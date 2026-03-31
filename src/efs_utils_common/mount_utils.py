#!/usr/bin/env python3
#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.


import logging
import os
import platform
import random
import subprocess
import sys
import threading
import time

from efs_utils_common.cloudwatch import publish_cloudwatch_log
from efs_utils_common.config_utils import (
    get_boolean_config_item_value,
    get_int_value_from_config_file,
)
from efs_utils_common.constants import (
    CONFIG_SECTION,
    DEFAULT_NFS_MAX_READAHEAD_MULTIPLIER,
    DEFAULT_NFS_MOUNT_COMMAND_RETRY_COUNT,
    DEFAULT_NFS_MOUNT_COMMAND_TIMEOUT_SEC,
    NFS_READAHEAD_CONFIG_PATH_FORMAT,
    NFS_READAHEAD_OPTIMIZE_LINUX_KERNEL_MIN_VERSION,
    OPTIMIZE_READAHEAD_ITEM,
    RETRYABLE_ERRORS,
    UBUNTU_24_RELEASE,
)
from efs_utils_common.context import MountContext
from efs_utils_common.error_reporting import fatal_error
from efs_utils_common.metadata import legacy_stunnel_mode_enabled
from efs_utils_common.mount_options import get_nfs_mount_options
from efs_utils_common.platform_utils import (
    check_if_platform_is_mac,
    decode_device_number,
    get_linux_kernel_version,
    get_system_release_version,
    is_ipv6_address,
)
from efs_utils_common.proxy import bootstrap_proxy, poll_tunnel_process


def mount_nfs(config, dns_name, path, mountpoint, options, fallback_ip_address=None):
    if legacy_stunnel_mode_enabled(options, config):
        if "tls" in options:
            mount_path = "127.0.0.1:%s" % path
        elif fallback_ip_address:
            if is_ipv6_address(fallback_ip_address):
                mount_path = f"[{fallback_ip_address}]:{path}"
            else:
                mount_path = "%s:%s" % (fallback_ip_address, path)
        else:
            mount_path = "%s:%s" % (dns_name, path)
    else:
        mount_path = "127.0.0.1:%s" % path

    nfs_options = get_nfs_mount_options(options, config)

    if not check_if_platform_is_mac():
        command = [
            "/sbin/mount.nfs4",
            mount_path,
            mountpoint,
            "-o",
            nfs_options,
        ]
    else:
        command = [
            "/sbin/mount_nfs",
            "-o",
            nfs_options,
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
    context = MountContext()
    publish_cloudwatch_log(context.cloudwatch_agent, message)

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
                is_access_point_mount = "accesspoint" in options

                continue_retry = any(
                    error_string in str(err) for error_string in RETRYABLE_ERRORS
                )

                # Only retry "access denied" for access point mounts, handles race condition that can occur during AP backend provisioning
                if not continue_retry and "access denied by server" in str(err):
                    continue_retry = is_access_point_mount

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

    system_release_version = get_system_release_version()
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
        if UBUNTU_24_RELEASE in system_release_version:
            # For Ubuntu 24, we use a delayed approach to setting the readahead value.
            # This is necessary because on Ubuntu 24, there's a race condition with udev
            # rules that can reset our readahead value immediately after we set it.
            p = subprocess.Popen(
                "sleep 2 && echo %s > %s"
                % (fixed_readahead_kb, read_ahead_kb_config_file),
                shell=True,
                stderr=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
            )
            logging.debug("Started background thread for delayed readahead setting")
            return

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
