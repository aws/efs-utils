#!/usr/bin/env python3
#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.

import logging
import os
import subprocess
import sys

from efs_utils_common.constants import AMAZON_LINUX_2_RELEASE_VERSIONS, CLONE_NEWNET
from efs_utils_common.error_reporting import fatal_error
from efs_utils_common.platform_utils import (
    check_if_platform_is_mac,
    get_system_release_version,
)


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

    existing_path = os.environ.get("PATH", "")
    search_path = env_path + ":" + existing_path if existing_path else env_path

    env = os.environ.copy()
    env["PATH"] = search_path

    try:
        path = subprocess.check_output(["which", command], env=env)
        return path.strip().decode()
    except subprocess.CalledProcessError as e:
        fatal_error(
            "Failed to locate %s in %s - %s" % (command, env_path, install_method), e
        )


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


def assert_root():
    if os.geteuid() != 0:
        sys.stderr.write("only root can run this command\n")
        sys.exit(1)


def add_field_in_options(options, field_key, field_value):
    if field_value and field_key not in options:
        options[field_key] = field_value
    return options
