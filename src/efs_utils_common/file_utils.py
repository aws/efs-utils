#!/usr/bin/env python3
#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.


import errno
import logging
import os
import sys
from datetime import datetime, timezone

try:
    from configparser import NoOptionError
except ImportError:
    from ConfigParser import NoOptionError

from efs_utils_common.config_utils import get_config_file_path
from efs_utils_common.constants import CONFIG_SECTION, MOUNT_TYPE_S3FILES
from efs_utils_common.context import MountContext


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
                get_config_file_path(),
            )
    except NoOptionError:
        pass

    try:
        os.makedirs(directory, mode)
    except OSError as e:
        if errno.EEXIST != e.errno or not os.path.isdir(directory):
            raise


def usage(out, exit_code=1):
    context = MountContext()
    prog_name = (
        "mount.s3files" if context.mount_type == MOUNT_TYPE_S3FILES else "mount.efs"
    )
    out.write(
        "Usage: %s [--version] [-h|--help] <fsname> <mountpoint> [-o <options>]\n"
        % prog_name
    )
    sys.exit(exit_code)


def get_utc_now():
    """
    Wrapped for patching purposes in unit tests
    """
    return datetime.now(timezone.utc)


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
