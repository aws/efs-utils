#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import errno
import os

import pytest

import watchdog

LOCK_FILE_NAME = "efs-utils-lock"


def test_clean_up_certificate_lock_file_removes_existing_lock(tmpdir):
    """clean_up_certificate_lock_file must unconditionally remove the
    'efs-utils-lock' file when it is present in the state file dir."""
    lock_file = tmpdir.join(LOCK_FILE_NAME)
    lock_file.write("locked", ensure=True)
    assert os.path.exists(str(lock_file))

    watchdog.clean_up_certificate_lock_file(state_file_dir=str(tmpdir))

    assert not os.path.exists(str(lock_file))


def test_clean_up_certificate_lock_file_swallows_missing_lock(tmpdir):
    """When the lock file is already gone, clean_up_certificate_lock_file must
    not raise (ENOENT is swallowed by check_and_remove_file)."""
    lock_file = tmpdir.join(LOCK_FILE_NAME)
    assert not os.path.exists(str(lock_file))

    # Should complete without raising.
    watchdog.clean_up_certificate_lock_file(state_file_dir=str(tmpdir))

    assert not os.path.exists(str(lock_file))


def test_check_and_remove_lock_file_reraises_non_enoent_ebadf(mocker):
    """check_and_remove_lock_file swallows ENOENT/EBADF but must re-raise any
    other OSError (e.g. EPERM) as an Exception."""
    mocker.patch("os.close")
    mocker.patch(
        "os.remove", side_effect=OSError(errno.EPERM, "Operation not permitted")
    )

    with pytest.raises(Exception):
        watchdog.check_and_remove_lock_file("/var/run/efs/efs-utils-lock", 5)


def test_check_and_remove_lock_file_swallows_enoent(mocker):
    """check_and_remove_lock_file must swallow ENOENT (file already removed)."""
    mocker.patch("os.close")
    mocker.patch(
        "os.remove", side_effect=OSError(errno.ENOENT, "No such file or directory")
    )

    # Should complete without raising.
    watchdog.check_and_remove_lock_file("/var/run/efs/efs-utils-lock", 5)
