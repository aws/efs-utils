#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import json
import os
import tempfile

import watchdog

from .. import utils

FAKE_MOUNT_STATE_DIR = "/fake/path"
PID = 99999999999999999


def create_temp_file(tmpdir, content=""):
    temp_file = tmpdir.join(tempfile.mkstemp()[1])
    temp_file.write(content, ensure=True)
    return temp_file


def create_state_file(tmpdir, extra_files=list(), mount_state_dir=None):
    state_dict = {"pid": PID, "files": extra_files}

    if mount_state_dir:
        state_dict["mountStateDir"] = mount_state_dir

    state_file = create_temp_file(tmpdir, json.dumps(state_dict))

    return state_file.dirname, state_file.basename, str(state_file)


def setup_mock(
    mocker,
    is_stunnel_proc_running_first_check=True,
    is_stunnel_proc_running_second_check=False,
):
    mocker.patch("os.getpgid")
    # The watchdog clean_up_mount_state function has two procedures:
    # 1. Kill the stunnel process if it is still running
    # 2. Check whether the stunnel process is still running, if not, cleanup the state file of the mount
    # Each procedure will check whether the mount stunnel process is running, so we have two mock here.
    mocker.patch(
        "watchdog.is_mount_stunnel_proc_running",
        side_effect=[
            is_stunnel_proc_running_first_check,
            is_stunnel_proc_running_second_check,
        ],
    )
    return mocker.patch("os.killpg")


def test_clean_up_on_first_try(mocker, tmpdir):
    """
    This test verifies when the stunnel is running at first then got killed, watchdog will cleanup the mount state file
    """
    killpg_mock = setup_mock(mocker)

    state_dir, state_file, abs_state_file = create_state_file(tmpdir)

    assert os.path.exists(abs_state_file)

    watchdog.clean_up_mount_state(state_dir, state_file, PID)

    utils.assert_called_once(killpg_mock)
    assert not os.path.exists(abs_state_file)


def _test_clean_up_files(mocker, tmpdir, files_should_exist):
    killpg_mock = setup_mock(mocker)

    extra_files = [
        str(create_temp_file(tmpdir)),
        str(create_temp_file(tmpdir)),
    ]

    state_dir, state_file, abs_state_file = create_state_file(tmpdir, extra_files)

    assert os.path.exists(abs_state_file)
    for f in extra_files:
        if not files_should_exist:
            os.remove(f)
        assert os.path.exists(f) or not files_should_exist

    watchdog.clean_up_mount_state(state_dir, state_file, PID)

    utils.assert_called_once(killpg_mock)
    assert not os.path.exists(abs_state_file)
    for f in extra_files:
        assert not os.path.exists(f)


def test_clean_up_nonexistent_files(mocker, tmpdir):
    _test_clean_up_files(mocker, tmpdir, files_should_exist=False)


def test_clean_up_multiple_files(mocker, tmpdir):
    """
    This test verifies when there are extra files created in the mount state dir, watchdog can clean up the state file
    """
    _test_clean_up_files(mocker, tmpdir, files_should_exist=True)


def test_clean_up_pid_still_lives(mocker, tmpdir):
    """
    This test verifies when the stunnel process is still running after killing event, watchdog won't clean up the state
    file
    """
    killpg_mock = setup_mock(
        mocker,
        is_stunnel_proc_running_first_check=True,
        is_stunnel_proc_running_second_check=True,
    )

    state_dir, state_file, abs_state_file = create_state_file(tmpdir)

    assert os.path.exists(abs_state_file)

    watchdog.clean_up_mount_state(state_dir, state_file, PID)

    utils.assert_called_once(killpg_mock)
    assert os.path.exists(abs_state_file)


def test_clean_up_pid_already_killed(mocker, tmpdir):
    """
    This test verifies when the stunnel process is already killed, the kill signal won't be sent, and watchdog will
    clean up the state file
    """
    state_dir, state_file, abs_state_file = create_state_file(tmpdir)
    pid = None
    is_running = watchdog.is_mount_stunnel_proc_running(pid, state_file, state_dir)
    killpg_mock = setup_mock(
        mocker,
        is_stunnel_proc_running_first_check=is_running,
        is_stunnel_proc_running_second_check=False,
    )

    assert os.path.exists(abs_state_file)

    watchdog.clean_up_mount_state(state_dir, state_file, pid)

    utils.assert_not_called(killpg_mock)
    assert not os.path.exists(abs_state_file)


def test_pid_not_running(mocker, tmpdir):
    """
    This test verifies when the stunnel process is already not running, the kill signal won't be sent, and watchdog will
    clean up the state file
    """
    killpg_mock = setup_mock(
        mocker,
        is_stunnel_proc_running_first_check=False,
        is_stunnel_proc_running_second_check=False,
    )

    state_dir, state_file, abs_state_file = create_state_file(tmpdir)

    assert os.path.exists(abs_state_file)

    watchdog.clean_up_mount_state(state_dir, state_file, PID)

    utils.assert_not_called(killpg_mock)
    assert not os.path.exists(abs_state_file)


def test_clean_up_mount_state_dir_success(mocker, tmpdir):
    """
    This test verifies when the stunnel process is already not running, watchdog will clean up the mount state dir
    """
    setup_mock(
        mocker,
        is_stunnel_proc_running_first_check=False,
        is_stunnel_proc_running_second_check=False,
    )
    mocker.patch("os.path.isdir", return_value=True)
    rm_tree = mocker.patch("shutil.rmtree")

    state_dir, state_file, abs_state_file = create_state_file(
        tmpdir, mount_state_dir=FAKE_MOUNT_STATE_DIR
    )

    assert os.path.exists(abs_state_file)

    watchdog.clean_up_mount_state(
        state_dir, state_file, PID, mount_state_dir=FAKE_MOUNT_STATE_DIR
    )

    utils.assert_called_once(rm_tree)
    assert not os.path.exists(abs_state_file)


def test_clean_up_mount_state_dir_fail(mocker, tmpdir):
    """
    This test verifies when the stunnel process is already not running, watchdog will not clean up the mount state dir
    if the mount state dir path is not a directory
    """
    setup_mock(
        mocker,
        is_stunnel_proc_running_first_check=False,
        is_stunnel_proc_running_second_check=False,
    )
    mocker.patch("os.path.isdir", return_value=False)
    rm_tree = mocker.patch("shutil.rmtree")

    state_dir, state_file, abs_state_file = create_state_file(
        tmpdir, mount_state_dir=FAKE_MOUNT_STATE_DIR
    )

    assert os.path.exists(abs_state_file)

    watchdog.clean_up_mount_state(
        state_dir, state_file, PID, mount_state_dir=FAKE_MOUNT_STATE_DIR
    )

    utils.assert_not_called(rm_tree)
    assert not os.path.exists(abs_state_file)
