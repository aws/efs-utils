# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.

import json
import os
import tempfile
from signal import SIGHUP, SIGKILL, SIGTERM

import watchdog

from .. import utils

PID = 100
STATE_FILE = "fs-deadbeef.mnt.12345"
MOUNT_STATE_DIR = STATE_FILE + "+"


def create_file(tmpdir, file_name=tempfile.mkstemp()[1], content=""):
    temp_file = tmpdir.join(file_name)
    temp_file.write(content, ensure=True)
    return temp_file


def create_dir(tmpdir, dirname):
    abs_dir_path = tmpdir.join(dirname)
    os.mkdir(str(abs_dir_path))
    return abs_dir_path


def create_pid_file(tmpdir, pid):
    pid_file = create_file(tmpdir, watchdog.STUNNEL_PID_FILE, str(pid))
    return pid_file.dirname, pid_file.basename, str(pid_file)


def create_state_file(tmpdir, state_dict, state_file_name):
    state_file = create_file(tmpdir, state_file_name, json.dumps(state_dict))
    return state_file.dirname, state_file.basename, str(state_file)


def test_is_pid_running_pid_empty():
    assert False == watchdog.is_pid_running(None)


def test_is_pid_running_pid_running(mocker):
    mocker.patch("os.kill")
    assert True == watchdog.is_pid_running(PID)


def test_is_pid_running_pid_not_running(mocker):
    mocker.patch("os.kill", side_effect=OSError)
    assert False == watchdog.is_pid_running(PID)


def test_get_pid_in_state_dir(tmpdir):
    mount_dir = create_dir(tmpdir, MOUNT_STATE_DIR)
    pid_dir, pid_file, abs_pid_file = create_pid_file(mount_dir, PID)
    assert os.path.exists(str(mount_dir))
    assert os.path.exists(abs_pid_file)

    state_dict = {"pid": PID}
    state_dir, state_file, abs_state_file = create_state_file(
        tmpdir, state_dict, STATE_FILE
    )
    assert os.path.exists(abs_state_file)

    assert PID == int(watchdog.get_pid_in_state_dir(STATE_FILE, str(tmpdir)))


def test_pid_file_not_in_state_dir(tmpdir):
    mount_dir = create_dir(tmpdir, MOUNT_STATE_DIR)
    assert os.path.exists(str(mount_dir))
    assert not os.path.exists(os.path.join(str(mount_dir), watchdog.STUNNEL_PID_FILE))

    state_dict = {"pid": PID}
    state_dir, state_file, abs_state_file = create_state_file(
        tmpdir, state_dict, STATE_FILE
    )
    assert os.path.exists(abs_state_file)

    assert watchdog.get_pid_in_state_dir(STATE_FILE, str(tmpdir)) is None


def test_is_mount_stunnel_proc_running_pid_empty(tmpdir):
    assert False == watchdog.is_mount_stunnel_proc_running(None, STATE_FILE, tmpdir)


def test_is_mount_stunnel_proc_running_process_not_stunnel(mocker, tmpdir):
    mocker.patch("watchdog.check_process_name", return_value="java")
    mock_log_debug = mocker.patch("logging.debug")

    assert False == watchdog.is_mount_stunnel_proc_running(PID, STATE_FILE, tmpdir)
    debug_log = mock_log_debug.call_args[0][0]
    assert "is not a stunnel process" in debug_log


def test_is_mount_stunnel_proc_running_process_not_running(mocker, tmpdir):
    mocker.patch("watchdog.check_process_name", return_value="stunnel")
    mocker.patch("watchdog.is_pid_running", return_value=False)
    mock_log_debug = mocker.patch("logging.debug")

    assert False == watchdog.is_mount_stunnel_proc_running(PID, STATE_FILE, tmpdir)

    debug_log = mock_log_debug.call_args[0][0]
    assert "is not running anymore" in debug_log


def test_is_mount_stunnel_proc_running_pid_file_not_exist(mocker, tmpdir):
    mocker.patch("watchdog.check_process_name", return_value="stunnel")
    mocker.patch("watchdog.is_pid_running", return_value=True)
    mount_dir = create_dir(tmpdir, MOUNT_STATE_DIR)
    assert not os.path.exists(os.path.join(str(mount_dir), watchdog.STUNNEL_PID_FILE))
    mock_log_debug = mocker.patch("logging.debug")

    assert True == watchdog.is_mount_stunnel_proc_running(PID, STATE_FILE, str(tmpdir))

    assert "Pid file of stunnel does not exist" in str(
        mock_log_debug.call_args_list[0][0]
    )
    assert "is running with pid " in str(mock_log_debug.call_args_list[1][0])


def test_is_mount_stunnel_proc_running_pid_mismatch(mocker, tmpdir):
    mocker.patch("watchdog.check_process_name", return_value="stunnel")
    mocker.patch("watchdog.is_pid_running", return_value=True)
    mount_dir = create_dir(tmpdir, MOUNT_STATE_DIR)
    create_pid_file(mount_dir, PID + 1)
    mock_log_warning = mocker.patch("logging.warning")

    assert False == watchdog.is_mount_stunnel_proc_running(PID, STATE_FILE, str(tmpdir))

    warning_log = mock_log_warning.call_args[0][0]
    assert "Stunnel pid mismatch in state file" in warning_log


def test_is_mount_stunnel_proc_running(mocker, tmpdir):
    mocker.patch("watchdog.check_process_name", return_value="stunnel")
    mocker.patch("watchdog.is_pid_running", return_value=True)
    mount_dir = create_dir(tmpdir, MOUNT_STATE_DIR)
    create_pid_file(mount_dir, PID)
    mock_log_debug = mocker.patch("logging.debug")

    assert True == watchdog.is_mount_stunnel_proc_running(PID, STATE_FILE, str(tmpdir))

    debug_log = mock_log_debug.call_args[0][0]
    assert "is running with pid" in debug_log


def test_send_sigkill_to_stunnel_process_group(mocker, tmpdir):
    _test_send_signal_to_stunnel_process_group_helper(mocker, tmpdir, SIGKILL)


def test_send_sigkill_to_stunnel_process_group_not_running(mocker, tmpdir):
    _test_send_signal_to_stunnel_process_group_helper(
        mocker, tmpdir, SIGKILL, is_process_running=False
    )


def test_send_sighup_to_stunnel_process_group(mocker, tmpdir):
    _test_send_signal_to_stunnel_process_group_helper(mocker, tmpdir, SIGHUP)


def test_send_sighup_to_stunnel_process_group_not_running(mocker, tmpdir):
    _test_send_signal_to_stunnel_process_group_helper(
        mocker, tmpdir, SIGHUP, is_process_running=False
    )


def test_send_sigterm_to_stunnel_process_group(mocker, tmpdir):
    _test_send_signal_to_stunnel_process_group_helper(mocker, tmpdir, SIGTERM)


def test_send_sigterm_to_stunnel_process_group_not_running(mocker, tmpdir):
    _test_send_signal_to_stunnel_process_group_helper(
        mocker, tmpdir, SIGTERM, is_process_running=False
    )


def _test_send_signal_to_stunnel_process_group_helper(
    mocker, tmpdir, signal, is_process_running=True
):
    mocker.patch(
        "watchdog.is_mount_stunnel_proc_running", return_value=is_process_running
    )
    mocker.patch("os.getpgid")
    kill_mock = mocker.patch("os.killpg")

    send_result = watchdog.send_signal_to_running_stunnel_process_group(
        PID, STATE_FILE, tmpdir, signal
    )
    if is_process_running:
        assert True == send_result
        utils.assert_called_once(kill_mock)
    else:
        assert False == send_result
        utils.assert_not_called(kill_mock)
