# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
from unittest.mock import MagicMock

import pytest

import efs_utils_common.proxy as proxy

from .. import utils

FS_ID = "fs-deadbeef"


def _dead_tunnel_proc(returncode=1, stderr="boom"):
    tunnel_proc = MagicMock()
    tunnel_proc.returncode = returncode
    tunnel_proc.communicate.return_value = (None, stderr)
    return tunnel_proc


def _live_tunnel_proc():
    tunnel_proc = MagicMock()
    # A still-running process reports returncode None after poll().
    tunnel_proc.returncode = None
    return tunnel_proc


def test_test_tunnel_process_dead_tunnel_triggers_fatal_error(mocker):
    fatal_error_mock = mocker.patch("efs_utils_common.proxy.fatal_error")
    tunnel_proc = _dead_tunnel_proc(returncode=7, stderr="stunnel exploded")

    proxy.test_tunnel_process(tunnel_proc, FS_ID)

    utils.assert_called_once(tunnel_proc.poll)
    utils.assert_called_once(fatal_error_mock)
    user_message = fatal_error_mock.call_args[0][0]
    log_message = fatal_error_mock.call_args[0][1]
    assert FS_ID in user_message
    # The dead process's returncode and stderr must be surfaced in the log message.
    assert "errno=7" in log_message
    assert "stunnel exploded" in log_message


def test_test_tunnel_process_live_tunnel_does_not_fatal_error(mocker):
    fatal_error_mock = mocker.patch("efs_utils_common.proxy.fatal_error")
    tunnel_proc = _live_tunnel_proc()

    proxy.test_tunnel_process(tunnel_proc, FS_ID)

    utils.assert_called_once(tunnel_proc.poll)
    utils.assert_not_called(fatal_error_mock)
    # A running process must never be reaped via communicate() by this health check.
    utils.assert_not_called(tunnel_proc.communicate)


def test_poll_tunnel_process_dead_tunnel_calls_os_exit(mocker):
    # fatal_error() ends in sys.exit(); reproduce that SystemExit so poll_tunnel_process's
    # except SystemExit / os._exit path is exercised.
    mocker.patch("efs_utils_common.proxy.fatal_error", side_effect=SystemExit(1))
    os_exit_mock = mocker.patch("efs_utils_common.proxy.os._exit")
    tunnel_proc = _dead_tunnel_proc(returncode=1)

    mount_completed = MagicMock()
    # Enter the loop once (is_set() False), then terminate it on the next check so the
    # test does not spin forever once os._exit is mocked into a no-op.
    mount_completed.is_set.side_effect = [False, True]

    proxy.poll_tunnel_process(tunnel_proc, FS_ID, mount_completed)

    utils.assert_called_once(os_exit_mock)
    assert os_exit_mock.call_args[0][0] == 1


def test_poll_tunnel_process_live_tunnel_does_not_exit(mocker):
    fatal_error_mock = mocker.patch("efs_utils_common.proxy.fatal_error")
    os_exit_mock = mocker.patch("efs_utils_common.proxy.os._exit")
    tunnel_proc = _live_tunnel_proc()

    mount_completed = MagicMock()
    # One polling iteration with a healthy tunnel, then the mount completes.
    mount_completed.is_set.side_effect = [False, True]

    proxy.poll_tunnel_process(tunnel_proc, FS_ID, mount_completed)

    utils.assert_not_called(fatal_error_mock)
    utils.assert_not_called(os_exit_mock)
    # The loop should wait between health checks rather than busy-spin.
    mount_completed.wait.assert_called_once_with(0.5)


def test_poll_tunnel_process_skips_check_when_already_completed(mocker):
    fatal_error_mock = mocker.patch("efs_utils_common.proxy.fatal_error")
    os_exit_mock = mocker.patch("efs_utils_common.proxy.os._exit")
    # Even a dead tunnel must not exit if the mount already completed before we polled.
    tunnel_proc = _dead_tunnel_proc(returncode=1)

    mount_completed = MagicMock()
    mount_completed.is_set.return_value = True

    proxy.poll_tunnel_process(tunnel_proc, FS_ID, mount_completed)

    utils.assert_not_called(tunnel_proc.poll)
    utils.assert_not_called(fatal_error_mock)
    utils.assert_not_called(os_exit_mock)


@pytest.mark.parametrize("returncode", [0, 143])
def test_poll_tunnel_process_dead_tunnel_propagates_exit_code(mocker, returncode):
    # os._exit must receive whatever exit code fatal_error's SystemExit carried.
    mocker.patch(
        "efs_utils_common.proxy.fatal_error", side_effect=SystemExit(returncode)
    )
    os_exit_mock = mocker.patch("efs_utils_common.proxy.os._exit")
    tunnel_proc = _dead_tunnel_proc(returncode=1)

    mount_completed = MagicMock()
    mount_completed.is_set.side_effect = [False, True]

    proxy.poll_tunnel_process(tunnel_proc, FS_ID, mount_completed)

    utils.assert_called_once(os_exit_mock)
    assert os_exit_mock.call_args[0][0] == returncode
