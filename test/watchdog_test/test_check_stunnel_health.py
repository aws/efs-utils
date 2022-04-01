#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import json
import subprocess
import tempfile

import watchdog
from mock import MagicMock

from .. import utils

try:
    import ConfigParser
except ImportError:
    from configparser import ConfigParser


DEFAULT_MOUNT_POINT = "/mnt"
FIXED_TIME = 1648627041.66836
DEFAULT_MOUNT_TIME = (
    FIXED_TIME - watchdog.DEFAULT_STUNNEL_HEALTH_CHECK_INTERVAL_MIN * 60 * 2 - 1
)
DEFAULT_LAST_STUNNEL_CHECK_TIME = (
    FIXED_TIME - watchdog.DEFAULT_STUNNEL_HEALTH_CHECK_INTERVAL_MIN * 60 - 1
)
DEFAULT_MOUNTS = {
    "mnt": watchdog.Mount(
        "127.0.0.1", DEFAULT_MOUNT_POINT, "nfs4", "port=12345", "0", "0"
    ),
}


def setup_mocks(
    mocker, mock_subprocess_success=False, mock_subprocess_timeout_sec=None
):
    check_time_mock = mocker.patch("time.time", return_value=FIXED_TIME)
    popen_mock = None
    if mock_subprocess_success:
        process_mock = MagicMock()
        process_mock.communicate.return_value = (
            "stdout",
            "stderr",
        )
        process_mock.returncode = 0
        popen_mock = mocker.patch("subprocess.Popen", return_value=process_mock)
    elif mock_subprocess_timeout_sec:
        process_mock = MagicMock()
        process_mock.communicate.side_effect = subprocess.TimeoutExpired(
            "cmd", timeout=mock_subprocess_timeout_sec
        )
        popen_mock = mocker.patch("subprocess.Popen", return_value=process_mock)
    return check_time_mock, popen_mock


def _get_config(
    stunnel_health_check_enabled=True,
    stunnel_health_check_interval_min=5,
    stunnel_health_check_command_timeout_sec=30,
):
    try:
        config = ConfigParser.SafeConfigParser()
    except AttributeError:
        config = ConfigParser()

    config.add_section(watchdog.CONFIG_SECTION)
    config.set(
        watchdog.CONFIG_SECTION,
        "stunnel_health_check_enabled",
        "true" if stunnel_health_check_enabled else "false",
    )
    config.set(
        watchdog.CONFIG_SECTION,
        "stunnel_health_check_interval_min",
        str(stunnel_health_check_interval_min),
    )
    config.set(
        watchdog.CONFIG_SECTION,
        "stunnel_health_check_command_timeout_sec",
        str(stunnel_health_check_command_timeout_sec),
    )
    return config


def test_stunnel_health_not_checked_when_feature_disabled(mocker, tmpdir):
    check_time_mock, _ = setup_mocks(mocker)
    config = _get_config(stunnel_health_check_enabled=False)

    state = {}
    state_file = tmpdir.join(tempfile.mkstemp()[1])
    state_file.write(json.dumps(state), ensure=True)
    watchdog.check_stunnel_health(
        config, state, state_file.dirname, state_file.basename, [], DEFAULT_MOUNTS
    )
    utils.assert_not_called(check_time_mock)


def test_stunnel_health_not_checked_mount_time_not_exist(mocker, tmpdir):
    check_time_mock, subprocess_mock = setup_mocks(mocker, mock_subprocess_success=True)
    config = _get_config(stunnel_health_check_enabled=True)

    state = {}
    state_file = tmpdir.join(tempfile.mkstemp()[1])
    state_file.write(json.dumps(state), ensure=True)
    watchdog.check_stunnel_health(
        config, state, state_file.dirname, state_file.basename, [], DEFAULT_MOUNTS
    )
    utils.assert_called_once(check_time_mock)
    utils.assert_not_called(subprocess_mock)
    with state_file.open() as f:
        new_state = json.load(f)
    assert FIXED_TIME == new_state["mount_time"]


def test_stunnel_health_not_checked_when_mount_passed_short_time(mocker, tmpdir):
    check_time_mock, subprocess_mock = setup_mocks(mocker, mock_subprocess_success=True)
    config = _get_config(stunnel_health_check_enabled=True)

    state = {"mount_time": FIXED_TIME - 1}
    state_file = tmpdir.join(tempfile.mkstemp()[1])
    state_file.write(json.dumps(state), ensure=True)
    watchdog.check_stunnel_health(
        config, state, state_file.dirname, state_file.basename, [], DEFAULT_MOUNTS
    )
    utils.assert_called_once(check_time_mock)
    utils.assert_not_called(subprocess_mock)


def test_stunnel_health_not_checked_when_last_stunnel_check_passed_short_time(
    mocker, tmpdir
):
    check_time_mock, subprocess_mock = setup_mocks(mocker, mock_subprocess_success=True)
    config = _get_config(stunnel_health_check_enabled=True)

    state = {
        "mount_time": DEFAULT_MOUNT_TIME,
        "last_stunnel_check_time": FIXED_TIME
        - watchdog.DEFAULT_STUNNEL_HEALTH_CHECK_INTERVAL_MIN * 60
        + 1,
    }
    state_file = tmpdir.join(tempfile.mkstemp()[1])
    state_file.write(json.dumps(state), ensure=True)
    watchdog.check_stunnel_health(
        config, state, state_file.dirname, state_file.basename, [], DEFAULT_MOUNTS
    )
    utils.assert_called_once(check_time_mock)
    utils.assert_not_called(subprocess_mock)


def test_stunnel_health_checked_passed_for_first_check(mocker, tmpdir):
    check_time_mock, subprocess_mock = setup_mocks(mocker, mock_subprocess_success=True)
    config = _get_config(stunnel_health_check_enabled=True)

    state = {
        "mount_time": DEFAULT_MOUNT_TIME,
        "mountpoint": "/mnt",
        "pid": 9999,
    }
    state_file = tmpdir.join(tempfile.mkstemp()[1])
    state_file.write(json.dumps(state), ensure=True)
    watchdog.check_stunnel_health(
        config, state, state_file.dirname, state_file.basename, [], DEFAULT_MOUNTS
    )

    utils.assert_called_once(check_time_mock)
    utils.assert_called_once(subprocess_mock)
    with state_file.open() as f:
        new_state = json.load(f)
    assert FIXED_TIME == new_state["last_stunnel_check_time"]


def test_stunnel_health_checked_passed_for_non_first_check_default_interval(
    mocker, tmpdir
):
    config = _get_config(stunnel_health_check_enabled=True)
    _test_stunnel_health_checked_passed_for_non_first_check_helper(
        mocker, tmpdir, config
    )


def test_stunnel_health_checked_passed_for_non_first_check_short_interval(
    mocker, tmpdir
):
    config = _get_config(
        stunnel_health_check_enabled=True, stunnel_health_check_interval_min=1
    )
    _test_stunnel_health_checked_passed_for_non_first_check_helper(
        mocker, tmpdir, config, last_stunnel_check_time=FIXED_TIME - 61
    )


def test_stunnel_health_failed_due_to_timeout_not_kill_stunnel(mocker, tmpdir):
    _, subprocess_mock = setup_mocks(
        mocker,
        mock_subprocess_timeout_sec=watchdog.DEFAULT_STUNNEL_HEALTH_CHECK_TIMEOUT_SEC,
    )
    config = _get_config(stunnel_health_check_enabled=True)

    state = {
        "mount_time": DEFAULT_MOUNT_TIME,
        "mountpoint": "/mnt",
        "pid": 9999,
        "last_stunnel_check_time": DEFAULT_LAST_STUNNEL_CHECK_TIME,
    }
    state_file = tmpdir.join(tempfile.mkstemp()[1])
    state_file.write(json.dumps(state), ensure=True)

    mocker.patch("watchdog.is_pid_running", return_value=False)
    watchdog.check_stunnel_health(
        config, state, state_file.dirname, state_file.basename, [], DEFAULT_MOUNTS
    )
    utils.assert_called_once(subprocess_mock)


def test_stunnel_health_failed_due_to_timeout_kill_stunnel(mocker, tmpdir):
    _, subprocess_mock = setup_mocks(
        mocker,
        mock_subprocess_timeout_sec=watchdog.DEFAULT_STUNNEL_HEALTH_CHECK_TIMEOUT_SEC,
    )
    config = _get_config(stunnel_health_check_enabled=True)

    state = {
        "mount_time": DEFAULT_MOUNT_TIME,
        "mountpoint": "/mnt",
        "pid": 9999,
        "last_stunnel_check_time": DEFAULT_LAST_STUNNEL_CHECK_TIME,
    }
    state_file = tmpdir.join(tempfile.mkstemp()[1])
    state_file.write(json.dumps(state), ensure=True)

    mocker.patch("watchdog.is_pid_running", return_value=True)
    mocker.patch("os.getpgid", return_value="fakepg")
    kill_mock = mocker.patch("os.killpg")
    restart_tls_tunnel_mock = mocker.patch("watchdog.restart_tls_tunnel")
    watchdog.check_stunnel_health(
        config, state, state_file.dirname, state_file.basename, [], DEFAULT_MOUNTS
    )
    utils.assert_called_once(subprocess_mock)
    utils.assert_called_once(kill_mock)
    utils.assert_called_once(restart_tls_tunnel_mock)


def test_stunnel_health_checked_passed_for_non_first_check_no_mountpoint_info(
    mocker, tmpdir
):
    config = _get_config(stunnel_health_check_enabled=True)
    _test_stunnel_health_checked_passed_for_non_first_check_helper(
        mocker, tmpdir, config, mountpoint=None
    )


def _test_stunnel_health_checked_passed_for_non_first_check_helper(
    mocker,
    tmpdir,
    config,
    mount_time=DEFAULT_MOUNT_TIME,
    last_stunnel_check_time=DEFAULT_LAST_STUNNEL_CHECK_TIME,
    mountpoint=DEFAULT_MOUNT_POINT,
):
    _, subprocess_mock = setup_mocks(mocker, mock_subprocess_success=True)
    state = {
        "mount_time": mount_time,
        "pid": 9999,
        "last_stunnel_check_time": last_stunnel_check_time,
    }

    if mountpoint:
        state["mountpoint"] = mountpoint

    state_file = tmpdir.join(tempfile.mkstemp()[1])
    state_file.write(json.dumps(state), ensure=True)
    watchdog.check_stunnel_health(
        config, state, state_file.dirname, state_file.basename, [], DEFAULT_MOUNTS
    )

    utils.assert_called_once(subprocess_mock)
    with state_file.open() as f:
        new_state = json.load(f)
    assert FIXED_TIME == new_state["last_stunnel_check_time"]
    if not mountpoint:
        assert mountpoint == new_state["mountpoint"]
