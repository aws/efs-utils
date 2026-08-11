#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import watchdog

from .. import utils

try:
    import ConfigParser
except ImportError:
    from configparser import ConfigParser


def _get_config(enabled=True, poll_interval_sec=1, unmount_grace_period_sec=30):
    try:
        config = ConfigParser.SafeConfigParser()
    except AttributeError:
        config = ConfigParser()

    config.add_section(watchdog.CONFIG_SECTION)
    config.set(watchdog.CONFIG_SECTION, "enabled", "true" if enabled else "false")
    config.set(watchdog.CONFIG_SECTION, "poll_interval_sec", str(poll_interval_sec))
    config.set(
        watchdog.CONFIG_SECTION,
        "unmount_grace_period_sec",
        str(unmount_grace_period_sec),
    )
    return config


def test_main_enabled_runs_startup_then_one_poll_iteration(mocker):
    """When enabled, main() should run its startup steps in order and then
    execute exactly one poll iteration (check_efs_mounts + check_child_procs)
    before time.sleep breaks the loop."""
    config = _get_config(enabled=True)
    call_order = []

    def recorder(name, ret=None):
        def _rec(*args, **kwargs):
            call_order.append(name)
            return ret

        return _rec

    parse_arguments_mock = mocker.patch(
        "watchdog.parse_arguments", side_effect=recorder("parse_arguments")
    )
    assert_root_mock = mocker.patch(
        "watchdog.assert_root", side_effect=recorder("assert_root")
    )
    read_config_mock = mocker.patch(
        "watchdog.read_config", side_effect=recorder("read_config", ret=config)
    )
    bootstrap_logging_mock = mocker.patch(
        "watchdog.bootstrap_logging", side_effect=recorder("bootstrap_logging")
    )
    clean_up_pids_mock = mocker.patch(
        "watchdog.clean_up_previous_tunnel_pids",
        side_effect=recorder("clean_up_previous_tunnel_pids"),
    )
    clean_up_lock_mock = mocker.patch(
        "watchdog.clean_up_certificate_lock_file",
        side_effect=recorder("clean_up_certificate_lock_file"),
    )
    check_efs_mounts_mock = mocker.patch(
        "watchdog.check_efs_mounts", side_effect=recorder("check_efs_mounts")
    )
    check_child_procs_mock = mocker.patch(
        "watchdog.check_child_procs", side_effect=recorder("check_child_procs")
    )

    def sleep_side_effect(*args, **kwargs):
        call_order.append("sleep")
        raise InterruptedError("break out of poll loop")

    sleep_mock = mocker.patch("time.sleep", side_effect=sleep_side_effect)

    # main() loops forever; time.sleep raises to break out after one iteration.
    try:
        watchdog.main()
        raise AssertionError("expected InterruptedError to break the poll loop")
    except InterruptedError:
        pass

    # Startup steps ran once, in the expected order, followed by exactly one
    # poll iteration (loop re-reads config, then the two checks, then sleep).
    assert call_order == [
        "parse_arguments",
        "assert_root",
        "read_config",
        "bootstrap_logging",
        "clean_up_previous_tunnel_pids",
        "clean_up_certificate_lock_file",
        "read_config",
        "check_efs_mounts",
        "check_child_procs",
        "sleep",
    ]

    utils.assert_called_once(parse_arguments_mock)
    utils.assert_called_once(assert_root_mock)
    utils.assert_called_once(bootstrap_logging_mock)
    utils.assert_called_once(clean_up_pids_mock)
    utils.assert_called_once(clean_up_lock_mock)
    utils.assert_called_once(check_efs_mounts_mock)
    utils.assert_called_once(check_child_procs_mock)
    utils.assert_called_once(sleep_mock)
    # read_config is called once at startup and once per loop iteration.
    utils.assert_called_n_times(read_config_mock, 2)


def test_main_disabled_returns_without_entering_poll_loop(mocker):
    """When [mount-watchdog] enabled is False, main() must log and return
    without entering the poll loop."""
    config = _get_config(enabled=False)

    mocker.patch("watchdog.parse_arguments")
    mocker.patch("watchdog.assert_root")
    mocker.patch("watchdog.read_config", return_value=config)
    mocker.patch("watchdog.bootstrap_logging")
    clean_up_pids_mock = mocker.patch("watchdog.clean_up_previous_tunnel_pids")
    clean_up_lock_mock = mocker.patch("watchdog.clean_up_certificate_lock_file")
    check_efs_mounts_mock = mocker.patch("watchdog.check_efs_mounts")
    check_child_procs_mock = mocker.patch("watchdog.check_child_procs")
    sleep_mock = mocker.patch("time.sleep")

    watchdog.main()

    # Poll loop and its per-iteration setup are never reached.
    utils.assert_not_called(clean_up_pids_mock)
    utils.assert_not_called(clean_up_lock_mock)
    utils.assert_not_called(check_efs_mounts_mock)
    utils.assert_not_called(check_child_procs_mock)
    utils.assert_not_called(sleep_mock)
