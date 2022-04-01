#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import json
import tempfile
from datetime import datetime

import mount_efs
import watchdog

from .. import utils

try:
    import ConfigParser
except ImportError:
    from configparser import ConfigParser

TIME = 1514764800
GRACE_PERIOD = 30
PID = 1234
UNMOUNT_COUNT = 5
STATE = {
    "pid": PID,
    "commonName": "deadbeef.com",
    "certificate": "/tmp/foobar",
    "certificateCreationTime": datetime.utcnow().strftime(
        watchdog.CERT_DATETIME_FORMAT
    ),
    "mountStateDir": "fs-deadbeef.mount.dir.12345",
    "privateKey": "/tmp/foobarbaz",
    "accessPoint": "fsap-fedcba9876543210",
    "mount_time": TIME,
}


def _get_config():
    try:
        config = ConfigParser.SafeConfigParser()
    except AttributeError:
        config = ConfigParser()
    config.add_section(mount_efs.CONFIG_SECTION)
    config.set(mount_efs.CONFIG_SECTION, "state_file_dir_mode", "750")
    config.add_section(watchdog.CONFIG_SECTION)
    config.set(watchdog.CONFIG_SECTION, "stunnel_health_check_enabled", "false")
    return config


def setup_mocks(mocker, mounts, state_files, is_pid_running=True):
    state = dict(STATE)
    state["unmount_time"] = TIME - GRACE_PERIOD

    mocker.patch("watchdog.get_current_local_nfs_mounts", return_value=mounts)
    mocker.patch("watchdog.get_state_files", return_value=state_files)
    mocker.patch("watchdog.is_pid_running", return_value=is_pid_running)
    mocker.patch("time.time", return_value=TIME + GRACE_PERIOD + 1)

    clean_up_mock = mocker.patch("watchdog.clean_up_mount_state")
    restart_tls_mock = mocker.patch("watchdog.restart_tls_tunnel")
    check_certificate_call = mocker.patch("watchdog.check_certificate")
    rewrite_state_mock = mocker.patch("watchdog.rewrite_state_file")
    mark_as_unmounted_mock = mocker.patch(
        "watchdog.mark_as_unmounted", return_value=state
    )

    return (
        clean_up_mock,
        restart_tls_mock,
        check_certificate_call,
        rewrite_state_mock,
        mark_as_unmounted_mock,
    )


def create_state_file(tmpdir, content=json.dumps(STATE)):
    state_file = tmpdir.join(tempfile.mkstemp()[1])
    state_file.write(content, ensure=True)

    return state_file.dirname, state_file.basename


def test_no_state_files(mocker):
    clean_up_mock, restart_tls_mock, _, _, _ = setup_mocks(
        mocker,
        mounts={"mnt": watchdog.Mount("127.0.0.1", "/mnt", "nfs4", "", "0", "0")},
        state_files={},
    )

    watchdog.check_efs_mounts(_get_config(), [], GRACE_PERIOD, UNMOUNT_COUNT)

    utils.assert_not_called(clean_up_mock)
    utils.assert_not_called(restart_tls_mock)


def test_malformed_state_file(mocker, tmpdir):
    state_file_dir, state_file = create_state_file(tmpdir, "not-json")

    clean_up_mock, restart_tls_mock, _, _, _ = setup_mocks(
        mocker, mounts={}, state_files={"mnt": state_file}
    )

    watchdog.check_efs_mounts(
        _get_config(),
        [],
        GRACE_PERIOD,
        UNMOUNT_COUNT,
        state_file_dir=state_file_dir,
    )

    utils.assert_not_called(clean_up_mock)
    utils.assert_not_called(restart_tls_mock)


def test_no_mount_for_state_file(mocker, tmpdir):
    state = dict(STATE)

    state_file_dir, state_file = create_state_file(tmpdir, content=json.dumps(state))

    clean_up_mock, restart_tls_mock, _, rewrite_state_mock, _ = setup_mocks(
        mocker, mounts={}, state_files={"mnt": state_file}
    )

    watchdog.check_efs_mounts(
        _get_config(),
        [],
        GRACE_PERIOD,
        UNMOUNT_COUNT,
        state_file_dir=state_file_dir,
    )

    utils.assert_called_once(rewrite_state_mock)
    utils.assert_not_called(clean_up_mock)
    utils.assert_not_called(restart_tls_mock)


def test_no_mount_for_state_file_out_of_grace_period(mocker, tmpdir):
    state = dict(STATE)
    state["unmount_time"] = TIME - GRACE_PERIOD

    state_file_dir, state_file = create_state_file(tmpdir, content=json.dumps(state))

    clean_up_mock, restart_tls_mock, check_certificate_call, _, _ = setup_mocks(
        mocker, mounts={}, state_files={"mnt": state_file}
    )

    watchdog.check_efs_mounts(
        _get_config(),
        [],
        GRACE_PERIOD,
        UNMOUNT_COUNT,
        state_file_dir=state_file_dir,
    )

    utils.assert_called_once(clean_up_mock)
    utils.assert_not_called(restart_tls_mock)
    utils.assert_not_called(check_certificate_call)


def test_no_mount_for_state_file_mark_as_unmounted(mocker, tmpdir):
    state = dict(STATE)
    state["unmount_count"] = UNMOUNT_COUNT + 1

    state_file_dir, state_file = create_state_file(tmpdir, content=json.dumps(state))

    (
        clean_up_mock,
        restart_tls_mock,
        check_certificate_call,
        _,
        mark_as_unmounted_mock,
    ) = setup_mocks(mocker, mounts={}, state_files={"mnt": state_file})

    watchdog.check_efs_mounts(
        _get_config(),
        [],
        GRACE_PERIOD,
        UNMOUNT_COUNT,
        state_file_dir=state_file_dir,
    )

    utils.assert_called_once(mark_as_unmounted_mock)
    utils.assert_not_called(restart_tls_mock)
    utils.assert_not_called(check_certificate_call)


def test_no_mount_for_state_file_in_grace_period(mocker, tmpdir):
    state = dict(STATE)
    state["unmount_time"] = TIME + GRACE_PERIOD

    state_file_dir, state_file = create_state_file(tmpdir, content=json.dumps(state))

    clean_up_mock, restart_tls_mock, _, _, _ = setup_mocks(
        mocker, mounts={}, state_files={"mnt": state_file}
    )

    watchdog.check_efs_mounts(
        _get_config(),
        [],
        GRACE_PERIOD,
        UNMOUNT_COUNT,
        state_file_dir=state_file_dir,
    )

    utils.assert_not_called(clean_up_mock)
    utils.assert_not_called(restart_tls_mock)


def test_tls_not_running(mocker, tmpdir):
    state_file_dir, state_file = create_state_file(tmpdir)

    clean_up_mock, restart_tls_mock, _, _, _ = setup_mocks(
        mocker,
        mounts={"mnt": watchdog.Mount("127.0.0.1", "/mnt", "nfs4", "", "0", "0")},
        state_files={"mnt": state_file},
        is_pid_running=False,
    )

    watchdog.check_efs_mounts(
        _get_config(),
        [],
        GRACE_PERIOD,
        UNMOUNT_COUNT,
        state_file_dir=state_file_dir,
    )

    utils.assert_not_called(clean_up_mock)
    utils.assert_called_once(restart_tls_mock)


def test_tls_not_running_due_to_pid_clean_up(mocker, tmpdir):
    state = dict(STATE)
    state.pop("pid")

    state_file_dir, state_file = create_state_file(tmpdir, content=json.dumps(state))

    clean_up_mock, restart_tls_mock, _, _, _ = setup_mocks(
        mocker,
        mounts={"mnt": watchdog.Mount("127.0.0.1", "/mnt", "nfs4", "", "0", "0")},
        state_files={"mnt": state_file},
        is_pid_running=True,
    )

    watchdog.check_efs_mounts(
        _get_config(),
        [],
        GRACE_PERIOD,
        UNMOUNT_COUNT,
        state_file_dir=state_file_dir,
    )

    utils.assert_not_called(clean_up_mock)
    utils.assert_called_once(restart_tls_mock)


def test_ap_mount_with_extra_mount(mocker, tmpdir):
    state_file_dir, state_file = create_state_file(tmpdir)

    clean_up_mock, restart_tls_mock, check_certificate_call, _, _ = setup_mocks(
        mocker,
        mounts={
            "mnt": watchdog.Mount("127.0.0.1", "/mnt", "nfs4", "", "0", "0"),
            "mnt2": watchdog.Mount("192.168.1.1", "/mnt2", "nfs4", "", "0", "0"),
        },
        state_files={"mnt": state_file},
    )

    watchdog.check_efs_mounts(
        _get_config(),
        [],
        GRACE_PERIOD,
        UNMOUNT_COUNT,
        state_file_dir=state_file_dir,
    )

    utils.assert_not_called(clean_up_mock)
    utils.assert_not_called(restart_tls_mock)
    utils.assert_called_once(check_certificate_call)
