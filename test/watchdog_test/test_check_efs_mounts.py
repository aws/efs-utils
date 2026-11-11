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

import efs_utils_common
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
    "service_type": "elasticfilesystem",
}


def _get_config():
    try:
        config = ConfigParser.SafeConfigParser()
    except AttributeError:
        config = ConfigParser()
    config.add_section(efs_utils_common.constants.CONFIG_SECTION)
    config.set(efs_utils_common.constants.CONFIG_SECTION, "state_file_dir_mode", "750")
    config.add_section(watchdog.CONFIG_SECTION)
    config.set(watchdog.CONFIG_SECTION, "stunnel_health_check_enabled", "false")
    return config


def setup_mocks(
    mocker, mounts, state_files, is_stunnel_process_running=True, is_pid_running=True
):
    state = dict(STATE)
    state["unmount_time"] = TIME - GRACE_PERIOD

    mocker.patch("watchdog.get_current_local_nfs_mounts", return_value=mounts)
    mocker.patch("watchdog.get_state_files", return_value=state_files)
    mocker.patch(
        "watchdog.is_mount_stunnel_proc_running",
        return_value=is_stunnel_process_running,
    )
    mocker.patch("watchdog.is_pid_running", return_value=is_pid_running)
    mocker.patch("time.time", return_value=TIME + GRACE_PERIOD + 1)
    mocker.patch("watchdog.get_local_nfs_client_ports", return_value=set())

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
    state_file = tmpdir.join(tempfile.mkstemp(prefix="fs-")[1])
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
        is_stunnel_process_running=False,
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
        is_stunnel_process_running=False,
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


NFS_PORT = 20049
PORTED_STATE_FILE = "fs-deadbeef.mnt.%d" % NFS_PORT


SETTLE = watchdog.KERNEL_NFS_CLIENT_SETTLE_SEC
MAX_WAIT = 90
GONE = watchdog.KERNEL_NFS_CLIENT_GONE_TIME
LOGGED = watchdog.KERNEL_NFS_CLIENT_WAIT_LOGGED
PAST_GRACE = TIME + GRACE_PERIOD + 1


def _config_with_max_wait(value):
    config = _get_config()
    config.set(
        watchdog.CONFIG_SECTION,
        watchdog.KERNEL_NFS_CLIENT_TEARDOWN_MAX_WAIT_ITEM,
        str(value),
    )
    return config


def _check_unmounted(
    mocker, tmpdir, nfs_client_ports, now, config=None, **state_fields
):
    """One watchdog pass over a mount unmounted at TIME, whose tunnel is on NFS_PORT."""
    state = dict(STATE)
    state["unmount_time"] = TIME
    state.update(state_fields)
    tmpdir.join(PORTED_STATE_FILE).write(json.dumps(state), ensure=True)

    clean_up_mock, restart_tls_mock, _, rewrite_state_mock, _ = setup_mocks(
        mocker, mounts={}, state_files={"mnt.%d" % NFS_PORT: PORTED_STATE_FILE}
    )
    ports_mock = mocker.patch(
        "watchdog.get_local_nfs_client_ports", return_value=nfs_client_ports
    )
    mocker.patch("time.time", return_value=now)

    watchdog.check_efs_mounts(
        config if config is not None else _config_with_max_wait(MAX_WAIT),
        [],
        GRACE_PERIOD,
        UNMOUNT_COUNT,
        state_file_dir=str(tmpdir),
    )

    utils.assert_not_called(restart_tls_mock)
    return clean_up_mock, ports_mock, rewrite_state_mock


def _written_state(rewrite_state_mock):
    utils.assert_called_once(rewrite_state_mock)
    return rewrite_state_mock.call_args[0][0]


def test_in_grace_period_kernel_client_present_keeps_tunnel(mocker, tmpdir):
    clean_up_mock, ports_mock, rewrite_state_mock = _check_unmounted(
        mocker, tmpdir, {NFS_PORT}, now=TIME + GRACE_PERIOD
    )

    utils.assert_not_called(clean_up_mock)
    utils.assert_called_once(ports_mock)
    utils.assert_not_called(rewrite_state_mock)


def test_in_grace_period_kernel_client_gone_keeps_tunnel_and_records_the_time(
    mocker, tmpdir
):
    clean_up_mock, _, rewrite_state_mock = _check_unmounted(
        mocker, tmpdir, {NFS_PORT + 1}, now=TIME + 1
    )

    utils.assert_not_called(clean_up_mock)
    assert _written_state(rewrite_state_mock)[GONE] == TIME + 1


def test_in_grace_period_kernel_client_gone_and_settled_keeps_tunnel(mocker, tmpdir):
    clean_up_mock, _, _ = _check_unmounted(
        mocker, tmpdir, set(), now=TIME + GRACE_PERIOD, **{GONE: TIME + 1}
    )

    utils.assert_not_called(clean_up_mock)


def test_past_grace_period_kernel_client_present_keeps_tunnel_and_logs_once(
    mocker, tmpdir
):
    clean_up_mock, _, rewrite_state_mock = _check_unmounted(
        mocker, tmpdir, {NFS_PORT}, now=PAST_GRACE
    )

    utils.assert_not_called(clean_up_mock)
    assert _written_state(rewrite_state_mock)[LOGGED]


def test_past_grace_period_kernel_client_present_already_logged(mocker, tmpdir):
    clean_up_mock, _, rewrite_state_mock = _check_unmounted(
        mocker, tmpdir, {NFS_PORT}, now=PAST_GRACE, **{LOGGED: True}
    )

    utils.assert_not_called(clean_up_mock)
    utils.assert_not_called(rewrite_state_mock)


def test_past_grace_period_kernel_client_just_gone_waits_to_settle(mocker, tmpdir):
    clean_up_mock, _, rewrite_state_mock = _check_unmounted(
        mocker, tmpdir, set(), now=PAST_GRACE, **{LOGGED: True}
    )

    utils.assert_not_called(clean_up_mock)
    assert _written_state(rewrite_state_mock)[GONE] == PAST_GRACE


def test_past_grace_period_kernel_client_gone_not_settled_keeps_tunnel(mocker, tmpdir):
    clean_up_mock, _, _ = _check_unmounted(
        mocker,
        tmpdir,
        set(),
        now=PAST_GRACE + SETTLE - 1,
        **{GONE: PAST_GRACE, LOGGED: True}
    )

    utils.assert_not_called(clean_up_mock)


def test_past_grace_period_kernel_client_gone_and_settled_cleans_up(mocker, tmpdir):
    clean_up_mock, _, _ = _check_unmounted(
        mocker, tmpdir, set(), now=PAST_GRACE + SETTLE, **{GONE: PAST_GRACE}
    )

    utils.assert_called_once(clean_up_mock)


def test_grace_period_ends_with_kernel_client_long_gone(mocker, tmpdir):
    clean_up_mock, _, _ = _check_unmounted(
        mocker, tmpdir, set(), now=PAST_GRACE, **{GONE: TIME + 1}
    )

    utils.assert_called_once(clean_up_mock)


def test_kernel_client_back_clears_the_time(mocker, tmpdir):
    clean_up_mock, _, rewrite_state_mock = _check_unmounted(
        mocker, tmpdir, {NFS_PORT}, now=PAST_GRACE, **{GONE: TIME + 1, LOGGED: True}
    )

    utils.assert_not_called(clean_up_mock)
    assert GONE not in _written_state(rewrite_state_mock)


def test_kernel_client_present_within_the_max_wait(mocker, tmpdir):
    clean_up_mock, _, _ = _check_unmounted(
        mocker,
        tmpdir,
        {NFS_PORT},
        now=TIME + GRACE_PERIOD + MAX_WAIT - 1,
        **{LOGGED: True}
    )

    utils.assert_not_called(clean_up_mock)


def test_kernel_client_present_past_the_max_wait_cleans_up(mocker, tmpdir):
    clean_up_mock, _, _ = _check_unmounted(
        mocker, tmpdir, {NFS_PORT}, now=TIME + GRACE_PERIOD + MAX_WAIT
    )

    utils.assert_called_once(clean_up_mock)


def test_kernel_client_present_within_the_configured_max_wait(mocker, tmpdir):
    clean_up_mock, _, _ = _check_unmounted(
        mocker,
        tmpdir,
        {NFS_PORT},
        now=TIME + GRACE_PERIOD + 200,
        config=_config_with_max_wait(300),
    )

    utils.assert_not_called(clean_up_mock)


def test_max_wait_zero_cleans_up_at_the_grace_period(mocker, tmpdir):
    clean_up_mock, ports_mock, _ = _check_unmounted(
        mocker, tmpdir, {NFS_PORT}, now=PAST_GRACE, config=_config_with_max_wait(0)
    )

    utils.assert_called_once(clean_up_mock)
    utils.assert_not_called(ports_mock)


def test_default_max_wait_is_off():
    assert watchdog.DEFAULT_KERNEL_NFS_CLIENT_TEARDOWN_MAX_WAIT_SEC == 0


def test_missing_max_wait_cleans_up_at_the_grace_period(mocker, tmpdir):
    clean_up_mock, ports_mock, _ = _check_unmounted(
        mocker, tmpdir, {NFS_PORT}, now=PAST_GRACE, config=_get_config()
    )

    utils.assert_called_once(clean_up_mock)
    utils.assert_not_called(ports_mock)


def test_invalid_max_wait_uses_the_default(mocker, tmpdir):
    clean_up_mock, ports_mock, _ = _check_unmounted(
        mocker,
        tmpdir,
        {NFS_PORT},
        now=PAST_GRACE,
        config=_config_with_max_wait("abc"),
    )

    utils.assert_called_once(clean_up_mock)
    utils.assert_not_called(ports_mock)


def test_negative_max_wait_uses_the_default():
    config = _config_with_max_wait(-1)

    assert watchdog.get_kernel_nfs_client_teardown_max_wait_sec(config) == 0


def test_missing_max_wait_uses_the_default():
    assert watchdog.get_kernel_nfs_client_teardown_max_wait_sec(_get_config()) == 0


def test_kernel_clients_unknown_keeps_tunnel_in_grace_period(mocker, tmpdir):
    clean_up_mock, _, rewrite_state_mock = _check_unmounted(
        mocker, tmpdir, None, now=TIME + GRACE_PERIOD
    )

    utils.assert_not_called(clean_up_mock)
    utils.assert_not_called(rewrite_state_mock)


def test_kernel_clients_unknown_cleans_up_at_the_grace_period(mocker, tmpdir):
    clean_up_mock, _, _ = _check_unmounted(mocker, tmpdir, None, now=PAST_GRACE)

    utils.assert_called_once(clean_up_mock)


def test_kernel_clients_read_once_per_pass(mocker, tmpdir):
    state = dict(STATE)
    state["unmount_time"] = TIME
    state_files = {}
    for port in (NFS_PORT, NFS_PORT + 1):
        name = "fs-deadbeef.mnt.%d" % port
        tmpdir.join(name).write(json.dumps(state), ensure=True)
        state_files["mnt.%d" % port] = name

    clean_up_mock, _, _, _, _ = setup_mocks(mocker, mounts={}, state_files=state_files)
    ports_mock = mocker.patch(
        "watchdog.get_local_nfs_client_ports", return_value={NFS_PORT}
    )
    mocker.patch("time.time", return_value=TIME + 1)

    watchdog.check_efs_mounts(
        _config_with_max_wait(MAX_WAIT),
        [],
        GRACE_PERIOD,
        UNMOUNT_COUNT,
        state_file_dir=str(tmpdir),
    )

    utils.assert_called_once(ports_mock)
    utils.assert_not_called(clean_up_mock)


def test_mounted_does_not_read_kernel_clients(mocker, tmpdir):
    state_file_dir, state_file = create_state_file(tmpdir)
    setup_mocks(
        mocker,
        mounts={"mnt": watchdog.Mount("127.0.0.1", "/mnt", "nfs4", "", "0", "0")},
        state_files={"mnt": state_file},
    )
    ports_mock = mocker.patch("watchdog.get_local_nfs_client_ports")

    watchdog.check_efs_mounts(
        _config_with_max_wait(MAX_WAIT),
        [],
        GRACE_PERIOD,
        UNMOUNT_COUNT,
        state_file_dir=state_file_dir,
    )

    utils.assert_not_called(ports_mock)
