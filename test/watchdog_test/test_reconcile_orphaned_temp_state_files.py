#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#
"""Tests for reconcile_orphaned_temp_state_files."""

import errno
import json
import logging
import os
import time

import pytest

import watchdog
from efs_utils_common import proxy

MOUNTPOINT = "/mount/dir"
TEMP_NAME = "~fs-deadbeef.mount.dir.12345"
FINAL_NAME = "fs-deadbeef.mount.dir.12345"
MOUNT_STATE_DIR = FINAL_NAME + "+"
PID = 4242
WRITER_PID = 31337
WRITER_START = 123456789


def _write(tmpdir, name, content):
    p = tmpdir.join(name)
    p.write(content, ensure=True)
    return str(p)


def _temp(tmpdir, **extra):
    state = {
        "cmd": ["/usr/bin/efs-proxy"],
        "pid": PID,
        "mountpoint": MOUNTPOINT,
        "writer_pid": WRITER_PID,
        "writer_start_time": WRITER_START,
    }
    state.update(extra)
    return _write(tmpdir, TEMP_NAME, json.dumps(state))


def _legacy_temp(tmpdir, **extra):
    """A temp from a mount helper that did not record its writer."""
    state = {"cmd": ["/usr/bin/efs-proxy"], "pid": PID, "mountpoint": MOUNTPOINT}
    state.update(extra)
    return _write(tmpdir, TEMP_NAME, json.dumps(state))


def _backdate(path, seconds=watchdog.ORPHANED_TEMP_STATE_FILE_GRACE_SEC + 60):
    old = time.time() - seconds
    os.utime(path, (old, old))


def _writer(mocker, start_time):
    """Make the writer pid look like a process with the given start time (None: gone)."""
    return mocker.patch("watchdog.get_process_start_time", return_value=start_time)


# ---- get_orphaned_temp_state_files ----


def test_get_orphaned_temp_state_files_finds_only_temp(tmpdir):
    _write(tmpdir, TEMP_NAME, "{}")
    _write(tmpdir, FINAL_NAME, "{}")
    tmpdir.mkdir("~fs-adir")

    orphans = watchdog.get_orphaned_temp_state_files(str(tmpdir))

    assert orphans == [str(tmpdir.join(TEMP_NAME))]


def test_get_orphaned_temp_state_files_nonexistent_dir(tmpdir):
    assert watchdog.get_orphaned_temp_state_files(str(tmpdir.join("nope"))) == []


# ---- writer liveness ----


def test_finalizes_when_writer_is_gone(tmpdir, mocker):
    _writer(mocker, None)
    temp = _temp(tmpdir)

    watchdog.reconcile_orphaned_temp_state_files(str(tmpdir))

    assert not os.path.exists(temp)
    with open(str(tmpdir.join(FINAL_NAME))) as f:
        assert json.load(f)["pid"] == PID


def test_finalizes_when_writer_pid_was_reused(tmpdir, mocker):
    _writer(mocker, WRITER_START + 1)
    temp = _temp(tmpdir)

    watchdog.reconcile_orphaned_temp_state_files(str(tmpdir))

    assert not os.path.exists(temp)
    assert os.path.exists(str(tmpdir.join(FINAL_NAME)))


def test_skips_while_writer_is_alive_regardless_of_age(tmpdir, mocker):
    _writer(mocker, WRITER_START)
    temp = _temp(tmpdir)
    _backdate(temp, seconds=3600)

    watchdog.reconcile_orphaned_temp_state_files(str(tmpdir))

    assert os.path.exists(temp)
    assert not os.path.exists(str(tmpdir.join(FINAL_NAME)))


def test_finalizing_keeps_mount_artifacts(tmpdir, mocker):
    # check_efs_mounts owns the record from here; nothing is deleted.
    _writer(mocker, None)
    cert = _write(tmpdir, "fs-deadbeef.crt", "cert")
    msd = tmpdir.mkdir(MOUNT_STATE_DIR)
    temp = _temp(tmpdir, files=[cert], mountStateDir=MOUNT_STATE_DIR)

    watchdog.reconcile_orphaned_temp_state_files(str(tmpdir))

    assert not os.path.exists(temp)
    assert "mount.dir.12345" in watchdog.get_state_files(str(tmpdir))
    assert os.path.exists(cert) and os.path.isdir(str(msd))


def test_writer_check_reads_real_proc_stat(tmpdir):
    # Unmocked: our own pid is alive with its real start time, so the temp stays.
    temp = _temp(
        tmpdir,
        writer_pid=os.getpid(),
        writer_start_time=watchdog.get_process_start_time(os.getpid()),
    )
    _backdate(temp)

    watchdog.reconcile_orphaned_temp_state_files(str(tmpdir))

    assert os.path.exists(temp)


def test_tolerates_writer_finishing_its_own_rename_first(tmpdir, mocker):
    _writer(mocker, None)
    _temp(tmpdir)
    mocker.patch("watchdog.os.rename", side_effect=FileNotFoundError())

    watchdog.reconcile_orphaned_temp_state_files(str(tmpdir))  # must not raise


# ---- legacy temps with no recorded writer: grace period ----


def test_legacy_temp_finalized_past_grace(tmpdir):
    temp = _legacy_temp(tmpdir)
    _backdate(temp)

    watchdog.reconcile_orphaned_temp_state_files(str(tmpdir))

    assert not os.path.exists(temp)
    assert os.path.exists(str(tmpdir.join(FINAL_NAME)))


def test_legacy_temp_kept_within_grace(tmpdir):
    temp = _legacy_temp(tmpdir)

    watchdog.reconcile_orphaned_temp_state_files(str(tmpdir))

    assert os.path.exists(temp)
    assert not os.path.exists(str(tmpdir.join(FINAL_NAME)))


def test_temp_without_start_time_is_treated_as_legacy(tmpdir, mocker):
    _writer(mocker, None)
    temp = _legacy_temp(tmpdir, writer_pid=WRITER_PID)

    watchdog.reconcile_orphaned_temp_state_files(str(tmpdir))

    assert os.path.exists(temp)


# ---- temps that cannot be finalized ----


def test_removes_stale_temp_when_final_exists(tmpdir, mocker):
    _writer(mocker, None)
    cert = _write(tmpdir, "fs-deadbeef.crt", "cert")
    msd = tmpdir.mkdir(MOUNT_STATE_DIR)
    final = _write(tmpdir, FINAL_NAME, json.dumps({"pid": PID}))
    temp = _temp(tmpdir, files=[cert], mountStateDir=MOUNT_STATE_DIR)

    watchdog.reconcile_orphaned_temp_state_files(str(tmpdir), grace_period_sec=0)

    assert not os.path.exists(temp)
    with open(final) as f:
        assert json.load(f) == {"pid": PID}
    assert os.path.exists(cert) and os.path.isdir(str(msd))


def test_keeps_recent_temp_when_final_exists(tmpdir, mocker):
    _writer(mocker, None)
    _write(tmpdir, FINAL_NAME, "{}")
    temp = _temp(tmpdir)

    watchdog.reconcile_orphaned_temp_state_files(str(tmpdir))

    assert os.path.exists(temp)


@pytest.mark.parametrize("content", ["{not-json", "", json.dumps({"pid": PID})])
def test_removes_unreadable_temp_past_grace(tmpdir, content):
    temp = _write(tmpdir, TEMP_NAME, content)

    watchdog.reconcile_orphaned_temp_state_files(str(tmpdir), grace_period_sec=0)

    assert not os.path.exists(temp)
    assert not os.path.exists(str(tmpdir.join(FINAL_NAME)))


def test_keeps_recent_unreadable_temp(tmpdir):
    temp = _write(tmpdir, TEMP_NAME, "{not-json")

    watchdog.reconcile_orphaned_temp_state_files(str(tmpdir))

    assert os.path.exists(temp)


SCRATCH_NAME = "~" + TEMP_NAME + ".tmp"


def test_removes_stale_scratch_file(tmpdir):
    scratch = _write(tmpdir, SCRATCH_NAME, "{")
    _backdate(scratch)

    watchdog.reconcile_orphaned_temp_state_files(str(tmpdir))

    assert not os.path.exists(scratch)


def test_keeps_recent_scratch_file(tmpdir):
    scratch = _write(tmpdir, SCRATCH_NAME, "{")

    watchdog.reconcile_orphaned_temp_state_files(str(tmpdir))

    assert os.path.exists(scratch)


def test_scratch_file_is_not_mistaken_for_a_temp(tmpdir, mocker):
    """A leaked scratch must never be finalized into a state file."""
    _writer(mocker, None)
    _write(tmpdir, SCRATCH_NAME, json.dumps({"cmd": ["x"], "pid": PID}))

    watchdog.reconcile_orphaned_temp_state_files(str(tmpdir), grace_period_sec=0)

    assert os.listdir(str(tmpdir)) == []


def test_scratch_sweep_ignores_other_files(tmpdir):
    kept = [
        _write(tmpdir, FINAL_NAME, "{}"),
        _write(tmpdir, "stunnel-config." + FINAL_NAME, ""),
        _write(tmpdir, "unrelated.tmp", ""),
    ]
    for path in kept:
        _backdate(path)
    tmpdir.mkdir("~dir.tmp")

    watchdog.remove_stale_scratch_files(str(tmpdir), 0, time.time())

    assert all(os.path.exists(path) for path in kept)
    assert os.path.isdir(str(tmpdir.join("~dir.tmp")))


PROXY_START = 55555


def _final_state(tmpdir):
    with open(str(tmpdir.join(FINAL_NAME))) as f:
        return json.load(f)


def test_finalizing_drops_proxy_pid_reused_by_another_process(tmpdir, mocker):
    _writer(mocker, None)
    _temp(tmpdir, pid_start_time=PROXY_START)
    mocker.patch(
        "watchdog.get_process_start_time",
        side_effect=lambda pid: None if pid == WRITER_PID else PROXY_START + 1,
    )

    watchdog.reconcile_orphaned_temp_state_files(str(tmpdir))

    state = _final_state(tmpdir)
    assert "pid" not in state and "pid_start_time" not in state
    assert state["cmd"] == ["/usr/bin/efs-proxy"]
    assert os.listdir(str(tmpdir)) == [FINAL_NAME]


def test_finalizing_keeps_proxy_pid_that_still_matches(tmpdir, mocker):
    _temp(tmpdir, pid_start_time=PROXY_START)
    mocker.patch(
        "watchdog.get_process_start_time",
        side_effect=lambda pid: None if pid == WRITER_PID else PROXY_START,
    )

    watchdog.reconcile_orphaned_temp_state_files(str(tmpdir))

    assert _final_state(tmpdir)["pid"] == PID


def test_finalizing_keeps_legacy_proxy_pid(tmpdir, mocker):
    """Without a recorded start time the pid cannot be validated; check_efs_mounts decides."""
    _writer(mocker, None)
    _temp(tmpdir)

    watchdog.reconcile_orphaned_temp_state_files(str(tmpdir))

    assert _final_state(tmpdir)["pid"] == PID


def test_proxy_and_watchdog_start_time_agree():
    """The watchdog cannot import proxy, so the two copies are pinned here."""
    assert watchdog.get_process_start_time(os.getpid()) == proxy.get_process_start_time(
        os.getpid()
    )
    assert watchdog.PS_LSTART_ENV == proxy.PS_LSTART_ENV


def test_proxy_and_watchdog_run_ps_identically(mocker):
    mocker.patch("watchdog.check_if_running_on_macos", return_value=True)
    mocker.patch("efs_utils_common.proxy.check_if_platform_is_mac", return_value=True)
    proc = mocker.MagicMock()
    proc.communicate.return_value = (b"x\n", b"")
    popen = mocker.patch("subprocess.Popen", return_value=proc)

    watchdog.get_process_start_time(7)
    proxy.get_process_start_time(7)

    first, second = popen.call_args_list
    assert first[0] == second[0]
    assert first[1]["env"] == second[1]["env"]


def test_logs_mountpoint_when_finalizing(tmpdir, mocker, caplog):
    _writer(mocker, None)
    _temp(tmpdir)

    watchdog.reconcile_orphaned_temp_state_files(str(tmpdir))

    assert MOUNTPOINT in caplog.text


# ---- robustness ----


def test_leaves_finalized_state_file_untouched(tmpdir):
    final = _write(tmpdir, FINAL_NAME, json.dumps({"pid": PID}))

    watchdog.reconcile_orphaned_temp_state_files(str(tmpdir), grace_period_sec=0)

    assert os.path.exists(final)


def test_noop_on_empty_dir(tmpdir):
    watchdog.reconcile_orphaned_temp_state_files(str(tmpdir), grace_period_sec=0)


def test_skips_temp_when_stat_fails(tmpdir, mocker):
    _writer(mocker, None)
    temp = _temp(tmpdir)
    mocker.patch("watchdog.os.path.getmtime", side_effect=OSError("gone"))

    watchdog.reconcile_orphaned_temp_state_files(str(tmpdir))

    assert os.path.exists(temp)


# ---- get_process_start_time ----


def test_get_process_start_time_of_self_is_stable():
    first = watchdog.get_process_start_time(os.getpid())

    assert isinstance(first, int)
    assert watchdog.get_process_start_time(os.getpid()) == first


def test_get_process_start_time_of_missing_pid_is_none():
    assert watchdog.get_process_start_time(2**22 + 1) is None


def test_get_process_start_time_handles_parentheses_in_name(mocker):
    stat = (
        b"7 (a (weird) name) S 1 7 7 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 98765 0 0\n"
    )
    mocker.patch("builtins.open", mocker.mock_open(read_data=stat))

    assert watchdog.get_process_start_time(7) == 98765


def test_get_process_start_time_on_macos_uses_ps(mocker):
    mocker.patch("watchdog.check_if_running_on_macos", return_value=True)
    proc = mocker.MagicMock()
    proc.communicate.return_value = (b"Thu Oct  8 12:00:00 2026\n", b"")
    popen = mocker.patch("watchdog.subprocess.Popen", return_value=proc)

    assert watchdog.get_process_start_time(7) == "Thu Oct  8 12:00:00 2026"
    assert popen.call_args[0][0] == ["ps", "-p", "7", "-o", "lstart="]
    assert popen.call_args[1]["env"] == proxy.PS_LSTART_ENV


def test_get_process_start_time_on_macos_missing_pid_is_none(mocker):
    mocker.patch("watchdog.check_if_running_on_macos", return_value=True)
    proc = mocker.MagicMock()
    proc.communicate.return_value = (b"", b"")
    mocker.patch("watchdog.subprocess.Popen", return_value=proc)

    assert watchdog.get_process_start_time(7) is None


def test_get_process_start_time_on_macos_times_out_as_none(mocker):
    mocker.patch("watchdog.check_if_running_on_macos", return_value=True)
    proc = mocker.MagicMock()
    proc.communicate.side_effect = [
        watchdog.subprocess.TimeoutExpired("ps", watchdog.PROCESS_NAME_TIMEOUT_SEC),
        (b"", b""),
    ]
    mocker.patch("watchdog.subprocess.Popen", return_value=proc)

    assert watchdog.get_process_start_time(7) is None
    proc.kill.assert_called_once()


@pytest.mark.parametrize("stat", [b"7 (short) S 1 7\n", b"7 (x) S " + b"a " * 25])
def test_get_process_start_time_with_malformed_stat_is_none(mocker, stat):
    mocker.patch("builtins.open", mocker.mock_open(read_data=stat))

    assert watchdog.get_process_start_time(7) is None


def test_remove_orphaned_path_logs_unexpected_error(mocker, caplog):
    mocker.patch("watchdog.os.remove", side_effect=OSError(errno.EACCES, "denied"))

    with caplog.at_level(logging.DEBUG):
        watchdog._remove_orphaned_path("/state/~fs-x")

    assert "Failed to remove orphaned path" in caplog.text


def test_scratch_sweep_skips_file_that_vanishes(tmpdir, mocker):
    scratch = _write(tmpdir, SCRATCH_NAME, "{")
    mocker.patch("watchdog.os.path.getmtime", side_effect=OSError("gone"))

    watchdog.remove_stale_scratch_files(str(tmpdir), 0, time.time())

    assert os.path.exists(scratch)


def test_writer_check_on_macos_compares_ps_output(tmpdir, mocker):
    mocker.patch("watchdog.check_if_running_on_macos", return_value=True)
    proc = mocker.MagicMock()
    proc.communicate.return_value = (b"Thu Oct  8 12:00:00 2026\n", b"")
    mocker.patch("watchdog.subprocess.Popen", return_value=proc)
    temp = _temp(tmpdir, writer_start_time="Thu Oct  8 12:00:00 2026")
    _backdate(temp, seconds=3600)

    watchdog.reconcile_orphaned_temp_state_files(str(tmpdir))

    assert os.path.exists(temp)
