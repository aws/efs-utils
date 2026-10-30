# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
import gc
import os
import signal
import subprocess
import sys
import threading
import time
from unittest import mock

import pytest

import watchdog


def _block_before_exec():
    # Stands in for a child stuck on an inherited lock between fork and exec.
    time.sleep(60)


def _with_posix_spawn_support(mocker, supported=True):
    mocker.patch.object(subprocess, "_USE_POSIX_SPAWN", supported, create=True)


def _assert_no_timer_or_handler_left_behind(previous_handler):
    assert (0.0, 0.0) == signal.getitimer(signal.ITIMER_REAL)
    assert previous_handler == signal.getsignal(signal.SIGALRM)


def test_returns_running_process():
    previous_handler = signal.getsignal(signal.SIGALRM)

    process = watchdog.popen_with_spawn_deadline(
        ["echo", "hello"], stdout=subprocess.PIPE, close_fds=True
    )

    assert b"hello\n" == process.communicate(timeout=10)[0]
    assert 0 == process.returncode
    _assert_no_timer_or_handler_left_behind(previous_handler)


def test_child_that_never_execs_is_killed_and_reaped():
    previous_handler = signal.getsignal(signal.SIGALRM)
    start = time.monotonic()

    with pytest.raises(watchdog.SpawnTimeoutError) as excinfo:
        watchdog.popen_with_spawn_deadline(
            ["true"],
            spawn_timeout_sec=1,
            preexec_fn=_block_before_exec,
            close_fds=True,
        )

    assert time.monotonic() - start < 30
    process = excinfo.value.process
    assert process is not None
    assert -signal.SIGKILL == process.returncode
    with pytest.raises(ProcessLookupError):
        os.kill(process.pid, 0)
    _assert_no_timer_or_handler_left_behind(previous_handler)


def test_alarm_outside_the_exec_wait_is_ignored():
    # e.g. an alarm delivered after Popen() returned but before it was disarmed
    assert watchdog._raise_spawn_timeout(signal.SIGALRM, sys._getframe()) is None


def test_spawn_timeout_is_an_os_error():
    assert issubclass(watchdog.SpawnTimeoutError, OSError)


def test_missing_executable_still_raises_file_not_found():
    previous_handler = signal.getsignal(signal.SIGALRM)

    with pytest.raises(FileNotFoundError):
        watchdog.popen_with_spawn_deadline(["/nonexistent/efs-test-binary"])

    _assert_no_timer_or_handler_left_behind(previous_handler)


def test_no_deadline_off_the_main_thread(mocker):
    _with_posix_spawn_support(mocker)
    mocker.patch("shutil.which", return_value="/bin/true")
    popen_mock = mocker.patch("subprocess.Popen")
    setitimer_mock = mocker.patch("signal.setitimer")
    result = {}

    def spawn():
        result["process"] = watchdog.popen_with_spawn_deadline(["true"])

    thread = threading.Thread(target=spawn)
    thread.start()
    thread.join()

    popen_mock.assert_called_once_with(["/bin/true"], close_fds=False)
    assert popen_mock.return_value == result["process"]
    setitimer_mock.assert_not_called()


def test_no_deadline_when_another_timer_is_armed(mocker):
    _with_posix_spawn_support(mocker)
    mocker.patch("shutil.which", return_value="/bin/true")
    popen_mock = mocker.patch("subprocess.Popen")
    mocker.patch("signal.getitimer", return_value=(5.0, 0.0))
    setitimer_mock = mocker.patch("signal.setitimer")

    watchdog.popen_with_spawn_deadline(["true"])

    popen_mock.assert_called_once_with(["/bin/true"], close_fds=False)
    setitimer_mock.assert_not_called()


def _fake_process(pid=4321):
    process = subprocess.Popen.__new__(subprocess.Popen)
    process.pid = pid
    process.returncode = None
    return process


def test_kill_skipped_when_child_cannot_be_identified(mocker, caplog):
    kill_mock = mocker.patch("os.kill")

    watchdog._kill_unexeced_child(None, ["df"], 60)

    kill_mock.assert_not_called()
    assert "could not be identified" in caplog.text


def test_kill_failure_is_logged(mocker, caplog):
    mocker.patch("os.kill", side_effect=PermissionError("denied"))
    waitpid_mock = mocker.patch("os.waitpid")

    watchdog._kill_unexeced_child(_fake_process(), ["df"], 60)

    waitpid_mock.assert_not_called()
    assert "Failed to kill child process 4321" in caplog.text


def test_child_already_reaped_elsewhere(mocker):
    mocker.patch("os.kill")
    mocker.patch("os.waitpid", side_effect=ChildProcessError)
    process = _fake_process()

    watchdog._kill_unexeced_child(process, ["df"], 60)

    assert process.returncode is None


def test_child_not_exited_before_reap_deadline(mocker, caplog):
    mocker.patch("os.kill")
    mocker.patch("os.waitpid", return_value=(0, 0))
    mocker.patch(
        "time.monotonic",
        side_effect=[0, 0, watchdog.SPAWN_KILL_REAP_TIMEOUT_SEC + 1],
    )
    sleep_mock = mocker.patch("time.sleep")
    process = _fake_process()

    watchdog._kill_unexeced_child(process, ["df"], 60)

    sleep_mock.assert_called_once()
    assert process.returncode is None
    assert "Killed child process 4321 has not exited yet" in caplog.text


def test_child_left_unreaped_is_reaped_after_popen_is_dropped():
    process = subprocess.Popen(["sleep", "30"])
    pid = process.pid
    with mock.patch("os.waitpid", return_value=(0, 0)), mock.patch(
        "time.monotonic", side_effect=[0, watchdog.SPAWN_KILL_REAP_TIMEOUT_SEC + 1]
    ), mock.patch("time.sleep"):
        watchdog._kill_unexeced_child(process, ["sleep"], 60)

    del process
    gc.collect()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        subprocess.Popen(["true"]).wait()
        try:
            os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return
        time.sleep(0.05)
    pytest.fail("killed child %s was never reaped" % pid)


def test_prefer_posix_spawn_resolves_executable_and_keeps_fds_open(mocker):
    _with_posix_spawn_support(mocker)
    mocker.patch("shutil.which", return_value="/usr/bin/df")

    args, kwargs = watchdog._prefer_posix_spawn(
        ["df", "/mnt"], {"close_fds": True, "stdout": subprocess.DEVNULL}
    )

    assert ["/usr/bin/df", "/mnt"] == args
    assert {"close_fds": False, "stdout": subprocess.DEVNULL} == kwargs


def test_prefer_posix_spawn_leaves_unresolvable_executable_alone(mocker):
    _with_posix_spawn_support(mocker)
    mocker.patch("shutil.which", return_value=None)

    args, kwargs = watchdog._prefer_posix_spawn(["no-such-binary"], {"close_fds": True})

    assert ["no-such-binary"] == args
    assert {"close_fds": True} == kwargs


def test_prefer_posix_spawn_leaves_args_alone_without_posix_spawn_support(mocker):
    _with_posix_spawn_support(mocker, supported=False)
    which_mock = mocker.patch("shutil.which")

    args, kwargs = watchdog._prefer_posix_spawn(["df"], {"close_fds": True})

    which_mock.assert_not_called()
    assert ["df"] == args
    assert {"close_fds": True} == kwargs


def test_prefer_posix_spawn_leaves_shell_command_alone(mocker):
    _with_posix_spawn_support(mocker)
    which_mock = mocker.patch("shutil.which")

    args, kwargs = watchdog._prefer_posix_spawn("echo 1 > /tmp/x", {"shell": True})

    which_mock.assert_not_called()
    assert "echo 1 > /tmp/x" == args
    assert {"shell": True, "close_fds": False} == kwargs


@pytest.mark.parametrize(
    "option",
    [
        {"preexec_fn": _block_before_exec},
        {"start_new_session": True},
        {"cwd": "/"},
        {"pass_fds": (3,)},
    ],
)
def test_prefer_posix_spawn_leaves_child_side_options_alone(mocker, option):
    _with_posix_spawn_support(mocker)
    which_mock = mocker.patch("shutil.which")
    kwargs = dict(option, close_fds=True)

    args, new_kwargs = watchdog._prefer_posix_spawn(["df"], kwargs)

    which_mock.assert_not_called()
    assert ["df"] == args
    assert kwargs == new_kwargs


@pytest.mark.skipif(
    not getattr(subprocess, "_USE_POSIX_SPAWN", False),
    reason="this interpreter's subprocess has no posix_spawn() path",
)
def test_spawn_uses_posix_spawn_when_available(mocker):
    posix_spawn = mocker.spy(os, "posix_spawn")

    process = watchdog.popen_with_spawn_deadline(
        ["true"], stdout=subprocess.DEVNULL, close_fds=True
    )

    assert 0 == process.wait(timeout=10)
    posix_spawn.assert_called_once()
