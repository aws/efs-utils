# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
import subprocess
import sys
import time

import pytest

import watchdog

PID = 1234


def write_stat_file(tmpdir, pid, content):
    """Point the lookup at a stat file we control, so the parser can be tested
    against contents a real process cannot easily be made to produce."""
    stat_file = tmpdir.join("%s.stat" % pid)
    stat_file.write(content, ensure=True)
    return str(tmpdir) + "/%s.stat"


def test_returns_name_and_state_of_a_live_process():
    proc = subprocess.Popen(["sleep", "30"])
    try:
        name, state = watchdog.check_process_name_and_state(proc.pid)

        assert b"sleep" == name
        # Sleeping or running depending on scheduling, but never a dead state.
        assert state not in watchdog.DEAD_RUN_STATES
    finally:
        proc.kill()
        proc.wait()


def test_does_not_spawn_a_subprocess_on_linux(mocker):
    """Reading a process name must not fork a reader that can block in the kernel.
    If this fails, the watchdog can again deadlock its poll loop on a wedged pid."""
    # Start the real process before patching, which replaces the Popen used here.
    proc = subprocess.Popen(["sleep", "30"])
    try:
        popen = mocker.patch("watchdog.subprocess.Popen")

        name, _ = watchdog.check_process_name_and_state(proc.pid)

        assert b"sleep" == name
        assert not popen.called
    finally:
        proc.kill()
        proc.wait()


def test_reports_the_zombie_run_state():
    """A zombie's name is still readable, so only the state distinguishes it from a
    healthy process."""
    # Popen does not reap the child until wait()/poll(), so it is left a zombie.
    proc = subprocess.Popen(["true"])
    try:
        deadline = time.time() + 5
        while time.time() < deadline:
            with open("/proc/%s/stat" % proc.pid, "rb") as f:
                if f.read().rsplit(b")", 1)[1].split()[0] == b"Z":
                    break
            time.sleep(0.05)
        else:
            pytest.skip("could not observe the child in the zombie state")

        assert (b"true", b"Z") == watchdog.check_process_name_and_state(proc.pid)
    finally:
        proc.wait()


def test_name_that_impersonates_the_state_field(tmpdir):
    """Field 2 is attacker-controlled via prctl(PR_SET_NAME). A name like
    "x) Z 1 2 3" makes a parse that splits on the FIRST ')' read the state as "Z",
    reporting a live process as dead. Parsing from the LAST ')' defeats that."""
    script = tmpdir.join("spoof.py")
    script.write(
        "import ctypes, os, time\n"
        'ctypes.CDLL("libc.so.6").prctl(15, ctypes.c_char_p(b"x) Z 1 2 3"), 0, 0, 0)\n'
        "print(os.getpid(), flush=True)\n"
        "time.sleep(60)\n"
    )
    proc = subprocess.Popen(
        [sys.executable, str(script)], stdout=subprocess.PIPE, close_fds=True
    )
    try:
        pid = int(proc.stdout.readline().strip())

        deadline = time.time() + 5
        while time.time() < deadline:
            with open("/proc/%s/comm" % pid, "rb") as f:
                if f.read().strip() == b"x) Z 1 2 3":
                    break
            time.sleep(0.05)
        else:
            pytest.skip("could not observe the renamed comm")

        with open("/proc/%s/stat" % pid, "rb") as f:
            raw = f.read()
        # Establish the hostile shape is really present before asserting on it.
        assert raw.split(b")")[1].split()[0] == b"Z"

        name, state = watchdog.check_process_name_and_state(pid)

        # Alive, so the name comes back intact and the spoofed "Z" is not the state.
        assert b"x) Z 1 2 3" == name
        assert state not in watchdog.DEAD_RUN_STATES
    finally:
        proc.kill()
        proc.wait()


def test_returns_no_name_or_state_when_the_process_does_not_exist():
    with open("/proc/sys/kernel/pid_max") as f:
        pid_max = int(f.read().strip())

    # Pids are allocated below pid_max, so pid_max itself is never assigned.
    assert (None, None) == watchdog.check_process_name_and_state(pid_max)


def test_name_with_parentheses_is_parsed(mocker, tmpdir):
    """Field 2 is delimited by the LAST ')' in the line, not the first, because
    the name itself may contain both spaces and parentheses."""
    path_format = write_stat_file(tmpdir, PID, "%s (weird (name) here) S 1 2 3" % PID)
    mocker.patch.object(watchdog, "PROC_STAT_PATH_FORMAT", path_format)

    assert (b"weird (name) here", b"S") == watchdog.check_process_name_and_state(PID)


def test_zombie_with_parentheses_in_name_is_parsed(mocker, tmpdir):
    path_format = write_stat_file(tmpdir, PID, "%s (weird (name) here) Z 1 2 3" % PID)
    mocker.patch.object(watchdog, "PROC_STAT_PATH_FORMAT", path_format)

    assert (b"weird (name) here", b"Z") == watchdog.check_process_name_and_state(PID)


@pytest.mark.parametrize("state", ["X", "x"])
def test_reports_dead_run_states(mocker, tmpdir, state):
    """Neither is expected to be observed -- X is transient and x only existed on
    Linux 2.6.33-3.13 -- so these pin defensive behaviour rather than real cases."""
    path_format = write_stat_file(tmpdir, PID, "%s (efs-proxy) %s 1 2 3" % (PID, state))
    mocker.patch.object(watchdog, "PROC_STAT_PATH_FORMAT", path_format)

    name, run_state = watchdog.check_process_name_and_state(PID)

    assert b"efs-proxy" == name
    assert run_state in watchdog.DEAD_RUN_STATES


def test_returns_no_name_or_state_for_malformed_stat_content(mocker, tmpdir):
    path_format = write_stat_file(tmpdir, PID, "no parentheses here")
    mocker.patch.object(watchdog, "PROC_STAT_PATH_FORMAT", path_format)

    assert (None, None) == watchdog.check_process_name_and_state(PID)


def test_macos_uses_ps_and_reports_no_state(mocker):
    """macOS has no procfs, so `ps` gives a name but no run state."""
    mocker.patch("watchdog.check_if_running_on_macos", return_value=True)
    popen = mocker.patch("watchdog.subprocess.Popen")
    popen.return_value.communicate.return_value = (b"/usr/bin/efs-proxy config", b"")

    assert (
        b"/usr/bin/efs-proxy config",
        None,
    ) == watchdog.check_process_name_and_state(PID)

    assert ["ps", "-p", str(PID), "-o", "command="] == popen.call_args[0][0]
    assert (
        watchdog.PROCESS_NAME_TIMEOUT_SEC
        == popen.return_value.communicate.call_args[1]["timeout"]
    )


def test_macos_kills_ps_and_returns_nothing_on_timeout(mocker):
    mocker.patch("watchdog.check_if_running_on_macos", return_value=True)
    popen = mocker.patch("watchdog.subprocess.Popen")
    # Only the first call times out. The second is the post-kill reap, which is
    # issued without a timeout and so cannot raise TimeoutExpired.
    popen.return_value.communicate.side_effect = [
        subprocess.TimeoutExpired(cmd="ps", timeout=watchdog.PROCESS_NAME_TIMEOUT_SEC),
        (b"", b""),
    ]

    assert (None, None) == watchdog.check_process_name_and_state(PID)

    assert popen.return_value.kill.called


def test_macos_reaps_the_killed_ps_child_on_timeout(mocker):
    """kill() only signals. Without a second communicate() the child stays a zombie
    and leaks its two pipes, once per timeout, for the life of the host."""
    mocker.patch("watchdog.check_if_running_on_macos", return_value=True)
    popen = mocker.patch("watchdog.subprocess.Popen")
    communicate = popen.return_value.communicate
    communicate.side_effect = [
        subprocess.TimeoutExpired(cmd="ps", timeout=watchdog.PROCESS_NAME_TIMEOUT_SEC),
        (b"", b""),
    ]

    assert (None, None) == watchdog.check_process_name_and_state(PID)

    assert 2 == communicate.call_count
    # The reap carries no timeout: the child is already SIGKILLed so the wait is
    # bounded, and a second TimeoutExpired here would escape the handler.
    assert {} == communicate.call_args_list[1][1]
