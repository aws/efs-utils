# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
import logging
import os
import socket
import subprocess
import sys
import time
from unittest.mock import MagicMock

import pytest

import efs_utils_common.network_utils as network_utils
import efs_utils_common.proxy as proxy

from .. import utils

FS_ID = "fs-deadbeef"

needs_procfs = pytest.mark.skipif(
    not os.path.exists("/proc/self/net/tcp"), reason="requires procfs"
)

# Binds and listens on the port in argv[1], or exits 1 if the bind fails, like a
# tunnel whose port is already taken.
LISTENER = (
    "import socket, sys, time\n"
    "s = socket.socket()\n"
    "try:\n"
    "    s.bind(('127.0.0.1', int(sys.argv[1])))\n"
    "except OSError:\n"
    "    sys.exit(1)\n"
    "s.listen(1)\n"
    "print('listening', flush=True)\n"
    "time.sleep(60)\n"
)


def _listening_socket():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    return sock, sock.getsockname()[1]


def _free_port():
    sock, port = _listening_socket()
    sock.close()
    return port


def _start_listener(port):
    proc = subprocess.Popen(
        [sys.executable, "-c", LISTENER, str(port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    line = proc.stdout.readline()
    assert b"listening" in line, proc.communicate()
    return proc


def _stop(proc):
    proc.kill()
    proc.communicate()


def _tunnel_mock(returncode=None, pid=12345):
    tunnel_proc = MagicMock()
    tunnel_proc.pid = pid
    tunnel_proc.returncode = returncode
    tunnel_proc.communicate.return_value = (b"", b"Failed to bind 127.0.0.1")
    return tunnel_proc


@needs_procfs
def test_process_listens_on_port_own_listener():
    sock, port = _listening_socket()
    try:
        assert network_utils.process_listens_on_port(os.getpid(), port) is True
    finally:
        sock.close()


@needs_procfs
def test_process_listens_on_port_other_process_listener():
    port = _free_port()
    other = _start_listener(port)
    try:
        assert network_utils.process_listens_on_port(os.getpid(), port) is False
        assert network_utils.process_listens_on_port(other.pid, port) is True
    finally:
        _stop(other)


@needs_procfs
def test_process_listens_on_port_bound_but_not_listening():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    try:
        port = sock.getsockname()[1]
        assert network_utils.process_listens_on_port(os.getpid(), port) is False
    finally:
        sock.close()


@needs_procfs
def test_process_listens_on_port_other_address():
    """A listener on the port at another loopback address is not the proxy's."""
    sock = socket.socket()
    sock.bind(("127.0.0.2", 0))
    sock.listen(1)
    try:
        port = sock.getsockname()[1]
        assert network_utils.process_listens_on_port(os.getpid(), port) is False
        assert (
            network_utils.process_listens_on_port(os.getpid(), port, "127.0.0.2")
            is True
        )
    finally:
        sock.close()


def test_proc_net_tcp_address():
    expected_address = "0100007F" if sys.byteorder == "little" else "7F000001"
    assert (
        network_utils._proc_net_tcp_address("127.0.0.1", 20049)
        == expected_address + ":4E51"
    )


def test_process_listens_on_port_without_procfs(tmpdir):
    assert (
        network_utils.process_listens_on_port(1234, 20049, proc_root=str(tmpdir))
        is None
    )


def test_process_listens_on_port_unreadable_process(tmpdir):
    """A process whose entries are gone, such as one that is exiting, is not listening."""
    tmpdir.mkdir("self").mkdir("net")
    assert (
        network_utils.process_listens_on_port(4321, 20049, proc_root=str(tmpdir))
        is False
    )


@needs_procfs
def test_process_listens_on_port_exited_process():
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait()
    assert network_utils.process_listens_on_port(proc.pid, 20049) is False


LISTEN_ROW = (
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    "   0: 0100007F:4E51 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 333 1\n"
)


def _proc_with_listener(tmpdir, pid=4321):
    """A fake procfs where `pid` has a LISTEN row for 127.0.0.1:20049, inode 333."""
    tmpdir.mkdir("self").mkdir("net")
    tmpdir.mkdir(str(pid)).mkdir("net").join("tcp").write(LISTEN_ROW)
    return pid, 20049


def test_process_listens_on_port_no_fd_dir(tmpdir):
    """The socket table is readable but the fd directory is gone: the process exited."""
    pid, port = _proc_with_listener(tmpdir)
    assert (
        network_utils.process_listens_on_port(pid, port, proc_root=str(tmpdir)) is False
    )


def test_process_listens_on_port_fd_dir_refused(tmpdir, mocker):
    """Listing the fd directory is refused: fall back rather than report "not listening"."""
    pid, port = _proc_with_listener(tmpdir)
    tmpdir.join(str(pid)).mkdir("fd")
    mocker.patch(
        "efs_utils_common.network_utils.os.listdir",
        side_effect=PermissionError(13, "Permission denied"),
    )
    assert (
        network_utils.process_listens_on_port(pid, port, proc_root=str(tmpdir)) is None
    )


def test_process_listens_on_port_socket_table_refused(tmpdir, mocker):
    pid, port = _proc_with_listener(tmpdir)
    mocker.patch(
        "efs_utils_common.network_utils.get_listening_socket_inodes",
        side_effect=PermissionError(13, "Permission denied"),
    )
    assert (
        network_utils.process_listens_on_port(pid, port, proc_root=str(tmpdir)) is None
    )


def test_process_listens_on_port_fd_link_refused(tmpdir, mocker):
    pid, port = _proc_with_listener(tmpdir)
    fd_dir = tmpdir.join(str(pid)).mkdir("fd")
    os.symlink("socket:[333]", str(fd_dir.join("3")))
    mocker.patch(
        "efs_utils_common.network_utils.os.readlink",
        side_effect=PermissionError(13, "Permission denied"),
    )
    assert (
        network_utils.process_listens_on_port(pid, port, proc_root=str(tmpdir)) is None
    )


def test_process_listens_on_port_fd_closed_during_listing(tmpdir, mocker):
    """An fd closed between the listing and the readlink is skipped, not a refusal."""
    pid, port = _proc_with_listener(tmpdir)
    fd_dir = tmpdir.join(str(pid)).mkdir("fd")
    os.symlink("socket:[111]", str(fd_dir.join("3")))
    mocker.patch(
        "efs_utils_common.network_utils.os.readlink",
        side_effect=FileNotFoundError(2, "No such file or directory"),
    )
    assert (
        network_utils.process_listens_on_port(pid, port, proc_root=str(tmpdir)) is False
    )


def test_process_listens_on_port_found_despite_refused_link(tmpdir, mocker):
    pid, port = _proc_with_listener(tmpdir)
    fd_dir = tmpdir.join(str(pid)).mkdir("fd")
    real_readlink = os.readlink

    def readlink(path):
        if path.endswith("/3"):
            raise PermissionError(13, "Permission denied")
        return real_readlink(path)

    os.symlink("socket:[111]", str(fd_dir.join("3")))
    os.symlink("socket:[333]", str(fd_dir.join("4")))
    mocker.patch("efs_utils_common.network_utils.os.readlink", side_effect=readlink)
    assert (
        network_utils.process_listens_on_port(pid, port, proc_root=str(tmpdir)) is True
    )


def test_process_listens_on_port_parses_socket_table(tmpdir):
    pid, port = 4321, 20049
    tmpdir.mkdir("self").mkdir("net")
    net_dir = tmpdir.mkdir(str(pid)).mkdir("net")
    fd_dir = tmpdir.join(str(pid)).mkdir("fd")
    header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    net_dir.join("tcp").write(
        header
        # Established connection on the port: not a listener.
        + "   0: 0100007F:4E51 0100007F:D431 01 00000000:00000000 00:00000000 00000000     0        0 111 1\n"
        # Listener on another port.
        + "   1: 0100007F:4E52 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 222 1\n"
        # Listener on the port.
        + "   2: 0100007F:4E51 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 333 1\n"
        # Listener on the same port at another address (127.0.0.2): not the one
        # mount.nfs4 connects to.
        + "   3: 0200007F:4E51 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 444 1\n"
    )
    os.symlink("socket:[111]", str(fd_dir.join("3")))
    os.symlink("socket:[222]", str(fd_dir.join("4")))
    os.symlink("socket:[444]", str(fd_dir.join("6")))
    os.symlink("pipe:[333]", str(fd_dir.join("7")))
    assert (
        network_utils.process_listens_on_port(pid, port, proc_root=str(tmpdir)) is False
    )

    os.symlink("socket:[333]", str(fd_dir.join("5")))
    assert (
        network_utils.process_listens_on_port(pid, port, proc_root=str(tmpdir)) is True
    )


def test_wait_for_tunnel_to_listen_returns_once_tunnel_listens(mocker):
    listens_mock = mocker.patch(
        "efs_utils_common.proxy.process_listens_on_port",
        side_effect=[False, False, True],
    )
    sleep_mock = mocker.patch("efs_utils_common.proxy.time.sleep")
    tlsport_mock = mocker.patch("efs_utils_common.proxy.test_tlsport")

    proxy.wait_for_tunnel_to_listen(_tunnel_mock(), FS_ID, {"tlsport": 20049})

    utils.assert_called_n_times(listens_mock, 3)
    utils.assert_called_n_times(sleep_mock, 2)
    utils.assert_not_called(tlsport_mock)


def test_wait_for_tunnel_to_listen_fails_when_tunnel_exits(mocker, capsys):
    mocker.patch("efs_utils_common.proxy.process_listens_on_port", return_value=False)
    mocker.patch("efs_utils_common.proxy.time.sleep")

    with pytest.raises(SystemExit) as ex:
        proxy.wait_for_tunnel_to_listen(
            _tunnel_mock(returncode=1), FS_ID, {"tlsport": 20049}
        )

    assert 0 != ex.value.code
    _, err = capsys.readouterr()
    assert "Failed to initialize tunnel for %s" % FS_ID in err


def test_wait_for_tunnel_to_listen_falls_back_to_connect_check(mocker):
    mocker.patch("efs_utils_common.proxy.procfs_available", return_value=False)
    mocker.patch("efs_utils_common.proxy.process_listens_on_port", return_value=None)
    tlsport_mock = mocker.patch("efs_utils_common.proxy.test_tlsport")

    proxy.wait_for_tunnel_to_listen(_tunnel_mock(), FS_ID, {"tlsport": 20049})

    tlsport_mock.assert_called_once_with(20049)


def test_wait_for_tunnel_to_listen_connect_check_under_netns(mocker):
    mocker.patch("efs_utils_common.proxy.procfs_available", return_value=False)
    mocker.patch("efs_utils_common.proxy.process_listens_on_port", return_value=None)
    tlsport_mock = mocker.patch("efs_utils_common.proxy.test_tlsport")
    netns_mock = mocker.patch("efs_utils_common.proxy.NetNS")

    proxy.wait_for_tunnel_to_listen(
        _tunnel_mock(), FS_ID, {"tlsport": 20049, "netns": "/proc/1000/ns/net"}
    )

    netns_mock.assert_called_once_with(nspath="/proc/1000/ns/net")
    tlsport_mock.assert_called_once_with(20049)


def test_wait_for_tunnel_to_listen_gives_up_waiting(mocker, caplog):
    mocker.patch("efs_utils_common.proxy.process_listens_on_port", return_value=False)
    mocker.patch("efs_utils_common.proxy.TUNNEL_LISTEN_TIMEOUT_SEC", 0)
    mocker.patch(
        "efs_utils_common.proxy.verify_tlsport_can_be_connected", return_value=False
    )

    with caplog.at_level(logging.WARNING):
        proxy.wait_for_tunnel_to_listen(_tunnel_mock(), FS_ID, {"tlsport": 20049})

    assert "is not listening on port 20049" in caplog.text


def test_wait_for_tunnel_to_listen_fails_when_port_answers_at_deadline(mocker, capsys):
    """
    The tunnel is still running but not listening when the wait ends, and another
    process answers on the port: mount.nfs4 would be attached to that process.
    """
    mocker.patch("efs_utils_common.proxy.process_listens_on_port", return_value=False)
    mocker.patch("efs_utils_common.proxy.TUNNEL_LISTEN_TIMEOUT_SEC", 0)
    mocker.patch(
        "efs_utils_common.proxy.verify_tlsport_can_be_connected", return_value=True
    )

    with pytest.raises(SystemExit) as ex:
        proxy.wait_for_tunnel_to_listen(_tunnel_mock(), FS_ID, {"tlsport": 20049})

    assert 0 != ex.value.code
    _, err = capsys.readouterr()
    assert "port 20049 is held by another process" in err


def test_wait_for_tunnel_to_listen_deadline_connect_check_under_netns(mocker):
    mocker.patch("efs_utils_common.proxy.process_listens_on_port", return_value=False)
    mocker.patch("efs_utils_common.proxy.TUNNEL_LISTEN_TIMEOUT_SEC", 0)
    connect_mock = mocker.patch(
        "efs_utils_common.proxy.verify_tlsport_can_be_connected", return_value=False
    )
    netns_mock = mocker.patch("efs_utils_common.proxy.NetNS")

    proxy.wait_for_tunnel_to_listen(
        _tunnel_mock(), FS_ID, {"tlsport": 20049, "netns": "/proc/1000/ns/net"}
    )

    netns_mock.assert_called_once_with(nspath="/proc/1000/ns/net")
    connect_mock.assert_called_once_with(20049)


def test_wait_for_tunnel_to_listen_own_listener_appears_at_deadline(mocker):
    """The tunnel starts listening between the last procfs read and the connect."""
    listens_mock = mocker.patch(
        "efs_utils_common.proxy.process_listens_on_port", side_effect=[False, True]
    )
    mocker.patch("efs_utils_common.proxy.TUNNEL_LISTEN_TIMEOUT_SEC", 0)
    mocker.patch(
        "efs_utils_common.proxy.verify_tlsport_can_be_connected", return_value=True
    )

    proxy.wait_for_tunnel_to_listen(_tunnel_mock(), FS_ID, {"tlsport": 20049})

    utils.assert_called_n_times(listens_mock, 2)


def test_wait_for_tunnel_to_listen_ownership_unreadable_at_deadline(mocker):
    """Ownership cannot be read at the deadline: do not claim another process holds the port."""
    mocker.patch(
        "efs_utils_common.proxy.process_listens_on_port", side_effect=[False, None]
    )
    mocker.patch("efs_utils_common.proxy.TUNNEL_OWNERSHIP_UNREADABLE_GRACE_SEC", 0)
    mocker.patch("efs_utils_common.proxy.TUNNEL_LISTEN_TIMEOUT_SEC", 0)
    mocker.patch(
        "efs_utils_common.proxy.verify_tlsport_can_be_connected", return_value=True
    )
    fatal_mock = mocker.patch("efs_utils_common.proxy.fatal_error")

    proxy.wait_for_tunnel_to_listen(_tunnel_mock(), FS_ID, {"tlsport": 20049})

    utils.assert_not_called(fatal_mock)


def test_wait_for_tunnel_to_listen_unreadable_while_tunnel_exits(mocker, capsys):
    """
    Ownership is unreadable because the tunnel is exiting (the kernel refuses reading
    an exiting process's fds): the mount fails, without the connect check that another
    process's listener would pass.
    """
    tunnel = _tunnel_mock()
    calls = {"n": 0}

    def unreadable_then_exit(pid, port):
        calls["n"] += 1
        if calls["n"] == 2:
            tunnel.returncode = 101
        return None

    mocker.patch(
        "efs_utils_common.proxy.process_listens_on_port",
        side_effect=unreadable_then_exit,
    )
    mocker.patch("efs_utils_common.proxy.procfs_available", return_value=True)
    mocker.patch("efs_utils_common.proxy.time.sleep")
    tlsport_mock = mocker.patch("efs_utils_common.proxy.test_tlsport")

    with pytest.raises(SystemExit):
        proxy.wait_for_tunnel_to_listen(tunnel, FS_ID, {"tlsport": 20049})

    _, err = capsys.readouterr()
    assert "Failed to initialize tunnel for %s" % FS_ID in err
    utils.assert_not_called(tlsport_mock)


def test_wait_for_tunnel_to_listen_unreadable_for_live_tunnel_falls_back(mocker):
    """Reads stay refused while the tunnel stays alive: rely on the connect check."""
    mocker.patch("efs_utils_common.proxy.process_listens_on_port", return_value=None)
    mocker.patch("efs_utils_common.proxy.procfs_available", return_value=True)
    mocker.patch("efs_utils_common.proxy.TUNNEL_OWNERSHIP_UNREADABLE_GRACE_SEC", 0)
    tlsport_mock = mocker.patch("efs_utils_common.proxy.test_tlsport")

    proxy.wait_for_tunnel_to_listen(_tunnel_mock(), FS_ID, {"tlsport": 20049})

    tlsport_mock.assert_called_once_with(20049)


def test_wait_for_tunnel_to_listen_unreadable_then_readable(mocker):
    mocker.patch(
        "efs_utils_common.proxy.process_listens_on_port", side_effect=[None, True]
    )
    mocker.patch("efs_utils_common.proxy.procfs_available", return_value=True)
    mocker.patch("efs_utils_common.proxy.time.sleep")
    tlsport_mock = mocker.patch("efs_utils_common.proxy.test_tlsport")

    proxy.wait_for_tunnel_to_listen(_tunnel_mock(), FS_ID, {"tlsport": 20049})

    utils.assert_not_called(tlsport_mock)


def test_wait_for_tunnel_to_listen_no_procfs_falls_back_at_once(mocker):
    mocker.patch("efs_utils_common.proxy.process_listens_on_port", return_value=None)
    mocker.patch("efs_utils_common.proxy.procfs_available", return_value=False)
    sleep_mock = mocker.patch("efs_utils_common.proxy.time.sleep")
    tlsport_mock = mocker.patch("efs_utils_common.proxy.test_tlsport")

    proxy.wait_for_tunnel_to_listen(_tunnel_mock(), FS_ID, {"tlsport": 20049})

    tlsport_mock.assert_called_once_with(20049)
    utils.assert_not_called(sleep_mock)


def test_tunnel_listen_timeout():
    assert 30 == proxy.TUNNEL_LISTEN_TIMEOUT_SEC


@needs_procfs
def test_wait_for_tunnel_to_listen_rejects_port_held_by_other_process(mocker, capsys):
    """
    This mount's tunnel loses its port to another process and exits. A connect to
    the port still succeeds, because the other process listens on it, but the mount
    must fail before mount.nfs4 attaches to that other process: through the tunnel
    exit check, without falling back to the connect check.
    """
    mocker.patch("efs_utils_common.proxy.TUNNEL_LISTEN_TIMEOUT_SEC", 30)
    tlsport_mock = mocker.patch("efs_utils_common.proxy.test_tlsport")
    port = _free_port()
    other = _start_listener(port)
    tunnel_proc = subprocess.Popen(
        [sys.executable, "-c", LISTENER, str(port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        assert network_utils.verify_tlsport_can_be_connected(port)
        with pytest.raises(SystemExit) as ex:
            proxy.wait_for_tunnel_to_listen(tunnel_proc, FS_ID, {"tlsport": port})
        assert 0 != ex.value.code
        _, err = capsys.readouterr()
        assert "Failed to initialize tunnel for %s" % FS_ID in err
        assert "held by another process" not in err
        utils.assert_not_called(tlsport_mock)
    finally:
        _stop(other)
        if tunnel_proc.poll() is None:
            _stop(tunnel_proc)


@needs_procfs
def test_wait_for_tunnel_to_listen_accepts_own_listener():
    port = _free_port()
    tunnel_proc = _start_listener(port)
    try:
        proxy.wait_for_tunnel_to_listen(tunnel_proc, FS_ID, {"tlsport": port})
    finally:
        _stop(tunnel_proc)
