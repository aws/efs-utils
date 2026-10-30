# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
import socket
import subprocess
import sys
import time
from unittest.mock import MagicMock

import pytest

import efs_utils_common.proxy as proxy

# Stands in for efs-proxy: adopts the socket named by --listen-fd, checks it is bound to
# the port in argv[1], listens, reports, and accepts one connection.
FAKE_PROXY = (
    "import socket, sys\n"
    "fd = int(sys.argv[sys.argv.index('--listen-fd') + 1])\n"
    "s = socket.socket(fileno=fd)\n"
    "assert s.getsockname()[1] == int(sys.argv[1]), s.getsockname()\n"
    "s.listen(1)\n"
    "print('listening', flush=True)\n"
    "conn, _ = s.accept()\n"
    "conn.sendall(b'hello')\n"
)


def _bound_socket():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    return sock, sock.getsockname()[1]


def test_start_tunnel_process_hands_bound_socket_to_proxy():
    sock, port = _bound_socket()
    tunnel_args = [sys.executable, "-c", FAKE_PROXY, str(port)]

    proc = proxy.start_tunnel_process(tunnel_args, True, listen_sock=sock)
    proc.stderr.close()
    try:
        # This process's copy is closed, yet the port is still bound: the proxy holds it.
        assert sock.fileno() == -1
        other = socket.socket()
        with pytest.raises(OSError):
            other.bind(("127.0.0.1", port))
        other.close()

        # The proxy listens on the very socket it inherited. Until it calls listen(), the
        # socket is bound but refuses connections.
        deadline = time.monotonic() + 10
        while True:
            try:
                client = socket.create_connection(("127.0.0.1", port), timeout=10)
                break
            except ConnectionRefusedError:
                assert proc.poll() is None, "stand-in proxy exited"
                assert time.monotonic() < deadline
                time.sleep(0.05)
        assert client.recv(5) == b"hello"
        client.close()
        assert proc.wait(timeout=10) == 0
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()

    # The caller's argument list is not changed.
    assert tunnel_args == [sys.executable, "-c", FAKE_PROXY, str(port)]


def test_start_tunnel_process_adds_listen_fd(mocker):
    popen_mock = mocker.patch("subprocess.Popen")
    sock = MagicMock()
    sock.fileno.return_value = 9

    proxy.start_tunnel_process(
        ["/sbin/efs-proxy", "cfg", "--tls"], True, listen_sock=sock
    )

    args, kwargs = popen_mock.call_args
    assert args[0] == ["/sbin/efs-proxy", "cfg", "--tls", "--listen-fd", "9"]
    assert kwargs["pass_fds"] == (9,)
    assert kwargs["close_fds"] is True
    sock.close.assert_called_once_with()


def test_start_tunnel_process_without_socket(mocker):
    popen_mock = mocker.patch("subprocess.Popen")

    proxy.start_tunnel_process(["/usr/bin/stunnel", "cfg"], False)

    args, kwargs = popen_mock.call_args
    assert args[0] == ["/usr/bin/stunnel", "cfg"]
    assert kwargs["pass_fds"] == ()


def test_start_tunnel_process_keeps_netns_wrapper(mocker):
    popen_mock = mocker.patch("subprocess.Popen")
    sock = MagicMock()
    sock.fileno.return_value = 9
    tunnel_args = ["nsenter", "--net=/proc/1/ns/net", "/sbin/efs-proxy", "cfg"]

    proxy.start_tunnel_process(tunnel_args, True, listen_sock=sock)

    # nsenter runs efs-proxy with the remaining arguments and keeps open descriptors.
    assert popen_mock.call_args[0][0] == tunnel_args + ["--listen-fd", "9"]


def test_start_tunnel_process_closes_socket_when_start_fails(mocker):
    mocker.patch("subprocess.Popen", side_effect=OSError("exec failed"))
    sock = MagicMock()
    sock.fileno.return_value = 9

    with pytest.raises(OSError):
        proxy.start_tunnel_process(["/sbin/efs-proxy", "cfg"], True, listen_sock=sock)
    sock.close.assert_called_once_with()


def test_start_tunnel_process_stand_in_fails_without_inherited_socket():
    """
    The stand-in exits when the descriptor named by --listen-fd was not inherited, so
    the handover test above passes only because the socket really is inherited.
    """
    _, port = _bound_socket()
    proc = subprocess.run(
        [sys.executable, "-c", FAKE_PROXY, str(port), "--listen-fd", "255"],
        capture_output=True,
        timeout=10,
    )
    assert proc.returncode != 0
    assert b"Bad file descriptor" in proc.stderr or b"OSError" in proc.stderr
