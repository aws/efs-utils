# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
import logging
import os
import random
import socket
import sys
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, call

import pytest

import efs_utils_common
import efs_utils_common.constants as constants
import efs_utils_common.context as context
import efs_utils_common.network_utils as network_utils
import efs_utils_common.proxy as proxy

from .. import utils

try:
    import ConfigParser
except ImportError:
    from configparser import ConfigParser

DEFAULT_TLS_PORT_RANGE_LOW = 20049
DEFAULT_TLS_PORT_RANGE_HIGH = 21049
DEFAULT_TLS_PORT = random.randrange(
    DEFAULT_TLS_PORT_RANGE_LOW, DEFAULT_TLS_PORT_RANGE_HIGH
)


@pytest.fixture(autouse=True)
def setup_method(mocker):
    mount_context = context.MountContext()
    mount_context.reset()
    mount_context.mount_type = constants.MOUNT_TYPE_EFS
    mount_context.config_file_path = constants.CONFIG_FILE
    yield mount_context


def _get_config():
    try:
        config = ConfigParser.SafeConfigParser()
    except AttributeError:
        config = ConfigParser()
    config.add_section(efs_utils_common.constants.CONFIG_SECTION)
    config.set(
        efs_utils_common.constants.CONFIG_SECTION,
        "port_range_lower_bound",
        str(DEFAULT_TLS_PORT_RANGE_LOW),
    )
    config.set(
        efs_utils_common.constants.CONFIG_SECTION,
        "port_range_upper_bound",
        str(DEFAULT_TLS_PORT_RANGE_HIGH),
    )
    return config


def test_choose_tls_port_first_try(mocker, tmpdir):
    sock_mock = MagicMock()
    sock_mock.getsockname.return_value = ("local_host", DEFAULT_TLS_PORT)
    mocker.patch("socket.socket", return_value=sock_mock)
    options = {}

    tls_port_sock = proxy.choose_tls_port_and_get_bind_sock(
        _get_config(), options, str(tmpdir)
    )
    tls_port = proxy.get_tls_port_from_sock(tls_port_sock)
    assert DEFAULT_TLS_PORT_RANGE_LOW <= tls_port <= DEFAULT_TLS_PORT_RANGE_HIGH


def test_choose_tls_port_second_try(mocker, tmpdir):
    bad_sock = MagicMock()
    bad_sock.bind.side_effect = [socket.error, None]
    bad_sock.getsockname.return_value = ("local_host", DEFAULT_TLS_PORT)
    options = {}

    mocker.patch("socket.socket", return_value=bad_sock)

    tls_port_sock = proxy.choose_tls_port_and_get_bind_sock(
        _get_config(), options, str(tmpdir)
    )
    tls_port = proxy.get_tls_port_from_sock(tls_port_sock)

    assert DEFAULT_TLS_PORT_RANGE_LOW <= tls_port <= DEFAULT_TLS_PORT_RANGE_HIGH
    assert 2 == bad_sock.bind.call_count
    assert 1 == bad_sock.getsockname.call_count


@unittest.skipIf(sys.version_info < (3, 6), reason="requires python3.6")
def test_choose_tls_port_collision(mocker, tmpdir, caplog):
    """Ensure we don't choose a port that is pending mount"""
    sock = MagicMock()
    mocker.patch("socket.socket", return_value=sock)
    mocker.patch(
        "random.shuffle",
        return_value=range(DEFAULT_TLS_PORT_RANGE_LOW, DEFAULT_TLS_PORT_RANGE_HIGH),
    )

    port_suffix = ".%s" % str(DEFAULT_TLS_PORT_RANGE_LOW)
    temp_state_file = tempfile.NamedTemporaryFile(
        suffix=port_suffix, prefix="~", dir=tmpdir
    )

    options = {}
    with caplog.at_level(logging.DEBUG):
        proxy.choose_tls_port_and_get_bind_sock(_get_config(), options, tmpdir)

    temp_state_file.close()
    sock.bind.assert_called_once_with(("127.0.0.1", DEFAULT_TLS_PORT_RANGE_LOW + 1))
    assert "Skip binding TLS port" in caplog.text


def _free_ports(count):
    socks = []
    for _ in range(count):
        s = socket.socket()
        s.bind(("localhost", 0))
        socks.append(s)
    ports = [s.getsockname()[1] for s in socks]
    for s in socks:
        s.close()
    return ports


def test_find_tls_port_leaves_claimed_port_free(tmpdir):
    claimed_port, free_port = _free_ports(2)
    state_file_dir = str(tmpdir)
    open(os.path.join(state_file_dir, "fs-other.mnt.%d" % claimed_port), "w").close()

    tls_port_sock = proxy.find_tls_port_in_range_and_get_bind_sock(
        [claimed_port, free_port], state_file_dir
    )
    try:
        assert free_port == proxy.get_tls_port_from_sock(tls_port_sock)
        # The claimed port is left free, so its owner can still bind it.
        owner = socket.socket()
        owner.bind(("localhost", claimed_port))
        owner.close()
    finally:
        tls_port_sock.close()


def test_choose_tls_port_never_succeeds(mocker, tmpdir, capsys):
    bad_sock = MagicMock()
    bad_sock.bind.side_effect = socket.error()
    options = {}

    mocker.patch("socket.socket", return_value=bad_sock)

    with pytest.raises(SystemExit) as ex:
        proxy.choose_tls_port_and_get_bind_sock(_get_config(), options, str(tmpdir))

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert "Failed to locate an available port" in err

    assert (
        DEFAULT_TLS_PORT_RANGE_HIGH - DEFAULT_TLS_PORT_RANGE_LOW
        == bad_sock.bind.call_count
    )


def test_choose_tls_port_option_specified(mocker, tmpdir):
    sock_mock = MagicMock()
    sock_mock.getsockname.return_value = ("local_host", DEFAULT_TLS_PORT)
    mocker.patch("socket.socket", return_value=sock_mock)
    options = {"tlsport": DEFAULT_TLS_PORT}

    tls_port_sock = proxy.choose_tls_port_and_get_bind_sock(
        _get_config(), options, str(tmpdir)
    )
    tls_port = proxy.get_tls_port_from_sock(tls_port_sock)

    assert DEFAULT_TLS_PORT == tls_port


def test_choose_tls_port_option_specified_unavailable(mocker, tmpdir, capsys):
    bad_sock = MagicMock()
    bad_sock.bind.side_effect = socket.error()
    options = {"tlsport": 1000}

    mocker.patch("socket.socket", return_value=bad_sock)

    with pytest.raises(SystemExit) as ex:
        proxy.choose_tls_port_and_get_bind_sock(_get_config(), options, str(tmpdir))

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert "Specified port [1000] is unavailable" in err

    assert 1 == bad_sock.bind.call_count


def test_choose_tls_port_under_netns(mocker, tmpdir):
    mocker.patch("builtins.open")
    setns_mock = mocker.patch(
        "efs_utils_common.process_utils.setns", return_value=(None, None)
    )
    mocker.patch("socket.socket", return_value=MagicMock())
    options = {"netns": "/proc/1000/ns/net"}

    proxy.choose_tls_port_and_get_bind_sock(_get_config(), options, str(tmpdir))
    utils.assert_called(setns_mock)


def test_verify_tls_port(mocker):
    sock = MagicMock()
    sock.connect.side_effect = [ConnectionRefusedError, None]
    mocker.patch("socket.socket", return_value=sock)
    result = network_utils.verify_tlsport_can_be_connected(1000)
    assert result is False
    result = network_utils.verify_tlsport_can_be_connected(1000)
    assert result is True
    assert 2 == sock.connect.call_count


def test_find_tls_port_skips_port_claimed_before_probe_bind(mocker, tmpdir):
    """
    Another mount can write its state file and release its probe socket between
    this mount's look at the state files and its probe bind. The bind then
    succeeds, so the port must still be rejected because of that state file.
    """
    claimed_port, free_port = 20101, 20102
    state_file_dir = str(tmpdir)
    sock = MagicMock()

    def bind(address):
        if address[1] == claimed_port:
            # The other mount writes its state file, then closes its probe socket.
            open(
                os.path.join(state_file_dir, "~fs-other.mnt.%d" % claimed_port), "w"
            ).close()

    sock.bind.side_effect = bind
    sock.getsockname.return_value = ("127.0.0.1", free_port)
    mocker.patch("socket.socket", return_value=sock)

    tls_port_sock = proxy.find_tls_port_in_range_and_get_bind_sock(
        [claimed_port, free_port], state_file_dir
    )

    assert sock.bind.call_args_list[-1] == call(("127.0.0.1", free_port))
    assert free_port == proxy.get_tls_port_from_sock(tls_port_sock)


def test_find_tls_port_concurrent_mounts_get_distinct_ports(tmpdir):
    """
    Concurrent mounts in a port range smaller than the number of mounts. Each mount
    holds its probe socket, writes its state file, then releases the probe, as
    bootstrap_proxy does. No port may be handed to more than one mount.
    """
    ports = _free_ports(4)
    state_file_dir = str(tmpdir)
    chosen = []
    lock = threading.Lock()
    start = threading.Barrier(8)

    def mount(idx):
        start.wait()
        ports_to_try = list(ports)
        random.shuffle(ports_to_try)
        sock = proxy.find_tls_port_in_range_and_get_bind_sock(
            ports_to_try, state_file_dir
        )
        if sock is None:
            return
        port = proxy.get_tls_port_from_sock(sock)
        open(os.path.join(state_file_dir, "~fs-%d.mnt.%d" % (idx, port)), "w").close()
        sock.close()
        with lock:
            chosen.append(port)

    threads = [threading.Thread(target=mount, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(chosen) == len(set(chosen))
    assert set(chosen) <= set(ports)


def test_find_tls_port_binds_tunnel_listen_address(tmpdir):
    """The probe is bound to 127.0.0.1, which efs-proxy requires of an inherited socket."""
    sock = proxy.find_tls_port_in_range_and_get_bind_sock(_free_ports(1), str(tmpdir))
    try:
        assert sock.getsockname()[0] == "127.0.0.1"
    finally:
        sock.close()


def test_find_tls_port_does_not_resolve_localhost(mocker, tmpdir):
    sock = MagicMock()
    mocker.patch("socket.socket", return_value=sock)

    proxy.find_tls_port_in_range_and_get_bind_sock([20049], str(tmpdir))

    sock.bind.assert_called_once_with(("127.0.0.1", 20049))
