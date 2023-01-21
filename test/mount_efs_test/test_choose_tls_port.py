# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
import logging
import random
import socket
import sys
import tempfile
import unittest
from unittest.mock import MagicMock

import pytest

import mount_efs

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


def _get_config():
    try:
        config = ConfigParser.SafeConfigParser()
    except AttributeError:
        config = ConfigParser()
    config.add_section(mount_efs.CONFIG_SECTION)
    config.set(
        mount_efs.CONFIG_SECTION,
        "port_range_lower_bound",
        str(DEFAULT_TLS_PORT_RANGE_LOW),
    )
    config.set(
        mount_efs.CONFIG_SECTION,
        "port_range_upper_bound",
        str(DEFAULT_TLS_PORT_RANGE_HIGH),
    )
    return config


def test_choose_tls_port_first_try(mocker, tmpdir):
    sock_mock = MagicMock()
    sock_mock.getsockname.return_value = ("local_host", DEFAULT_TLS_PORT)
    mocker.patch("socket.socket", return_value=sock_mock)
    options = {}

    tls_port_sock = mount_efs.choose_tls_port_and_get_bind_sock(
        _get_config(), options, str(tmpdir)
    )
    tls_port = mount_efs.get_tls_port_from_sock(tls_port_sock)
    assert DEFAULT_TLS_PORT_RANGE_LOW <= tls_port <= DEFAULT_TLS_PORT_RANGE_HIGH


def test_choose_tls_port_second_try(mocker, tmpdir):
    bad_sock = MagicMock()
    bad_sock.bind.side_effect = [socket.error, None]
    bad_sock.getsockname.return_value = ("local_host", DEFAULT_TLS_PORT)
    options = {}

    mocker.patch("socket.socket", return_value=bad_sock)

    tls_port_sock = mount_efs.choose_tls_port_and_get_bind_sock(
        _get_config(), options, str(tmpdir)
    )
    tls_port = mount_efs.get_tls_port_from_sock(tls_port_sock)

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
        mount_efs.choose_tls_port_and_get_bind_sock(_get_config(), options, tmpdir)

    temp_state_file.close()
    sock.bind.assert_called_once_with(("localhost", DEFAULT_TLS_PORT_RANGE_LOW + 1))
    assert "Skip binding TLS port" in caplog.text


def test_choose_tls_port_never_succeeds(mocker, tmpdir, capsys):
    bad_sock = MagicMock()
    bad_sock.bind.side_effect = socket.error()
    options = {}

    mocker.patch("socket.socket", return_value=bad_sock)

    with pytest.raises(SystemExit) as ex:
        mount_efs.choose_tls_port_and_get_bind_sock(_get_config(), options, str(tmpdir))

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

    tls_port_sock = mount_efs.choose_tls_port_and_get_bind_sock(
        _get_config(), options, str(tmpdir)
    )
    tls_port = mount_efs.get_tls_port_from_sock(tls_port_sock)

    assert DEFAULT_TLS_PORT == tls_port


def test_choose_tls_port_option_specified_unavailable(mocker, tmpdir, capsys):
    bad_sock = MagicMock()
    bad_sock.bind.side_effect = socket.error()
    options = {"tlsport": 1000}

    mocker.patch("socket.socket", return_value=bad_sock)

    with pytest.raises(SystemExit) as ex:
        mount_efs.choose_tls_port_and_get_bind_sock(_get_config(), options, str(tmpdir))

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert "Specified port [1000] is unavailable" in err

    assert 1 == bad_sock.bind.call_count


def test_choose_tls_port_under_netns(mocker, tmpdir):
    mocker.patch("builtins.open")
    setns_mock = mocker.patch("mount_efs.setns", return_value=(None, None))
    mocker.patch("socket.socket", return_value=MagicMock())
    options = {"netns": "/proc/1000/ns/net"}

    mount_efs.choose_tls_port_and_get_bind_sock(_get_config(), options, str(tmpdir))
    utils.assert_called(setns_mock)


def test_verify_tls_port(mocker):
    sock = MagicMock()
    sock.connect.side_effect = [ConnectionRefusedError, None]
    mocker.patch("socket.socket", return_value=sock)
    result = mount_efs.verify_tlsport_can_be_connected(1000)
    assert result is False
    result = mount_efs.verify_tlsport_can_be_connected(1000)
    assert result is True
    assert 2 == sock.connect.call_count
