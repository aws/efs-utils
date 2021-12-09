# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.

import socket

import mount_efs
import pytest
from mock import MagicMock

from .. import utils

try:
    import ConfigParser
except ImportError:
    from configparser import ConfigParser

DEFAULT_TLS_PORT_RANGE_LOW = 20049
DEFAULT_TLS_PORT_RANGE_HIGH = 20449


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


def test_choose_tls_port_first_try(mocker):
    mocker.patch("socket.socket", return_value=MagicMock())
    options = {}

    tls_port = mount_efs.choose_tls_port(_get_config(), options)

    assert DEFAULT_TLS_PORT_RANGE_LOW <= tls_port <= DEFAULT_TLS_PORT_RANGE_HIGH


def test_choose_tls_port_second_try(mocker):
    bad_sock = MagicMock()
    bad_sock.bind.side_effect = [socket.error, None]
    options = {}

    mocker.patch("socket.socket", return_value=bad_sock)

    tls_port = mount_efs.choose_tls_port(_get_config(), options)

    assert DEFAULT_TLS_PORT_RANGE_LOW <= tls_port <= DEFAULT_TLS_PORT_RANGE_HIGH
    assert 2 == bad_sock.bind.call_count


def test_choose_tls_port_never_succeeds(mocker, capsys):
    bad_sock = MagicMock()
    bad_sock.bind.side_effect = socket.error()
    options = {}

    mocker.patch("socket.socket", return_value=bad_sock)

    with pytest.raises(SystemExit) as ex:
        mount_efs.choose_tls_port(_get_config(), options)

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert "Failed to locate an available port" in err

    assert (
        DEFAULT_TLS_PORT_RANGE_HIGH - DEFAULT_TLS_PORT_RANGE_LOW
        == bad_sock.bind.call_count
    )


def test_choose_tls_port_option_specified(mocker):
    mocker.patch("socket.socket", return_value=MagicMock())
    options = {"tlsport": 1000}

    tls_port = mount_efs.choose_tls_port(_get_config(), options)

    assert 1000 == tls_port


def test_choose_tls_port_option_specified_unavailable(mocker, capsys):
    bad_sock = MagicMock()
    bad_sock.bind.side_effect = socket.error()
    options = {"tlsport": 1000}

    mocker.patch("socket.socket", return_value=bad_sock)

    with pytest.raises(SystemExit) as ex:
        mount_efs.choose_tls_port(_get_config(), options)

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert "Specified port [1000] is unavailable" in err

    assert 1 == bad_sock.bind.call_count


def test_choose_tls_port_under_netns(mocker, capsys):
    mocker.patch("builtins.open")
    setns_mock = mocker.patch("mount_efs.setns", return_value=(None, None))
    mocker.patch("socket.socket", return_value=MagicMock())
    options = {"netns": "/proc/1000/ns/net"}

    mount_efs.choose_tls_port(_get_config(), options)
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
