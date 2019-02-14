#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import mount_efs
import socket

try:
    import ConfigParser as cp
except ImportError:
    import configparser as cp

import pytest

from mock import MagicMock

DEFAULT_TLS_PORT_RANGE_LOW = 20049
DEFAULT_TLS_PORT_RANGE_HIGH = 20449


def _get_config():
    config = cp.ConfigParser()
    config.add_section(mount_efs.CONFIG_SECTION)
    config.set(mount_efs.CONFIG_SECTION, 'port_range_lower_bound', str(DEFAULT_TLS_PORT_RANGE_LOW))
    config.set(mount_efs.CONFIG_SECTION, 'port_range_upper_bound', str(DEFAULT_TLS_PORT_RANGE_HIGH))
    return config


def test_choose_tls_port_first_try(mocker):
    mocker.patch('socket.socket', return_value=MagicMock())

    tls_port = mount_efs.choose_tls_port(_get_config())

    assert DEFAULT_TLS_PORT_RANGE_LOW <= tls_port <= DEFAULT_TLS_PORT_RANGE_HIGH


def test_choose_tls_port_second_try(mocker):
    bad_sock = MagicMock()
    bad_sock.bind.side_effect = [socket.error, None]

    mocker.patch('socket.socket', return_value=bad_sock)

    tls_port = mount_efs.choose_tls_port(_get_config())

    assert DEFAULT_TLS_PORT_RANGE_LOW <= tls_port <= DEFAULT_TLS_PORT_RANGE_HIGH
    assert 2 == bad_sock.bind.call_count


def test_choose_tls_port_never_succeeds(mocker, capsys):
    bad_sock = MagicMock()
    bad_sock.bind.side_effect = socket.error()

    mocker.patch('socket.socket', return_value=bad_sock)

    with pytest.raises(SystemExit) as ex:
        mount_efs.choose_tls_port(_get_config())

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert 'Failed to locate an available port' in err

    assert DEFAULT_TLS_PORT_RANGE_HIGH - DEFAULT_TLS_PORT_RANGE_LOW == bad_sock.bind.call_count
