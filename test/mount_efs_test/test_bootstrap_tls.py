#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import mount_efs
import os
import tempfile

import pytest

from mock import MagicMock

FS_ID = 'fs-deadbeef'
DNS_NAME = '%s.efs.us-east-1.amazonaws.com' % FS_ID
MOUNT_POINT = '/mnt'

DEFAULT_TLS_PORT = 20049

EXPECTED_STUNNEL_CONFIG_FILE_BASE = 'stunnel-config.fs-deadbeef.mnt.'
EXPECTED_STUNNEL_CONFIG_FILE = EXPECTED_STUNNEL_CONFIG_FILE_BASE + str(DEFAULT_TLS_PORT)

INIT_SYSTEM = 'upstart'

MOCK_CONFIG = MagicMock()


@pytest.fixture(autouse=True)
def setup(mocker):
    mocker.patch('mount_efs.start_watchdog')
    mocker.patch('mount_efs.get_tls_port_range', return_value=(DEFAULT_TLS_PORT, DEFAULT_TLS_PORT + 10))
    mocker.patch('mount_efs.choose_tls_port', return_value=DEFAULT_TLS_PORT)
    mocker.patch('mount_efs.write_tls_tunnel_state_file')
    mocker.patch('mount_efs.write_stunnel_config_file', return_value=EXPECTED_STUNNEL_CONFIG_FILE)
    mocker.patch('os.rename')


def _mock_popen(mocker, returncode=0):
    popen_mock = MagicMock()
    popen_mock.communicate.return_value = ('stdout', 'stderr', )
    popen_mock.returncode = returncode

    return mocker.patch('subprocess.Popen', return_value=popen_mock)


def test_bootstrap_tls_state_file_dir_exists(mocker, tmpdir):
    popen_mock = _mock_popen(mocker)
    mocker.patch('os.kill')
    state_file_dir = str(tmpdir)

    with mount_efs.bootstrap_tls(MOCK_CONFIG, INIT_SYSTEM, DNS_NAME, FS_ID, MOUNT_POINT, {}, state_file_dir):
        pass

    args, _ = popen_mock.call_args
    args = args[0]

    assert 'stunnel' in args
    assert EXPECTED_STUNNEL_CONFIG_FILE in args


def test_bootstrap_tls_state_file_nonexistent_dir(mocker, tmpdir):
    _mock_popen(mocker)
    mocker.patch('os.kill')
    state_file_dir = str(tmpdir.join(tempfile.mktemp()))

    assert not os.path.exists(state_file_dir)

    with mount_efs.bootstrap_tls(MOCK_CONFIG, INIT_SYSTEM, DNS_NAME, FS_ID, MOUNT_POINT, {}, state_file_dir):
        pass

    assert os.path.exists(state_file_dir)


def test_bootstrap_tls_non_default_port(mocker, tmpdir):
    popen_mock = _mock_popen(mocker)
    mocker.patch('os.kill')
    state_file_dir = str(tmpdir)

    tls_port = 1000
    with mount_efs.bootstrap_tls(MOCK_CONFIG, INIT_SYSTEM, DNS_NAME, FS_ID, MOUNT_POINT, {'tlsport': tls_port}, state_file_dir):
        pass

    args, _ = popen_mock.call_args
    args = args[0]

    assert 'stunnel' in args
    assert EXPECTED_STUNNEL_CONFIG_FILE in args


def test_bootstrap_tls_non_default_verify_level(mocker, tmpdir):
    popen_mock = _mock_popen(mocker)
    mocker.patch('os.kill')
    state_file_dir = str(tmpdir)

    verify = 0
    with mount_efs.bootstrap_tls(MOCK_CONFIG, INIT_SYSTEM, DNS_NAME, FS_ID, MOUNT_POINT, {'verify': verify}, state_file_dir):
        pass

    args, _ = popen_mock.call_args
    args = args[0]

    assert 'stunnel' in args
    assert EXPECTED_STUNNEL_CONFIG_FILE in args
