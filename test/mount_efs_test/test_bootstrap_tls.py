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

from mock import MagicMock

FS_ID = 'fs-deadbeef'
DNS_NAME = '%s.efs.us-east-1.amazonaws.com' % FS_ID
MOUNT_POINT = '/mnt'

DEFAULT_TLS_PORT = 20049

EXPECTED_STUNNEL_CONFIG_FILE_BASE = 'stunnel-config.fs-deadbeef.mnt.'
EXPECTED_STUNNEL_CONFIG_FILE = EXPECTED_STUNNEL_CONFIG_FILE_BASE + str(DEFAULT_TLS_PORT)

INIT_SYSTEM = 'upstart'

MOCK_CONFIG = MagicMock()


def setup_mocks(mocker):
    mocker.patch('mount_efs.start_watchdog')
    mocker.patch('mount_efs.get_tls_port_range', return_value=(DEFAULT_TLS_PORT, DEFAULT_TLS_PORT + 10))
    mocker.patch('socket.socket', return_value=MagicMock())
    mocker.patch('mount_efs.write_tls_tunnel_state_file', return_value="~mocktempfile")
    mocker.patch('os.rename')
    mocker.patch('os.kill')

    process_mock = MagicMock()
    process_mock.communicate.return_value = ('stdout', 'stderr', )
    process_mock.returncode = 0

    popen_mock = mocker.patch('subprocess.Popen', return_value=process_mock)
    write_config_mock = mocker.patch('mount_efs.write_stunnel_config_file', return_value=EXPECTED_STUNNEL_CONFIG_FILE)
    return popen_mock, write_config_mock


def test_bootstrap_tls_state_file_dir_exists(mocker, tmpdir):
    popen_mock, _ = setup_mocks(mocker)
    state_file_dir = str(tmpdir)

    with mount_efs.bootstrap_tls(MOCK_CONFIG, INIT_SYSTEM, DNS_NAME, FS_ID, MOUNT_POINT, {}, state_file_dir):
        pass

    args, _ = popen_mock.call_args
    args = args[0]

    assert 'stunnel' in args
    assert EXPECTED_STUNNEL_CONFIG_FILE in args


def test_bootstrap_tls_state_file_nonexistent_dir(mocker, tmpdir):
    popen_mock, _ = setup_mocks(mocker)
    state_file_dir = str(tmpdir.join(tempfile.mktemp()))

    def config_get_side_effect(section, field):
        if section == mount_efs.CONFIG_SECTION and field == 'state_file_dir_mode':
            return '0755'
        else:
            raise ValueError('Unexpected arguments')

    MOCK_CONFIG.get.side_effect = config_get_side_effect

    assert not os.path.exists(state_file_dir)

    with mount_efs.bootstrap_tls(MOCK_CONFIG, INIT_SYSTEM, DNS_NAME, FS_ID, MOUNT_POINT, {}, state_file_dir):
        pass

    assert os.path.exists(state_file_dir)


def test_bootstrap_tls_non_default_port(mocker, tmpdir):
    popen_mock, write_config_mock = setup_mocks(mocker)
    state_file_dir = str(tmpdir)

    tls_port = 1000
    with mount_efs.bootstrap_tls(MOCK_CONFIG, INIT_SYSTEM, DNS_NAME, FS_ID, MOUNT_POINT, {'tlsport': tls_port}, state_file_dir):
        pass

    popen_args, _ = popen_mock.call_args
    popen_args = popen_args[0]
    write_config_args, _ = write_config_mock.call_args

    assert 'stunnel' in popen_args
    assert EXPECTED_STUNNEL_CONFIG_FILE in popen_args
    assert 1000 == write_config_args[4]  # positional argument for tls_port


def test_bootstrap_tls_non_default_verify_level(mocker, tmpdir):
    popen_mock, write_config_mock = setup_mocks(mocker)
    state_file_dir = str(tmpdir)

    verify = 0
    with mount_efs.bootstrap_tls(MOCK_CONFIG, INIT_SYSTEM, DNS_NAME, FS_ID, MOUNT_POINT, {'verify': verify}, state_file_dir):
        pass

    popen_args, _ = popen_mock.call_args
    popen_args = popen_args[0]
    write_config_args, _ = write_config_mock.call_args

    assert 'stunnel' in popen_args
    assert EXPECTED_STUNNEL_CONFIG_FILE in popen_args
    assert 0 == write_config_args[6]  # positional argument for verify_level


def test_bootstrap_tls_ocsp_option(mocker, tmpdir):
    popen_mock, write_config_mock = setup_mocks(mocker)
    state_file_dir = str(tmpdir)

    with mount_efs.bootstrap_tls(MOCK_CONFIG, INIT_SYSTEM, DNS_NAME, FS_ID, MOUNT_POINT, {'ocsp': None}, state_file_dir):
        pass

    popen_args, _ = popen_mock.call_args
    popen_args = popen_args[0]
    write_config_args, _ = write_config_mock.call_args

    assert 'stunnel' in popen_args
    assert EXPECTED_STUNNEL_CONFIG_FILE in popen_args
    # positional argument for ocsp_override
    assert write_config_args[7] is True


def test_bootstrap_tls_noocsp_option(mocker, tmpdir):
    popen_mock, write_config_mock = setup_mocks(mocker)
    state_file_dir = str(tmpdir)

    with mount_efs.bootstrap_tls(MOCK_CONFIG, INIT_SYSTEM, DNS_NAME, FS_ID, MOUNT_POINT, {'noocsp': None}, state_file_dir):
        pass

    popen_args, _ = popen_mock.call_args
    popen_args = popen_args[0]
    write_config_args, _ = write_config_mock.call_args

    assert 'stunnel' in popen_args
    assert EXPECTED_STUNNEL_CONFIG_FILE in popen_args
    # positional argument for ocsp_override
    assert write_config_args[7] is False


def test_bootstrap_tls_ocsp_and_noocsp_option(mocker, tmpdir):
    setup_mocks(mocker)
    state_file_dir = str(tmpdir)

    exception_thrown = False
    try:
        with mount_efs.bootstrap_tls(MOCK_CONFIG, INIT_SYSTEM, DNS_NAME, FS_ID, MOUNT_POINT, {'ocsp': None, 'noocsp': None},
                                     state_file_dir):
            pass
    except SystemExit:
        exception_thrown = True

    assert exception_thrown
