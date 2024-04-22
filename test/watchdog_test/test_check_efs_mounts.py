#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import watchdog
import json
import tempfile

TIME = 1514764800
GRACE_PERIOD = 30
PID = 1234
STATE = {
    'pid': PID,
}


def setup_mocks(mocker, mounts, state_files, is_pid_running=True):
    state = dict(STATE)
    state['unmount_time'] = TIME - GRACE_PERIOD

    mocker.patch('watchdog.get_current_local_nfs_mounts', return_value=mounts)
    mocker.patch('watchdog.get_state_files', return_value=state_files)
    mocker.patch('watchdog.is_pid_running', return_value=is_pid_running)
    mocker.patch('watchdog.mark_as_unmounted', return_value=state)
    mocker.patch('time.time', return_value=TIME + GRACE_PERIOD + 1)

    clean_up_mock = mocker.patch('watchdog.clean_up_mount_state')
    restart_tls_mock = mocker.patch('watchdog.restart_tls_tunnel')

    return clean_up_mock, restart_tls_mock


def create_state_file(tmpdir, content=json.dumps(STATE)):
    state_file = tmpdir.join(tempfile.mktemp())
    state_file.write(content, ensure=True)

    return state_file.dirname, state_file.basename


def test_no_state_files(mocker):
    clean_up_mock, restart_tls_mock = setup_mocks(mocker,
                                                  mounts={'mnt': watchdog.Mount('127.0.0.1', '/mnt', 'nfs4', '', '0', '0')},
                                                  state_files={})

    watchdog.check_efs_mounts([], GRACE_PERIOD)

    clean_up_mock.assert_not_called()
    restart_tls_mock.assert_not_called()


def test_malformed_state_file(mocker, tmpdir):
    state_file_dir, state_file = create_state_file(tmpdir, 'not-json')

    clean_up_mock, restart_tls_mock = setup_mocks(mocker, mounts={}, state_files={'mnt': state_file})

    watchdog.check_efs_mounts([], GRACE_PERIOD, state_file_dir)

    clean_up_mock.assert_not_called()
    restart_tls_mock.assert_not_called()


def test_no_mount_for_state_file(mocker, tmpdir):
    state = dict(STATE)

    state_file_dir, state_file = create_state_file(tmpdir, content=json.dumps(state))

    clean_up_mock, restart_tls_mock = setup_mocks(mocker, mounts={}, state_files={'mnt': state_file})

    watchdog.check_efs_mounts([], GRACE_PERIOD, state_file_dir)

    clean_up_mock.assert_not_called()
    restart_tls_mock.assert_not_called()


def test_no_mount_for_state_file_out_of_grace_period(mocker, tmpdir):
    state = dict(STATE)
    state['unmount_time'] = TIME - GRACE_PERIOD

    state_file_dir, state_file = create_state_file(tmpdir, content=json.dumps(state))

    clean_up_mock, restart_tls_mock = setup_mocks(mocker, mounts={}, state_files={'mnt': state_file})

    watchdog.check_efs_mounts([], GRACE_PERIOD, state_file_dir)

    clean_up_mock.assert_called_once()
    restart_tls_mock.assert_not_called()


def test_no_mount_for_state_file_in_grace_period(mocker, tmpdir):
    state = dict(STATE)
    state['unmount_time'] = TIME + GRACE_PERIOD

    state_file_dir, state_file = create_state_file(tmpdir, content=json.dumps(state))

    clean_up_mock, restart_tls_mock = setup_mocks(mocker, mounts={}, state_files={'mnt': state_file})

    watchdog.check_efs_mounts([], GRACE_PERIOD, state_file_dir)

    clean_up_mock.assert_not_called()
    restart_tls_mock.assert_not_called()


def test_tls_not_running(mocker, tmpdir):
    state_file_dir, state_file = create_state_file(tmpdir)

    clean_up_mock, restart_tls_mock = setup_mocks(mocker,
                                                  mounts={'mnt': watchdog.Mount('127.0.0.1', '/mnt', 'nfs4', '', '0', '0')},
                                                  state_files={'mnt': state_file}, is_pid_running=False)

    watchdog.check_efs_mounts([], GRACE_PERIOD, state_file_dir)

    clean_up_mock.assert_not_called()
    restart_tls_mock.assert_called_once()


def test_extra_mount(mocker, tmpdir):
    state_file_dir, state_file = create_state_file(tmpdir)

    clean_up_mock, restart_tls_mock = setup_mocks(mocker,
                                                  mounts={
                                                      'mnt': watchdog.Mount('127.0.0.1', '/mnt', 'nfs4', '', '0', '0'),
                                                      'mnt2': watchdog.Mount('192.168.1.1', '/mnt2', 'nfs4', '', '0', '0'),
                                                  },
                                                  state_files={'mnt': state_file})

    watchdog.check_efs_mounts([], GRACE_PERIOD, state_file_dir)

    clean_up_mock.assert_not_called()
    restart_tls_mock.assert_not_called()
