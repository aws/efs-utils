#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import mount_efs

from mock import MagicMock

FS_ID = 'fs-deadbeef'


def test_upstart_system(mocker):
    process_mock = MagicMock()
    process_mock.communicate.return_value = ('stop', '', )
    process_mock.returncode = 0
    popen_mock = mocker.patch('subprocess.Popen', return_value=process_mock)

    mount_efs.start_watchdog('init')

    assert 2 == popen_mock.call_count
    assert '/sbin/start' in popen_mock.call_args[0][0]


def test_systemd_system(mocker):
    call_mock = mocker.patch('subprocess.call', return_value=1)
    popen_mock = mocker.patch('subprocess.Popen')

    mount_efs.start_watchdog('systemd')

    call_mock.assert_called_once()
    assert 'systemctl' in call_mock.call_args[0][0]
    assert 'is-active' in call_mock.call_args[0][0]
    popen_mock.assert_called_once()
    assert 'systemctl' in popen_mock.call_args[0][0]
    assert 'start' in popen_mock.call_args[0][0]


def test_unknown_system(mocker):
    popen_mock = mocker.patch('subprocess.Popen')

    mount_efs.start_watchdog('unknown')

    popen_mock.assert_not_called()
