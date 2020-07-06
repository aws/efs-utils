#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import watchdog
import json
import os
import tempfile

from .. import utils

PID = 99999999999999999


def create_temp_file(tmpdir, content=''):
    temp_file = tmpdir.join(tempfile.mktemp())
    temp_file.write(content, ensure=True)
    return temp_file


def create_state_file(tmpdir, extra_files=list(), mount_state_dir=None):
    state_dict = {'pid': PID, 'files': extra_files}

    if mount_state_dir:
        state_dict['mountStateDir'] = mount_state_dir

    state_file = create_temp_file(tmpdir, json.dumps(state_dict))

    return state_file.dirname, state_file.basename, str(state_file)


def setup_mock(mocker, is_pid_running):
    mocker.patch('os.getpgid')
    mocker.patch('watchdog.is_pid_running', return_value=is_pid_running)

    killpg_mock = mocker.patch('os.killpg')
    return killpg_mock


def test_clean_up_on_first_try(mocker, tmpdir):
    killpg_mock = setup_mock(mocker, False)

    state_dir, state_file, abs_state_file = create_state_file(tmpdir)

    assert os.path.exists(abs_state_file)

    watchdog.clean_up_mount_state(state_dir, state_file, PID, is_running=True)

    utils.assert_called_once(killpg_mock)
    assert not os.path.exists(abs_state_file)


def _test_clean_up_files(mocker, tmpdir, files_should_exist):
    killpg_mock = setup_mock(mocker, False)

    extra_files = [
        str(create_temp_file(tmpdir)),
        str(create_temp_file(tmpdir)),
    ]

    state_dir, state_file, abs_state_file = create_state_file(tmpdir, extra_files)

    assert os.path.exists(abs_state_file)
    for f in extra_files:
        if not files_should_exist:
            os.remove(f)
        assert os.path.exists(f) or not files_should_exist

    watchdog.clean_up_mount_state(state_dir, state_file, PID, is_running=True)

    utils.assert_called_once(killpg_mock)
    assert not os.path.exists(abs_state_file)
    for f in extra_files:
        assert not os.path.exists(f)


def test_clean_up_nonexistent_files(mocker, tmpdir):
    _test_clean_up_files(mocker, tmpdir, files_should_exist=False)


def test_clean_up_multiple_files(mocker, tmpdir):
    _test_clean_up_files(mocker, tmpdir, files_should_exist=True)


def test_clean_up_pid_still_lives(mocker, tmpdir):
    killpg_mock = setup_mock(mocker, True)

    state_dir, state_file, abs_state_file = create_state_file(tmpdir)

    assert os.path.exists(abs_state_file)

    watchdog.clean_up_mount_state(state_dir, state_file, PID, is_running=True)

    utils.assert_called_once(killpg_mock)
    assert os.path.exists(abs_state_file)


def test_clean_up_pid_already_killed(mocker, tmpdir):
    pid = None
    is_running = watchdog.is_pid_running(pid)
    killpg_mock = setup_mock(mocker, is_running)

    state_dir, state_file, abs_state_file = create_state_file(tmpdir)

    assert os.path.exists(abs_state_file)

    watchdog.clean_up_mount_state(state_dir, state_file, pid, is_running=is_running)

    utils.assert_not_called(killpg_mock)
    assert not os.path.exists(abs_state_file)


def test_pid_not_running(mocker, tmpdir):
    killpg_mock = setup_mock(mocker, False)

    state_dir, state_file, abs_state_file = create_state_file(tmpdir)

    assert os.path.exists(abs_state_file)

    watchdog.clean_up_mount_state(state_dir, state_file, PID, is_running=False)

    utils.assert_not_called(killpg_mock)
    assert not os.path.exists(abs_state_file)


def test_clean_up_mount_state_dir_success(mocker, tmpdir):
    setup_mock(mocker, False)
    mocker.patch('os.path.isdir', return_value=True)
    rm_tree = mocker.patch('shutil.rmtree')

    state_dir, state_file, abs_state_file = create_state_file(tmpdir, mount_state_dir='/fake/path')

    assert os.path.exists(abs_state_file)

    watchdog.clean_up_mount_state(state_dir, state_file, PID, is_running=False, mount_state_dir='/fake/path')

    utils.assert_called_once(rm_tree)


def test_clean_up_mount_state_dir_fail(mocker, tmpdir):
    setup_mock(mocker, False)
    mocker.patch('os.path.isdir', return_value=False)
    rm_tree = mocker.patch('shutil.rmtree')

    state_dir, state_file, abs_state_file = create_state_file(tmpdir)

    assert os.path.exists(abs_state_file)

    watchdog.clean_up_mount_state(state_dir, state_file, PID, is_running=False, mount_state_dir='/fake/path')

    utils.assert_not_called(rm_tree)
