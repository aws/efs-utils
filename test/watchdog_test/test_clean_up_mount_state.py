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

PID = 99999999999999999


def create_temp_file(tmpdir, content=''):
    temp_file = tmpdir.join(tempfile.mktemp())
    temp_file.write(content, ensure=True)
    return temp_file


def create_state_file(tmpdir, extra_files=list()):
    state_file = create_temp_file(tmpdir, json.dumps({'pid': PID, 'files': extra_files}))

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

    killpg_mock.assert_called_once()
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

    killpg_mock.assert_called_once()
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

    killpg_mock.assert_called_once()
    assert os.path.exists(abs_state_file)


def test_pid_not_running(mocker, tmpdir):
    killpg_mock = setup_mock(mocker, False)

    state_dir, state_file, abs_state_file = create_state_file(tmpdir)

    assert os.path.exists(abs_state_file)

    watchdog.clean_up_mount_state(state_dir, state_file, PID, is_running=False)

    killpg_mock.assert_not_called()
    assert not os.path.exists(abs_state_file)
