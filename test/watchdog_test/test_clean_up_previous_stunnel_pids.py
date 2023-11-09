#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import json
import tempfile
from datetime import datetime

import watchdog

from .. import utils

PID = 1234
STATE = {
    "pid": PID,
    "commonName": "deadbeef.com",
    "certificate": "/tmp/foobar",
    "certificateCreationTime": datetime.now(datetime.UTC).strftime(
        watchdog.CERT_DATETIME_FORMAT
    ),
    "mountStateDir": "fs-deadbeef.mount.dir.12345",
    "privateKey": "/tmp/foobarbaz",
    "accessPoint": "fsap-fedcba9876543210",
}

PROCESS_NAME_OUTPUT = "stunnel/var/run/efs/stunnel-config/fs-deadbeef.mount.dir.12345"
PROCESS_NAME_OUTPUT_LWP = "/foo/bar/baz"
PROCESS_NAME_OUTPUT_ERR = ""


def setup_mocks(mocker, state_files, process_name_output):
    mocker.patch("watchdog.get_state_files", return_value=state_files)
    mocker.patch("watchdog.check_process_name", return_value=process_name_output)

    return mocker.patch("watchdog.rewrite_state_file")


def create_state_file(tmpdir, content=json.dumps(STATE)):
    state_file = tmpdir.join(tempfile.mkstemp()[1])

    state_file.write(content, ensure=True)

    return state_file.dirname, state_file.basename


def test_malformed_state_file(mocker, tmpdir):
    state_file_dir, state_file = create_state_file(tmpdir, "not-json")

    rewrite_state_file_mock = setup_mocks(
        mocker, state_files={"mnt": state_file}, process_name_output=PROCESS_NAME_OUTPUT
    )

    watchdog.clean_up_previous_stunnel_pids(state_file_dir)

    utils.assert_not_called(rewrite_state_file_mock)


def test_clean_up_active_stunnel_from_previous_watchdog(mocker, tmpdir):
    state_file_dir, state_file = create_state_file(tmpdir)

    rewrite_state_file_mock = setup_mocks(
        mocker, state_files={"mnt": state_file}, process_name_output=PROCESS_NAME_OUTPUT
    )

    watchdog.clean_up_previous_stunnel_pids(state_file_dir)

    utils.assert_not_called(rewrite_state_file_mock)


def test_clean_up_active_LWP_from_driver(mocker, tmpdir):
    state_file_dir, state_file = create_state_file(tmpdir)

    rewrite_state_file_mock = setup_mocks(
        mocker,
        state_files={"mnt": state_file},
        process_name_output=PROCESS_NAME_OUTPUT_LWP,
    )

    watchdog.clean_up_previous_stunnel_pids(state_file_dir)

    utils.assert_called_once(rewrite_state_file_mock)


def test_clean_up_stunnel_pid_from_previous_driver(mocker, tmpdir):
    state_file_dir, state_file = create_state_file(tmpdir)

    rewrite_state_file_mock = setup_mocks(
        mocker,
        state_files={"mnt": state_file},
        process_name_output=PROCESS_NAME_OUTPUT_ERR,
    )

    watchdog.clean_up_previous_stunnel_pids(state_file_dir)

    utils.assert_called_once(rewrite_state_file_mock)


def test_no_state_files_from_previous_driver(mocker, tmpdir):
    rewrite_state_file_mock = setup_mocks(
        mocker, state_files={}, process_name_output=PROCESS_NAME_OUTPUT
    )

    watchdog.clean_up_previous_stunnel_pids(tmpdir)

    utils.assert_not_called(rewrite_state_file_mock)


def test_clean_up_multiple_stunnel_pids(mocker, tmpdir):
    state_file_dir, state_file_1 = create_state_file(tmpdir)

    state = dict(STATE)
    state["pid"] = 5678
    state_file_dir, state_file_2 = create_state_file(tmpdir, content=json.dumps(state))

    rewrite_state_file_mock = setup_mocks(
        mocker,
        state_files={"mnt/a1": state_file_1, "mnt/a2": state_file_2},
        process_name_output=PROCESS_NAME_OUTPUT_ERR,
    )

    watchdog.clean_up_previous_stunnel_pids(state_file_dir)

    utils.assert_called(rewrite_state_file_mock)


def test_clean_up_stunnel_no_pid(mocker, tmpdir):
    state = dict(STATE)
    state.pop("pid")

    state_file_dir, state_file = create_state_file(tmpdir, content=json.dumps(state))

    rewrite_state_file_mock = setup_mocks(
        mocker,
        state_files={"mnt": state_file},
        process_name_output=PROCESS_NAME_OUTPUT_LWP,
    )

    watchdog.clean_up_previous_stunnel_pids(state_file_dir)

    utils.assert_not_called(rewrite_state_file_mock)
