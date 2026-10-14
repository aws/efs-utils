#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import json
import os
from datetime import datetime

import pytest

import efs_utils_common.proxy as proxy
from efs_utils_common.constants import MOUNT_TYPE_EFS
from efs_utils_common.context import MountContext

FS_ID = "fs-deadbeef"
PID = 1234
PORT = 54323
COMMAND = ["stunnel", "/some/config/file"]
NETNS = "/proc/1/net/ns"
NETNS_COMMAND = ["nsenter", "--net=" + NETNS] + COMMAND
FILES = ["/tmp/foo", "/tmp/bar"]
DATETIME_FORMAT = "%y%m%d%H%M%SZ"


@pytest.fixture(autouse=True)
def setup_test():
    """
    Setup fixture that runs before each test function.
    Instantiate and reset the MountContext singleton for clean test state.
    """
    mount_context = MountContext()
    mount_context.reset()
    mount_context.mount_type = MOUNT_TYPE_EFS
    yield mount_context
    mount_context.reset()


def test_write_tunnel_state_file_netns(tmpdir):
    state_file_dir = str(tmpdir)

    mount_point = "/home/user/foo/mount"

    current_time = datetime.utcnow()
    cert_creation_time = current_time.strftime(DATETIME_FORMAT)

    cert_details = {
        "accessPoint": "fsap-fedcba9876543210",
        "certificate": "/tmp/baz",
        "privateKey": "/tmp/key.pem",
        "mountStateDir": "fs-deadbeef.mount.dir.12345",
        "commonName": "fs-deadbeef.efs.us-east-1.amazonaws.com",
        "region": "us-east-1",
        "fsId": FS_ID,
        "certificateCreationTime": cert_creation_time,
        "useIam": True,
    }

    state_file = proxy.write_tunnel_state_file(
        FS_ID,
        mount_point,
        PORT,
        PID,
        NETNS_COMMAND,
        FILES,
        state_file_dir,
        cert_details,
    )

    assert FS_ID in state_file
    assert os.sep not in state_file[state_file.find(FS_ID) :]

    assert os.path.exists(state_file_dir)

    state_file = os.path.join(state_file_dir, state_file)
    assert os.path.exists(state_file)

    with open(state_file) as f:
        state = json.load(f)

    assert PID == state.get("pid")
    assert NETNS_COMMAND == state.get("cmd")
    assert FILES == state.get("files")
    assert cert_details["commonName"] == state.get("commonName")
    assert cert_details["certificate"] == state.get("certificate")
    assert cert_details["certificateCreationTime"] == state.get(
        "certificateCreationTime"
    )
    assert cert_details["mountStateDir"] == state.get("mountStateDir")
    assert cert_details["privateKey"] == state.get("privateKey")
    assert cert_details["region"] == state.get("region")
    assert cert_details["accessPoint"] == state.get("accessPoint")
    assert cert_details["fsId"] == state.get("fsId")
    assert cert_details["useIam"] == state.get("useIam")


def test_write_tunnel_state_file(tmpdir):
    state_file_dir = str(tmpdir)

    mount_point = "/home/user/foo/mount"

    current_time = datetime.utcnow()
    cert_creation_time = current_time.strftime(DATETIME_FORMAT)

    cert_details = {
        "accessPoint": "fsap-fedcba9876543210",
        "certificate": "/tmp/baz",
        "privateKey": "/tmp/key.pem",
        "mountStateDir": "fs-deadbeef.mount.dir.12345",
        "commonName": "fs-deadbeef.efs.us-east-1.amazonaws.com",
        "region": "us-east-1",
        "fsId": FS_ID,
        "certificateCreationTime": cert_creation_time,
        "useIam": True,
    }

    state_file = proxy.write_tunnel_state_file(
        FS_ID, mount_point, PORT, PID, COMMAND, FILES, state_file_dir, cert_details
    )

    assert FS_ID in state_file
    assert os.sep not in state_file[state_file.find(FS_ID) :]

    assert os.path.exists(state_file_dir)

    state_file = os.path.join(state_file_dir, state_file)
    assert os.path.exists(state_file)

    with open(state_file) as f:
        state = json.load(f)

    assert PID == state.get("pid")
    assert COMMAND == state.get("cmd")
    assert FILES == state.get("files")
    assert cert_details["commonName"] == state.get("commonName")
    assert cert_details["certificate"] == state.get("certificate")
    assert cert_details["certificateCreationTime"] == state.get(
        "certificateCreationTime"
    )
    assert cert_details["mountStateDir"] == state.get("mountStateDir")
    assert cert_details["privateKey"] == state.get("privateKey")
    assert cert_details["region"] == state.get("region")
    assert cert_details["accessPoint"] == state.get("accessPoint")
    assert cert_details["fsId"] == state.get("fsId")
    assert cert_details["useIam"] == state.get("useIam")


def test_write_tunnel_state_file_no_cert(tmpdir):
    state_file_dir = str(tmpdir)

    mount_point = "/home/user/foo/mount"

    state_file = proxy.write_tunnel_state_file(
        FS_ID, mount_point, PORT, PID, COMMAND, FILES, state_file_dir
    )

    assert FS_ID in state_file
    assert os.sep not in state_file[state_file.find(FS_ID) :]

    assert os.path.exists(state_file_dir)

    state_file = os.path.join(state_file_dir, state_file)
    assert os.path.exists(state_file)

    with open(state_file) as f:
        state = json.load(f)

    assert PID == state.get("pid")
    assert COMMAND == state.get("cmd")
    assert FILES == state.get("files")
    assert "commonName" not in state
    assert "certificate" not in state
    assert "certificateCreationTime" not in state
    assert "mountStateDir" not in state
    assert "privateKey" not in state
    assert "region" not in state
    assert "accessPoint" not in state
    assert "fsId" not in state
    assert "useIam" not in state


def test_update_tunnel_temp_state_file_with_tunnel_pid(tmpdir):
    state_file_dir = str(tmpdir)
    state_file = proxy.write_tunnel_state_file(
        FS_ID, "/home/user/foo/mount", PORT, -1, COMMAND, FILES, state_file_dir
    )

    updated = proxy.update_tunnel_temp_state_file_with_tunnel_pid(
        state_file, state_file_dir, PID
    )

    assert updated == state_file
    with open(os.path.join(state_file_dir, state_file)) as f:
        state = json.load(f)
    assert PID == state.get("pid")
    assert state.get("pid_start_time") == proxy.get_process_start_time(PID)
    assert COMMAND == state.get("cmd")
    assert os.listdir(state_file_dir) == [state_file]


def test_update_tunnel_temp_state_file_leaves_record_intact_if_write_dies(
    tmpdir, mocker
):
    state_file_dir = str(tmpdir)
    state_file = proxy.write_tunnel_state_file(
        FS_ID, "/home/user/foo/mount", PORT, -1, COMMAND, FILES, state_file_dir
    )
    mocker.patch("efs_utils_common.proxy.json.dump", side_effect=OSError("killed"))

    with pytest.raises(OSError):
        proxy.update_tunnel_temp_state_file_with_tunnel_pid(
            state_file, state_file_dir, PID
        )

    with open(os.path.join(state_file_dir, state_file)) as f:
        assert json.load(f).get("pid") == -1
    assert os.listdir(state_file_dir) == [state_file]


def test_write_tunnel_state_file_records_writer(tmpdir):
    state_file_dir = str(tmpdir)

    state_file = proxy.write_tunnel_state_file(
        FS_ID, "/home/user/foo/mount", PORT, -1, COMMAND, FILES, state_file_dir
    )

    with open(os.path.join(state_file_dir, state_file)) as f:
        state = json.load(f)
    assert state["writer_pid"] == os.getpid()
    assert state["writer_start_time"] == proxy.get_process_start_time(os.getpid())
    assert os.listdir(state_file_dir) == [state_file]


def test_get_process_start_time_of_missing_pid_is_none():
    assert proxy.get_process_start_time(2**22 + 1) is None


def test_get_process_start_time_on_mac_pins_ps_environment(mocker):
    mocker.patch("efs_utils_common.proxy.check_if_platform_is_mac", return_value=True)
    proc = mocker.MagicMock()
    proc.communicate.return_value = (b"Thu Oct  8 12:00:00 2026\n", b"")
    popen = mocker.patch("efs_utils_common.proxy.subprocess.Popen", return_value=proc)

    assert proxy.get_process_start_time(7) == "Thu Oct  8 12:00:00 2026"
    assert popen.call_args[1]["env"] == {
        "LC_ALL": "C",
        "TZ": "UTC",
        "PATH": "/bin:/usr/bin",
    }
