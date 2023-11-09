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

import mount_efs

FS_ID = "fs-deadbeef"
PID = 1234
PORT = 54323
COMMAND = ["stunnel", "/some/config/file"]
NETNS = "/proc/1/net/ns"
NETNS_COMMAND = ["nsenter", "--net=" + NETNS] + COMMAND
FILES = ["/tmp/foo", "/tmp/bar"]
DATETIME_FORMAT = "%y%m%d%H%M%SZ"


def test_write_tls_tunnel_state_file_netns(tmpdir):
    state_file_dir = str(tmpdir)

    mount_point = "/home/user/foo/mount"

    current_time = datetime.now(datetime.UTC)
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

    state_file = mount_efs.write_tls_tunnel_state_file(
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


def test_write_tls_tunnel_state_file(tmpdir):
    state_file_dir = str(tmpdir)

    mount_point = "/home/user/foo/mount"

    current_time = datetime.now(datetime.UTC)
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

    state_file = mount_efs.write_tls_tunnel_state_file(
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


def test_write_tls_tunnel_state_file_no_cert(tmpdir):
    state_file_dir = str(tmpdir)

    mount_point = "/home/user/foo/mount"

    state_file = mount_efs.write_tls_tunnel_state_file(
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
