#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import mount_efs
import json
import os

FS_ID = 'fs-deadbeef'
PID = 1234
PORT = 54323
COMMAND = ['stunnel', '/some/config/file']
FILES = ['/tmp/foo', '/tmp/bar']


def test_write_tls_tunnel_state_file(tmpdir):
    state_file_dir = str(tmpdir)

    mount_point = '/home/user/foo/mount'

    state_file = mount_efs.write_tls_tunnel_state_file(FS_ID, mount_point, PORT, PID, COMMAND, FILES, state_file_dir)

    assert FS_ID in state_file
    assert os.sep not in state_file[state_file.find(FS_ID):]

    assert os.path.exists(state_file_dir)

    state_file = os.path.join(state_file_dir, state_file)
    assert os.path.exists(state_file)

    with open(state_file) as f:
        state = json.load(f)

    assert PID == state.get('pid')
    assert COMMAND == state.get('cmd')
    assert FILES == state.get('files')
