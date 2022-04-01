#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import tempfile

import mount_efs


def test_get_init_system_from_file(tmpdir):
    temp_file = tmpdir.join(tempfile.mkstemp()[1])
    temp_file.write("systemd\n", ensure=True)

    init_system = mount_efs.get_init_system(str(temp_file))

    assert "systemd" == init_system


def test_get_init_system_nonexistent_file(tmpdir):
    temp_file = tmpdir.join(tempfile.mkstemp()[1])

    init_system = mount_efs.get_init_system(str(temp_file))

    assert "unknown" == init_system
