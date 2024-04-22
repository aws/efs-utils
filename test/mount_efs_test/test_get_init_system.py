#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import mount_efs
import tempfile


def test_get_init_system_from_file(tmpdir):
    temp_file = tmpdir.join(tempfile.mktemp())
    temp_file.write('systemd\n', ensure=True)

    init_system = mount_efs.get_init_system(str(temp_file))

    assert 'systemd' == init_system


def test_get_init_system_nonexistent_file(tmpdir):
    temp_file = tmpdir.join(tempfile.mktemp())

    init_system = mount_efs.get_init_system(str(temp_file))

    assert 'unknown' == init_system
