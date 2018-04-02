#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import watchdog


def test_non_existent_dir(tmpdir):
    state_files = watchdog.get_state_files(str(tmpdir.join('new-dir')))

    assert {} == state_files


def test_empty_dir(tmpdir):
    state_files = watchdog.get_state_files(str(tmpdir))

    assert {} == state_files


def test_no_state_files(tmpdir):
    tmpdir.join('~fs-deadbeef.mount.dir.12345').write('')

    state_files = watchdog.get_state_files(str(tmpdir))

    assert {} == state_files


def test_state_files(tmpdir):
    efs_config = 'fs-deadbeef.mount.dir.12345'
    tmpdir.join(efs_config).write('')

    stunnel_config = 'stunnel-config.fs-deadbeef.mount.dir.12345'
    tmpdir.join(stunnel_config).write('')

    state_files = watchdog.get_state_files(str(tmpdir))

    assert 1 == len(state_files)
    assert 'mount.dir' in state_files
