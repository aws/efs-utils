#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import watchdog


MOUNT_FMT_LINE = '{address}:/ {mountpoint} {fs_type} rw,port=12345 0 0'


def _create_mount_file(tmpdir, lines):
    mount_file = tmpdir.join('mounts')
    mount_file.write('\n'.join(lines))
    return str(mount_file)


def test_no_mounts(tmpdir):
    mount_file = _create_mount_file(tmpdir, [])

    mounts = watchdog.get_current_local_nfs_mounts(mount_file)

    assert {} == mounts


def test_no_local_mounts(tmpdir):
    mount_file = _create_mount_file(tmpdir, [MOUNT_FMT_LINE.format(address='10.1.0.1', mountpoint='/mnt', fs_type='nfs4')])

    mounts = watchdog.get_current_local_nfs_mounts(mount_file)

    assert {} == mounts


def test_no_local_nfs_mounts(tmpdir):
    mount_file = _create_mount_file(tmpdir, [MOUNT_FMT_LINE.format(address='127.0.0.1', mountpoint='/mnt', fs_type='ext4')])

    mounts = watchdog.get_current_local_nfs_mounts(mount_file)

    assert {} == mounts


def test_local_nfs_mount(tmpdir):
    mount_file = _create_mount_file(tmpdir, [MOUNT_FMT_LINE.format(address='127.0.0.1', mountpoint='/mnt', fs_type='nfs4')])

    mounts = watchdog.get_current_local_nfs_mounts(mount_file)

    assert 1 == len(mounts)
    assert 'mnt.12345' in mounts
