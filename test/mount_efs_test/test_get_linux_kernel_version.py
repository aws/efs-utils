#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import mount_efs

DEFAULT_KERNEL_VERSION_NEEDED_LEN = len(
    mount_efs.NFS_READAHEAD_OPTIMIZE_LINUX_KERNEL_MIN_VERSION
)


def test_get_linux_kernel_version_empty(mocker):
    mocker.patch("platform.release", return_value="")
    assert [0, 0] == mount_efs.get_linux_kernel_version(
        DEFAULT_KERNEL_VERSION_NEEDED_LEN
    )


def test_get_linux_kernel_version_only_dash(mocker):
    mocker.patch("platform.release", return_value="-")
    assert [0, 0] == mount_efs.get_linux_kernel_version(
        DEFAULT_KERNEL_VERSION_NEEDED_LEN
    )


def test_get_linux_kernel_version_no_number(mocker):
    mocker.patch("platform.release", return_value="test")
    assert [0, 0] == mount_efs.get_linux_kernel_version(
        DEFAULT_KERNEL_VERSION_NEEDED_LEN
    )


def test_get_linux_kernel_version(mocker):
    mocker.patch("platform.release", return_value="3.10.0-1160.el7.x86_64")
    assert [3, 10] == mount_efs.get_linux_kernel_version(
        DEFAULT_KERNEL_VERSION_NEEDED_LEN
    )


def test_get_linux_kernel_version_only_major_version(mocker):
    mocker.patch("platform.release", return_value="3-1160.el7.x86_64")
    assert [3, 0] == mount_efs.get_linux_kernel_version(
        DEFAULT_KERNEL_VERSION_NEEDED_LEN
    )


def test_get_linux_kernel_version_no_dash(mocker):
    mocker.patch("platform.release", return_value="3.10.0")
    assert [3, 10] == mount_efs.get_linux_kernel_version(
        DEFAULT_KERNEL_VERSION_NEEDED_LEN
    )
