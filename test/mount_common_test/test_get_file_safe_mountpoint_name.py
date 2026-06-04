#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

from efs_utils_common.file_utils import get_file_safe_mountpoint_name


def test_standard_path():
    assert "mnt" == get_file_safe_mountpoint_name("/mnt")


def test_nested_path():
    assert "mnt.efs.data" == get_file_safe_mountpoint_name("/mnt/efs/data")


def test_root_path():
    """/ -> . -> '' (empty string)"""
    assert "" == get_file_safe_mountpoint_name("/")


def test_hidden_directory():
    """/.efs -> ..efs -> efs (the bug-fix case from GitHub issue #218)"""
    assert "efs" == get_file_safe_mountpoint_name("/.efs")


def test_hidden_directory_nested():
    assert "hidden.data" == get_file_safe_mountpoint_name("/.hidden/data")


def test_hidden_directory_multiple_leading_dots():
    """/...efs -> ....efs -> efs"""
    assert "efs" == get_file_safe_mountpoint_name("/...efs")


def test_mid_path_dot_preserved():
    """Only leading dots are stripped, not dots in the middle of the path."""
    assert "hidden..secret.data" == get_file_safe_mountpoint_name(
        "/.hidden/.secret/data"
    )
