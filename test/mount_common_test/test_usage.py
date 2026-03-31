# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.

import io

import pytest

from efs_utils_common.constants import MOUNT_TYPE_EFS, MOUNT_TYPE_S3FILES
from efs_utils_common.context import MountContext
from efs_utils_common.file_utils import usage


@pytest.fixture(autouse=True)
def reset_context():
    context = MountContext()
    context.reset()
    yield context
    context.reset()


def test_usage_shows_mount_s3files_when_mount_type_is_s3files(reset_context):
    reset_context.mount_type = MOUNT_TYPE_S3FILES
    out = io.StringIO()
    with pytest.raises(SystemExit):
        usage(out)
    assert "mount.s3files" in out.getvalue()


def test_usage_shows_mount_efs_when_mount_type_is_efs(reset_context):
    reset_context.mount_type = MOUNT_TYPE_EFS
    out = io.StringIO()
    with pytest.raises(SystemExit):
        usage(out)
    assert "mount.efs" in out.getvalue()


def test_usage_shows_mount_efs_when_mount_type_is_none(reset_context):
    reset_context.mount_type = None
    out = io.StringIO()
    with pytest.raises(SystemExit):
        usage(out)
    assert "mount.efs" in out.getvalue()
