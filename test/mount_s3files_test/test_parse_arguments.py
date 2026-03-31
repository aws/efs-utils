# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.

import pytest

import efs_utils_common.context as context
import mount_s3files
from efs_utils_common.constants import MOUNT_TYPE_S3FILES


@pytest.fixture(autouse=True)
def setup_test():
    mount_context = context.MountContext()
    mount_context.reset()
    mount_context.fqdn_regex_pattern = mount_s3files.FQDN_REGEX_PATTERN
    mount_context.mount_type = MOUNT_TYPE_S3FILES
    yield mount_context
    mount_context.reset()


def test_parse_arguments_with_fqdn_uses_azid_not_az(mocker):
    """
    When mounting with FQDN containing az_id, verify it's added as 'azid' not 'az'.
    'az' is in MOUNT_TYPE_SPECIFIC_UNSUPPORTED_OPTIONS for s3files.
    """
    dns_name = "use1-az2.fs-deadbeef.s3files.us-east-1.on.aws"
    mocker.patch(
        "mount_s3files.match_device", return_value=("fs-deadbeef", "/", "use1-az2")
    )

    fsid, path, mountpoint, options = mount_s3files.parse_arguments(
        None, ["mount", dns_name, "/dir", "-o", "rw"]
    )

    assert fsid == "fs-deadbeef"
    assert path == "/"
    assert mountpoint == "/dir"
    assert "azid" in options
    assert options["azid"] == "use1-az2"
    assert "az" not in options, "'az' is unsupported for s3files, should use 'azid'"
