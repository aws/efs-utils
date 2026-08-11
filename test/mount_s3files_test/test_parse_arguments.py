# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.

import pytest

import efs_utils_common.constants as constants
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

    fsid, path, mountpoint, options, fake = mount_s3files.parse_arguments(
        None, ["mount", dns_name, "/dir", "-o", "rw"]
    )

    assert fsid == "fs-deadbeef"
    assert path == "/"
    assert mountpoint == "/dir"
    assert "azid" in options
    assert options["azid"] == "use1-az2"
    assert "az" not in options, "'az' is unsupported for s3files, should use 'azid'"
    assert fake is False


# Entry-point failure paths, brought to parity with the mount_efs equivalents in
# test/mount_common_test/test_parse_arguments.py (help / version / usage failures).


def _test_parse_arguments_help(capsys, help_flag):
    with pytest.raises(SystemExit) as ex:
        mount_s3files.parse_arguments_early_exit(["mount", "foo", "bar", help_flag])

    assert 0 == ex.value.code

    out, _ = capsys.readouterr()
    assert "Usage:" in out


def test_parse_arguments_help_long(capsys):
    _test_parse_arguments_help(capsys, "--help")


def test_parse_arguments_help_short(capsys):
    _test_parse_arguments_help(capsys, "-h")


def test_parse_arguments_version(capsys):
    with pytest.raises(SystemExit) as ex:
        mount_s3files.parse_arguments_early_exit(["mount", "foo", "bar", "--version"])

    assert 0 == ex.value.code

    out, _ = capsys.readouterr()
    assert "Version: %s" % constants.VERSION in out


def test_parse_arguments_no_fs_id(capsys):
    """Usage failure: no file system name supplied exits non-zero with usage on stderr."""
    with pytest.raises(SystemExit) as ex:
        mount_s3files.parse_arguments(None, ["mount"])

    assert 0 != ex.value.code

    _, err = capsys.readouterr()
    assert "Usage:" in err


def test_parse_arguments_no_mount_point(capsys):
    """Usage failure: fs name but no mount point exits non-zero with usage on stderr."""
    with pytest.raises(SystemExit) as ex:
        mount_s3files.parse_arguments(None, ["mount", "fs-deadbeef"])

    assert 0 != ex.value.code

    _, err = capsys.readouterr()
    assert "Usage:" in err


def test_parse_arguments_fake_arg_not_early_exit(capsys):
    """A non-help/version early-exit flag (e.g. '--fake-arg') must NOT trigger early exit."""
    # parse_arguments_early_exit should return normally (no SystemExit) for unknown flags.
    assert (
        mount_s3files.parse_arguments_early_exit(["mount", "foo", "bar", "--fake-arg"])
        is None
    )
