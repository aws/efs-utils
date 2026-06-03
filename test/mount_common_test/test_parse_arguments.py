# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
import pytest

import efs_utils_common.constants as constants
import efs_utils_common.context as context
import mount_efs
from efs_utils_common.constants import MOUNT_TYPE_EFS


@pytest.fixture(autouse=True)
def setup_test():
    # Get the singleton instance and reset it to clean state
    mount_context = context.MountContext()
    mount_context.reset()
    mount_context.fqdn_regex_pattern = mount_efs.FQDN_REGEX_PATTERN
    mount_context.mount_type = MOUNT_TYPE_EFS
    yield mount_context
    mount_context.reset()


def _test_parse_arguments_help(capsys, help):
    with pytest.raises(SystemExit) as ex:
        mount_efs.parse_arguments_early_exit(["mount", "foo", "bar", help])

    assert 0 == ex.value.code

    out, err = capsys.readouterr()
    assert "Usage:" in out


def test_parse_arguments_help_long(capsys):
    _test_parse_arguments_help(capsys, "--help")


def test_parse_arguments_help_short(capsys):
    _test_parse_arguments_help(capsys, "-h")


def test_parse_arguments_version(capsys):
    with pytest.raises(SystemExit) as ex:
        mount_efs.parse_arguments_early_exit(["mount", "foo", "bar", "--version"])

    assert 0 == ex.value.code

    out, err = capsys.readouterr()
    assert "Version: %s" % constants.VERSION in out


def test_parse_arguments_no_fs_id(capsys):
    with pytest.raises(SystemExit) as ex:
        mount_efs.parse_arguments(None, ["mount"])

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert "Usage:" in err


def test_parse_arguments_no_mount_point(capsys):
    with pytest.raises(SystemExit) as ex:
        mount_efs.parse_arguments(None, ["mount", "fs-deadbeef"])

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert "Usage:" in err


def test_parse_arguments_default_path():
    fsid, path, mountpoint, options, fake = mount_efs.parse_arguments(
        None, ["mount", "fs-deadbeef", "/dir"]
    )

    assert "fs-deadbeef" == fsid
    assert "/" == path
    assert "/dir" == mountpoint
    assert {} == options
    assert fake is False


def test_parse_arguments_custom_path():
    fsid, path, mountpoint, options, fake = mount_efs.parse_arguments(
        None, ["mount", "fs-deadbeef:/home", "/dir"]
    )

    assert "fs-deadbeef" == fsid
    assert "/home" == path
    assert "/dir" == mountpoint
    assert {} == options
    assert fake is False


def test_parse_arguments_verbose():
    fsid, path, mountpoint, options, fake = mount_efs.parse_arguments(
        None, ["mount", "fs-deadbeef:/home", "/dir", "-v", "-o", "foo,bar=baz,quux"]
    )

    assert "fs-deadbeef" == fsid
    assert "/home" == path
    assert "/dir" == mountpoint
    assert {"foo": None, "bar": "baz", "quux": None} == options
    assert fake is False


def test_parse_arguments():
    fsid, path, mountpoint, options, fake = mount_efs.parse_arguments(
        None, ["mount", "fs-deadbeef:/home", "/dir", "-o", "foo,bar=baz,quux"]
    )

    assert "fs-deadbeef" == fsid
    assert "/home" == path
    assert "/dir" == mountpoint
    assert {"foo": None, "bar": "baz", "quux": None} == options
    assert fake is False


def test_parse_arguments_with_az_dns_name_mount_az_not_in_option(mocker):
    # When dns_name is provided for mounting, if the az is not provided in the mount option, also dns_name contains az
    # info, verify that the az info is present in the options
    dns_name = "us-east-1a.fs-deadbeef.efs.us-east-1.amazonaws.com"
    mocker.patch(
        "mount_efs.match_device", return_value=("fs-deadbeef", "/", "us-east-1a")
    )
    fsid, path, mountpoint, options, fake = mount_efs.parse_arguments(
        None, ["mount", dns_name, "/dir", "-o", "foo,bar=baz,quux"]
    )

    assert "fs-deadbeef" == fsid
    assert "/" == path
    assert "/dir" == mountpoint
    assert {"foo": None, "bar": "baz", "quux": None, "az": "us-east-1a"} == options
    assert fake is False


def test_parse_arguments_macos(mocker):
    mocker.patch("mount_efs.check_if_platform_is_mac", return_value=True)
    fsid, path, mountpoint, options, fake = mount_efs.parse_arguments(
        None,
        [
            "mount",
            "-o",
            "foo",
            "-o",
            "bar=baz",
            "-o",
            "quux",
            "fs-deadbeef:/home",
            "/dir",
        ],
    )

    assert "fs-deadbeef" == fsid
    assert "/home" == path
    assert "/dir" == mountpoint
    assert {"foo": None, "bar": "baz", "quux": None} == options
    assert fake is False


# ---------------------------------------------------------------------------
# Fake mount (-f) detection tests
#
# On Linux, mount(8) passes -f as a standalone flag to the helper after the
# positional args (spec, dir). See the EXTERNAL HELPERS section of mount(8):
#   /sbin/mount.suffix spec dir [-sfnv] [-o options]
#   https://man7.org/linux/man-pages/man8/mount.8.html
#
# On macOS, mount(8) does NOT pass -f to the helper. -f means MNT_FORCE
# (force permission downgrade), not fake/dry-run, and is converted to "-o force".
#   Source: mountfs() in apple-oss-distributions/diskdev_cmds/mount.tproj/mount.c
# ---------------------------------------------------------------------------


def test_parse_arguments_fake_mount_linux():
    """Linux: -f after fsname and mountpoint is detected as fake mount."""
    fsid, path, mountpoint, options, fake = mount_efs.parse_arguments(
        None, ["mount.efs", "fs-deadbeef", "/mnt", "-f"]
    )
    assert fake is True


def test_parse_arguments_fake_mount_linux_with_options():
    """Linux: -f before -o options is detected as fake mount while respecting options.

    mount(8) constructs: /sbin/mount.efs spec dir [-sfnv] [-o options]
    """
    fsid, path, mountpoint, options, fake = mount_efs.parse_arguments(
        None, ["mount.efs", "fs-deadbeef", "/mnt", "-f", "-o", "tls"]
    )
    assert fake is True
    assert "tls" in options


def test_parse_arguments_fake_mount_linux_with_verbose():
    """Linux: -f alongside -v (verbose) flag."""
    fsid, path, mountpoint, options, fake = mount_efs.parse_arguments(
        None, ["mount.efs", "fs-deadbeef", "/mnt", "-f", "-v", "-o", "tls"]
    )
    assert fake is True


def test_parse_arguments_no_fake_mount_linux():
    """Linux: no -f flag means fake is False."""
    fsid, path, mountpoint, options, fake = mount_efs.parse_arguments(
        None, ["mount.efs", "fs-deadbeef", "/mnt", "-o", "tls"]
    )
    assert fake is False


def test_parse_arguments_no_fake_mount_minimal():
    """Linux: minimal args (no flags, no options) means fake is False."""
    fsid, path, mountpoint, options, fake = mount_efs.parse_arguments(
        None, ["mount.efs", "fs-deadbeef", "/mnt"]
    )
    assert fake is False


def test_parse_arguments_fake_not_in_spec(mocker):
    """Linux: -f appearing as the spec (args[1]) is not treated as fake.

    args[1] is the file system name, not a flag. Only args[3:] are checked.
    match_device is mocked because "-f" is not a valid file system name
    and would fail before we can check the fake flag.
    """
    mocker.patch("mount_efs.match_device", return_value=("-f", "/", None))
    fsid, path, mountpoint, options, fake = mount_efs.parse_arguments(
        None, ["mount.efs", "-f", "/mnt"]
    )
    assert fake is False


def test_parse_arguments_fake_not_in_dir():
    """Linux: -f appearing as the dir (args[2]) is not treated as fake.

    args[2] is the mountpoint, not a flag. Only args[3:] are checked.
    """
    fsid, path, mountpoint, options, fake = mount_efs.parse_arguments(
        None, ["mount.efs", "fs-deadbeef", "-f"]
    )
    assert fake is False
    assert mountpoint == "-f"


def test_parse_arguments_fake_mount_macos_ignored(mocker):
    """macOS: -f in argv is NOT treated as fake mount.

    On macOS, mount(8) converts -f to MNT_FORCE and passes it as "-o force",
    never as a standalone -f flag. If -f somehow appeared in argv on macOS
    (e.g. direct invocation), it should be ignored.
    """
    mocker.patch("mount_efs.check_if_platform_is_mac", return_value=True)
    fsid, path, mountpoint, options, fake = mount_efs.parse_arguments(
        None,
        ["mount_efs", "-o", "tls", "-f", "fs-deadbeef:/home", "/dir"],
    )
    assert fake is False
