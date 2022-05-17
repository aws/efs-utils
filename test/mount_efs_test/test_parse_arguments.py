# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.

import pytest

import mount_efs


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
    assert "Version: %s" % mount_efs.VERSION in out


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
    fsid, path, mountpoint, options = mount_efs.parse_arguments(
        None, ["mount", "fs-deadbeef", "/dir"]
    )

    assert "fs-deadbeef" == fsid
    assert "/" == path
    assert "/dir" == mountpoint
    assert {} == options


def test_parse_arguments_custom_path():
    fsid, path, mountpoint, options = mount_efs.parse_arguments(
        None, ["mount", "fs-deadbeef:/home", "/dir"]
    )

    assert "fs-deadbeef" == fsid
    assert "/home" == path
    assert "/dir" == mountpoint
    assert {} == options


def test_parse_arguments_verbose():
    fsid, path, mountpoint, options = mount_efs.parse_arguments(
        None, ["mount", "fs-deadbeef:/home", "/dir", "-v", "-o", "foo,bar=baz,quux"]
    )

    assert "fs-deadbeef" == fsid
    assert "/home" == path
    assert "/dir" == mountpoint
    assert {"foo": None, "bar": "baz", "quux": None} == options


def test_parse_arguments():
    fsid, path, mountpoint, options = mount_efs.parse_arguments(
        None, ["mount", "fs-deadbeef:/home", "/dir", "-o", "foo,bar=baz,quux"]
    )

    assert "fs-deadbeef" == fsid
    assert "/home" == path
    assert "/dir" == mountpoint
    assert {"foo": None, "bar": "baz", "quux": None} == options


def test_parse_arguments_with_az_dns_name_mount_az_not_in_option(mocker):
    # When dns_name is provided for mounting, if the az is not provided in the mount option, also dns_name contains az
    # info, verify that the az info is present in the options
    dns_name = "us-east-1a.fs-deadbeef.efs.us-east-1.amazonaws.com"
    mocker.patch(
        "mount_efs.match_device", return_value=("fs-deadbeef", "/", "us-east-1a")
    )
    fsid, path, mountpoint, options = mount_efs.parse_arguments(
        None, ["mount", dns_name, "/dir", "-o", "foo,bar=baz,quux"]
    )

    assert "fs-deadbeef" == fsid
    assert "/" == path
    assert "/dir" == mountpoint
    assert {"foo": None, "bar": "baz", "quux": None, "az": "us-east-1a"} == options


def test_parse_arguments_macos(mocker):
    mocker.patch("mount_efs.check_if_platform_is_mac", return_value=True)
    fsid, path, mountpoint, options = mount_efs.parse_arguments(
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
