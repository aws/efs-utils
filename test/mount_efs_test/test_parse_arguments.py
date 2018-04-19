#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import mount_efs

import pytest


def _test_parse_arguments_help(capsys, help):
    with pytest.raises(SystemExit) as ex:
        mount_efs.parse_arguments(['mount', 'foo', 'bar', help])

    assert 0 == ex.value.code

    out, err = capsys.readouterr()
    assert 'Usage:' in out


def test_parse_arguments_help_long(capsys):
    _test_parse_arguments_help(capsys, '--help')


def test_parse_arguments_help_short(capsys):
    _test_parse_arguments_help(capsys, '-h')


def test_parse_arguments_version(capsys):
    with pytest.raises(SystemExit) as ex:
        mount_efs.parse_arguments(['mount', 'foo', 'bar', '--version'])

    assert 0 == ex.value.code

    out, err = capsys.readouterr()
    assert 'Version: %s' % mount_efs.VERSION in out


def test_parse_arguments_no_fs_id(capsys):
    with pytest.raises(SystemExit) as ex:
        mount_efs.parse_arguments(['mount'])

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert 'Usage:' in err


def test_parse_arguments_no_mount_point(capsys):
    with pytest.raises(SystemExit) as ex:
        mount_efs.parse_arguments(['mount', 'fs-deadbeef'])

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert 'Usage:' in err


def test_parse_arguments_invalid_fs_id(capsys):
    with pytest.raises(SystemExit) as ex:
        mount_efs.parse_arguments(['mount', 'not-a-file-system-id', '/dir'])

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert 'Invalid file system name' in err


def test_parse_arguments_default_path():
    fsid, path, mountpoint, options = mount_efs.parse_arguments(['mount', 'fs-deadbeef', '/dir'])

    assert 'fs-deadbeef' == fsid
    assert '/' == path
    assert '/dir' == mountpoint
    assert {} == options


def test_parse_arguments_custom_path():
    fsid, path, mountpoint, options = mount_efs.parse_arguments(['mount', 'fs-deadbeef:/home', '/dir'])

    assert 'fs-deadbeef' == fsid
    assert '/home' == path
    assert '/dir' == mountpoint
    assert {} == options


def test_parse_arguments():
    fsid, path, mountpoint, options = mount_efs.parse_arguments(['mount', 'fs-deadbeef:/home', '/dir', '-o', 'foo,bar=baz,quux'])

    assert 'fs-deadbeef' == fsid
    assert '/home' == path
    assert '/dir' == mountpoint
    assert {'foo': None, 'bar': 'baz', 'quux': None} == options
