#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#
import socket

import pytest

import mount_efs

CORRECT_DEVICE_DESCRIPTORS_FS_ID = [
    ('fs-deadbeef', ('fs-deadbeef', '/')),
    ('fs-deadbeef:/', ('fs-deadbeef', '/')),
    ('fs-deadbeef:/some/subpath', ('fs-deadbeef', '/some/subpath')),
    ('fs-deadbeef:/some/subpath/with:colons', ('fs-deadbeef', '/some/subpath/with:colons')),
]
CORRECT_DEVICE_DESCRIPTORS_EFS_FQDN = [
    ('fs-deadbeef.efs.us-east-1.amazonaws.com', ('fs-deadbeef', '/')),
    ('fs-deadbeef.efs.us-east-1.amazonaws.com:/', ('fs-deadbeef', '/')),
    ('fs-deadbeef.efs.us-east-1.amazonaws.com:/some/subpath', ('fs-deadbeef', '/some/subpath')),
    ('fs-deadbeef.efs.us-east-1.amazonaws.com:/some/subpath/with:colons', ('fs-deadbeef', '/some/subpath/with:colons')),
]
CORRECT_DEVICE_DESCRIPTORS_CNAME_DNS = [
    ('custom-cname.example.com', ('fs-deadbeef', '/')),
    ('custom-cname.example.com:/', ('fs-deadbeef', '/')),
    ('custom-cname.example.com:/some/subpath', ('fs-deadbeef', '/some/subpath')),
    ('custom-cname.example.com:/some/subpath/with:colons', ('fs-deadbeef', '/some/subpath/with:colons')),
]


def test_match_device_correct_descriptors_fs_id(mocker):
    for device, (fs_id, path) in CORRECT_DEVICE_DESCRIPTORS_FS_ID:
        assert (fs_id, path) == mount_efs.match_device(None, device)


def test_match_device_correct_descriptors_efs_fqdn(mocker):
    get_dns_name_mock = mocker.patch('mount_efs.get_dns_name', return_value='fs-deadbeef.efs.us-east-1.amazonaws.com')
    for device, (fs_id, path) in CORRECT_DEVICE_DESCRIPTORS_EFS_FQDN:
        assert (fs_id, path) == mount_efs.match_device(None, device)
    get_dns_name_mock.assert_called()


def test_match_device_correct_descriptors_cname_dns_primary(mocker):
    get_dns_name_mock = mocker.patch('mount_efs.get_dns_name', return_value='fs-deadbeef.efs.us-east-1.amazonaws.com')
    gethostbyname_ex_mock = mocker.patch('socket.gethostbyname_ex',
                                         return_value=('fs-deadbeef.efs.us-east-1.amazonaws.com', [], None))
    for device, (fs_id, path) in CORRECT_DEVICE_DESCRIPTORS_CNAME_DNS:
        assert (fs_id, path) == mount_efs.match_device(None, device)
    get_dns_name_mock.assert_called()
    gethostbyname_ex_mock.assert_called()


def test_match_device_correct_descriptors_cname_dns_secondary(mocker):
    get_dns_name_mock = mocker.patch('mount_efs.get_dns_name', return_value='fs-deadbeef.efs.us-east-1.amazonaws.com')
    gethostbyname_ex_mock = mocker.patch('socket.gethostbyname_ex',
                                         return_value=(None, ['fs-deadbeef.efs.us-east-1.amazonaws.com'], None))
    for device, (fs_id, path) in CORRECT_DEVICE_DESCRIPTORS_CNAME_DNS:
        assert (fs_id, path) == mount_efs.match_device(None, device)
    get_dns_name_mock.assert_called()
    gethostbyname_ex_mock.assert_called()


def test_match_device_correct_descriptors_cname_dns_tertiary(mocker):
    get_dns_name_mock = mocker.patch('mount_efs.get_dns_name', return_value='fs-deadbeef.efs.us-east-1.amazonaws.com')
    gethostbyname_ex_mock = mocker.patch('socket.gethostbyname_ex',
                                         return_value=(None, [None, 'fs-deadbeef.efs.us-east-1.amazonaws.com'], None))
    for device, (fs_id, path) in CORRECT_DEVICE_DESCRIPTORS_CNAME_DNS:
        assert (fs_id, path) == mount_efs.match_device(None, device)
    get_dns_name_mock.assert_called()
    gethostbyname_ex_mock.assert_called()


def test_match_device_correct_descriptors_cname_dns_amongst_invalid(mocker):
    get_dns_name_mock = mocker.patch('mount_efs.get_dns_name', return_value='fs-deadbeef.efs.us-east-1.amazonaws.com')
    gethostbyname_ex_mock = mocker.patch(
        'socket.gethostbyname_ex',
        return_value=('fs-deadbeef.efs.us-west-1.amazonaws.com',
                      ['fs-deadbeef.efs.us-east-1.amazonaws.com', 'invalid-efs-name.example.com'],
                      None)
    )
    for device, (fs_id, path) in CORRECT_DEVICE_DESCRIPTORS_CNAME_DNS:
        assert (fs_id, path) == mount_efs.match_device(None, device)
    get_dns_name_mock.assert_called()
    gethostbyname_ex_mock.assert_called()


def test_match_device_wrong_efs_dns_name(mocker, capsys):
    get_dns_name_mock = mocker.patch('mount_efs.get_dns_name', return_value='fs-deadbeef.efs.us-west-1.amazonaws.com')
    with pytest.raises(SystemExit) as ex:
        mount_efs.match_device(None, 'fs-deadbeef.efs.us-east-1.amazonaws.com:/')

    assert 0 != ex.value.code
    out, err = capsys.readouterr()
    assert 'Fully qualified EFS domain name specified' in err
    assert 'didn\'t match the expected value' in err
    get_dns_name_mock.assert_called()


def test_match_device_unresolvable_domain(mocker, capsys):
    mocker.patch('socket.gethostbyname_ex', side_effect=socket.gaierror)
    with pytest.raises(SystemExit) as ex:
        mount_efs.match_device(None, 'custom-cname.example.com')

    assert 0 != ex.value.code
    out, err = capsys.readouterr()
    assert 'Failed to resolve' in err


def test_match_device_no_hostnames(mocker, capsys):
    gethostbyname_ex_mock = mocker.patch('socket.gethostbyname_ex',
                                         return_value=(None, [], None))
    with pytest.raises(SystemExit) as ex:
        mount_efs.match_device(None, 'custom-cname.example.com')

    assert 0 != ex.value.code
    out, err = capsys.readouterr()
    assert 'returned no entries' in err
    gethostbyname_ex_mock.assert_called()


def test_match_device_no_hostnames2(mocker, capsys):
    gethostbyname_ex_mock = mocker.patch('socket.gethostbyname_ex',
                                         return_value=(None, [None, None], None))
    with pytest.raises(SystemExit) as ex:
        mount_efs.match_device(None, 'custom-cname.example.com')

    assert 0 != ex.value.code
    out, err = capsys.readouterr()
    assert 'returned no entries' in err
    gethostbyname_ex_mock.assert_called()


def test_match_device_resolve_to_invalid_efs_dns_name(mocker, capsys):
    gethostbyname_ex_mock = mocker.patch('socket.gethostbyname_ex',
                                         return_value=('invalid-efs-name.example.com', [], None))
    with pytest.raises(SystemExit) as ex:
        mount_efs.match_device(None, 'custom-cname.example.com')

    assert 0 != ex.value.code
    out, err = capsys.readouterr()
    assert 'resolved to no valid/expected EFS DNS name' in err
    gethostbyname_ex_mock.assert_called()


def test_match_device_resolve_to_unexpected_efs_dns_name(mocker, capsys):
    get_dns_name_mock = mocker.patch('mount_efs.get_dns_name', return_value='fs-deadbeef.efs.us-west-1.amazonaws.com')
    gethostbyname_ex_mock = mocker.patch('socket.gethostbyname_ex',
                                         return_value=('fs-deadbeef.efs.us-east-1.amazonaws.com', [], None))
    with pytest.raises(SystemExit) as ex:
        mount_efs.match_device(None, 'custom-cname.example.com')

    assert 0 != ex.value.code
    out, err = capsys.readouterr()
    assert 'resolved to no valid/expected EFS DNS name' in err
    get_dns_name_mock.assert_called()
    gethostbyname_ex_mock.assert_called()
