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

from .. import utils

try:
    import ConfigParser
except ImportError:
    from configparser import ConfigParser

DEFAULT_AZ = 'us-east-1a'
CORRECT_DEVICE_DESCRIPTORS_FS_ID = [
    ('fs-deadbeef', ('fs-deadbeef', '/', None)),
    ('fs-deadbeef:/', ('fs-deadbeef', '/', None)),
    ('fs-deadbeef:/some/subpath', ('fs-deadbeef', '/some/subpath', None)),
    ('fs-deadbeef:/some/subpath/with:colons', ('fs-deadbeef', '/some/subpath/with:colons', None)),
]
CORRECT_DEVICE_DESCRIPTORS_CNAME_DNS = [
    ('custom-cname.example.com', ('fs-deadbeef', '/', None)),
    ('custom-cname.example.com:/', ('fs-deadbeef', '/', None)),
    ('custom-cname.example.com:/some/subpath', ('fs-deadbeef', '/some/subpath', None)),
    ('custom-cname.example.com:/some/subpath/with:colons', ('fs-deadbeef', '/some/subpath/with:colons', None)),
]
CORRECT_DEVICE_DESCRIPTORS_CNAME_DNS_WITH_AZ = [
    ('custom-cname.example.com', ('fs-deadbeef', '/', DEFAULT_AZ)),
    ('custom-cname.example.com:/', ('fs-deadbeef', '/', DEFAULT_AZ)),
    ('custom-cname.example.com:/some/subpath', ('fs-deadbeef', '/some/subpath', DEFAULT_AZ)),
    ('custom-cname.example.com:/some/subpath/with:colons', ('fs-deadbeef', '/some/subpath/with:colons', DEFAULT_AZ)),
]
DEFAULT_REGION = 'us-east-1'
DEFAULT_NFS_OPTIONS = {}
FS_ID = 'fs-deadbeef'
OPTIONS_WITH_AZ = {'az': DEFAULT_AZ}

@pytest.fixture(autouse=True)
def setup(mocker):
    mocker.patch('mount_efs.get_target_region', return_value=DEFAULT_REGION)
    mocker.patch('socket.gethostbyname')

def _get_mock_config(dns_name_format='{az}.{fs_id}.efs.{region}.{dns_name_suffix}', dns_name_suffix='amazonaws.com',
                     cloudwatch_enabled='false', has_fallback_to_mount_target_ip_address_item=True,
                     fallback_to_mount_target_ip_address=False):
    try:
        config = ConfigParser.SafeConfigParser()
    except AttributeError:
        config = ConfigParser()
    config.add_section(mount_efs.CONFIG_SECTION)
    config.add_section(mount_efs.CLOUDWATCH_LOG_SECTION)
    config.set(mount_efs.CONFIG_SECTION, 'dns_name_format', dns_name_format)
    config.set(mount_efs.CONFIG_SECTION, 'dns_name_suffix', dns_name_suffix)
    config.set(mount_efs.CLOUDWATCH_LOG_SECTION, 'enabled', cloudwatch_enabled)
    if has_fallback_to_mount_target_ip_address_item:
        config.set(mount_efs.CONFIG_SECTION, mount_efs.FALLBACK_TO_MOUNT_TARGET_IP_ADDRESS_ITEM,
                   str(fallback_to_mount_target_ip_address))

    return config


def test_match_device_correct_descriptors_fs_id(mocker):
    config = _get_mock_config()
    for device, (fs_id, path, az) in CORRECT_DEVICE_DESCRIPTORS_FS_ID:
        assert (fs_id, path, az) == mount_efs.match_device(config, device, DEFAULT_NFS_OPTIONS)


def test_match_device_correct_descriptors_cname_dns_suffix_override_region(mocker):
    get_dns_name_mock = mocker.patch('mount_efs.get_dns_name_and_fallback_mount_target_ip_address',
                                     return_value=('fs-deadbeef.efs.cn-north-1.amazonaws.com.cn', None))
    gethostbyname_ex_mock = mocker.patch('socket.gethostbyname_ex',
                                         return_value=('fs-deadbeef.efs.cn-north-1.amazonaws.com.cn', [], None))
    config = _get_mock_config()
    for device, (fs_id, path, az) in CORRECT_DEVICE_DESCRIPTORS_CNAME_DNS:
        assert (fs_id, path, az) == mount_efs.match_device(config, device, DEFAULT_NFS_OPTIONS)
    utils.assert_called(get_dns_name_mock)
    utils.assert_called(gethostbyname_ex_mock)


def test_match_device_correct_descriptors_cname_dns_primary(mocker):
    get_dns_name_mock = mocker.patch('mount_efs.get_dns_name_and_fallback_mount_target_ip_address',
                                     return_value=('fs-deadbeef.efs.us-east-1.amazonaws.com', None))
    gethostbyname_ex_mock = mocker.patch('socket.gethostbyname_ex',
                                         return_value=('fs-deadbeef.efs.us-east-1.amazonaws.com', [], None))
    config = _get_mock_config()
    for device, (fs_id, path, az) in CORRECT_DEVICE_DESCRIPTORS_CNAME_DNS:
        assert (fs_id, path, az) == mount_efs.match_device(config, device, DEFAULT_NFS_OPTIONS)
    utils.assert_called(get_dns_name_mock)
    utils.assert_called(gethostbyname_ex_mock)


def test_match_device_correct_descriptors_cname_dns_secondary(mocker):
    get_dns_name_mock = mocker.patch('mount_efs.get_dns_name_and_fallback_mount_target_ip_address',
                                     return_value=('fs-deadbeef.efs.us-east-1.amazonaws.com', None))
    gethostbyname_ex_mock = mocker.patch('socket.gethostbyname_ex',
                                         return_value=(None, ['fs-deadbeef.efs.us-east-1.amazonaws.com'], None))
    config = _get_mock_config()
    for device, (fs_id, path, az) in CORRECT_DEVICE_DESCRIPTORS_CNAME_DNS:
        assert (fs_id, path, az) == mount_efs.match_device(config, device, DEFAULT_NFS_OPTIONS)
    utils.assert_called(get_dns_name_mock)
    utils.assert_called(gethostbyname_ex_mock)


def test_match_device_correct_descriptors_cname_dns_tertiary(mocker):
    get_dns_name_mock = mocker.patch('mount_efs.get_dns_name_and_fallback_mount_target_ip_address',
                                     return_value=('fs-deadbeef.efs.us-east-1.amazonaws.com', None))
    gethostbyname_ex_mock = mocker.patch('socket.gethostbyname_ex',
                                         return_value=(None, [None, 'fs-deadbeef.efs.us-east-1.amazonaws.com'], None))
    config = _get_mock_config()
    for device, (fs_id, path, az) in CORRECT_DEVICE_DESCRIPTORS_CNAME_DNS:
        assert (fs_id, path, az) == mount_efs.match_device(config, device, DEFAULT_NFS_OPTIONS)
    utils.assert_called(get_dns_name_mock)
    utils.assert_called(gethostbyname_ex_mock)


def test_match_device_correct_descriptors_cname_dns_amongst_invalid(mocker):
    get_dns_name_mock = mocker.patch('mount_efs.get_dns_name_and_fallback_mount_target_ip_address',
                                     return_value=('fs-deadbeef.efs.us-east-1.amazonaws.com', None))
    gethostbyname_ex_mock = mocker.patch(
        'socket.gethostbyname_ex',
        return_value=('fs-deadbeef.efs.us-west-1.amazonaws.com',
                      ['fs-deadbeef.efs.us-east-1.amazonaws.com', 'invalid-efs-name.example.com'],
                      None)
    )
    config = _get_mock_config()
    for device, (fs_id, path, az) in CORRECT_DEVICE_DESCRIPTORS_CNAME_DNS:
        assert (fs_id, path, az) == mount_efs.match_device(config, device, DEFAULT_NFS_OPTIONS)
    utils.assert_called(get_dns_name_mock)
    utils.assert_called(gethostbyname_ex_mock)


def test_match_device_unresolvable_domain(mocker, capsys):
    mocker.patch('socket.gethostbyname_ex', side_effect=socket.gaierror)
    config = _get_mock_config()
    with pytest.raises(SystemExit) as ex:
        mount_efs.match_device(config, 'custom-cname.example.com', DEFAULT_NFS_OPTIONS)

    assert 0 != ex.value.code
    out, err = capsys.readouterr()
    assert 'Failed to resolve' in err


def test_match_device_no_hostnames(mocker, capsys):
    gethostbyname_ex_mock = mocker.patch('socket.gethostbyname_ex',
                                         return_value=(None, [], None))
    config = _get_mock_config()
    with pytest.raises(SystemExit) as ex:
        mount_efs.match_device(config, 'custom-cname.example.com', DEFAULT_NFS_OPTIONS)

    assert 0 != ex.value.code
    out, err = capsys.readouterr()
    assert 'did not resolve to an EFS mount target' in err
    utils.assert_called(gethostbyname_ex_mock)


def test_match_device_no_hostnames2(mocker, capsys):
    gethostbyname_ex_mock = mocker.patch('socket.gethostbyname_ex',
                                         return_value=(None, [None, None], None))
    config = _get_mock_config()
    with pytest.raises(SystemExit) as ex:
        mount_efs.match_device(config, 'custom-cname.example.com', DEFAULT_NFS_OPTIONS)

    assert 0 != ex.value.code
    out, err = capsys.readouterr()
    assert 'did not resolve to an EFS mount target' in err
    utils.assert_called(gethostbyname_ex_mock)


def test_match_device_resolve_to_invalid_efs_dns_name(mocker, capsys):
    gethostbyname_ex_mock = mocker.patch('socket.gethostbyname_ex',
                                         return_value=('invalid-efs-name.example.com', [], None))
    config = _get_mock_config()
    with pytest.raises(SystemExit) as ex:
        mount_efs.match_device(config, 'custom-cname.example.com', DEFAULT_NFS_OPTIONS)

    assert 0 != ex.value.code
    out, err = capsys.readouterr()
    assert 'did not resolve to a valid DNS name' in err
    utils.assert_called(gethostbyname_ex_mock)


def test_match_device_resolve_to_unexpected_efs_dns_name(mocker, capsys):
    get_dns_name_mock = mocker.patch('mount_efs.get_dns_name_and_fallback_mount_target_ip_address',
                                     return_value=('fs-deadbeef.efs.us-west-1.amazonaws.com', None))
    gethostbyname_ex_mock = mocker.patch('socket.gethostbyname_ex',
                                         return_value=('fs-deadbeef.efs.us-east-1.amazonaws.com', [], None))
    config = _get_mock_config()
    with pytest.raises(SystemExit) as ex:
        mount_efs.match_device(config, 'custom-cname.example.com', DEFAULT_NFS_OPTIONS)

    assert 0 != ex.value.code
    out, err = capsys.readouterr()
    assert 'did not resolve to a valid DNS name' in err
    utils.assert_called(get_dns_name_mock)
    utils.assert_called(gethostbyname_ex_mock)


def test_match_device_fqdn_same_as_dns_name(mocker, capsys):
    dns_name = '%s.efs.us-east-1.amazonaws.com' % FS_ID
    gethostbyname_ex_mock = mocker.patch('socket.gethostbyname_ex',
                                         return_value=(dns_name, [], None))
    efs_fqdn_match = mount_efs.EFS_FQDN_RE.match(dns_name)
    assert efs_fqdn_match
    assert FS_ID == efs_fqdn_match.group('fs_id')

    config = _get_mock_config()
    expected_dns_name, ip_address = mount_efs.get_dns_name_and_fallback_mount_target_ip_address(config, FS_ID, DEFAULT_NFS_OPTIONS)
    assert dns_name == expected_dns_name
    assert None == ip_address

    for device, (fs_id, path, az) in CORRECT_DEVICE_DESCRIPTORS_CNAME_DNS:
        assert (fs_id, path, az) == mount_efs.match_device(config, device, DEFAULT_NFS_OPTIONS)
    utils.assert_called(gethostbyname_ex_mock)


def test_match_device_fqdn_same_as_dns_name_with_az(mocker, capsys):
    dns_name = '%s.%s.efs.us-east-1.amazonaws.com' % (DEFAULT_AZ, FS_ID)
    gethostbyname_ex_mock = mocker.patch('socket.gethostbyname_ex',
                                         return_value=(dns_name, [], None))
    efs_fqdn_match = mount_efs.EFS_FQDN_RE.match(dns_name)
    assert efs_fqdn_match
    assert FS_ID == efs_fqdn_match.group('fs_id')

    config = _get_mock_config()
    expected_dns_name, ip_address = mount_efs.get_dns_name_and_fallback_mount_target_ip_address(config, FS_ID, OPTIONS_WITH_AZ)
    assert dns_name == expected_dns_name
    assert None == ip_address
    for device, (fs_id, path, az) in CORRECT_DEVICE_DESCRIPTORS_CNAME_DNS_WITH_AZ:
        assert (fs_id, path, az) == mount_efs.match_device(config, device, OPTIONS_WITH_AZ)
    utils.assert_called(gethostbyname_ex_mock)


def test_match_device_with_az_dns_name_mount_az_not_in_option(mocker):
    # When dns_name is provided for mounting, if the az is not provided in the mount option, also dns_name contains az
    # info, verify that the az info returned is equal to the az info in the dns name
    dns_name = 'us-east-1a.fs-deadbeef.efs.us-east-1.amazonaws.com'
    config = _get_mock_config()
    get_dns_name_mock = mocker.patch('mount_efs.get_dns_name_and_fallback_mount_target_ip_address', return_value=(dns_name, None))
    gethostbyname_ex_mock = mocker.patch('socket.gethostbyname_ex', return_value=(dns_name, [], None))
    fsid, path, az = mount_efs.match_device(config, dns_name, DEFAULT_NFS_OPTIONS)

    assert az == 'us-east-1a'

    utils.assert_called(get_dns_name_mock)
    utils.assert_called(gethostbyname_ex_mock)


def test_match_device_with_az_dns_name_mount_az_in_option(mocker):
    # When dns_name is provided for mounting, if the az is provided in the mount option, also dns_name contains az
    # info, verify that the az info returned is equal to the az info in the dns name
    dns_name = 'us-east-1a.fs-deadbeef.efs.us-east-1.amazonaws.com'
    config = _get_mock_config()
    get_dns_name_mock = mocker.patch('mount_efs.get_dns_name_and_fallback_mount_target_ip_address', return_value=(dns_name, None))
    gethostbyname_ex_mock = mocker.patch('socket.gethostbyname_ex', return_value=(dns_name, [], None))
    fsid, path, az = mount_efs.match_device(config, dns_name, OPTIONS_WITH_AZ)

    assert az == 'us-east-1a'

    utils.assert_called(get_dns_name_mock)
    utils.assert_called(gethostbyname_ex_mock)


def test_match_device_with_dns_name_mount_az_in_option(mocker):
    # When dns_name is mapping to the az_dns_name, and the az field is provided to the option, verify that the az info returned is
    # equal to the az info in the dns name
    dns_name = 'example.random.com'
    az_dns_name = 'us-east-1a.fs-deadbeef.efs.us-east-1.amazonaws.com'
    config = _get_mock_config()
    get_dns_name_mock = mocker.patch('mount_efs.get_dns_name_and_fallback_mount_target_ip_address',
                                     return_value=(az_dns_name, None))
    gethostbyname_ex_mock = mocker.patch('socket.gethostbyname_ex', return_value=(az_dns_name, [], None))
    fsid, path, az = mount_efs.match_device(config, dns_name, OPTIONS_WITH_AZ)

    assert az == 'us-east-1a'

    utils.assert_called(get_dns_name_mock)
    utils.assert_called(gethostbyname_ex_mock)


def test_match_device_with_dns_name_mount_az_in_option_not_match(mocker, capsys):
    # When dns_name is mapping to the az_dns_name, and the az field is provided to the option, while the two az value is not
    # the same, verify that exception is thrown
    dns_name = 'example.random.com'
    az_dns_name = 'us-east-1b.fs-deadbeef.efs.us-east-1.amazonaws.com'
    config = _get_mock_config()
    get_dns_name_mock = mocker.patch('mount_efs.get_dns_name_and_fallback_mount_target_ip_address',
                                     return_value=(az_dns_name, None))
    gethostbyname_ex_mock = mocker.patch('socket.gethostbyname_ex', return_value=(az_dns_name, [], None))

    with pytest.raises(SystemExit) as ex:
        mount_efs.match_device(config, dns_name, OPTIONS_WITH_AZ)

    assert 0 != ex.value.code
    out, err = capsys.readouterr()
    assert 'does not match the az provided' in err
    utils.assert_not_called(get_dns_name_mock)
    utils.assert_called(gethostbyname_ex_mock)
