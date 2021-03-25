#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import mount_efs
import socket

import pytest

from mock import MagicMock

from .. import utils

try:
    from configparser import NoOptionError
except ImportError:
    import ConfigParser
    from ConfigParser import NoOptionError

FS_ID = 'fs-deadbeef'
DEFAULT_REGION = 'us-east-1'
DEFAULT_AZ = 'us-east-1a'
SPECIAL_REGION_DNS_DICT = {
    "cn-north-1": "amazonaws.com.cn",
    "cn-northwest-1": "amazonaws.com.cn",
    "us-iso-east-1": "c2s.ic.gov",
    "us-isob-east-1": "sc2s.sgov.gov"
}
SPECIAL_REGIONS = ["cn-north-1", "cn-northwest-1", "us-iso-east-1", "us-isob-east-1"]
DEFAULT_NFS_OPTIONS = {}
OPTIONS_WITH_AZ = {'az': DEFAULT_AZ}


@pytest.fixture(autouse=True)
def setup(mocker):
    mocker.patch('mount_efs.get_target_region', return_value=DEFAULT_REGION)
    mocker.patch('socket.gethostbyname')


def _get_mock_config(dns_name_format='{az}.{fs_id}.efs.{region}.{dns_name_suffix}', dns_name_suffix='amazonaws.com',
                     config_section='mount'):
    def config_get_side_effect(section, field):
        if section == mount_efs.CONFIG_SECTION and field == 'dns_name_format':
            return dns_name_format
        elif section == config_section and field == 'dns_name_suffix':
            return dns_name_suffix
        else:
            raise ValueError('Unexpected arguments')

    mock_config = MagicMock()
    mock_config.get.side_effect = config_get_side_effect
    mock_config.has_section.return_value = False
    return mock_config


def test_get_dns_name(mocker):
    config = _get_mock_config()

    dns_name = mount_efs.get_dns_name(config, FS_ID, DEFAULT_NFS_OPTIONS)

    assert '%s.efs.%s.amazonaws.com' % (FS_ID, DEFAULT_REGION) == dns_name


def test_get_dns_name_with_az_in_options(mocker):
    config = _get_mock_config('{az}.{fs_id}.efs.{region}.amazonaws.com')

    dns_name = mount_efs.get_dns_name(config, FS_ID, OPTIONS_WITH_AZ)

    assert '%s.%s.efs.%s.amazonaws.com' % (DEFAULT_AZ, FS_ID, DEFAULT_REGION) == dns_name


def test_get_dns_name_without_az_in_options(mocker):
    config = _get_mock_config('{az}.{fs_id}.efs.{region}.amazonaws.com')

    dns_name = mount_efs.get_dns_name(config, FS_ID, DEFAULT_NFS_OPTIONS)

    assert '%s.efs.%s.amazonaws.com' % (FS_ID, DEFAULT_REGION) == dns_name


def test_get_dns_name_suffix_hardcoded(mocker):
    config = _get_mock_config('{az}.{fs_id}.efs.{region}.amazonaws.com')

    dns_name = mount_efs.get_dns_name(config, FS_ID, DEFAULT_NFS_OPTIONS)

    assert '%s.efs.%s.amazonaws.com' % (FS_ID, DEFAULT_REGION) == dns_name


def test_get_dns_name_region_hardcoded(mocker):
    get_target_region_mock = mocker.patch('mount_efs.get_target_region')

    config = _get_mock_config('{az}.{fs_id}.efs.%s.{dns_name_suffix}' % DEFAULT_REGION)

    dns_name = mount_efs.get_dns_name(config, FS_ID, DEFAULT_NFS_OPTIONS)

    utils.assert_not_called(get_target_region_mock)

    assert '%s.efs.%s.amazonaws.com' % (FS_ID, DEFAULT_REGION) == dns_name


def test_get_dns_name_region_and_suffix_hardcoded(mocker):
    get_target_region_mock = mocker.patch('mount_efs.get_target_region')

    config = _get_mock_config('{az}.{fs_id}.efs.us-west-2.amazonaws.com')

    dns_name = mount_efs.get_dns_name(config, FS_ID, DEFAULT_NFS_OPTIONS)

    utils.assert_not_called(get_target_region_mock)

    assert '%s.efs.us-west-2.amazonaws.com' % FS_ID == dns_name


def test_get_dns_name_bad_format_wrong_specifiers(mocker):
    config = _get_mock_config('{foo}.efs.{bar}')

    with pytest.raises(ValueError) as ex:
        mount_efs.get_dns_name(config, FS_ID, DEFAULT_NFS_OPTIONS)

    assert 'must include' in str(ex.value)


def test_get_dns_name_bad_format_too_many_specifiers_1(mocker):
    config = _get_mock_config('{fs_id}.efs.{foo}')

    with pytest.raises(ValueError) as ex:
        mount_efs.get_dns_name(config, FS_ID, DEFAULT_NFS_OPTIONS)

    assert 'incorrect number' in str(ex.value)


def test_get_dns_name_bad_format_too_many_specifiers_2(mocker):
    config = _get_mock_config('{fs_id}.efs.{region}.{foo}')

    with pytest.raises(ValueError) as ex:
        mount_efs.get_dns_name(config, FS_ID, DEFAULT_NFS_OPTIONS)

    assert 'incorrect number' in str(ex.value)


def test_get_dns_name_unresolvable(mocker, capsys):
    config = _get_mock_config()

    mocker.patch('socket.gethostbyname', side_effect=socket.gaierror)

    with pytest.raises(SystemExit) as ex:
        mount_efs.get_dns_name(config, FS_ID, DEFAULT_NFS_OPTIONS)

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert 'Failed to resolve' in err


def test_get_dns_name_special_region(mocker):
    for special_region in SPECIAL_REGIONS:
        mocker.patch('mount_efs.get_target_region', return_value=special_region)

        config_section = 'mount.%s' % special_region
        special_dns_name_suffix = SPECIAL_REGION_DNS_DICT[special_region]

        config = _get_mock_config(dns_name_suffix=special_dns_name_suffix, config_section=config_section)
        config.has_section.return_value = True

        dns_name = mount_efs.get_dns_name(config, FS_ID, DEFAULT_NFS_OPTIONS)

        assert '%s.efs.%s.%s' % (FS_ID, special_region, special_dns_name_suffix) == dns_name


def test_get_dns_name_region_in_suffix(mocker):
    get_target_region_mock = mocker.patch('mount_efs.get_target_region')

    for special_region in SPECIAL_REGIONS:
        special_dns_name_suffix = SPECIAL_REGION_DNS_DICT[special_region]
        dns_name_suffix = '%s.%s' % (special_region, special_dns_name_suffix)

        config = _get_mock_config('{fs_id}.efs.{dns_name_suffix}', dns_name_suffix=dns_name_suffix)

        dns_name = mount_efs.get_dns_name(config, FS_ID, DEFAULT_NFS_OPTIONS)

        utils.assert_not_called(get_target_region_mock)

        assert '%s.efs.%s.%s' % (FS_ID, special_region, special_dns_name_suffix) == dns_name
