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

FS_ID = 'fs-deadbeef'
DEFAULT_REGION = 'us-east-1'
SPECIAL_DNS_NAME_SUFFIX = 'amazonaws.com.cn'
SPECIAL_REGION = 'cn-north-1'


@pytest.fixture(autouse=True)
def setup(mocker):
    mocker.patch('mount_efs.get_region', return_value=DEFAULT_REGION)
    mocker.patch('socket.gethostbyname')


def _get_mock_config(dns_name_format='{fs_id}.efs.{region}.{dns_name_suffix}', dns_name_suffix='amazonaws.com',
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

    dns_name = mount_efs.get_dns_name(config, FS_ID)

    assert '%s.efs.%s.amazonaws.com' % (FS_ID, DEFAULT_REGION) == dns_name


def test_get_dns_name_suffix_hardcoded(mocker):
    config = _get_mock_config('{fs_id}.elastic-file-system.{region}.amazonaws.com')

    dns_name = mount_efs.get_dns_name(config, FS_ID)

    assert '%s.elastic-file-system.%s.amazonaws.com' % (FS_ID, DEFAULT_REGION) == dns_name


def test_get_dns_name_region_hardcoded(mocker):
    get_region_mock = mocker.patch('mount_efs.get_region')

    config = _get_mock_config('{fs_id}.efs.%s.{dns_name_suffix}' % DEFAULT_REGION)

    dns_name = mount_efs.get_dns_name(config, FS_ID)

    get_region_mock.assert_not_called()

    assert '%s.efs.%s.amazonaws.com' % (FS_ID, DEFAULT_REGION) == dns_name


def test_get_dns_name_region_and_suffix_hardcoded(mocker):
    get_region_mock = mocker.patch('mount_efs.get_region')

    config = _get_mock_config('{fs_id}.elastic-file-system.us-west-2.amazonaws.com')

    dns_name = mount_efs.get_dns_name(config, FS_ID)

    get_region_mock.assert_not_called()

    assert '%s.elastic-file-system.us-west-2.amazonaws.com' % FS_ID == dns_name


def test_get_dns_name_bad_format_wrong_specifiers(mocker):
    config = _get_mock_config('{foo}.efs.{bar}')

    with pytest.raises(ValueError) as ex:
        mount_efs.get_dns_name(config, FS_ID)

    assert 'must include' in str(ex.value)


def test_get_dns_name_bad_format_too_many_specifiers_1(mocker):
    config = _get_mock_config('{fs_id}.efs.{foo}')

    with pytest.raises(ValueError) as ex:
        mount_efs.get_dns_name(config, FS_ID)

    assert 'incorrect number' in str(ex.value)


def test_get_dns_name_bad_format_too_many_specifiers_2(mocker):
    config = _get_mock_config('{fs_id}.efs.{region}.{foo}')

    with pytest.raises(ValueError) as ex:
        mount_efs.get_dns_name(config, FS_ID)

    assert 'incorrect number' in str(ex.value)


def test_get_dns_name_unresolvable(mocker, capsys):
    config = _get_mock_config()

    mocker.patch('socket.gethostbyname', side_effect=socket.gaierror)

    with pytest.raises(SystemExit) as ex:
        mount_efs.get_dns_name(config, FS_ID)

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert 'Failed to resolve' in err


def test_get_dns_name_special_region(mocker):
    mocker.patch('mount_efs.get_region', return_value=SPECIAL_REGION)

    config_section = 'mount.%s' % SPECIAL_REGION
    config = _get_mock_config(dns_name_suffix=SPECIAL_DNS_NAME_SUFFIX, config_section=config_section)
    config.has_section.return_value = True

    dns_name = mount_efs.get_dns_name(config, FS_ID)

    assert '%s.efs.%s.%s' % (FS_ID, SPECIAL_REGION, SPECIAL_DNS_NAME_SUFFIX) == dns_name


def test_get_dns_name_region_in_suffix(mocker):
    get_region_mock = mocker.patch('mount_efs.get_region')

    dns_name_suffix = '%s.%s' % (SPECIAL_REGION, SPECIAL_DNS_NAME_SUFFIX)
    config = _get_mock_config('{fs_id}.efs.{dns_name_suffix}', dns_name_suffix=dns_name_suffix)

    dns_name = mount_efs.get_dns_name(config, FS_ID)

    get_region_mock.assert_not_called()

    assert '%s.efs.%s.%s' % (FS_ID, SPECIAL_REGION, SPECIAL_DNS_NAME_SUFFIX) == dns_name
