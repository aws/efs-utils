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


@pytest.fixture(autouse=True)
def setup(mocker):
    mocker.patch('mount_efs.get_region', return_value=DEFAULT_REGION)
    mocker.patch('socket.gethostbyname')


def _get_mock_config(dns_name_format='{fs_id}.efs.{region}.amazonaws.com'):
    mock_config = MagicMock()
    mock_config.get.return_value = dns_name_format
    return mock_config


def test_get_dns_name(mocker):
    config = _get_mock_config()

    dns_name = mount_efs.get_dns_name(config, FS_ID)

    assert '%s.efs.%s.amazonaws.com' % (FS_ID, DEFAULT_REGION) == dns_name


def test_get_dns_name_other_format(mocker):
    config = _get_mock_config('{fs_id}.elastic-file-system.{region}.amazonaws.com')

    dns_name = mount_efs.get_dns_name(config, FS_ID)

    assert '%s.elastic-file-system.%s.amazonaws.com' % (FS_ID, DEFAULT_REGION) == dns_name


def test_get_dns_name_region_hardcoded(mocker):
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
