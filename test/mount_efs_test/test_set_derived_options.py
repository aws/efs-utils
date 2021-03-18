#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import mount_efs

import pytest

from mock import MagicMock


DEFAULT_REGION = 'us-east-1'
FS_ID = 'fs-deadbeef'


@pytest.fixture(autouse=True)
def setup(mocker):
    mocker.patch('mount_efs.get_target_region', return_value=DEFAULT_REGION)


def test_set_derived_options(mocker, capsys):
    mocker.patch('mount_efs.get_subnet_ids', return_value=['subnet-111111111111'])
    mocker.patch('mount_efs.get_mount_target_ip', return_value='10.0.0.1')

    config = MagicMock()
    options = {'dnshostnamesdisabled': None}

    mount_efs.set_derived_options(config, FS_ID, options)

    assert options['mounttargetip'] == '10.0.0.1'


def test_set_derived_options_no_subnet_ids(mocker, capsys):
    mocker.patch('mount_efs.get_subnet_ids', return_value=[])

    config = MagicMock()
    options = {'dnshostnamesdisabled': None}

    with pytest.raises(SystemExit) as ex:
        mount_efs.set_derived_options(config, FS_ID, options)

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert 'Failed to find subnet IDs for network interfaces attached to instance' in err
