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
from botocore.stub import Stubber


FS_ID = 'fs-deadbeef'
DEFAULT_REGION = 'us-east-1'
TARGET_SUBNET_ID = "subnet-111111111111"
UNKNOWN_SUBNET_ID = "subnet-333333333333"
DESCRIBE_MOUNT_TARGETS_RESPONSE = {
  "ResponseMetadata": {
    "RequestId": "00000000",
    "HTTPStatusCode": 200,
    "HTTPHeaders": {
      "x-amzn-requestid": "00000000",
      "content-type": "application/json",
      "content-length": "1024",
      "date": "Wed, 31 Mar 2021 01:17:08 GMT"
    },
    "RetryAttempts": 0
  },
  "MountTargets": [
    {
      "OwnerId": "123456789",
      "MountTargetId": "fsmt-1111111111111",
      "FileSystemId": FS_ID,
      "SubnetId": TARGET_SUBNET_ID,
      "LifeCycleState": "available",
      "IpAddress": "10.0.0.1",
      "NetworkInterfaceId": "eni-1",
      "AvailabilityZoneId": "usw2-az1",
      "AvailabilityZoneName": "us-west-2a",
      "VpcId": "vpc-12345678"
    },
    {
      "OwnerId": "123456789",
      "MountTargetId": "fsmt-2222222222222",
      "FileSystemId": FS_ID,
      "SubnetId": "subnet-222222222222",
      "LifeCycleState": "available",
      "IpAddress": "10.0.0.2",
      "NetworkInterfaceId": "eni-2",
      "AvailabilityZoneId": "usw2-az3",
      "AvailabilityZoneName": "us-west-2c",
      "VpcId": "vpc-12345678"
    },
    {
      "OwnerId": "123456789",
      "MountTargetId": "fsmt-3333333333333",
      "FileSystemId": FS_ID,
      "SubnetId": TARGET_SUBNET_ID,
      "LifeCycleState": "available",
      "IpAddress": "10.0.0.3",
      "NetworkInterfaceId": "eni-3",
      "AvailabilityZoneId": "usw2-az1",
      "AvailabilityZoneName": "us-west-2a",
      "VpcId": "vpc-12345678"
    }
  ]
}
EXPECTED_DESCRIBE_MOUNT_TARGETS_PARAMS = {'FileSystemId': FS_ID}


@pytest.fixture(autouse=True)
def setup(mocker):
    mocker.patch('mount_efs.get_target_region', return_value=DEFAULT_REGION)


def test_get_mount_target_ip(mocker):
    mock_config = MagicMock()
    efs_client = mount_efs.get_botocore_client(mock_config, 'efs')

    with Stubber(efs_client) as stubber:
        stubber.add_response('describe_mount_targets', DESCRIBE_MOUNT_TARGETS_RESPONSE, EXPECTED_DESCRIBE_MOUNT_TARGETS_PARAMS)

        mount_target_ip = mount_efs.get_mount_target_ip(efs_client, FS_ID, [TARGET_SUBNET_ID])
        assert mount_target_ip == '10.0.0.1'


def test_get_mount_target_ip_no_results(mocker, capsys):
    mock_config = MagicMock()
    efs_client = mount_efs.get_botocore_client(mock_config, 'efs')

    with Stubber(efs_client) as stubber:
        stubber.add_response('describe_mount_targets', DESCRIBE_MOUNT_TARGETS_RESPONSE, EXPECTED_DESCRIBE_MOUNT_TARGETS_PARAMS)

        with pytest.raises(SystemExit) as ex:
            mount_efs.get_mount_target_ip(efs_client, FS_ID, [UNKNOWN_SUBNET_ID])

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert 'Failed to locate any mount targets' in err


def test_get_mount_target_ip_client_error(mocker, capsys):
    mock_config = MagicMock()
    efs_client = mount_efs.get_botocore_client(mock_config, 'efs')

    with Stubber(efs_client) as stubber:
        stubber.add_client_error('describe_mount_targets',
                                 service_error_code='FileSystemNotFound',
                                 service_message='File system not found')

        with pytest.raises(SystemExit) as ex:
            mount_efs.get_mount_target_ip(efs_client, FS_ID, [TARGET_SUBNET_ID])

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert 'File system not found' in err
