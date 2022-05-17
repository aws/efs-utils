# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.

import pytest
from botocore.exceptions import ClientError, EndpointConnectionError, NoCredentialsError

import mount_efs

from .. import utils

AZ_NAME = "us-east-2b"
AZ_ID = "use2-az2"
FS_ID = "fs-deadbeef"
IP_ADDRESS = "192.0.0.1"
MOCK_EFS_AGENT = "fake-efs-client"
MOCK_EC2_AGENT = "fake-ec2-client"
MOUNT_TARGET_ID = "fsmt-abcdefgh"
MOUNT_TARGET_INFO = {
    "MountTargetId": MOUNT_TARGET_ID,
    "AvailabilityZoneId": AZ_ID,
    "AvailabilityZoneName": AZ_NAME,
    "FileSystemId": FS_ID,
    "LifeCycleState": "available",
    "IpAddress": IP_ADDRESS,
}
OPERATION_NAME = "DescribeMountTargets"


def _test_describe_mount_targets_response(
    mocker,
    response,
    expected_describe_time,
    desired_mount_targets=None,
    desired_exception=None,
    desired_message=None,
):
    describe_mount_targets_mock = mocker.patch(
        "mount_efs.efs_describe_mount_targets_helper", side_effect=[response]
    )

    if desired_exception:
        assert desired_message != None
        with pytest.raises(mount_efs.FallbackException) as excinfo:
            mount_efs.get_mount_targets_info(MOCK_EFS_AGENT, FS_ID)
        assert desired_message in str(excinfo)
    else:
        mount_targets = mount_efs.get_mount_targets_info(MOCK_EFS_AGENT, FS_ID)
        assert mount_targets == desired_mount_targets

    utils.assert_called_n_times(describe_mount_targets_mock, expected_describe_time)


def test_describe_mount_targets_return_correct(mocker):
    response = {
        "MountTargets": [
            {
                "MountTargetId": MOUNT_TARGET_ID,
                "AvailabilityZoneId": AZ_ID,
                "AvailabilityZoneName": AZ_NAME,
                "FileSystemId": FS_ID,
                "LifeCycleState": "available",
                "IpAddress": IP_ADDRESS,
            }
        ]
    }
    _test_describe_mount_targets_response(
        mocker, response, 1, response.get("MountTargets")
    )


def test_describe_mount_targets_failed_file_system_not_found(mocker):
    exception_response = {
        "Error": {"Code": "FileSystemNotFound", "Message": "FileSystemNotFound"}
    }
    _test_describe_mount_targets_response(
        mocker,
        ClientError(exception_response, OPERATION_NAME),
        1,
        desired_exception=mount_efs.FallbackException,
        desired_message="not found",
    )


def test_describe_mount_targets_failed_service_unavailable(mocker):
    exception_response = {
        "Error": {
            "Code": "ServiceUnavailableException",
            "Message": "ServiceUnavailableException",
        }
    }
    _test_describe_mount_targets_response(
        mocker,
        ClientError(exception_response, OPERATION_NAME),
        1,
        desired_exception=mount_efs.FallbackException,
        desired_message="The elasticfilesystem service cannot complete the request",
    )


def test_describe_mount_targets_failed_access_denied(mocker):
    exception_message = "is not authorized to perform"
    exception_response = {
        "Error": {"Code": "AccessDeniedException", "Message": exception_message}
    }
    _test_describe_mount_targets_response(
        mocker,
        ClientError(exception_response, OPERATION_NAME),
        1,
        desired_exception=mount_efs.FallbackException,
        desired_message=exception_message,
    )


def test_describe_mount_targets_failed_unknown_client_error(mocker):
    exception_response = {
        "Error": {"Code": "UnknownException", "Message": "UnknownException"}
    }
    _test_describe_mount_targets_response(
        mocker,
        ClientError(exception_response, OPERATION_NAME),
        1,
        desired_exception=mount_efs.FallbackException,
        desired_message="Unexpected error",
    )


def test_describe_mount_targets_failed_unknown_error(mocker):
    _test_describe_mount_targets_response(
        mocker,
        Exception("Unknown"),
        1,
        desired_exception=mount_efs.FallbackException,
        desired_message="Unknown error",
    )


def test_describe_mount_targets_failed_endpoint_error(mocker):
    _test_describe_mount_targets_response(
        mocker,
        EndpointConnectionError(endpoint_url="https://efs.us-east-1.com"),
        1,
        desired_exception=mount_efs.FallbackException,
        desired_message="Could not connect to the endpoint",
    )


def test_describe_availability_zones_dryrun_failed_no_credential_error(mocker):
    _test_describe_mount_targets_response(
        mocker,
        NoCredentialsError(),
        1,
        desired_exception=mount_efs.FallbackException,
        desired_message="please confirm your aws credentials are properly configured",
    )


def _test_get_mount_target_in_az(
    mocker,
    get_mount_targets_info_response,
    desired_describe_time,
    desired_get_az_id_time,
    desired_mount_target=None,
    az_id=AZ_ID,
    az_name=AZ_NAME,
    desired_exception=None,
    desired_message=None,
    on_premise=False,
):
    get_mount_targets_info_mock = mocker.patch(
        "mount_efs.get_mount_targets_info",
        side_effect=[get_mount_targets_info_response],
    )
    get_az_id_by_az_name_mock = mocker.patch(
        "mount_efs.get_az_id_by_az_name", return_value=az_id
    )

    if desired_exception:
        assert desired_message is not None
        with pytest.raises(mount_efs.FallbackException) as excinfo:
            mount_efs.get_mount_target_in_az(
                MOCK_EFS_AGENT, MOCK_EC2_AGENT, FS_ID, az_name
            )
        assert desired_message in str(excinfo)
    else:
        mount_target = mount_efs.get_mount_target_in_az(
            MOCK_EFS_AGENT, MOCK_EC2_AGENT, FS_ID, az_name
        )

        if not on_premise:
            assert mount_target == desired_mount_target
        else:
            assert mount_target in get_mount_targets_info_response

    utils.assert_called_n_times(get_mount_targets_info_mock, desired_describe_time)
    utils.assert_called_n_times(get_az_id_by_az_name_mock, desired_get_az_id_time)


def test_get_mount_target_in_az_with_match_az_id(mocker):
    """
    When the mount target in the same az id exists
    """
    response = [
        MOUNT_TARGET_INFO,
        {
            "MountTargetId": "fsmt-ijklmnop",
            "AvailabilityZoneId": "use2-az3",
            "AvailabilityZoneName": "us-east-2c",
            "FileSystemId": FS_ID,
            "LifeCycleState": "available",
            "IpAddress": "192.1.2.3",
        },
        {
            "MountTargetId": "fsmt-qrstuvwx",
            "AvailabilityZoneId": "use2-az1",
            "AvailabilityZoneName": "us-east-2a",
            "FileSystemId": FS_ID,
            "LifeCycleState": "available",
            "IpAddress": "192.4.5.6",
        },
    ]

    _test_get_mount_target_in_az(
        mocker,
        response,
        desired_describe_time=1,
        desired_get_az_id_time=1,
        desired_mount_target=MOUNT_TARGET_INFO,
        az_id=AZ_ID,
    )


def test_get_mount_target_in_az_no_mount_targets(mocker):
    """
    When there is no mount target for the given file system
    """
    get_mount_targets_info_response = None

    _test_get_mount_target_in_az(
        mocker,
        get_mount_targets_info_response,
        desired_describe_time=1,
        desired_get_az_id_time=0,
        desired_exception=mount_efs.FallbackException,
        desired_message="Cannot find mount target",
    )


def test_get_mount_target_in_az_no_available_mount_targets(mocker):
    """
    When all the mount target for the given file system is not available yet
    """
    get_mount_targets_info_response = [
        {
            "MountTargetId": "fsmt-ijklmnop",
            "AvailabilityZoneId": "use2-az3",
            "AvailabilityZoneName": "us-east-2c",
            "FileSystemId": FS_ID,
            "LifeCycleState": "creating",
            "IpAddress": "192.1.2.3",
        },
        {
            "MountTargetId": "fsmt-qrstuvwx",
            "AvailabilityZoneId": "use2-az1",
            "AvailabilityZoneName": "us-east-2a",
            "FileSystemId": FS_ID,
            "LifeCycleState": "creating",
            "IpAddress": "192.4.5.6",
        },
    ]

    _test_get_mount_target_in_az(
        mocker,
        get_mount_targets_info_response,
        desired_describe_time=1,
        desired_get_az_id_time=0,
        desired_exception=mount_efs.FallbackException,
        desired_message="is in available state yet",
    )


def test_get_mount_target_in_az_no_az_id_match_to_az_name(mocker):
    """
    When the az_name provided does not have a valid az_id
    """
    get_mount_targets_info_response = [
        MOUNT_TARGET_INFO,
        {
            "MountTargetId": "fsmt-ijklmnop",
            "AvailabilityZoneId": "use2-az3",
            "AvailabilityZoneName": "us-east-2c",
            "FileSystemId": FS_ID,
            "LifeCycleState": "available",
            "IpAddress": "192.1.2.3",
        },
        {
            "MountTargetId": "fsmt-qrstuvwx",
            "AvailabilityZoneId": "use2-az1",
            "AvailabilityZoneName": "us-east-2a",
            "FileSystemId": FS_ID,
            "LifeCycleState": "available",
            "IpAddress": "192.4.5.6",
        },
    ]

    _test_get_mount_target_in_az(
        mocker,
        get_mount_targets_info_response,
        desired_describe_time=1,
        desired_get_az_id_time=1,
        az_id=None,
        desired_exception=mount_efs.FallbackException,
        desired_message="No matching az id",
    )


def test_get_mount_target_in_az_random_pick_mount_target_for_on_premise(mocker):
    """
    When the az info is not passed via options, also the metadata call failed to get the az info, we assume this is the on-premise
    instance, so we randomly pick one mount target
    """
    get_mount_targets_info_response = [
        {
            "MountTargetId": "fsmt-ijklmnop",
            "AvailabilityZoneId": "use2-az3",
            "AvailabilityZoneName": "us-east-2c",
            "FileSystemId": FS_ID,
            "LifeCycleState": "available",
            "IpAddress": "192.1.2.3",
        },
        {
            "MountTargetId": "fsmt-qrstuvwx",
            "AvailabilityZoneId": "use2-az1",
            "AvailabilityZoneName": "us-east-2a",
            "FileSystemId": FS_ID,
            "LifeCycleState": "available",
            "IpAddress": "192.4.5.6",
        },
    ]

    _test_get_mount_target_in_az(
        mocker,
        get_mount_targets_info_response,
        desired_describe_time=1,
        desired_get_az_id_time=0,
        az_name=None,
        on_premise=True,
    )


def test_get_mount_target_in_az_no_mount_target_in_az(mocker):
    """
    When there is no mount target match the az_id derived by the az_name provided
    """
    get_mount_targets_info_response = [
        {
            "MountTargetId": "fsmt-ijklmnop",
            "AvailabilityZoneId": "use2-az3",
            "AvailabilityZoneName": "us-east-2c",
            "FileSystemId": FS_ID,
            "LifeCycleState": "available",
            "IpAddress": "192.1.2.3",
        },
        {
            "MountTargetId": "fsmt-qrstuvwx",
            "AvailabilityZoneId": "use2-az1",
            "AvailabilityZoneName": "us-east-2a",
            "FileSystemId": FS_ID,
            "LifeCycleState": "available",
            "IpAddress": "192.4.5.6",
        },
    ]

    _test_get_mount_target_in_az(
        mocker,
        get_mount_targets_info_response,
        desired_describe_time=1,
        desired_get_az_id_time=1,
        desired_exception=mount_efs.FallbackException,
        desired_message="No matching mount target in the az",
    )


def test_get_mount_target_in_az_mount_target_in_az_is_creating(mocker):
    """
    If the az option is not passed, and the az mount target is in creating state
    """
    TEMP_MOUNT_TARGET_INFO = MOUNT_TARGET_INFO
    TEMP_MOUNT_TARGET_INFO["LifeCycleState"] = "creating"
    get_mount_targets_info_response = [
        TEMP_MOUNT_TARGET_INFO,
        {
            "MountTargetId": "fsmt-ijklmnop",
            "AvailabilityZoneId": "use2-az3",
            "AvailabilityZoneName": "us-east-2c",
            "FileSystemId": FS_ID,
            "LifeCycleState": "available",
            "IpAddress": "192.1.2.3",
        },
        {
            "MountTargetId": "fsmt-qrstuvwx",
            "AvailabilityZoneId": "use2-az1",
            "AvailabilityZoneName": "us-east-2a",
            "FileSystemId": FS_ID,
            "LifeCycleState": "available",
            "IpAddress": "192.4.5.6",
        },
    ]

    _test_get_mount_target_in_az(
        mocker,
        get_mount_targets_info_response,
        desired_describe_time=1,
        desired_get_az_id_time=1,
        desired_exception=mount_efs.FallbackException,
        desired_message="retry in 5 minutes",
    )


def test_get_mount_target_in_az_mount_target_in_az_is_deleting(mocker):
    """
    If the az option is not passed, and the az mount target is in deleting state
    """
    TEMP_MOUNT_TARGET_INFO = MOUNT_TARGET_INFO
    TEMP_MOUNT_TARGET_INFO["LifeCycleState"] = "deleting"
    get_mount_targets_info_response = [
        TEMP_MOUNT_TARGET_INFO,
        {
            "MountTargetId": "fsmt-ijklmnop",
            "AvailabilityZoneId": "use2-az3",
            "AvailabilityZoneName": "us-east-2c",
            "FileSystemId": FS_ID,
            "LifeCycleState": "available",
            "IpAddress": "192.1.2.3",
        },
        {
            "MountTargetId": "fsmt-qrstuvwx",
            "AvailabilityZoneId": "use2-az1",
            "AvailabilityZoneName": "us-east-2a",
            "FileSystemId": FS_ID,
            "LifeCycleState": "available",
            "IpAddress": "192.4.5.6",
        },
    ]

    _test_get_mount_target_in_az(
        mocker,
        get_mount_targets_info_response,
        desired_describe_time=1,
        desired_get_az_id_time=1,
        desired_exception=mount_efs.FallbackException,
        desired_message="create a new one",
    )


def _test_get_mount_target_in_az_agent_is_none(mocker, efs_agent, ec2_agent):
    get_mount_targets_info_mock = mocker.patch("mount_efs.get_mount_targets_info")
    with pytest.raises(mount_efs.FallbackException) as excinfo:
        mount_efs.get_mount_target_in_az(efs_agent, ec2_agent, FS_ID, AZ_NAME)
    assert "Boto client cannot be null" in str(excinfo)
    utils.assert_not_called(get_mount_targets_info_mock)


def test_get_mount_target_in_az_efs_agent_is_none(mocker):
    _test_get_mount_target_in_az_agent_is_none(
        mocker, efs_agent=MOCK_EFS_AGENT, ec2_agent=None
    )


def test_get_mount_target_in_az_ec2_agent_is_none(mocker):
    _test_get_mount_target_in_az_agent_is_none(
        mocker, efs_agent=None, ec2_agent=MOCK_EC2_AGENT
    )


def test_get_mount_target_in_az_efs_ec2_agent_are_none(mocker):
    _test_get_mount_target_in_az_agent_is_none(mocker, efs_agent=None, ec2_agent=None)
