# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.

import pytest
from botocore.exceptions import ClientError, EndpointConnectionError, NoCredentialsError

import mount_efs

from .. import utils

MOCK_EC2_AGENT = "fake-client"
AZ_NAME = "us-east-2b"
AZ_ID = "use2-az2"
OPERATION_NAME = "DescribeAvailabilityZones"


def _test_describe_availability_zones_response(
    mocker,
    dryrun_effect,
    response,
    expected_describe_time,
    desired_az_id=None,
    desired_exception=None,
    desired_message=None,
):
    describe_mock = mocker.patch(
        "mount_efs.ec2_describe_availability_zones_helper",
        side_effect=[dryrun_effect, response],
    )

    if desired_exception:
        assert desired_message != None
        with pytest.raises(mount_efs.FallbackException) as excinfo:
            mount_efs.get_az_id_by_az_name(MOCK_EC2_AGENT, AZ_NAME)
        assert desired_message in str(excinfo)
    else:
        az_id = mount_efs.get_az_id_by_az_name(MOCK_EC2_AGENT, AZ_NAME)
        assert az_id == desired_az_id

    utils.assert_called_n_times(describe_mock, expected_describe_time)


def test_describe_availability_zones_dryrun_succeed_return_correct(mocker):
    dryrun_exception_response = {
        "Error": {"Code": "DryRunOperation", "Message": "DryRunOperation"}
    }
    response = {
        "AvailabilityZones": [
            {
                "Messages": [],
                "ZoneId": AZ_ID,
                "State": "available",
                "ZoneName": AZ_NAME,
                "RegionName": "us-east-2",
            }
        ]
    }
    _test_describe_availability_zones_response(
        mocker,
        ClientError(dryrun_exception_response, OPERATION_NAME),
        response,
        2,
        AZ_ID,
    )


def test_describe_availability_zones_dryrun_failed_unauthorized_operation(mocker):
    dryrun_exception_response = {
        "Error": {"Code": "UnauthorizedOperation", "Message": "UnauthorizedOperation"}
    }
    _test_describe_availability_zones_response(
        mocker,
        ClientError(dryrun_exception_response, OPERATION_NAME),
        None,
        1,
        desired_exception=mount_efs.FallbackException,
        desired_message="Unauthorized to perform operation",
    )


def test_describe_availability_zones_dryrun_failed_invalid_az_name(mocker):
    dryrun_exception_response = {
        "Error": {"Code": "InvalidParameterValue", "Message": "InvalidParameterValue"}
    }
    _test_describe_availability_zones_response(
        mocker,
        ClientError(dryrun_exception_response, OPERATION_NAME),
        None,
        1,
        desired_exception=mount_efs.FallbackException,
        desired_message="Invalid availability zone",
    )


def test_describe_availability_zones_dryrun_failed_service_unavailable(mocker):
    dryrun_exception_response = {
        "Error": {
            "Code": "ServiceUnavailableException",
            "Message": "ServiceUnavailableException",
        }
    }
    _test_describe_availability_zones_response(
        mocker,
        ClientError(dryrun_exception_response, OPERATION_NAME),
        None,
        1,
        desired_exception=mount_efs.FallbackException,
        desired_message="The ec2 service cannot",
    )


def test_describe_availability_zones_dryrun_failed_access_denied(mocker):
    exception_message = "is not authorized to perform"
    dryrun_exception_response = {
        "Error": {"Code": "AccessDeniedException", "Message": exception_message}
    }
    _test_describe_availability_zones_response(
        mocker,
        ClientError(dryrun_exception_response, OPERATION_NAME),
        None,
        1,
        desired_exception=mount_efs.FallbackException,
        desired_message=exception_message,
    )


def test_describe_availability_zones_dryrun_failed_unknown_exception(mocker):
    dryrun_exception_response = {
        "Error": {"Code": "UnknownException", "Message": "UnknownException"}
    }
    _test_describe_availability_zones_response(
        mocker,
        ClientError(dryrun_exception_response, OPERATION_NAME),
        None,
        1,
        desired_exception=mount_efs.FallbackException,
        desired_message="Unexpected error",
    )


def test_describe_availability_zones_dryrun_failed_no_credential_error(mocker):
    _test_describe_availability_zones_response(
        mocker,
        NoCredentialsError(),
        None,
        1,
        desired_exception=mount_efs.FallbackException,
        desired_message="confirm your aws credentials are properly configured",
    )


def test_describe_availability_zones_failed_unknown_error(mocker):
    _test_describe_availability_zones_response(
        mocker,
        Exception("Unknown"),
        None,
        1,
        desired_exception=mount_efs.FallbackException,
        desired_message="Unknown error",
    )


def test_describe_availability_zones_failed_endpoing_error(mocker):
    _test_describe_availability_zones_response(
        mocker,
        EndpointConnectionError(endpoint_url="https://efs.us-east-1.com"),
        None,
        1,
        desired_exception=mount_efs.FallbackException,
        desired_message="Could not connect to the endpoint",
    )


def test_describe_availability_zones_return_empty_az_info(mocker):
    dryrun_exception_response = {
        "Error": {"Code": "DryRunOperation", "Message": "DryRunOperation"}
    }
    response = {"AvailabilityZones": []}
    _test_describe_availability_zones_response(
        mocker,
        ClientError(dryrun_exception_response, OPERATION_NAME),
        response,
        2,
        None,
    )


def test_describe_availability_zones_return_none_az_info(mocker):
    dryrun_exception_response = {
        "Error": {"Code": "DryRunOperation", "Message": "DryRunOperation"}
    }
    _test_describe_availability_zones_response(
        mocker, ClientError(dryrun_exception_response, OPERATION_NAME), None, 2, None
    )
