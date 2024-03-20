# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.

import json
import socket

import pytest

import mount_efs

from .. import utils

try:
    import ConfigParser
except ImportError:
    from configparser import ConfigParser

try:
    from urllib2 import HTTPError, URLError
except ImportError:
    from urllib.error import HTTPError, URLError

FARGATE_AZ_ID_ENDPOINT = (
    "http://169.254.170.2" + mount_efs.ECS_FARGATE_TASK_METADATA_ENDPOINT_URL_EXTENSION
)
INSTANCE_AZ_ID = "use1-az1"
INSTANCE_DATA_ECS_FARGATE = {
    "Cluster": "arn:aws:ecs:us-east-1:123456789012:cluster/clusterName",
    "TaskARN": "arn:aws:ecs:us-east-1:123456789012:task/MyEmptyCluster/bfa2636268144d039771334145e490c5",
    "Family": "sample-fargate",
    "Revision": "5",
    "DesiredStatus": "RUNNING",
    "KnownStatus": "RUNNING",
    "Limits": {"CPU": 0.25, "Memory": 512},
    "PullStartedAt": "2023-07-21T15:45:33.532811081Z",
    "PullStoppedAt": "2023-07-21T15:45:38.541068435Z",
    "AvailabilityZone": "us-east-1a",
}
INSTANCE_DOCUMENT_ECS_FARGATE = json.dumps(INSTANCE_DATA_ECS_FARGATE)

OPTIONS = {"crossaccount": None}
DESCRIBE_AVAILABILITY_ZONES_RESPONSE = {
    "AvailabilityZones": [
        {
            "State": "available",
            "OptInStatus": "opt-in-not-required",
            "Messages": [],
            "RegionName": "us-east-1",
            "ZoneName": "us-east-1a",
            "ZoneId": "use1-az1",
            "GroupName": "us-east-1",
            "NetworkBorderGroup": "us-east-1",
        },
        {
            "State": "available",
            "OptInStatus": "opt-in-not-required",
            "Messages": [],
            "RegionName": "us-east-1",
            "ZoneName": "us-east-1b",
            "ZoneId": "use1-az2",
            "GroupName": "us-east-1",
            "NetworkBorderGroup": "us-east-1",
        },
        {
            "State": "available",
            "OptInStatus": "opt-in-not-required",
            "Messages": [],
            "RegionName": "us-east-1",
            "ZoneName": "us-east-1c",
            "ZoneId": "use1-az3",
            "GroupName": "us-east-1",
            "NetworkBorderGroup": "us-east-1",
        },
        {
            "State": "available",
            "OptInStatus": "opt-in-not-required",
            "Messages": [],
            "RegionName": "us-east-1",
            "ZoneName": "us-east-1d",
            "ZoneId": "use1-az4",
            "GroupName": "us-east-1",
            "NetworkBorderGroup": "us-east-1",
        },
    ]
}


@pytest.fixture(autouse=True)
def setup(mocker):
    mount_efs.INSTANCE_AZ_ID_METADATA = None


class MockHeaders(object):
    def __init__(self, content_charset=None):
        self.content_charset = content_charset

    def get_content_charset(self):
        return self.content_charset


class MockUrlLibResponse(object):
    def __init__(self, code=200, data=INSTANCE_AZ_ID, headers=MockHeaders()):
        self.code = code
        self.data = data
        self.headers = headers

    def getcode(self):
        return self.code

    def read(self):
        return self.data


class MockUrlLibResponseECSFargate(object):
    def __init__(
        self, code=200, data=INSTANCE_DOCUMENT_ECS_FARGATE, headers=MockHeaders()
    ):
        self.code = code
        self.data = data
        self.headers = headers

    def getcode(self):
        return self.code

    def read(self):
        return self.data


def _get_config(is_fargate=False):
    try:
        config = ConfigParser.SafeConfigParser()
    except AttributeError:
        config = ConfigParser()
    config.add_section(mount_efs.CONFIG_SECTION)
    if is_fargate:
        config.add_section(mount_efs.CLIENT_INFO_SECTION)
        config.set(mount_efs.CLIENT_INFO_SECTION, "source", "ecs.fargate")
    config.set(
        mount_efs.CONFIG_SECTION,
        "dns_name_format",
        "{az}.{fs_id}.efs.{region}.amazonaws.com",
    )
    return config


def test_get_instance_az_id_helper():
    return mount_efs.get_az_id_info_from_instance_metadata(_get_config(), OPTIONS)


def test_get_instance_az_id_with_token(mocker):
    mocker.patch("mount_efs.get_aws_ec2_metadata_token", return_value="ABCDEFG==")
    mocker.patch("mount_efs.urlopen", return_value=MockUrlLibResponse())
    assert INSTANCE_AZ_ID == test_get_instance_az_id_helper()


def test_get_instance_az_id_without_token(mocker):
    mocker.patch("mount_efs.get_aws_ec2_metadata_token", return_value=None)
    mocker.patch("mount_efs.urlopen", return_value=MockUrlLibResponse())
    assert INSTANCE_AZ_ID == test_get_instance_az_id_helper()


# Reproduce https://github.com/aws/efs-utils/issues/46
def test_get_instance_az_id_token_fetch_time_out(mocker):
    # get_aws_ec2_metadata_token timeout, fallback to call without session token
    mocker.patch(
        "mount_efs.urlopen", side_effect=[socket.timeout, MockUrlLibResponse()]
    )
    assert INSTANCE_AZ_ID == test_get_instance_az_id_helper()


def test_get_instance_az_id_py3_no_charset(mocker):
    mocker.patch("mount_efs.get_aws_ec2_metadata_token", return_value=None)
    mocker.patch(
        "mount_efs.urlopen",
        return_value=MockUrlLibResponse(data=bytearray(INSTANCE_AZ_ID, "us-ascii")),
    )
    assert INSTANCE_AZ_ID == test_get_instance_az_id_helper()


def test_get_instance_az_id_py3_utf8_charset(mocker):
    charset = "utf-8"
    mocker.patch("mount_efs.get_aws_ec2_metadata_token", return_value=None)
    mocker.patch(
        "mount_efs.urlopen",
        return_value=MockUrlLibResponse(data=bytearray(INSTANCE_AZ_ID, charset)),
        headers=MockHeaders(content_charset=charset),
    )
    assert INSTANCE_AZ_ID == test_get_instance_az_id_helper()


def test_get_instance_az_id_config_metadata_unavailable(mocker):
    mocker.patch("mount_efs.get_aws_ec2_metadata_token", return_value=None)
    mocker.patch("mount_efs.urlopen", side_effect=URLError("test error"))
    instance_az_id = test_get_instance_az_id_helper()
    assert instance_az_id == None


def _test_get_instance_az_id_error(mocker, response=None, error=None):
    mocker.patch("mount_efs.get_aws_ec2_metadata_token", return_value=None)
    if (response and error) or (not response and not error):
        raise ValueError("Invalid arguments")
    elif response:
        mocker.patch("mount_efs.urlopen", return_value=response)
    elif error:
        mocker.patch("mount_efs.urlopen", side_effect=error)

    instance_az_id = test_get_instance_az_id_helper()
    assert instance_az_id == None


def test_get_instance_az_id_bad_response(mocker):
    _test_get_instance_az_id_error(
        mocker, error=HTTPError("url", 400, "Bad Request Error", None, None)
    )


def test_get_instance_az_id_error_response(mocker):
    _test_get_instance_az_id_error(mocker, error=URLError("test error"))


def test_get_instance_az_id_missing_instance_az_id(mocker):
    _test_get_instance_az_id_error(
        mocker,
        response=MockUrlLibResponse(data=""),
    )


def test_get_instance_az_id_ecs_fargate(mocker):
    mocker.patch("os.getenv", return_value="http://169.254.170.2")
    mocker.patch("mount_efs.urlopen", return_value=MockUrlLibResponseECSFargate())
    mocker.patch("mount_efs.get_botocore_client", side_effect=[None, None])
    mocker.patch(
        "mount_efs.get_az_id_by_az_name_helper",
        return_value=DESCRIBE_AVAILABILITY_ZONES_RESPONSE,
    )
    assert INSTANCE_AZ_ID == mount_efs.get_az_id_info_from_instance_metadata(
        _get_config(is_fargate=True), OPTIONS
    )


def test_is_ecs_fargate_client_true(mocker):
    assert mount_efs.is_ecs_fargate_client(_get_config(is_fargate=True)) == True


def test_is_ecs_fargate_client_false(mocker):
    assert mount_efs.is_ecs_fargate_client(_get_config(is_fargate=False)) == False


def test_get_instance_az_id_metadata_url_ecs_fargate(mocker):
    get_env_mock = mocker.patch("os.getenv", return_value="http://169.254.170.2")
    assert (
        mount_efs.get_instance_az_id_metadata_url(_get_config(is_fargate=True))
        == FARGATE_AZ_ID_ENDPOINT
    )
    utils.assert_called_n_times(get_env_mock, 1)


def test_get_instance_az_id_metadata_url_ec2(mocker):
    assert (
        mount_efs.get_instance_az_id_metadata_url(_get_config(is_fargate=False))
        == mount_efs.INSTANCE_METADATA_SERVICE_AZ_ID_URL
    )


def test_get_instance_az_id_via_cached_instance_az_identity(mocker):
    mocker.patch("mount_efs.get_aws_ec2_metadata_token", return_value="ABCDEFG==")
    url_request_helper_mock_1 = mocker.patch(
        "mount_efs.urlopen", return_value=MockUrlLibResponse()
    )
    assert mount_efs.INSTANCE_AZ_ID_METADATA == None
    assert INSTANCE_AZ_ID == test_get_instance_az_id_helper()
    utils.assert_called_n_times(url_request_helper_mock_1, 1)

    # Verify the global INSTANCE_AZ_ID is cached with previous metadata api call result
    assert mount_efs.INSTANCE_AZ_ID_METADATA == INSTANCE_AZ_ID
    url_request_helper_mock_2 = mocker.patch("mount_efs.urlopen")
    assert INSTANCE_AZ_ID == test_get_instance_az_id_helper()
    # Verify there is no second api call when INSTANCE_AZ_ID is present
    utils.assert_not_called(url_request_helper_mock_2)
