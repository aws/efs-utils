# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
import json
import socket

import pytest

import efs_utils_common
import efs_utils_common.constants as constants
import efs_utils_common.context as context
import efs_utils_common.metadata as metadata

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
    "http://169.254.170.2"
    + efs_utils_common.constants.ECS_FARGATE_TASK_METADATA_ENDPOINT_URL_EXTENSION
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
    mount_context = context.MountContext()
    mount_context.reset()
    mount_context.mount_type = constants.MOUNT_TYPE_EFS
    mount_context.config_file_path = constants.CONFIG_FILE
    yield mount_context


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
    config.add_section(efs_utils_common.constants.CONFIG_SECTION)
    if is_fargate:
        config.add_section(efs_utils_common.constants.CLIENT_INFO_SECTION)
        config.set(
            efs_utils_common.constants.CLIENT_INFO_SECTION, "source", "ecs.fargate"
        )
    config.set(
        efs_utils_common.constants.CONFIG_SECTION,
        "dns_name_format",
        "{az}.{fs_id}.efs.{region}.amazonaws.com",
    )
    config.set(
        efs_utils_common.constants.CONFIG_SECTION,
        "az_id",
        INSTANCE_AZ_ID,
    )
    return config


def test_get_instance_az_id_helper():
    return metadata.get_az_id_info_from_instance_metadata(_get_config(), OPTIONS)


def test_get_instance_az_id_with_token(mocker):
    mocker.patch(
        "efs_utils_common.metadata.get_aws_ec2_metadata_token", return_value="ABCDEFG=="
    )

    url_open_mock = mocker.patch.object(
        metadata, "urlopen", return_value=MockUrlLibResponse()
    )

    assert INSTANCE_AZ_ID == test_get_instance_az_id_helper()


def test_get_instance_az_id_without_token(mocker):
    mocker.patch(
        "efs_utils_common.metadata.get_aws_ec2_metadata_token", return_value=None
    )

    url_open_mock = mocker.patch.object(
        metadata, "urlopen", return_value=MockUrlLibResponse()
    )

    assert INSTANCE_AZ_ID == test_get_instance_az_id_helper()


# Reproduce https://github.com/aws/efs-utils/issues/46
def test_get_instance_az_id_token_fetch_time_out(mocker):
    # get_aws_ec2_metadata_token timeout, fallback to call without session token
    side_effect = [
        socket.timeout
        for _ in range(
            0, efs_utils_common.constants.DEFAULT_GET_AWS_EC2_METADATA_TOKEN_RETRY_COUNT
        )
    ]
    side_effect.append(MockUrlLibResponse())
    mocker.patch("efs_utils_common.metadata.urlopen", side_effect=side_effect)
    assert INSTANCE_AZ_ID == test_get_instance_az_id_helper()


def test_get_instance_az_id_py3_no_charset(mocker):
    mocker.patch(
        "efs_utils_common.metadata.get_aws_ec2_metadata_token", return_value=None
    )
    mocker.patch(
        "efs_utils_common.metadata.urlopen",
        return_value=MockUrlLibResponse(data=bytearray(INSTANCE_AZ_ID, "us-ascii")),
    )
    assert INSTANCE_AZ_ID == test_get_instance_az_id_helper()


def test_get_instance_az_id_py3_utf8_charset(mocker):
    charset = "utf-8"
    mocker.patch(
        "efs_utils_common.metadata.get_aws_ec2_metadata_token", return_value=None
    )
    mocker.patch(
        "efs_utils_common.metadata.urlopen",
        return_value=MockUrlLibResponse(data=bytearray(INSTANCE_AZ_ID, charset)),
        headers=MockHeaders(content_charset=charset),
    )
    assert INSTANCE_AZ_ID == test_get_instance_az_id_helper()


def test_get_instance_az_id_config_metadata_unavailable(mocker):
    mocker.patch(
        "efs_utils_common.metadata.get_aws_ec2_metadata_token", return_value=None
    )
    mocker.patch(
        "efs_utils_common.metadata.urlopen", side_effect=URLError("test error")
    )
    instance_az_id = test_get_instance_az_id_helper()
    assert instance_az_id == None


def _test_get_instance_az_id_error(mocker, response=None, error=None):
    mocker.patch(
        "efs_utils_common.metadata.get_aws_ec2_metadata_token", return_value=None
    )
    if (response and error) or (not response and not error):
        raise ValueError("Invalid arguments")
    elif response:
        mocker.patch("efs_utils_common.metadata.urlopen", return_value=response)
    elif error:
        mocker.patch("efs_utils_common.metadata.urlopen", side_effect=error)

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
    mocker.patch(
        "efs_utils_common.metadata.urlopen", return_value=MockUrlLibResponseECSFargate()
    )
    mocker.patch(
        "efs_utils_common.metadata.get_botocore_client", side_effect=[None, None]
    )
    mocker.patch(
        "efs_utils_common.metadata.get_az_id_by_az_name_helper",
        return_value=DESCRIBE_AVAILABILITY_ZONES_RESPONSE,
    )
    assert INSTANCE_AZ_ID == metadata.get_az_id_info_from_instance_metadata(
        _get_config(is_fargate=True), OPTIONS
    )


def test_is_ecs_fargate_client_true(mocker):
    assert metadata.is_ecs_fargate_client(_get_config(is_fargate=True)) == True


def test_is_ecs_fargate_client_false(mocker):
    assert metadata.is_ecs_fargate_client(_get_config(is_fargate=False)) == False


def test_get_instance_az_id_metadata_url_ecs_fargate(mocker):
    get_env_mock = mocker.patch("os.getenv", return_value="http://169.254.170.2")
    assert (
        metadata.get_instance_az_id_metadata_url(_get_config(is_fargate=True))
        == FARGATE_AZ_ID_ENDPOINT
    )
    utils.assert_called_n_times(get_env_mock, 1)


def test_get_instance_az_id_metadata_url_ec2(mocker):
    assert (
        metadata.get_instance_az_id_metadata_url(_get_config(is_fargate=False))
        == efs_utils_common.constants.INSTANCE_METADATA_SERVICE_AZ_ID_URL
    )


def test_get_instance_az_id_via_cached_instance_az_identity(mocker):
    mount_context = context.MountContext()
    mocker.patch(
        "efs_utils_common.metadata.get_aws_ec2_metadata_token", return_value="ABCDEFG=="
    )
    url_request_helper_mock_1 = mocker.patch(
        "efs_utils_common.metadata.urlopen", return_value=MockUrlLibResponse()
    )
    assert mount_context.instance_az_id_metadata == None
    assert INSTANCE_AZ_ID == test_get_instance_az_id_helper()
    utils.assert_called_n_times(url_request_helper_mock_1, 1)

    assert mount_context.instance_az_id_metadata == INSTANCE_AZ_ID
    url_request_helper_mock_2 = mocker.patch("efs_utils_common.metadata.urlopen")
    assert INSTANCE_AZ_ID == test_get_instance_az_id_helper()
    utils.assert_not_called(url_request_helper_mock_2)


def test_get_az_id_from_instance_metadata_uses_azid_option():
    """Test that get_az_id_from_instance_metadata returns azid from options when provided"""
    config = _get_config()
    options = {"azid": "use1-az2"}

    result = metadata.get_az_id_from_instance_metadata(config, options)

    assert result == "use1-az2"
