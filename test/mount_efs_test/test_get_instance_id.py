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

INSTANCE_ID = "i-deadbeefdeadbeef0"
INSTANCE_DATA = {
    "devpayProductCodes": None,
    "privateIp": "192.168.1.1",
    "availabilityZone": "us-east-1a",
    "version": "2010-08-31",
    "instanceId": INSTANCE_ID,
    "billingProducts": None,
    "pendingTime": "2017-06-20T18:32:00Z",
    "instanceType": "m3.xlarge",
    "accountId": "123412341234",
    "architecture": "x86_64",
    "kernelId": None,
    "ramdiskId": None,
    "imageId": "ami-deadbeef",
    "region": "us-east-1",
}
INSTANCE_DOCUMENT = json.dumps(INSTANCE_DATA)


@pytest.fixture(autouse=True)
def setup(mocker):
    mount_efs.INSTANCE_IDENTITY = None


class MockHeaders(object):
    def __init__(self, content_charset=None):
        self.content_charset = content_charset

    def get_content_charset(self):
        return self.content_charset


class MockUrlLibResponse(object):
    def __init__(self, code=200, data=INSTANCE_DOCUMENT, headers=MockHeaders()):
        self.code = code
        self.data = data
        self.headers = headers

    def getcode(self):
        return self.code

    def read(self):
        return self.data


def get_config():
    try:
        config = ConfigParser.SafeConfigParser()
    except AttributeError:
        config = ConfigParser()
    config.add_section(mount_efs.CONFIG_SECTION)
    return config


def test_get_instance_id_helper():
    return mount_efs.get_instance_identity_info_from_instance_metadata(
        get_config(), "instanceId"
    )


def test_get_instance_id_with_token(mocker):
    mocker.patch("mount_efs.get_aws_ec2_metadata_token", return_value="ABCDEFG==")
    mocker.patch("mount_efs.urlopen", return_value=MockUrlLibResponse())
    assert INSTANCE_ID == test_get_instance_id_helper()


def test_get_instance_id_without_token(mocker):
    mocker.patch("mount_efs.get_aws_ec2_metadata_token", return_value=None)
    mocker.patch("mount_efs.urlopen", return_value=MockUrlLibResponse())
    assert INSTANCE_ID == test_get_instance_id_helper()


# Reproduce https://github.com/aws/efs-utils/issues/46
def test_get_instance_id_token_fetch_time_out(mocker):
    # get_aws_ec2_metadata_token timeout, fallback to call without session token
    side_effect = [
        socket.timeout
        for _ in range(0, mount_efs.DEFAULT_GET_AWS_EC2_METADATA_TOKEN_RETRY_COUNT)
    ]
    side_effect.append(MockUrlLibResponse())
    mocker.patch("mount_efs.urlopen", side_effect=side_effect)
    assert INSTANCE_ID == test_get_instance_id_helper()


def test_get_instance_id_py3_no_charset(mocker):
    mocker.patch("mount_efs.get_aws_ec2_metadata_token", return_value=None)
    mocker.patch(
        "mount_efs.urlopen",
        return_value=MockUrlLibResponse(data=bytearray(INSTANCE_DOCUMENT, "us-ascii")),
    )
    assert INSTANCE_ID == test_get_instance_id_helper()


def test_get_instance_id_py3_utf8_charset(mocker):
    charset = "utf-8"
    mocker.patch("mount_efs.get_aws_ec2_metadata_token", return_value=None)
    mocker.patch(
        "mount_efs.urlopen",
        return_value=MockUrlLibResponse(data=bytearray(INSTANCE_DOCUMENT, charset)),
        headers=MockHeaders(content_charset=charset),
    )
    assert INSTANCE_ID == test_get_instance_id_helper()


def test_get_instance_id_config_metadata_unavailable(mocker):
    mocker.patch("mount_efs.get_aws_ec2_metadata_token", return_value=None)
    mocker.patch("mount_efs.urlopen", side_effect=URLError("test error"))
    instance_id = test_get_instance_id_helper()
    assert instance_id == None


def _test_get_instance_id_error(mocker, response=None, error=None):
    mocker.patch("mount_efs.get_aws_ec2_metadata_token", return_value=None)
    if (response and error) or (not response and not error):
        raise ValueError("Invalid arguments")
    elif response:
        mocker.patch("mount_efs.urlopen", return_value=response)
    elif error:
        mocker.patch("mount_efs.urlopen", side_effect=error)

    instance_id = test_get_instance_id_helper()
    assert instance_id == None


def test_get_instance_id_bad_response(mocker):
    _test_get_instance_id_error(
        mocker, error=HTTPError("url", 400, "Bad Request Error", None, None)
    )


def test_get_instance_id_error_response(mocker):
    _test_get_instance_id_error(mocker, error=URLError("test error"))


def test_get_instance_id_bad_json(mocker):
    _test_get_instance_id_error(mocker, response=MockUrlLibResponse(data="not json"))


def test_get_instance_id_missing_instance_id(mocker):
    _test_get_instance_id_error(
        mocker,
        response=MockUrlLibResponse(data=json.dumps({"accountId": "123412341234"})),
    )


def test_get_instance_id_via_cached_instance_identity(mocker):
    mocker.patch("mount_efs.get_aws_ec2_metadata_token", return_value="ABCDEFG==")
    url_request_helper_mock_1 = mocker.patch(
        "mount_efs.urlopen", return_value=MockUrlLibResponse()
    )
    assert mount_efs.INSTANCE_IDENTITY == None
    assert INSTANCE_ID == test_get_instance_id_helper()
    utils.assert_called_n_times(url_request_helper_mock_1, 1)

    # Verify the global INSTANCE_IDENTITY is cached with previous metadata api call result
    assert mount_efs.INSTANCE_IDENTITY == INSTANCE_DATA
    url_request_helper_mock_2 = mocker.patch("mount_efs.urlopen")
    assert INSTANCE_ID == test_get_instance_id_helper()
    # Verify there is no second api call when INSTANCE_IDENTITY is present
    utils.assert_not_called(url_request_helper_mock_2)
