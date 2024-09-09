# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.

import json
import socket

import pytest

import mount_efs

try:
    import ConfigParser
except ImportError:
    from configparser import ConfigParser

try:
    from urllib2 import HTTPError, URLError
except ImportError:
    from urllib.error import HTTPError, URLError

DEFAULT_DNS_NAME_FORMAT = "{az}.{fs_id}.efs.{region}.{dns_name_suffix}"
TARGET_REGION = "us-east-1"
TARGET_AZ = "us-east-1a"

INSTANCE_DATA = {
    "devpayProductCodes": None,
    "privateIp": "192.168.1.1",
    "availabilityZone": TARGET_AZ,
    "version": "2010-08-31",
    "instanceId": "i-deadbeefdeadbeef0",
    "billingProducts": None,
    "pendingTime": "2017-06-20T18:32:00Z",
    "instanceType": "m3.xlarge",
    "accountId": "123412341234",
    "architecture": "x86_64",
    "kernelId": None,
    "ramdiskId": None,
    "imageId": "ami-deadbeef",
    "region": TARGET_REGION,
}

INSTANCE_DOCUMENT = json.dumps(INSTANCE_DATA)
DNS_NAME_SUFFIX = "amazonaws.com"


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


def get_config(dns_name_format, region=None):
    try:
        config = ConfigParser.SafeConfigParser()
    except AttributeError:
        config = ConfigParser()
    config.add_section(mount_efs.CONFIG_SECTION)
    config.set(mount_efs.CONFIG_SECTION, "dns_name_format", dns_name_format)
    if region:
        config.set(mount_efs.CONFIG_SECTION, "region", region)
    return config


def get_target_region_helper(options={}):
    config = get_config(DEFAULT_DNS_NAME_FORMAT)
    return mount_efs.get_target_region(config, options)


def get_target_az_helper(options={}):
    return mount_efs.get_target_az(get_config(DEFAULT_DNS_NAME_FORMAT), options)


"""
Get target region from ec2 instance metadata
"""


def test_get_target_region_with_token(mocker):
    mocker.patch("mount_efs.get_aws_ec2_metadata_token", return_value="ABCDEFG==")
    mocker.patch("mount_efs.urlopen", return_value=MockUrlLibResponse())
    assert "us-east-1" == get_target_region_helper()


def test_get_target_region_without_token(mocker):
    mocker.patch("mount_efs.get_aws_ec2_metadata_token", return_value=None)
    mocker.patch("mount_efs.urlopen", return_value=MockUrlLibResponse())
    assert "us-east-1" == get_target_region_helper()


# Reproduce https://github.com/aws/efs-utils/issues/46
def test_get_target_region_token_endpoint_fetching_timeout(mocker):
    # get_aws_ec2_metadata_token timeout, fallback to call without session token
    side_effect = [
        socket.timeout
        for _ in range(0, mount_efs.DEFAULT_GET_AWS_EC2_METADATA_TOKEN_RETRY_COUNT)
    ]
    side_effect.append(MockUrlLibResponse())
    mocker.patch("mount_efs.urlopen", side_effect=side_effect)
    assert "us-east-1" == get_target_region_helper()


def test_get_target_region_token_fetch_httperror(mocker):
    side_effect = [
        HTTPError("url", 405, "Now Allowed", None, None)
        for _ in range(0, mount_efs.DEFAULT_GET_AWS_EC2_METADATA_TOKEN_RETRY_COUNT)
    ]
    side_effect.append(MockUrlLibResponse())
    mocker.patch("mount_efs.urlopen", side_effect=side_effect)
    assert "us-east-1" == get_target_region_helper()


def test_get_target_region_token_fetch_unknownerror(mocker):
    side_effect = [
        Exception("Unknown Exception")
        for _ in range(0, mount_efs.DEFAULT_GET_AWS_EC2_METADATA_TOKEN_RETRY_COUNT)
    ]
    side_effect.append(MockUrlLibResponse())
    mocker.patch("mount_efs.urlopen", side_effect=side_effect)
    assert "us-east-1" == get_target_region_helper()


def test_get_target_region_py3_no_charset(mocker):
    mocker.patch("mount_efs.get_aws_ec2_metadata_token", return_value=None)
    mocker.patch(
        "mount_efs.urlopen",
        return_value=MockUrlLibResponse(data=bytearray(INSTANCE_DOCUMENT, "us-ascii")),
    )
    assert "us-east-1" == get_target_region_helper()


def test_get_target_region_py3_utf8_charset(mocker):
    charset = "utf-8"
    mocker.patch("mount_efs.get_aws_ec2_metadata_token", return_value=None)
    mocker.patch(
        "mount_efs.urlopen",
        return_value=MockUrlLibResponse(data=bytearray(INSTANCE_DOCUMENT, charset)),
        headers=MockHeaders(content_charset=charset),
    )
    assert "us-east-1" == get_target_region_helper()


def test_get_target_region_from_metadata(mocker):
    mocker.patch("mount_efs.get_aws_ec2_metadata_token", return_value=None)
    mocker.patch("mount_efs.urlopen", return_value=MockUrlLibResponse())
    config = get_config("{fs_id}.efs.{region}.{dns_name_suffix}", None)
    assert TARGET_REGION == mount_efs.get_target_region(config, {})


def test_get_target_region_config_metadata_unavailable(mocker, capsys):
    mocker.patch("mount_efs.get_aws_ec2_metadata_token", return_value=None)
    mocker.patch("mount_efs.urlopen", side_effect=URLError("test error"))
    config = get_config("{fs_id}.efs.{region}.{dns_name_suffix}")
    with pytest.raises(SystemExit) as ex:
        mount_efs.get_target_region(config, {})

    assert 0 != ex.value.code
    out, err = capsys.readouterr()
    assert "Error retrieving region" in err


def _test_get_target_region_error(mocker, capsys, response=None, error=None):
    mocker.patch("mount_efs.get_aws_ec2_metadata_token", return_value=None)
    if (response and error) or (not response and not error):
        raise ValueError("Invalid arguments")
    elif response:
        mocker.patch("mount_efs.urlopen", return_value=response)
    elif error:
        mocker.patch("mount_efs.urlopen", side_effect=error)

    with pytest.raises(SystemExit) as ex:
        get_target_region_helper()

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert "Error retrieving region" in err


def test_get_target_region_bad_response(mocker, capsys):
    _test_get_target_region_error(
        mocker, capsys, error=HTTPError("url", 400, "Bad Request Error", None, None)
    )


def test_get_target_region_error_response(mocker, capsys):
    _test_get_target_region_error(mocker, capsys, error=URLError("test error"))


def test_get_target_region_timeout_response(mocker, capsys):
    _test_get_target_region_error(mocker, capsys, error=socket.timeout)


def test_get_target_region_bad_json(mocker, capsys):
    _test_get_target_region_error(
        mocker, capsys, response=MockUrlLibResponse(data="not json")
    )


def test_get_target_region_missing_region(mocker, capsys):
    _test_get_target_region_error(
        mocker, capsys, response=MockUrlLibResponse(data=json.dumps({}))
    )


"""
Get target region from configuration file
"""


def test_get_target_region_from_config_variable(mocker):
    config = get_config("{az}.{fs_id}.efs.us-east-2.{dns_name_suffix}", TARGET_REGION)
    assert TARGET_REGION == mount_efs.get_target_region(config, {})


def _test_get_target_region_from_dns_format(mocker, config):
    mocker.patch("mount_efs.get_aws_ec2_metadata_token", return_value=None)
    mocker.patch("mount_efs.urlopen", side_effect=URLError("test error"))
    assert TARGET_REGION == mount_efs.get_target_region(config, {})


def test_get_target_region_from_legacy_dns_name_format(mocker):
    config = get_config("{az}.{fs_id}.efs.us-east-1.amazonaws.com")
    _test_get_target_region_from_dns_format(mocker, config)


def test_get_target_region_from_suffixed_dns_name_format(mocker):
    config = get_config("{az}.{fs_id}.efs.us-east-1.{dns_name_suffix}")
    config.set(mount_efs.CONFIG_SECTION, "dns_name_suffix", DNS_NAME_SUFFIX)
    _test_get_target_region_from_dns_format(mocker, config)


"""
Get target region from ec2 instance metadata
"""


def test_get_target_az_from_instance_metadata(mocker):
    mocker.patch("mount_efs.get_aws_ec2_metadata_token", return_value="ABCDEFG==")
    mocker.patch("mount_efs.urlopen", return_value=MockUrlLibResponse())
    assert TARGET_AZ == get_target_az_helper({})


def test_get_target_az_not_present_in_options_and_instance_metadata(mocker):
    mocker.patch("mount_efs.get_aws_ec2_metadata_token", return_value=None)
    mocker.patch("mount_efs.urlopen", side_effect=URLError("test error"))

    assert None == get_target_az_helper({})


"""
Get target region from options
"""


def test_get_target_az_from_options(mocker):
    assert TARGET_AZ == get_target_az_helper(options={"az": TARGET_AZ})


def test_get_target_region_from_options(mocker):
    assert TARGET_REGION == get_target_region_helper(options={"region": TARGET_REGION})
