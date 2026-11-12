# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
import json
import socket
from http.client import RemoteDisconnected

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
    mount_context = context.MountContext()
    mount_context.reset()
    mount_context.mount_type = constants.MOUNT_TYPE_EFS
    mount_context.config_file_path = constants.CONFIG_FILE
    efs_utils_common.constants.INSTANCE_IDENTITY = None
    yield mount_context


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
    config.add_section(efs_utils_common.constants.CONFIG_SECTION)
    return config


def test_get_instance_id_helper():
    return metadata.get_instance_identity_info_from_instance_metadata(
        get_config(), "instanceId"
    )


def test_get_instance_id_with_token(mocker):
    mocker.patch(
        "efs_utils_common.metadata.get_aws_ec2_metadata_token", return_value="ABCDEFG=="
    )
    mocker.patch.object(metadata, "urlopen", return_value=MockUrlLibResponse())
    assert INSTANCE_ID == test_get_instance_id_helper()


def test_get_instance_id_without_token(mocker):
    mocker.patch(
        "efs_utils_common.metadata.get_aws_ec2_metadata_token", return_value=None
    )
    mocker.patch.object(metadata, "urlopen", return_value=MockUrlLibResponse())
    assert INSTANCE_ID == test_get_instance_id_helper()


# Reproduce https://github.com/aws/efs-utils/issues/46
def test_get_instance_id_token_fetch_time_out(mocker):
    # get_aws_ec2_metadata_token timeout, fallback to call without session token
    side_effect = [
        socket.timeout
        for _ in range(
            0, efs_utils_common.constants.DEFAULT_GET_AWS_EC2_METADATA_TOKEN_RETRY_COUNT
        )
    ]
    side_effect.append(MockUrlLibResponse())
    mocker.patch.object(metadata, "urlopen", side_effect=side_effect)
    assert INSTANCE_ID == test_get_instance_id_helper()


def test_get_instance_id_py3_no_charset(mocker):
    mount_context = context.MountContext()
    assert mount_context.instance_identity is None

    mocker.patch(
        "efs_utils_common.metadata.get_aws_ec2_metadata_token", return_value=None
    )

    mocker.patch.object(
        metadata,
        "urlopen",
        return_value=MockUrlLibResponse(data=bytearray(INSTANCE_DOCUMENT, "us-ascii")),
    )

    result = test_get_instance_id_helper()

    assert INSTANCE_ID == result


def test_get_instance_id_py3_utf8_charset(mocker):
    charset = "utf-8"
    mocker.patch(
        "efs_utils_common.metadata.get_aws_ec2_metadata_token", return_value=None
    )

    mock_response = MockUrlLibResponse(
        data=bytearray(INSTANCE_DOCUMENT, charset),
        headers=MockHeaders(content_charset=charset),
    )

    mocker.patch.object(metadata, "urlopen", return_value=mock_response)

    result = test_get_instance_id_helper()

    assert INSTANCE_ID == result


def test_get_instance_id_config_metadata_unavailable(mocker):
    mocker.patch(
        "efs_utils_common.metadata.get_aws_ec2_metadata_token", return_value=None
    )
    mocker.patch.object(metadata, "urlopen", side_effect=URLError("test error"))
    instance_id = test_get_instance_id_helper()
    assert instance_id == None


def _test_get_instance_id_error(mocker, response=None, error=None):
    mocker.patch(
        "efs_utils_common.metadata.get_aws_ec2_metadata_token", return_value=None
    )
    if (response and error) or (not response and not error):
        raise ValueError("Invalid arguments")
    elif response:
        mocker.patch.object(metadata, "urlopen", return_value=response)
    elif error:
        mocker.patch.object(metadata, "urlopen", side_effect=error)

    instance_id = test_get_instance_id_helper()
    assert instance_id == None


def test_get_instance_id_bad_response(mocker):
    _test_get_instance_id_error(
        mocker, error=HTTPError("url", 400, "Bad Request Error", None, None)
    )


def test_get_instance_id_error_response(mocker):
    _test_get_instance_id_error(mocker, error=URLError("test error"))


def test_get_instance_id_bad_json(mocker):
    mocker.patch(
        "efs_utils_common.metadata.get_instance_identity_info_from_instance_metadata",
        return_value=None,
    )
    instance_id = test_get_instance_id_helper()
    assert instance_id == None


def test_get_instance_id_missing_instance_id(mocker):
    _test_get_instance_id_error(
        mocker,
        response=MockUrlLibResponse(data=json.dumps({"accountId": "123412341234"})),
    )


def test_get_instance_id_via_cached_instance_identity(mocker):
    mount_context = context.MountContext()
    mocker.patch(
        "efs_utils_common.metadata.get_aws_ec2_metadata_token", return_value="ABCDEFG=="
    )
    url_request_helper_mock_1 = mocker.patch.object(
        metadata, "urlopen", return_value=MockUrlLibResponse()
    )

    assert mount_context.instance_identity is None

    result = test_get_instance_id_helper()

    assert INSTANCE_ID == result
    utils.assert_called_n_times(url_request_helper_mock_1, 1)

    assert mount_context.instance_identity == INSTANCE_DATA

    url_request_helper_mock_2 = mocker.patch.object(metadata, "urlopen")
    assert INSTANCE_ID == test_get_instance_id_helper()

    utils.assert_not_called(url_request_helper_mock_2)


REFUSED = URLError(ConnectionRefusedError(111, "Connection refused"))


class FakeClock(object):
    """Stands in for time.monotonic and time.sleep, so a retry window is exact."""

    def __init__(self, mocker):
        self.now = 1000.0
        self.sleeps = []
        mocker.patch("efs_utils_common.metadata.time.monotonic", side_effect=self.read)
        mocker.patch("efs_utils_common.metadata.time.sleep", side_effect=self.sleep)

    def read(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


@pytest.mark.parametrize(
    "outage",
    [
        REFUSED,
        URLError(ConnectionResetError(104, "Connection reset by peer")),
        HTTPError("url", 503, "Service Unavailable", None, None),
        RemoteDisconnected("Remote end closed connection without response"),
        ConnectionResetError(104, "Connection reset by peer"),
    ],
)
def test_get_instance_id_rides_out_a_brief_imds_outage(mocker, outage):
    clock = FakeClock(mocker)
    mocker.patch(
        "efs_utils_common.metadata.get_aws_ec2_metadata_token", return_value=None
    )
    urlopen_mock = mocker.patch.object(
        metadata, "urlopen", side_effect=[outage, outage, MockUrlLibResponse()]
    )

    assert INSTANCE_ID == test_get_instance_id_helper()
    utils.assert_called_n_times(urlopen_mock, 3)
    assert clock.sleeps == [0.5, 1.0]


def test_get_instance_id_does_not_retry_a_timeout(mocker):
    # Hosts with no metadata service time out, and must not wait any longer.
    clock = FakeClock(mocker)
    mocker.patch(
        "efs_utils_common.metadata.get_aws_ec2_metadata_token", return_value=None
    )
    urlopen_mock = mocker.patch.object(
        metadata, "urlopen", side_effect=[socket.timeout, MockUrlLibResponse()]
    )

    assert test_get_instance_id_helper() is None
    utils.assert_called_once(urlopen_mock)
    assert clock.sleeps == []


@pytest.mark.parametrize(
    "error",
    [
        HTTPError("url", 404, "Not Found", None, None),
        URLError("test error"),
    ],
)
def test_get_instance_id_does_not_retry_a_non_outage_error(mocker, error):
    clock = FakeClock(mocker)
    mocker.patch(
        "efs_utils_common.metadata.get_aws_ec2_metadata_token", return_value=None
    )
    urlopen_mock = mocker.patch.object(
        metadata, "urlopen", side_effect=[error, MockUrlLibResponse()]
    )

    assert test_get_instance_id_helper() is None
    utils.assert_called_once(urlopen_mock)
    assert clock.sleeps == []


def test_imds_outage_retries_share_one_bounded_window(mocker):
    clock = FakeClock(mocker)
    mocker.patch(
        "efs_utils_common.metadata.get_aws_ec2_metadata_token", return_value=None
    )
    urlopen_mock = mocker.patch.object(metadata, "urlopen", side_effect=REFUSED)

    assert test_get_instance_id_helper() is None
    assert clock.sleeps == [0.5, 1.0, 2.0]
    assert sum(clock.sleeps) <= constants.IMDS_OUTAGE_RETRY_WINDOW_SEC
    utils.assert_called_n_times(urlopen_mock, 4)

    # A later read in the same mount gets only what is left of the window.
    assert test_get_instance_id_helper() is None
    assert clock.sleeps == [0.5, 1.0, 2.0, 0.5, 1.0]
    assert sum(clock.sleeps) <= constants.IMDS_OUTAGE_RETRY_WINDOW_SEC


@pytest.mark.parametrize("window", [2, constants.IMDS_OUTAGE_RETRY_WINDOW_SEC])
def test_imds_outage_window_bounds_the_token_fetch_too(mocker, window):
    clock = FakeClock(mocker)
    mocker.patch.object(metadata, "IMDS_OUTAGE_RETRY_WINDOW_SEC", window)
    mocker.patch.object(metadata, "urlopen", side_effect=REFUSED)
    token_sleeps_per_read = (
        constants.DEFAULT_GET_AWS_EC2_METADATA_TOKEN_RETRY_COUNT - 1
    ) * 0.5

    assert test_get_instance_id_helper() is None
    assert clock.now - 1000.0 <= window

    # Later reads add nothing beyond the token retries they always had.
    test_get_instance_id_helper()
    test_get_instance_id_helper()
    assert clock.now - 1000.0 <= window + 3 * token_sleeps_per_read


def test_non_imds_url_is_not_retried(mocker):
    clock = FakeClock(mocker)
    urlopen_mock = mocker.patch.object(metadata, "urlopen", side_effect=REFUSED)

    result = metadata.url_request_helper(
        get_config(), "http://169.254.170.2/v4/task", "unsuccessful", "unreachable"
    )

    assert result is None
    utils.assert_called_once(urlopen_mock)
    assert clock.sleeps == []


def test_a_reset_from_a_non_imds_url_is_raised(mocker):
    # Swallowing it would let a credentials lookup fall through to the instance role.
    clock = FakeClock(mocker)
    mocker.patch.object(
        metadata,
        "urlopen",
        side_effect=RemoteDisconnected("Remote end closed connection without response"),
    )

    with pytest.raises(ConnectionResetError):
        metadata.url_request_helper(
            get_config(),
            "http://169.254.170.2/v2/credentials/x",
            "unsuccessful",
            "unreachable",
        )
    assert clock.sleeps == []


class MockTokenResponse(object):
    def read(self):
        return b"TOKEN"


def mock_imds(mocker, puts, gets):
    """Route the token PUTs and the GETs to their own lists of results."""
    calls = {"PUT": list(puts), "GET": list(gets)}

    def urlopen(request, timeout=None):
        result = calls[request.get_method()].pop(0)
        if isinstance(result, BaseException):
            raise result
        return result

    return mocker.patch.object(metadata, "urlopen", side_effect=urlopen), calls


def test_a_401_after_a_refused_token_is_retried(mocker):
    # IMDS came back between the failed PUT and the GET, so the GET went out without a token.
    clock = FakeClock(mocker)
    _, calls = mock_imds(
        mocker,
        puts=[REFUSED, REFUSED, REFUSED, MockTokenResponse()],
        gets=[HTTPError("url", 401, "Unauthorized", None, None), MockUrlLibResponse()],
    )

    assert INSTANCE_ID == test_get_instance_id_helper()
    assert calls == {"PUT": [], "GET": []}
    assert clock.sleeps == [0.5, 0.5, 0.5]


def test_a_401_after_a_token_timeout_is_not_retried(mocker):
    # A container with hop limit 1 always times out on the token; it must not wait out the window.
    clock = FakeClock(mocker)
    _, calls = mock_imds(
        mocker,
        puts=[socket.timeout()] * 3,
        gets=[HTTPError("url", 401, "Unauthorized", None, None), MockUrlLibResponse()],
    )

    assert test_get_instance_id_helper() is None
    assert calls["PUT"] == []
    assert len(calls["GET"]) == 1
    assert clock.sleeps == [0.5, 0.5]
