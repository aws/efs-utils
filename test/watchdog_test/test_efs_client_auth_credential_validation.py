#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

from datetime import datetime, timezone

import pytest

import watchdog

FS_ID = "fs-deadbeef"
REGION = "us-east-1"
SERVICE = "elasticfilesystem"
FIXED_DT = datetime(2000, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

VALID_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
VALID_SESSION_TOKEN = "FAKEwJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY+/=-_"

# A credential value must be exactly one line; a second line is rejected whatever it holds.
MULTILINE_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE\nsecond-line"


@pytest.fixture(autouse=True)
def setup(mocker):
    # Isolate the validation logic from the openssl-backed signing helpers.
    mocker.patch("watchdog.get_public_key_sha1", return_value="fake_public_key_hash")
    mocker.patch("watchdog.calculate_signature", return_value="deadbeef")


def _build(access_key_id, session_token=None):
    return watchdog.efs_client_auth_builder(
        "fake_public_key_path",
        access_key_id,
        "FAKE_AWS_SECRET_ACCESS_KEY",
        FIXED_DT,
        REGION,
        FS_ID,
        SERVICE,
        session_token,
    )


def test_valid_access_key_id_and_token_pass():
    body = _build(VALID_ACCESS_KEY_ID, VALID_SESSION_TOKEN)
    assert "accessKeyId = UTF8String:" + VALID_ACCESS_KEY_ID in body
    assert "sessionToken = EXPLICIT:0,UTF8String:" + VALID_SESSION_TOKEN in body


def test_valid_access_key_id_without_token_passes():
    body = _build(VALID_ACCESS_KEY_ID, None)
    assert "accessKeyId = UTF8String:" + VALID_ACCESS_KEY_ID in body
    assert "sessionToken" not in body


# The STS Credentials.AccessKeyId grammar is length 16-128, pattern [\w] =
# [A-Za-z0-9_]. Validation matches the documented grammar, so a docs-valid key
# with lowercase or underscore is accepted even though real AKIA/ASIA keys are
# observed uppercase-only.
@pytest.mark.parametrize(
    "access_key_id",
    [
        "AKIAIOSFODNN7EXAMPLE",  # observed uppercase form
        "ASIAJEXAMPLEXEG2JICEA",  # temporary (STS) key form
        "akiaiosfodnn7example",  # lowercase: docs-valid per [\w]
        "AKIA_IOSF_ODNN_7EXMP",  # underscore: docs-valid per [\w]
        "A" * 128,  # maximum documented length
        "A" * 16,  # minimum documented length
    ],
)
def test_docs_valid_access_key_id_accepted(access_key_id):
    body = _build(access_key_id, VALID_SESSION_TOKEN)
    assert "accessKeyId = UTF8String:" + access_key_id in body


@pytest.mark.parametrize(
    "access_key_id",
    [
        MULTILINE_ACCESS_KEY_ID,
        "AKIAIOSFODNN7EXAMPLE\n",
        "AKIAIOSFODNN7EXAMPLE\r\nsecond-line",
        "AKIA-IOSF-ODNN",
        "SHORT",
        "A" * 129,
        "",
    ],
)
def test_malformed_access_key_id_rejected(caplog, access_key_id):
    # In the watchdog daemon a bad credential must NOT exit the process (that would
    # stop cert refresh for every mount on the host); the builder logs and returns
    # None so the caller skips just this refresh.
    assert _build(access_key_id, VALID_SESSION_TOKEN) is None
    assert "accessKeyId" in caplog.text
    assert "malformed" in caplog.text
    if access_key_id:
        assert access_key_id not in caplog.text


@pytest.mark.parametrize(
    "session_token",
    [
        "FAKEtoken\nsecond-line",
        "FAKEtoken\n",
        "FAKEtoken\r\nsecond-line",
        "FAKE token",
        "FAKEtoken\twith-tab",
    ],
)
def test_malformed_session_token_rejected(caplog, session_token):
    assert _build(VALID_ACCESS_KEY_ID, session_token) is None
    assert "sessionToken" in caplog.text
    assert "malformed" in caplog.text
    assert session_token not in caplog.text
