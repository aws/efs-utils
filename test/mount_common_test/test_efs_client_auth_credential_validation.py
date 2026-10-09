#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

from datetime import datetime

import pytest

import efs_utils_common.certificate_utils as certificate_utils
import efs_utils_common.constants as constants
import efs_utils_common.context as context

FS_ID = "fs-deadbeef"
REGION = "us-east-1"
FIXED_DT = datetime(2000, 1, 1, 12, 0, 0)

VALID_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
VALID_SESSION_TOKEN = "FAKEwJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY+/=-_"

# A credential value must be exactly one line; a second line is rejected whatever it holds.
MULTILINE_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE\nsecond-line"


@pytest.fixture(autouse=True)
def setup(mocker):
    mount_context = context.MountContext()
    mount_context.reset()
    mount_context.service = constants.EFS_SERVICE_NAME
    mount_context.mount_type = constants.MOUNT_TYPE_EFS
    mount_context.config_file_path = constants.CONFIG_FILE
    # Isolate the validation logic from the openssl-backed signing helpers.
    mocker.patch(
        "efs_utils_common.certificate_utils.get_public_key_sha1",
        return_value="fake_public_key_hash",
    )
    mocker.patch(
        "efs_utils_common.certificate_utils.calculate_signature",
        return_value="deadbeef",
    )
    yield mount_context
    mount_context.reset()


def _build(access_key_id, session_token=None):
    return certificate_utils.efs_client_auth_builder(
        "fake_public_key_path",
        access_key_id,
        "FAKE_AWS_SECRET_ACCESS_KEY",
        FIXED_DT,
        REGION,
        FS_ID,
        session_token,
    )


# ---- valid values pass and are serialized verbatim ----


def test_valid_access_key_id_and_token_pass():
    body = _build(VALID_ACCESS_KEY_ID, VALID_SESSION_TOKEN)
    assert "accessKeyId = UTF8String:" + VALID_ACCESS_KEY_ID in body
    assert "sessionToken = EXPLICIT:0,UTF8String:" + VALID_SESSION_TOKEN in body


def test_valid_access_key_id_without_token_passes():
    body = _build(VALID_ACCESS_KEY_ID, None)
    assert "accessKeyId = UTF8String:" + VALID_ACCESS_KEY_ID in body
    assert "sessionToken" not in body


# The STS Credentials.AccessKeyId grammar is length 16-128, pattern [\w] =
# [A-Za-z0-9_] ("any upper- or lowercase letter or digit"). Validation matches
# the documented grammar, so a docs-valid key with lowercase or underscore is
# accepted even though real AKIA/ASIA keys are observed uppercase-only.
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


# ---- malformed access key IDs are rejected ----


@pytest.mark.parametrize(
    "access_key_id",
    [
        MULTILINE_ACCESS_KEY_ID,  # embedded newline
        "AKIAIOSFODNN7EXAMPLE\n",  # trailing newline
        "AKIAIOSFODNN7EXAMPLE\r\nsecond-line",  # embedded CRLF
        "AKIA-IOSF-ODNN",  # hyphen not permitted
        "SHORT",  # below the minimum length
        "A" * 129,  # above the maximum length
        "",  # empty
    ],
)
def test_malformed_access_key_id_rejected(capsys, access_key_id):
    with pytest.raises(SystemExit):
        _build(access_key_id, VALID_SESSION_TOKEN)
    _, err = capsys.readouterr()
    assert "accessKeyId" in err
    assert "malformed" in err
    # The credential value must never be echoed into stderr / logs.
    if access_key_id:
        assert access_key_id not in err


# ---- malformed session tokens are rejected ----


@pytest.mark.parametrize(
    "session_token",
    [
        "FAKEtoken\nsecond-line",  # embedded newline
        "FAKEtoken\n",  # trailing newline
        "FAKEtoken\r\nsecond-line",  # embedded CRLF
        "FAKE token",  # whitespace
        "FAKEtoken\twith-tab",  # control character
    ],
)
def test_malformed_session_token_rejected(capsys, session_token):
    with pytest.raises(SystemExit):
        _build(VALID_ACCESS_KEY_ID, session_token)
    _, err = capsys.readouterr()
    assert "sessionToken" in err
    assert "malformed" in err
    assert session_token not in err
