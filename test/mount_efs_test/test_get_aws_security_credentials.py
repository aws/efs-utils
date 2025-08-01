# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.

import json
import logging
import os
import socket

import pytest

import mount_efs

from .. import utils

try:
    import ConfigParser
except ImportError:
    from configparser import ConfigParser

try:
    from urllib2 import HTTPError
except ImportError:
    from urllib.error import HTTPError


ACCESS_KEY_ID_KEY = "aws_access_key_id"
SECRET_ACCESS_KEY_KEY = "aws_secret_access_key"
SESSION_TOKEN_KEY = "aws_session_token"
ACCESS_KEY_ID_VAL = "FAKE_AWS_ACCESS_KEY_ID"
SECRET_ACCESS_KEY_VAL = "FAKE_AWS_SECRET_ACCESS_KEY"
SESSION_TOKEN_VAL = "FAKE_SESSION_TOKEN"
WRONG_ACCESS_KEY_ID_VAL = "WRONG_AWS_ACCESS_KEY_ID"
WRONG_SECRET_ACCESS_KEY_VAL = "WRONG_AWS_SECRET_ACCESS_KEY"
WRONG_SESSION_TOKEN_VAL = "WRONG_SESSION_TOKEN"

AWS_CONFIG_FILE = "fake_aws_config"
DEFAULT_PROFILE = "DEFAULT"
AWSPROFILE = "test_profile"
AWSCREDSURI = "/v2/credentials/{uuid}"

WEB_IDENTITY_ROLE_ARN = "FAKE_ROLE_ARN"
WEB_IDENTITY_TOKEN_FILE = "WEB_IDENTITY_TOKEN_FILE"

AWS_CONTAINER_CREDS_FULL_URI_ENV = "AWS_CONTAINER_CREDENTIALS_FULL_URI"
AWS_CONTAINER_AUTH_TOKEN_FILE_ENV = "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"
POD_IDENTITY_CREDS_URI = "http://169.254.170.23/v1/credentials"
POD_IDENTITY_TOKEN_FILE = (
    "/var/run/secrets/pods.eks.amazonaws.com/serviceaccount/eks-pod-identity-token"
)


class MockHeaders(object):
    def __init__(self, content_charset=None):
        self.content_charset = content_charset

    def get_content_charset(self):
        return self.content_charset


class MockUrlLibResponse(object):
    def __init__(self, code=200, data={}, headers=MockHeaders()):
        self.code = code
        self.data = data
        self.headers = headers

    def getcode(self):
        return self.code

    def read(self):
        return self.data


@pytest.fixture(autouse=True)
def setup(mocker):
    mocker.patch("os.path.expanduser")


def get_fake_aws_config_file(tmpdir):
    return os.path.join(str(tmpdir), AWS_CONFIG_FILE)


def get_fake_config(add_test_profile=False):
    try:
        config = ConfigParser.SafeConfigParser()
    except AttributeError:
        config = ConfigParser()

    if add_test_profile:
        config.add_section(AWSPROFILE)

    return config


def test_get_aws_security_credentials_config_or_creds_file_found_creds_found_without_token_with_awsprofile(
    mocker,
):
    config = get_fake_config()
    file_helper_resp = {
        "AccessKeyId": ACCESS_KEY_ID_VAL,
        "SecretAccessKey": SECRET_ACCESS_KEY_VAL,
        "Token": None,
    }

    mocker.patch.dict(os.environ, {})
    mocker.patch("os.path.exists", return_value=True)
    mocker.patch("mount_efs.credentials_file_helper", return_value=file_helper_resp)

    credentials, credentials_source = mount_efs.get_aws_security_credentials(
        config, True, "us-east-1", "test_profile"
    )

    assert credentials["AccessKeyId"] == ACCESS_KEY_ID_VAL
    assert credentials["SecretAccessKey"] == SECRET_ACCESS_KEY_VAL
    assert credentials["Token"] is None
    assert credentials_source == "credentials:test_profile"


def test_get_aws_security_credentials_config_or_creds_file_found_creds_found_with_token_with_awsprofile(
    mocker,
):
    config = get_fake_config()
    file_helper_resp = {
        "AccessKeyId": ACCESS_KEY_ID_VAL,
        "SecretAccessKey": SECRET_ACCESS_KEY_VAL,
        "Token": SESSION_TOKEN_VAL,
    }

    mocker.patch.dict(os.environ, {})
    mocker.patch("os.path.exists", return_value=True)
    mocker.patch("mount_efs.credentials_file_helper", return_value=file_helper_resp)

    credentials, credentials_source = mount_efs.get_aws_security_credentials(
        config, True, "us-east-1", "test_profile"
    )

    assert credentials["AccessKeyId"] == ACCESS_KEY_ID_VAL
    assert credentials["SecretAccessKey"] == SECRET_ACCESS_KEY_VAL
    assert credentials["Token"] is SESSION_TOKEN_VAL
    assert credentials_source == "credentials:test_profile"


def test_get_aws_security_credentials_do_not_use_iam():
    config = get_fake_config()
    credentials, credentials_source = mount_efs.get_aws_security_credentials(
        config, False, "us-east-1", "test_profile"
    )

    assert not credentials
    assert not credentials_source


def _test_get_aws_security_credentials_get_ecs_from_env_url(mocker):
    config = get_fake_config()
    mocker.patch.dict(os.environ, {})
    mocker.patch("os.path.exists", return_value=False)
    # Mock new credential functions to return None so they don't interfere
    mocker.patch("mount_efs.get_aws_security_credentials_from_cloudshell", return_value=(None, None))
    mocker.patch("mount_efs.get_aws_security_credentials_from_env_vars", return_value=(None, None))
    response = json.dumps(
        {
            "AccessKeyId": ACCESS_KEY_ID_VAL,
            "Expiration": "EXPIRATION_DATE",
            "RoleArn": "TASK_ROLE_ARN",
            "SecretAccessKey": SECRET_ACCESS_KEY_VAL,
            "Token": SESSION_TOKEN_VAL,
        }
    )
    mocker.patch.dict(
        os.environ, {"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "fake_uri"}
    )

    mocker.patch("mount_efs.urlopen", return_value=MockUrlLibResponse(data=response))

    credentials, credentials_source = mount_efs.get_aws_security_credentials(
        config, True, "us-east-1", None
    )

    assert credentials["AccessKeyId"] == ACCESS_KEY_ID_VAL
    assert credentials["SecretAccessKey"] == SECRET_ACCESS_KEY_VAL
    assert credentials["Token"] == SESSION_TOKEN_VAL
    assert credentials_source == "ecs:fake_uri"


def test_get_aws_security_credentials_get_ecs_from_option_url(mocker):
    config = get_fake_config()
    response = json.dumps(
        {
            "AccessKeyId": ACCESS_KEY_ID_VAL,
            "Expiration": "EXPIRATION_DATE",
            "RoleArn": "TASK_ROLE_ARN",
            "SecretAccessKey": SECRET_ACCESS_KEY_VAL,
            "Token": SESSION_TOKEN_VAL,
        }
    )
    mocker.patch("mount_efs.urlopen", return_value=MockUrlLibResponse(data=response))
    credentials, credentials_source = mount_efs.get_aws_security_credentials(
        config, True, "us-east-1", None, AWSCREDSURI
    )

    assert credentials["AccessKeyId"] == ACCESS_KEY_ID_VAL
    assert credentials["SecretAccessKey"] == SECRET_ACCESS_KEY_VAL
    assert credentials["Token"] == SESSION_TOKEN_VAL
    assert credentials_source == "ecs:" + AWSCREDSURI


def test_get_aws_security_credentials_get_instance_metadata_role_name_str(mocker):
    _test_get_aws_security_credentials_get_instance_metadata_role_name(
        mocker, is_name_str=True
    )


def test_get_aws_security_credentials_get_instance_metadata_role_name_str_with_token_fetch_error(
    mocker,
):
    for token_effect in [
        socket.timeout,
        HTTPError("url", 405, "Now Allowed", None, None),
        Exception("Unknown Error"),
    ]:
        _test_get_aws_security_credentials_get_instance_metadata_role_name(
            mocker,
            is_name_str=True,
            token_effects=[
                token_effect
                for _ in range(
                    0, mount_efs.DEFAULT_GET_AWS_EC2_METADATA_TOKEN_RETRY_COUNT
                )
            ],
        )


def test_get_aws_security_credentials_get_instance_metadata_role_name_bytes(mocker):
    _test_get_aws_security_credentials_get_instance_metadata_role_name(
        mocker, is_name_str=False
    )


def test_get_aws_security_credentials_get_instance_metadata_role_name_bytes_with_token_fetch_error(
    mocker,
):
    for token_effect in [
        socket.timeout,
        HTTPError("url", 405, "Now Allowed", None, None),
        Exception("Unknown Error"),
    ]:
        _test_get_aws_security_credentials_get_instance_metadata_role_name(
            mocker,
            is_name_str=False,
            token_effects=[
                token_effect
                for _ in range(
                    0, mount_efs.DEFAULT_GET_AWS_EC2_METADATA_TOKEN_RETRY_COUNT
                )
            ],
        )


def _test_get_aws_security_credentials_get_instance_metadata_role_name(
    mocker, is_name_str=True, token_effects=[MockUrlLibResponse(data="ABCDEFG==")]
):
    config = get_fake_config()
    mocker.patch.dict(os.environ, {})
    mocker.patch("os.path.exists", return_value=False)
    # Mock new credential functions to return None so they don't interfere
    mocker.patch("mount_efs.get_aws_security_credentials_from_cloudshell", return_value=(None, None))
    mocker.patch("mount_efs.get_aws_security_credentials_from_env_vars", return_value=(None, None))
    response = json.dumps(
        {
            "Code": "Success",
            "LastUpdated": "2019-10-25T14:41:42Z",
            "Type": "AWS-HMAC",
            "AccessKeyId": ACCESS_KEY_ID_VAL,
            "SecretAccessKey": SECRET_ACCESS_KEY_VAL,
            "Token": SESSION_TOKEN_VAL,
            "Expiration": "2019-10-25T21:17:24Z",
        }
    )
    if is_name_str:
        role_name_data = b"FAKE_IAM_ROLE_NAME"
    else:
        role_name_data = "FAKE_IAM_ROLE_NAME"

    side_effects = (
        token_effects
        + [MockUrlLibResponse(data=role_name_data)]
        + token_effects
        + [MockUrlLibResponse(data=response)]
    )
    mocker.patch("mount_efs.urlopen", side_effect=side_effects)

    credentials, credentials_source = mount_efs.get_aws_security_credentials(
        config, True, "us-east-1", None
    )

    assert credentials["AccessKeyId"] == ACCESS_KEY_ID_VAL
    assert credentials["SecretAccessKey"] == SECRET_ACCESS_KEY_VAL
    assert credentials["Token"] == SESSION_TOKEN_VAL
    assert credentials_source == "metadata:"


def test_get_aws_security_credentials_no_credentials_found(mocker, capsys):
    config = get_fake_config()
    mocker.patch.dict(os.environ, {})
    mocker.patch("os.path.exists", return_value=False)
    # Mock new credential functions to return None so they don't interfere
    mocker.patch("mount_efs.get_aws_security_credentials_from_cloudshell", return_value=(None, None))
    mocker.patch("mount_efs.get_aws_security_credentials_from_env_vars", return_value=(None, None))
    mocker.patch("mount_efs.urlopen")

    with pytest.raises(SystemExit) as ex:
        mount_efs.get_aws_security_credentials(config, True, "us-east-1", None)

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert (
        "AWS Access Key ID and Secret Access Key are not found in AWS credentials file"
        in err
    )
    assert (
        "from ECS credentials relative uri, or from the instance security credentials service"
        in err
    )


def test_get_aws_security_credentials_credentials_not_found_in_files_and_botocore_not_present(
    mocker, capsys
):
    config = get_fake_config()
    mocker.patch.dict(os.environ, {})
    mocker.patch("os.path.exists", return_value=False)
    mocker.patch("mount_efs.urlopen")
    mount_efs.BOTOCORE_PRESENT = False

    with pytest.raises(SystemExit) as ex:
        mount_efs.get_aws_security_credentials(config, True, "us-east-1", "default")

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert "AWS security credentials not found in" in err
    assert "under named profile [default]" in err


def test_get_aws_security_credentials_botocore_present_get_assumed_profile_credentials(
    mocker,
):
    config = get_fake_config()
    mocker.patch.dict(os.environ, {})
    mocker.patch("os.path.exists", return_value=False)
    mocker.patch("mount_efs.urlopen")
    mount_efs.BOTOCORE_PRESENT = True

    botocore_helper_resp = {
        "AccessKeyId": ACCESS_KEY_ID_VAL,
        "SecretAccessKey": SECRET_ACCESS_KEY_VAL,
        "Token": SESSION_TOKEN_VAL,
    }
    botocore_get_assumed_profile_credentials_mock = mocker.patch(
        "mount_efs.botocore_credentials_helper", return_value=botocore_helper_resp
    )

    credentials, credentials_source = mount_efs.get_aws_security_credentials(
        config, True, "us-east-1", awsprofile="test-profile"
    )
    assert credentials["AccessKeyId"] == ACCESS_KEY_ID_VAL
    assert credentials["SecretAccessKey"] == SECRET_ACCESS_KEY_VAL
    assert credentials["Token"] == SESSION_TOKEN_VAL
    assert credentials_source == "named_profile:test-profile"
    utils.assert_called(botocore_get_assumed_profile_credentials_mock)


def test_get_aws_security_credentials_credentials_not_found_in_aws_creds_uri(
    mocker, capsys
):
    config = get_fake_config()
    mocker.patch("mount_efs.urlopen")

    with pytest.raises(SystemExit) as ex:
        mount_efs.get_aws_security_credentials(
            config, True, "us-east-1", "default", AWSCREDSURI
        )

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert "Unsuccessful retrieval of AWS security credentials at" in err


def test_credentials_file_helper_awsprofile_found_with_token(tmpdir):
    fake_file = get_fake_aws_config_file(tmpdir)
    config = get_fake_config(add_test_profile=True)

    config.set(DEFAULT_PROFILE, ACCESS_KEY_ID_KEY, WRONG_ACCESS_KEY_ID_VAL)
    config.set(DEFAULT_PROFILE, SECRET_ACCESS_KEY_KEY, WRONG_SECRET_ACCESS_KEY_VAL)
    config.set(DEFAULT_PROFILE, SESSION_TOKEN_KEY, WRONG_SESSION_TOKEN_VAL)
    config.set(AWSPROFILE, ACCESS_KEY_ID_KEY, ACCESS_KEY_ID_VAL)
    config.set(AWSPROFILE, SECRET_ACCESS_KEY_KEY, SECRET_ACCESS_KEY_VAL)
    config.set(AWSPROFILE, SESSION_TOKEN_KEY, SESSION_TOKEN_VAL)
    with open(fake_file, "w") as f:
        config.write(f)

    credentials = mount_efs.credentials_file_helper(fake_file, AWSPROFILE)

    assert credentials["AccessKeyId"] == ACCESS_KEY_ID_VAL
    assert credentials["SecretAccessKey"] == SECRET_ACCESS_KEY_VAL
    assert credentials["Token"] == SESSION_TOKEN_VAL


def test_credentials_file_helper_awsprofile_found_without_token(caplog, tmpdir):
    caplog.set_level(logging.DEBUG)
    fake_file = get_fake_aws_config_file(tmpdir)
    config = get_fake_config(add_test_profile=True)

    config.set(DEFAULT_PROFILE, ACCESS_KEY_ID_KEY, WRONG_ACCESS_KEY_ID_VAL)
    config.set(DEFAULT_PROFILE, SECRET_ACCESS_KEY_KEY, WRONG_SECRET_ACCESS_KEY_VAL)
    config.set(AWSPROFILE, ACCESS_KEY_ID_KEY, ACCESS_KEY_ID_VAL)
    config.set(AWSPROFILE, SECRET_ACCESS_KEY_KEY, SECRET_ACCESS_KEY_VAL)
    with open(fake_file, "w") as f:
        config.write(f)

    credentials = mount_efs.credentials_file_helper(fake_file, awsprofile=AWSPROFILE)

    assert credentials["AccessKeyId"] == ACCESS_KEY_ID_VAL
    assert credentials["SecretAccessKey"] == SECRET_ACCESS_KEY_VAL
    assert credentials["Token"] is None
    assert "aws_session_token" in [rec.message for rec in caplog.records][0]


def test_credentials_file_helper_awsprofile_not_found(caplog, tmpdir):
    caplog.set_level(logging.DEBUG)
    fake_file = os.path.join(str(tmpdir), "fake_aws_config")
    tmpdir.join("fake_aws_config").write("")

    credentials = mount_efs.credentials_file_helper(fake_file, "default")

    assert credentials["AccessKeyId"] is None
    assert credentials["SecretAccessKey"] is None
    assert credentials["Token"] is None

    assert (
        "No [default] section found in config file %s" % fake_file
        in [rec.message for rec in caplog.records][0]
    )


def test_credentials_file_helper_awsprofile_found_missing_key(caplog, tmpdir):
    caplog.set_level(logging.DEBUG)
    fake_file = os.path.join(str(tmpdir), "fake_aws_config")
    tmpdir.join("fake_aws_config").write(
        "[default]\naws_access_key_id = WRONG_AWS_ACCESS_KEY_ID\n"
        "aws_secret_access_key = WRONG_AWS_SECRET_ACCESS_KEY\n\n"
        "[test_profile]\naws_secret_access_key = FAKE_AWS_SECRET_ACCESS_KEY"
    )

    credentials = mount_efs.credentials_file_helper(fake_file, "test_profile")

    assert credentials["AccessKeyId"] is None
    assert credentials["SecretAccessKey"] is None
    assert credentials["Token"] is None

    assert (
        "aws_access_key_id or aws_secret_access_key not found in %s under named profile [test_profile]"
        % fake_file
        in [rec.message for rec in caplog.records][0]
    )


def test_get_aws_security_credentials_from_webidentity_passed_in_both_params(mocker):
    config = get_fake_config()
    creds_mocked = {
        "AccessKeyId": ACCESS_KEY_ID_VAL,
        "SecretAccessKey": SECRET_ACCESS_KEY_VAL,
        "Token": SESSION_TOKEN_VAL,
    }
    credentials_source_mocked = "webidentity:" + ",".join(
        [WEB_IDENTITY_ROLE_ARN, WEB_IDENTITY_TOKEN_FILE]
    )

    mocker.patch.dict(os.environ, {})
    mocker.patch(
        "mount_efs.get_aws_security_credentials_from_webidentity",
        return_value=(creds_mocked, credentials_source_mocked),
    )

    credentials, credentials_source = mount_efs.get_aws_security_credentials(
        config,
        True,
        "us-east-1",
        jwt_path=WEB_IDENTITY_TOKEN_FILE,
        role_arn=WEB_IDENTITY_ROLE_ARN,
    )

    assert credentials["AccessKeyId"] == ACCESS_KEY_ID_VAL
    assert credentials["SecretAccessKey"] == SECRET_ACCESS_KEY_VAL
    assert credentials["Token"] == SESSION_TOKEN_VAL
    assert credentials_source == credentials_source_mocked


def test_get_aws_security_credentials_from_webidentity_passed_in_one_param(
    mocker, capsys
):
    config = get_fake_config(False)
    creds_mocked = {
        "AccessKeyId": ACCESS_KEY_ID_VAL,
        "SecretAccessKey": SECRET_ACCESS_KEY_VAL,
        "Token": SESSION_TOKEN_VAL,
    }
    credentials_source_mocked = "webidentity:" + ",".join(
        [WEB_IDENTITY_ROLE_ARN, WEB_IDENTITY_TOKEN_FILE]
    )

    mocker.patch.dict(os.environ, {})
    mocker.patch(
        "mount_efs.get_aws_security_credentials_from_webidentity",
        return_value=(creds_mocked, credentials_source_mocked),
    )
    mocker.patch("mount_efs.get_iam_role_name", return_value=None)

    with pytest.raises(SystemExit) as ex:
        mount_efs.get_aws_security_credentials(
            config, True, "us-east-1", jwt_path=WEB_IDENTITY_TOKEN_FILE
        )

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert (
        "AWS Access Key ID and Secret Access Key are not found in AWS credentials file"
        in err
    )
    assert (
        "from ECS credentials relative uri, or from the instance security credentials service"
        in err
    )


def test_get_aws_security_credentials_pod_identity(mocker):
    config = get_fake_config()
    token_content = "fake-token"
    response = json.dumps(
        {
            "AccessKeyId": ACCESS_KEY_ID_VAL,
            "SecretAccessKey": SECRET_ACCESS_KEY_VAL,
            "Token": SESSION_TOKEN_VAL,
        }
    )

    mocker.patch.dict(
        os.environ,
        {
            AWS_CONTAINER_CREDS_FULL_URI_ENV: POD_IDENTITY_CREDS_URI,
            AWS_CONTAINER_AUTH_TOKEN_FILE_ENV: POD_IDENTITY_TOKEN_FILE,
        },
    )

    mock_open = mocker.patch("builtins.open", mocker.mock_open(read_data=token_content))

    mocker.patch("mount_efs.url_request_helper", return_value=json.loads(response))
    mocker.patch("os.path.exists", return_value=False)
    mocker.patch("mount_efs.get_iam_role_name", return_value=None)

    credentials, credentials_source = mount_efs.get_aws_security_credentials(
        config, True, "us-east-1"
    )

    assert credentials["AccessKeyId"] == ACCESS_KEY_ID_VAL
    assert credentials["SecretAccessKey"] == SECRET_ACCESS_KEY_VAL
    assert credentials["Token"] == SESSION_TOKEN_VAL
    assert (
        credentials_source
        == f"podidentity:{POD_IDENTITY_CREDS_URI},{POD_IDENTITY_TOKEN_FILE}"
    )


def test_get_aws_security_credentials_pod_identity_invalid_token_file(mocker):
    config = get_fake_config()
    creds_uri = "http://169.254.170.23/v1/credentials"
    token_file = "/nonexistent/file"

    mocker.patch.dict(
        os.environ,
        {
            AWS_CONTAINER_CREDS_FULL_URI_ENV: creds_uri,
            AWS_CONTAINER_AUTH_TOKEN_FILE_ENV: token_file,
        },
    )

    mocker.patch("builtins.open", side_effect=IOError("File not found"))

    with pytest.raises(SystemExit) as ex:
        mount_efs.get_aws_security_credentials(config, True, "us-east-1")

    assert ex.value.code == 1


# Tests for CloudShell credential support
def test_get_aws_security_credentials_from_cloudshell_success(mocker):
    """Test successful CloudShell credential retrieval"""
    config = get_fake_config()
    token = "mock-token"
    credentials_response = {
        "AccessKeyId": ACCESS_KEY_ID_VAL,
        "SecretAccessKey": SECRET_ACCESS_KEY_VAL,
        "Token": SESSION_TOKEN_VAL,
        "LastUpdated": "1970-01-01T00:00:00Z",
        "Type": "",
        "Expiration": "2025-05-15T17:06:59Z",
        "Code": "Success"
    }
    
    # Mock token request
    mock_token_response = MockUrlLibResponse(data=token.encode('utf-8'))
    mocker.patch("mount_efs.urlopen", return_value=mock_token_response)
    
    # Mock credentials request
    mocker.patch("mount_efs.url_request_helper", return_value=credentials_response)
    
    credentials, credentials_source = mount_efs.get_aws_security_credentials_from_cloudshell(config, False)
    
    assert credentials == credentials_response
    assert credentials_source == "cloudshell"


def test_get_aws_security_credentials_from_cloudshell_token_failure(mocker):
    """Test CloudShell token request failure"""
    config = get_fake_config()
    
    # Mock token request failure
    mocker.patch("mount_efs.urlopen", side_effect=Exception("Connection refused"))
    
    credentials, credentials_source = mount_efs.get_aws_security_credentials_from_cloudshell(config, False)
    
    assert credentials is None
    assert credentials_source is None


def test_get_aws_security_credentials_from_cloudshell_credentials_failure(mocker):
    """Test CloudShell credentials request failure"""
    config = get_fake_config()
    token = "mock-token"
    
    # Mock successful token request
    mock_token_response = MockUrlLibResponse(data=token.encode('utf-8'))
    mocker.patch("mount_efs.urlopen", return_value=mock_token_response)
    
    # Mock credentials request failure
    mocker.patch("mount_efs.url_request_helper", return_value=None)
    
    credentials, credentials_source = mount_efs.get_aws_security_credentials_from_cloudshell(config, False)
    
    assert credentials is None
    assert credentials_source is None


def test_get_aws_security_credentials_from_cloudshell_invalid_credentials(mocker):
    """Test CloudShell with invalid credentials response"""
    config = get_fake_config()
    token = "mock-token"
    invalid_credentials = {
        "AccessKeyId": ACCESS_KEY_ID_VAL,
        # Missing SecretAccessKey and Token
        "LastUpdated": "1970-01-01T00:00:00Z",
    }
    
    # Mock token request
    mock_token_response = MockUrlLibResponse(data=token.encode('utf-8'))
    mocker.patch("mount_efs.urlopen", return_value=mock_token_response)
    
    # Mock credentials request with invalid response
    mocker.patch("mount_efs.url_request_helper", return_value=invalid_credentials)
    
    credentials, credentials_source = mount_efs.get_aws_security_credentials_from_cloudshell(config, False)
    
    assert credentials is None
    assert credentials_source is None


def test_get_aws_security_credentials_from_cloudshell_fatal_error(mocker):
    """Test CloudShell with fatal error flag"""
    config = get_fake_config()
    
    # Mock token request failure
    mocker.patch("mount_efs.urlopen", side_effect=Exception("Connection refused"))
    
    with pytest.raises(SystemExit) as ex:
        mount_efs.get_aws_security_credentials_from_cloudshell(config, True)
    
    assert ex.value.code == 1


# Tests for environment variable credential support
def test_get_aws_security_credentials_from_env_vars_success_with_token(mocker):
    """Test successful environment variable credential retrieval with session token"""
    mocker.patch.dict(os.environ, {
        "AWS_ACCESS_KEY_ID": ACCESS_KEY_ID_VAL,
        "AWS_SECRET_ACCESS_KEY": SECRET_ACCESS_KEY_VAL,
        "AWS_SESSION_TOKEN": SESSION_TOKEN_VAL
    })
    
    credentials, credentials_source = mount_efs.get_aws_security_credentials_from_env_vars()
    
    assert credentials["AccessKeyId"] == ACCESS_KEY_ID_VAL
    assert credentials["SecretAccessKey"] == SECRET_ACCESS_KEY_VAL
    assert credentials["Token"] == SESSION_TOKEN_VAL
    assert credentials_source == "environment"


def test_get_aws_security_credentials_from_env_vars_success_without_token(mocker):
    """Test successful environment variable credential retrieval without session token"""
    mocker.patch.dict(os.environ, {
        "AWS_ACCESS_KEY_ID": ACCESS_KEY_ID_VAL,
        "AWS_SECRET_ACCESS_KEY": SECRET_ACCESS_KEY_VAL
    })
    
    credentials, credentials_source = mount_efs.get_aws_security_credentials_from_env_vars()
    
    assert credentials["AccessKeyId"] == ACCESS_KEY_ID_VAL
    assert credentials["SecretAccessKey"] == SECRET_ACCESS_KEY_VAL
    assert credentials["Token"] is None
    assert credentials_source == "environment"


def test_get_aws_security_credentials_from_env_vars_missing_access_key(mocker):
    """Test environment variable credentials with missing access key"""
    mocker.patch.dict(os.environ, {
        "AWS_SECRET_ACCESS_KEY": SECRET_ACCESS_KEY_VAL,
        "AWS_SESSION_TOKEN": SESSION_TOKEN_VAL
    }, clear=True)
    
    credentials, credentials_source = mount_efs.get_aws_security_credentials_from_env_vars()
    
    assert credentials is None
    assert credentials_source is None


def test_get_aws_security_credentials_from_env_vars_missing_secret_key(mocker):
    """Test environment variable credentials with missing secret key"""
    mocker.patch.dict(os.environ, {
        "AWS_ACCESS_KEY_ID": ACCESS_KEY_ID_VAL,
        "AWS_SESSION_TOKEN": SESSION_TOKEN_VAL
    }, clear=True)
    
    credentials, credentials_source = mount_efs.get_aws_security_credentials_from_env_vars()
    
    assert credentials is None
    assert credentials_source is None


def test_get_aws_security_credentials_from_env_vars_no_env_vars(mocker):
    """Test environment variable credentials when no environment variables are set"""
    mocker.patch.dict(os.environ, {}, clear=True)
    
    credentials, credentials_source = mount_efs.get_aws_security_credentials_from_env_vars()
    
    assert credentials is None
    assert credentials_source is None


# Integration tests for the main credential function
def test_get_aws_security_credentials_cloudshell_integration(mocker):
    """Test that CloudShell credentials are used in the main credential chain"""
    config = get_fake_config()
    token = "mock-token"
    credentials_response = {
        "AccessKeyId": ACCESS_KEY_ID_VAL,
        "SecretAccessKey": SECRET_ACCESS_KEY_VAL,
        "Token": SESSION_TOKEN_VAL,
    }
    
    # Mock all preceding credential methods to fail
    mocker.patch.dict(os.environ, {}, clear=True)
    mocker.patch("os.path.exists", return_value=False)
    
    # Mock CloudShell success
    mock_token_response = MockUrlLibResponse(data=token.encode('utf-8'))
    mocker.patch("mount_efs.urlopen", return_value=mock_token_response)
    mocker.patch("mount_efs.url_request_helper", return_value=credentials_response)
    
    credentials, credentials_source = mount_efs.get_aws_security_credentials(
        config, True, "us-east-1"
    )
    
    assert credentials == credentials_response
    assert credentials_source == "cloudshell"


def test_get_aws_security_credentials_env_vars_integration(mocker):
    """Test that environment variable credentials are used in the main credential chain"""
    config = get_fake_config()
    
    # Mock all preceding credential methods to fail
    mocker.patch.dict(os.environ, {
        "AWS_ACCESS_KEY_ID": ACCESS_KEY_ID_VAL,
        "AWS_SECRET_ACCESS_KEY": SECRET_ACCESS_KEY_VAL,
        "AWS_SESSION_TOKEN": SESSION_TOKEN_VAL
    })
    mocker.patch("os.path.exists", return_value=False)
    
    # Mock CloudShell failure
    mocker.patch("mount_efs.urlopen", side_effect=Exception("Connection refused"))
    
    credentials, credentials_source = mount_efs.get_aws_security_credentials(
        config, True, "us-east-1"
    )
    
    assert credentials["AccessKeyId"] == ACCESS_KEY_ID_VAL
    assert credentials["SecretAccessKey"] == SECRET_ACCESS_KEY_VAL
    assert credentials["Token"] == SESSION_TOKEN_VAL
    assert credentials_source == "environment"
