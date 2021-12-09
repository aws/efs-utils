# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.

import logging
from collections import namedtuple

import mount_efs
import pytest
from botocore.exceptions import ProfileNotFound
from mock import MagicMock

from .. import utils

try:
    import ConfigParser
except ImportError:
    from configparser import ConfigParser

try:
    from urllib2 import URLError, HTTPError
except ImportError:
    from urllib.error import URLError, HTTPError


DEFAULT_REGION = "us-east-1"
ACCESS_KEY_ID_VAL = "FAKE_AWS_ACCESS_KEY_ID"
SECRET_ACCESS_KEY_VAL = "FAKE_AWS_SECRET_ACCESS_KEY"
SESSION_TOKEN_VAL = "FAKE_SESSION_TOKEN"


def get_config(
    config_section=mount_efs.CONFIG_SECTION, config_item=None, config_item_value=None
):
    try:
        config = ConfigParser.SafeConfigParser()
    except AttributeError:
        config = ConfigParser()
    if config_section:
        config.add_section(config_section)
        if config_item and config_item_value is not None:
            config.set(config_section, config_item, config_item_value)
    return config


def test_is_instance_metadata_url_helper():
    assert False == mount_efs.is_instance_metadata_url(mount_efs.ECS_TASK_METADATA_API)
    assert True == mount_efs.is_instance_metadata_url(
        mount_efs.INSTANCE_METADATA_TOKEN_URL
    )
    assert True == mount_efs.is_instance_metadata_url(
        mount_efs.INSTANCE_METADATA_SERVICE_URL
    )
    assert True == mount_efs.is_instance_metadata_url(mount_efs.INSTANCE_IAM_URL)


def _test_get_boolean_config_item_in_config_file_helper(
    config, config_section, config_item, default_value, expected_value
):
    assert expected_value == mount_efs.get_boolean_config_item_value(
        config, config_section, config_item, default_value
    )


def test_get_true_boolean_config_item_in_config_file():
    config_section = mount_efs.CONFIG_SECTION
    config_item = mount_efs.FALLBACK_TO_MOUNT_TARGET_IP_ADDRESS_ITEM
    config = get_config(config_section, config_item, "true")
    assert True == mount_efs.get_boolean_config_item_value(
        config, config_section, config_item, True
    )
    assert True == mount_efs.get_boolean_config_item_value(
        config, config_section, config_item, False
    )


def test_get_false_boolean_config_item_in_config_file():
    config_section = mount_efs.CONFIG_SECTION
    config_item = mount_efs.FALLBACK_TO_MOUNT_TARGET_IP_ADDRESS_ITEM
    config = get_config(config_section, config_item, "false")
    assert False == mount_efs.get_boolean_config_item_value(
        config, config_section, config_item, True
    )
    assert False == mount_efs.get_boolean_config_item_value(
        config, config_section, config_item, False
    )


def test_get_default_boolean_config_item_not_in_config_file(capsys):
    config_section = mount_efs.CONFIG_SECTION
    config_item = mount_efs.FALLBACK_TO_MOUNT_TARGET_IP_ADDRESS_ITEM
    config = get_config()

    assert True == mount_efs.get_boolean_config_item_value(
        config, config_section, config_item, True
    )
    out, _ = capsys.readouterr()
    assert "does not have" in out
    assert "item in section" in out

    assert False == mount_efs.get_boolean_config_item_value(
        config, config_section, config_item, False
    )
    out, _ = capsys.readouterr()
    assert "does not have" in out
    assert "item in section" in out

    assert True == mount_efs.get_boolean_config_item_value(
        config, config_section, config_item, True, emit_warning_message=False
    )
    out, _ = capsys.readouterr()
    assert "does not have" not in out
    assert "item in section" not in out

    assert False == mount_efs.get_boolean_config_item_value(
        config, config_section, config_item, False, emit_warning_message=False
    )
    out, _ = capsys.readouterr()
    assert "does not have" not in out
    assert "item in section" not in out


def test_get_default_boolean_config_section_not_in_config_file(capsys):
    config_section = "random"
    config_item = mount_efs.FALLBACK_TO_MOUNT_TARGET_IP_ADDRESS_ITEM
    config = get_config()

    assert True == mount_efs.get_boolean_config_item_value(
        config, config_section, config_item, True
    )
    out, _ = capsys.readouterr()
    assert "does not have section" in out

    assert False == mount_efs.get_boolean_config_item_value(
        config, config_section, config_item, False
    )
    out, _ = capsys.readouterr()
    assert "does not have section" in out

    assert True == mount_efs.get_boolean_config_item_value(
        config, config_section, config_item, True, emit_warning_message=False
    )
    out, _ = capsys.readouterr()
    assert "does not have section" not in out

    assert False == mount_efs.get_boolean_config_item_value(
        config, config_section, config_item, False, emit_warning_message=False
    )
    out, _ = capsys.readouterr()
    assert "does not have section" not in out


def test_fetch_ec2_metadata_token_disabled_default_value():
    config = get_config()
    assert False == mount_efs.fetch_ec2_metadata_token_disabled(config)


def test_url_request_helper_does_not_fetch_metadata_token_due_to_token_fetch_disabled_in_config_file(
    mocker,
):
    config_section = mount_efs.CONFIG_SECTION
    config_item = mount_efs.DISABLE_FETCH_EC2_METADATA_TOKEN_ITEM
    config = get_config(config_section, config_item, "true")
    get_aws_ec2_metadata_token_mock = mocker.patch(
        "mount_efs.get_aws_ec2_metadata_token"
    )
    url_open_mock = mocker.patch("mount_efs.urlopen")
    mount_efs.url_request_helper(
        config, mount_efs.INSTANCE_METADATA_SERVICE_URL, "", ""
    )
    utils.assert_not_called(get_aws_ec2_metadata_token_mock)
    utils.assert_called(url_open_mock)


def test_url_request_helper_does_not_fetch_metadata_token_due_to_url_not_instance_metadata_service(
    mocker,
):
    config_section = mount_efs.CONFIG_SECTION
    config_item = mount_efs.DISABLE_FETCH_EC2_METADATA_TOKEN_ITEM
    config = get_config(config_section, config_item, "false")
    get_aws_ec2_metadata_token_mock = mocker.patch(
        "mount_efs.get_aws_ec2_metadata_token"
    )
    url_open_mock = mocker.patch("mount_efs.urlopen")
    mount_efs.url_request_helper(config, mount_efs.ECS_TASK_METADATA_API, "", "")
    utils.assert_not_called(get_aws_ec2_metadata_token_mock)
    utils.assert_called(url_open_mock)


def test_url_request_helper_fetch_metadata_token_config_item_present(mocker):
    config_section = mount_efs.CONFIG_SECTION
    config_item = mount_efs.DISABLE_FETCH_EC2_METADATA_TOKEN_ITEM
    config = get_config(config_section, config_item, "false")
    get_aws_ec2_metadata_token_mock = mocker.patch(
        "mount_efs.get_aws_ec2_metadata_token", return_value="ABCDEFG="
    )
    url_open_mock = mocker.patch("mount_efs.urlopen")
    mount_efs.url_request_helper(
        config, mount_efs.INSTANCE_METADATA_SERVICE_URL, "", ""
    )
    utils.assert_called(get_aws_ec2_metadata_token_mock)
    utils.assert_called(url_open_mock)


def test_url_request_helper_fetch_metadata_token_config_item_not_present(mocker):
    config = get_config()
    get_aws_ec2_metadata_token_mock = mocker.patch(
        "mount_efs.get_aws_ec2_metadata_token", return_value="ABCDEFG="
    )
    url_open_mock = mocker.patch("mount_efs.urlopen")
    mount_efs.url_request_helper(
        config, mount_efs.INSTANCE_METADATA_SERVICE_URL, "", ""
    )
    utils.assert_called(get_aws_ec2_metadata_token_mock)
    utils.assert_called(url_open_mock)


def test_url_request_helper_unauthorized_error(mocker, caplog):
    caplog.set_level(logging.WARNING)

    config_section = mount_efs.CONFIG_SECTION
    config_item = mount_efs.DISABLE_FETCH_EC2_METADATA_TOKEN_ITEM
    config = get_config(config_section, config_item, "true")

    get_aws_ec2_metadata_token_mock = mocker.patch(
        "mount_efs.get_aws_ec2_metadata_token"
    )
    url_open_mock = mocker.patch(
        "mount_efs.urlopen",
        side_effect=HTTPError("url", 401, "Unauthorized", None, None),
    )
    resp = mount_efs.url_request_helper(
        config, mount_efs.INSTANCE_METADATA_SERVICE_URL, "", ""
    )

    assert None == resp
    utils.assert_called(url_open_mock)
    utils.assert_not_called(get_aws_ec2_metadata_token_mock)

    assert "Unauthorized request" in [rec.message for rec in caplog.records][0]
    assert (
        "ec2 metadata token is disabled" in [rec.message for rec in caplog.records][0]
    )


def test_get_botocore_client_use_awsprofile(mocker):
    config = get_config()
    get_target_region_mock = mocker.patch(
        "mount_efs.get_target_region", return_value=DEFAULT_REGION
    )
    mount_efs.BOTOCORE_PRESENT = True
    boto_session_mock = MagicMock()
    boto_session_mock.set_config_variable.return_value = None
    boto_session_mock.create_client.return_value = "fake-client"
    mocker.patch("botocore.session.get_session", return_value=boto_session_mock)

    client = mount_efs.get_botocore_client(config, "efs", {"awsprofile": "test"})

    assert client == "fake-client"
    boto_session_mock.set_config_variable.assert_called_once()
    utils.assert_called(get_target_region_mock)


def test_get_botocore_client_use_awsprofile_profile_not_found(mocker, capsys):
    config = get_config()
    get_target_region_mock = mocker.patch(
        "mount_efs.get_target_region", return_value=DEFAULT_REGION
    )
    mount_efs.BOTOCORE_PRESENT = True
    boto_session_mock = MagicMock()
    boto_session_mock.set_config_variable.return_value = None
    boto_session_mock.create_client.side_effect = [
        ProfileNotFound(profile="test_profile")
    ]
    mocker.patch("botocore.session.get_session", return_value=boto_session_mock)

    with pytest.raises(SystemExit) as ex:
        mount_efs.get_botocore_client(config, "efs", {"awsprofile": "test-profile"})

    assert 0 != ex.value.code

    out, err = capsys.readouterr()

    assert "could not be found" in err

    boto_session_mock.set_config_variable.assert_called_once()
    utils.assert_called(get_target_region_mock)


def test_get_botocore_client_botocore_not_present(mocker):
    config = get_config()
    get_target_region_mock = mocker.patch(
        "mount_efs.get_target_region", return_value=DEFAULT_REGION
    )
    mount_efs.BOTOCORE_PRESENT = False
    boto_session_mock = MagicMock()
    mocker.patch("botocore.session.get_session", return_value=boto_session_mock)

    client = mount_efs.get_botocore_client(config, "efs", {})

    assert client == None
    boto_session_mock.assert_not_called()
    utils.assert_not_called(get_target_region_mock)


def test_get_botocore_client_botocore_present(mocker):
    config = get_config()
    get_target_region_mock = mocker.patch(
        "mount_efs.get_target_region", return_value=DEFAULT_REGION
    )
    mount_efs.BOTOCORE_PRESENT = True
    boto_session_mock = MagicMock()
    boto_session_mock.set_config_variable.return_value = None
    boto_session_mock.create_client.return_value = "fake-client"
    mocker.patch("botocore.session.get_session", return_value=boto_session_mock)

    client = mount_efs.get_botocore_client(config, "efs", {})

    assert client == "fake-client"
    boto_session_mock.set_config_variable.assert_not_called()
    boto_session_mock.create_client.assert_called_once()
    utils.assert_called(get_target_region_mock)


def test_get_assumed_profile_credentials_via_botocore_botocore_not_present(mocker):
    expected_credentials = {"AccessKeyId": None, "SecretAccessKey": None, "Token": None}
    mount_efs.BOTOCORE_PRESENT = False

    boto_session_mock = MagicMock()
    boto_session_mock.set_config_variable.return_value = None
    mocker.patch("botocore.session.get_session", return_value=boto_session_mock)

    credentials = mount_efs.botocore_credentials_helper("test_profile")
    assert credentials == expected_credentials

    boto_session_mock.assert_not_called()


def test_get_assumed_profile_credentials_via_botocore_botocore_present(mocker):
    expected_credentials = {
        "AccessKeyId": ACCESS_KEY_ID_VAL,
        "SecretAccessKey": SECRET_ACCESS_KEY_VAL,
        "Token": SESSION_TOKEN_VAL,
    }
    mount_efs.BOTOCORE_PRESENT = True

    boto_session_mock = MagicMock()
    boto_session_mock.set_config_variable.return_value = None

    ReadOnlyCredentials = namedtuple(
        "ReadOnlyCredentials", ["access_key", "secret_key", "token"]
    )
    frozen_credentials = ReadOnlyCredentials(
        ACCESS_KEY_ID_VAL, SECRET_ACCESS_KEY_VAL, SESSION_TOKEN_VAL
    )

    get_credential_session_mock = MagicMock()
    boto_session_mock.get_credentials.return_value = get_credential_session_mock
    get_credential_session_mock.get_frozen_credentials.return_value = frozen_credentials

    mocker.patch("botocore.session.get_session", return_value=boto_session_mock)

    credentials = mount_efs.botocore_credentials_helper("test_profile")
    assert credentials == expected_credentials

    boto_session_mock.set_config_variable.assert_called_once()
    boto_session_mock.get_credentials.assert_called_once()
    get_credential_session_mock.get_frozen_credentials.assert_called_once()


def test_get_assumed_profile_credentials_via_botocore_botocore_present_profile_not_found(
    mocker, capsys
):
    mount_efs.BOTOCORE_PRESENT = True

    boto_session_mock = MagicMock()
    boto_session_mock.set_config_variable.return_value = None

    boto_session_mock.get_credentials.side_effect = [
        ProfileNotFound(profile="test_profile")
    ]

    mocker.patch("botocore.session.get_session", return_value=boto_session_mock)

    with pytest.raises(SystemExit) as ex:
        mount_efs.botocore_credentials_helper("test_profile")

    assert 0 != ex.value.code

    out, err = capsys.readouterr()

    assert "could not be found" in err

    boto_session_mock.set_config_variable.assert_called_once()
    boto_session_mock.get_credentials.assert_called_once()
