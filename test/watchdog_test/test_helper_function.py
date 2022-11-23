# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.

import logging
import sys
import unittest
from collections import namedtuple
from unittest.mock import MagicMock, mock_open

from botocore.exceptions import ProfileNotFound

import mount_efs
import watchdog

from .. import utils

try:
    import ConfigParser
except ImportError:
    from configparser import ConfigParser

try:
    from urllib2 import HTTPError, URLError
except ImportError:
    from urllib.error import HTTPError, URLError


DEFAULT_REGION = "us-east-1"
ACCESS_KEY_ID_VAL = "FAKE_AWS_ACCESS_KEY_ID"
SECRET_ACCESS_KEY_VAL = "FAKE_AWS_SECRET_ACCESS_KEY"
SESSION_TOKEN_VAL = "FAKE_SESSION_TOKEN"
MACOS = "macOS"
AL2 = "Amazon Linux release 2"


def get_config(
    config_section=watchdog.CONFIG_SECTION, config_item=None, config_item_value=None
):
    try:
        config = ConfigParser.SafeConfigParser()
    except AttributeError:
        config = ConfigParser()
    if config_section:
        config.add_section(config_section)
        if config_item and config_item_value is not None:
            config.set(config_section, config_item, str(config_item_value))
    return config


def test_is_instance_metadata_url_helper():
    assert False == watchdog.is_instance_metadata_url(mount_efs.ECS_TASK_METADATA_API)
    assert True == watchdog.is_instance_metadata_url(
        mount_efs.INSTANCE_METADATA_TOKEN_URL
    )
    assert True == watchdog.is_instance_metadata_url(
        mount_efs.INSTANCE_METADATA_SERVICE_URL
    )
    assert True == watchdog.is_instance_metadata_url(mount_efs.INSTANCE_IAM_URL)


def _test_get_boolean_config_item_in_config_file_helper(
    config, config_section, config_item, default_value, expected_value
):
    assert expected_value == watchdog.get_boolean_config_item_value(
        config, config_section, config_item, default_value
    )


def test_get_true_boolean_config_item_in_config_file():
    config_section = watchdog.MOUNT_CONFIG_SECTION
    config_item = mount_efs.FALLBACK_TO_MOUNT_TARGET_IP_ADDRESS_ITEM
    config = get_config(config_section, config_item, "true")
    assert True == watchdog.get_boolean_config_item_value(
        config, config_section, config_item, True
    )
    assert True == watchdog.get_boolean_config_item_value(
        config, config_section, config_item, False
    )


def test_get_false_boolean_config_item_in_config_file():
    config_section = watchdog.MOUNT_CONFIG_SECTION
    config_item = mount_efs.FALLBACK_TO_MOUNT_TARGET_IP_ADDRESS_ITEM
    config = get_config(config_section, config_item, "false")
    assert False == watchdog.get_boolean_config_item_value(
        config, config_section, config_item, True
    )
    assert False == watchdog.get_boolean_config_item_value(
        config, config_section, config_item, False
    )


def test_get_default_true_boolean_config_item_not_in_config_file(capsys):
    config_section = watchdog.MOUNT_CONFIG_SECTION
    config_item = mount_efs.FALLBACK_TO_MOUNT_TARGET_IP_ADDRESS_ITEM
    config = get_config()

    assert True == watchdog.get_boolean_config_item_value(
        config, config_section, config_item, True, emit_warning_message=True
    )
    out, _ = capsys.readouterr()
    assert "does not have" in out

    assert False == watchdog.get_boolean_config_item_value(
        config, config_section, config_item, False, emit_warning_message=True
    )
    out, _ = capsys.readouterr()
    assert "does not have" in out

    assert True == watchdog.get_boolean_config_item_value(
        config,
        config_section,
        config_item,
        True,
    )
    out, _ = capsys.readouterr()
    assert "does not have" not in out
    assert "item in section" not in out

    assert False == watchdog.get_boolean_config_item_value(
        config,
        config_section,
        config_item,
        False,
    )
    out, _ = capsys.readouterr()
    assert "does not have" not in out
    assert "item in section" not in out


def test_get_default_boolean_config_section_not_in_config_file(capsys):
    config_section = "random"
    config_item = mount_efs.FALLBACK_TO_MOUNT_TARGET_IP_ADDRESS_ITEM
    config = get_config()

    assert True == watchdog.get_boolean_config_item_value(
        config, config_section, config_item, True, emit_warning_message=True
    )
    out, _ = capsys.readouterr()
    assert "does not have section" in out

    assert False == watchdog.get_boolean_config_item_value(
        config, config_section, config_item, False, emit_warning_message=True
    )
    out, _ = capsys.readouterr()
    assert "does not have section" in out

    assert True == watchdog.get_boolean_config_item_value(
        config,
        config_section,
        config_item,
        True,
    )
    out, _ = capsys.readouterr()
    assert "does not have section" not in out

    assert False == watchdog.get_boolean_config_item_value(
        config,
        config_section,
        config_item,
        False,
    )
    out, _ = capsys.readouterr()
    assert "does not have section" not in out


def test_fetch_ec2_metadata_token_disabled_default_value():
    config = get_config()
    assert False == watchdog.fetch_ec2_metadata_token_disabled(config)


def test_url_request_helper_does_not_fetch_metadata_token_due_to_token_fetch_disabled_in_config_file(
    mocker,
):
    config_section = watchdog.MOUNT_CONFIG_SECTION
    config_item = watchdog.DISABLE_FETCH_EC2_METADATA_TOKEN_ITEM
    config = get_config(config_section, config_item, "true")
    get_aws_ec2_metadata_token_mock = mocker.patch(
        "watchdog.get_aws_ec2_metadata_token"
    )
    url_open_mock = mocker.patch("watchdog.urlopen")
    watchdog.url_request_helper(config, mount_efs.INSTANCE_METADATA_SERVICE_URL, "", "")
    utils.assert_not_called(get_aws_ec2_metadata_token_mock)
    utils.assert_called(url_open_mock)


def test_url_request_helper_does_not_fetch_metadata_token_due_to_url_not_instance_metadata_service(
    mocker,
):
    config_section = watchdog.MOUNT_CONFIG_SECTION
    config_item = watchdog.DISABLE_FETCH_EC2_METADATA_TOKEN_ITEM
    config = get_config(config_section, config_item, "false")
    get_aws_ec2_metadata_token_mock = mocker.patch(
        "watchdog.get_aws_ec2_metadata_token"
    )
    url_open_mock = mocker.patch("watchdog.urlopen")
    watchdog.url_request_helper(config, mount_efs.ECS_TASK_METADATA_API, "", "")
    utils.assert_not_called(get_aws_ec2_metadata_token_mock)
    utils.assert_called(url_open_mock)


def test_url_request_helper_fetch_metadata_token_config_item_present(mocker):
    config_section = watchdog.MOUNT_CONFIG_SECTION
    config_item = watchdog.DISABLE_FETCH_EC2_METADATA_TOKEN_ITEM
    config = get_config(config_section, config_item, "false")
    get_aws_ec2_metadata_token_mock = mocker.patch(
        "watchdog.get_aws_ec2_metadata_token", return_value="ABCDEFG="
    )
    url_open_mock = mocker.patch("watchdog.urlopen")
    watchdog.url_request_helper(config, mount_efs.INSTANCE_METADATA_SERVICE_URL, "", "")
    utils.assert_called(get_aws_ec2_metadata_token_mock)
    utils.assert_called(url_open_mock)


def test_url_request_helper_fetch_metadata_token_config_item_not_present(mocker):
    config = get_config()
    get_aws_ec2_metadata_token_mock = mocker.patch(
        "watchdog.get_aws_ec2_metadata_token", return_value="ABCDEFG="
    )
    url_open_mock = mocker.patch("watchdog.urlopen")
    watchdog.url_request_helper(config, mount_efs.INSTANCE_METADATA_SERVICE_URL, "", "")
    utils.assert_called(get_aws_ec2_metadata_token_mock)
    utils.assert_called(url_open_mock)


def test_url_request_helper_unauthorized_error(mocker, caplog):
    caplog.set_level(logging.WARNING)

    config_section = mount_efs.CONFIG_SECTION
    config_item = mount_efs.DISABLE_FETCH_EC2_METADATA_TOKEN_ITEM
    config = get_config(config_section, config_item, "true")

    get_aws_ec2_metadata_token_mock = mocker.patch(
        "watchdog.get_aws_ec2_metadata_token"
    )
    url_open_mock = mocker.patch(
        "watchdog.urlopen",
        side_effect=HTTPError("url", 401, "Unauthorized", None, None),
    )
    resp = watchdog.url_request_helper(
        config, mount_efs.INSTANCE_METADATA_SERVICE_URL, "", ""
    )

    assert None == resp
    utils.assert_called(url_open_mock)
    utils.assert_not_called(get_aws_ec2_metadata_token_mock)

    assert "Unauthorized request" in [rec.message for rec in caplog.records][0]
    assert (
        "ec2 metadata token is disabled" in [rec.message for rec in caplog.records][0]
    )


def test_get_assumed_profile_credentials_via_botocore_botocore_not_present(mocker):
    expected_credentials = {"AccessKeyId": None, "SecretAccessKey": None, "Token": None}
    mocker.patch.dict("sys.modules", {"botocore": None})

    credentials = watchdog.botocore_credentials_helper("test_profile")
    assert credentials == expected_credentials


def test_get_assumed_profile_credentials_via_botocore_botocore_present(mocker):
    expected_credentials = {
        "AccessKeyId": ACCESS_KEY_ID_VAL,
        "SecretAccessKey": SECRET_ACCESS_KEY_VAL,
        "Token": SESSION_TOKEN_VAL,
    }

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

    credentials = watchdog.botocore_credentials_helper("test_profile")
    assert credentials == expected_credentials

    boto_session_mock.set_config_variable.assert_called_once_with(
        "profile", "test_profile"
    )
    boto_session_mock.get_credentials.assert_called_once_with()
    get_credential_session_mock.get_frozen_credentials.assert_called_once_with()


def test_get_assumed_profile_credentials_via_botocore_botocore_present_profile_not_found(
    mocker,
):
    expected_credentials = {"AccessKeyId": None, "SecretAccessKey": None, "Token": None}

    boto_session_mock = MagicMock()
    boto_session_mock.set_config_variable.return_value = None

    boto_session_mock.get_credentials.side_effect = [
        ProfileNotFound(profile="test_profile")
    ]

    mocker.patch("botocore.session.get_session", return_value=boto_session_mock)

    credentials = watchdog.botocore_credentials_helper("test_profile")

    assert credentials == expected_credentials

    boto_session_mock.set_config_variable.assert_called_once_with(
        "profile", "test_profile"
    )
    boto_session_mock.get_credentials.assert_called_once_with()


def test_get_int_value_from_config_file():
    config_section = watchdog.CONFIG_SECTION
    config_item = "stunnel_health_check_interval_min"
    config_value = watchdog.DEFAULT_STUNNEL_HEALTH_CHECK_INTERVAL_MIN + 1
    config = get_config(config_section, config_item, config_value)
    assert config_value == watchdog.get_int_value_from_config_file(
        config, config_item, watchdog.DEFAULT_STUNNEL_HEALTH_CHECK_INTERVAL_MIN
    )


def test_get_int_value_from_config_file_not_positive_value():
    config_section = watchdog.CONFIG_SECTION
    config_item = "stunnel_health_check_interval_min"
    config_value = 0
    config = get_config(config_section, config_item, config_value)
    assert (
        watchdog.DEFAULT_STUNNEL_HEALTH_CHECK_INTERVAL_MIN
        == watchdog.get_int_value_from_config_file(
            config, config_item, watchdog.DEFAULT_STUNNEL_HEALTH_CHECK_INTERVAL_MIN
        )
    )


def test_get_int_value_from_config_file_no_config_value():
    config_item = "stunnel_health_check_interval_min"
    config = get_config()
    assert (
        watchdog.DEFAULT_STUNNEL_HEALTH_CHECK_INTERVAL_MIN
        == watchdog.get_int_value_from_config_file(
            config, config_item, watchdog.DEFAULT_STUNNEL_HEALTH_CHECK_INTERVAL_MIN
        )
    )


def test_get_int_value_from_config_file_wrong_type_value():
    config_section = watchdog.CONFIG_SECTION
    config_item = "stunnel_health_check_interval_min"
    config_value = "false"
    config = get_config(config_section, config_item, config_value)
    assert (
        watchdog.DEFAULT_STUNNEL_HEALTH_CHECK_INTERVAL_MIN
        == watchdog.get_int_value_from_config_file(
            config, config_item, watchdog.DEFAULT_STUNNEL_HEALTH_CHECK_INTERVAL_MIN
        )
    )


def test_get_mountpoint_from_state_file_name():
    state_file_name = "/var/run/efs/fs-deadbeef.home.efs.12345"
    nfs_mounts = {
        "mnt": watchdog.Mount("127.0.0.1", "/mnt", "nfs4", "port=12343", "0", "0"),
        "mnt1": watchdog.Mount("127.0.0.1", "/mnt1", "nfs4", "port=12342", "0", "0"),
        "home.efs": watchdog.Mount(
            "127.0.0.1", "/home/efs", "nfs4", "port=12345", "0", "0"
        ),
    }
    assert "/home/efs" == watchdog.get_mountpoint_from_nfs_mounts(
        state_file_name, nfs_mounts
    )

    state_file_name = (
        "/var/run/efs/fs-deadbeef.var.lib.kubelet.pods.2cbe4183-2c36-4a37-9f72-7e3c1a67538c.volumes"
        ".kubernetes.io~csi.pvc-008bf5dc-5859-482e-b8b9-0e5e6887e411.mount.12345"
    )
    nfs_mounts = {
        "mnt": watchdog.Mount("127.0.0.1", "/mnt", "nfs4", "port=12343", "0", "0"),
        "mnt1": watchdog.Mount("127.0.0.1", "/mnt1", "nfs4", "port=12342", "0", "0"),
        "test": watchdog.Mount(
            "127.0.0.1:/deadbeef/test-008bf5dc-5859-482e-b8b9-0e5e6887e411",
            "/var/lib/kubelet/pods/1234583-2c36-4a37-9f72-7e3c1a67538c/volumes/"
            "kubernetes.io~csi/pvc-008bf5dc-5859-482e-b8b9-0e5e6887e411/mount",
            "nfs4",
            "port=12345",
            "0",
            "0",
        ),
    }
    assert (
        "/var/lib/kubelet/pods/1234583-2c36-4a37-9f72-7e3c1a67538c/volumes/kubernetes.io~csi/pvc-008bf5dc-5859"
        "-482e-b8b9-0e5e6887e411/mount"
        == watchdog.get_mountpoint_from_nfs_mounts(state_file_name, nfs_mounts)
    )


def test_get_system_release_version_macos(mocker):
    mocker.patch("watchdog.check_if_platform_is_mac", return_value=True)
    platform_mock = mocker.patch("platform.platform", return_value=MACOS)
    assert MACOS == watchdog.get_system_release_version()
    utils.assert_called_once(platform_mock)


def test_get_system_release_version_linux_read_from_sys_release_path(mocker):
    mocker.patch("watchdog.check_if_platform_is_mac", return_value=False)
    open_mock = mocker.patch("builtins.open", mock_open(read_data=AL2))
    platform_mock = mocker.patch("platform.platform")
    assert AL2 == watchdog.get_system_release_version()
    utils.assert_not_called(platform_mock)
    utils.assert_called_once(open_mock)


@unittest.skipIf(sys.version_info[1] < 7, "Not supported in python3.6 and below.")
def test_get_system_release_version_linux_read_from_os_release_path(mocker):
    mocker.patch("watchdog.check_if_platform_is_mac", return_value=False)
    mock = mock_open()
    mock.side_effect = [
        FileNotFoundError,
        mock_open(read_data="PRETTY_NAME=Amazon Linux release 2").return_value,
    ]
    open_mock = mocker.patch("builtins.open", mock)
    platform_mock = mocker.patch("platform.platform")
    assert AL2 == watchdog.get_system_release_version()
    utils.assert_not_called(platform_mock)
    utils.assert_called_n_times(open_mock, 2)


def test_get_system_release_version_linux_unknown(mocker):
    mocker.patch("watchdog.check_if_platform_is_mac", return_value=False)
    open_mock = mocker.patch("builtins.open", side_effect=FileNotFoundError)
    platform_mock = mocker.patch("platform.platform")
    assert watchdog.DEFAULT_UNKNOWN_VALUE == watchdog.get_system_release_version()
    utils.assert_not_called(platform_mock)
    utils.assert_called_n_times(open_mock, 2)
