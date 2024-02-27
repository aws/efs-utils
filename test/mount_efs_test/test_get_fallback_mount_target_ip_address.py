# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.

import socket

import pytest

import mount_efs

from .. import utils

try:
    import ConfigParser
except ImportError:
    from configparser import ConfigParser


FS_ID = "fs-deadbeef"
DEFAULT_REGION = "us-east-1"
DEFAULT_AZ = "us-east-1a"
DEFAULT_AZ_ID = "use1-az1"
DNS_NAME = "test.example.com"
FALLBACK_IP_ADDRESS = "192.0.0.1"
SPECIAL_REGION_DNS_DICT = {
    "cn-north-1": "amazonaws.com.cn",
    "cn-northwest-1": "amazonaws.com.cn",
    "us-iso-east-1": "c2s.ic.gov",
    "us-isob-east-1": "sc2s.sgov.gov",
}
SPECIAL_REGIONS = ["cn-north-1", "cn-northwest-1", "us-iso-east-1", "us-isob-east-1"]
DEFAULT_NFS_OPTIONS = {}
OPTIONS_WITH_AZ = {"az": DEFAULT_AZ}
OPTIONS_WITH_CROSSACCOUNT = {"crossaccount": None}
MOCK_EFS_AGENT = "fake-efs-client"
MOCK_EC2_AGENT = "fake-ec2-client"


def _get_mock_config(
    config_section="mount",
    has_fallback_to_mount_target_ip_address_item=True,
    fallback_to_mount_target_ip_address=False,
):
    try:
        config = ConfigParser.SafeConfigParser()
    except AttributeError:
        config = ConfigParser()
    config.add_section(mount_efs.CONFIG_SECTION)
    if mount_efs.CONFIG_SECTION != config_section:
        config.add_section(config_section)
    if has_fallback_to_mount_target_ip_address_item:
        config.set(
            mount_efs.CONFIG_SECTION,
            mount_efs.FALLBACK_TO_MOUNT_TARGET_IP_ADDRESS_ITEM,
            str(fallback_to_mount_target_ip_address),
        )

    return config


def test_fall_back_to_mount_target_ip_address_not_enabled_in_config_file():
    config = _get_mock_config(
        has_fallback_to_mount_target_ip_address_item=True,
        fallback_to_mount_target_ip_address=False,
    )
    assert False == mount_efs.check_if_fall_back_to_mount_target_ip_address_is_enabled(
        config
    )


def test_fall_back_to_mount_target_ip_address_enabled_in_config_file():
    config = _get_mock_config(
        has_fallback_to_mount_target_ip_address_item=True,
        fallback_to_mount_target_ip_address=True,
    )
    assert True == mount_efs.check_if_fall_back_to_mount_target_ip_address_is_enabled(
        config
    )


def test_fall_back_to_mount_target_ip_address_item_not_in_config_file():
    config = _get_mock_config(has_fallback_to_mount_target_ip_address_item=False)
    assert True == mount_efs.check_if_fall_back_to_mount_target_ip_address_is_enabled(
        config
    )


def test_check_if_ip_can_be_resolved_ip_connect_to_mount_target_timeout(mocker):
    ip_mock = mocker.patch(
        "socket.create_connection",
        side_effect=[socket.timeout, socket.timeout, socket.timeout],
    )
    with pytest.raises(mount_efs.FallbackException) as excinfo:
        mount_efs.mount_target_ip_address_can_be_resolved(FALLBACK_IP_ADDRESS)
    assert "timeout" in str(excinfo)
    utils.assert_called_n_times(ip_mock, 3)


def test_check_if_ip_can_be_resolved_ip_connect_to_mount_target_timeout_first_time(
    mocker,
):
    ip_mock = mocker.patch(
        "socket.create_connection",
        side_effect=[socket.timeout, socket.socket(socket.AF_INET, socket.SOCK_STREAM)],
    )
    assert True == mount_efs.mount_target_ip_address_can_be_resolved(
        FALLBACK_IP_ADDRESS
    )
    utils.assert_called_n_times(ip_mock, 2)


def test_check_if_ip_can_be_resolved_ip_connect_to_mount_target_unknown_error(mocker):
    ip_mock = mocker.patch("socket.create_connection", side_effect=[socket.error])
    with pytest.raises(mount_efs.FallbackException) as excinfo:
        mount_efs.mount_target_ip_address_can_be_resolved(FALLBACK_IP_ADDRESS)
    assert "Unknown error" in str(excinfo)
    utils.assert_called_n_times(ip_mock, 1)


def test_check_if_ip_can_be_resolved_ip_resolve_succeed(mocker):
    ip_mock = mocker.patch("socket.create_connection")
    assert True == mount_efs.mount_target_ip_address_can_be_resolved(
        FALLBACK_IP_ADDRESS
    )
    utils.assert_called(ip_mock)


def test_get_fallback_mount_target_ip_address_throw_fallback_exception(mocker):
    """
    This tests make sure that all exception is not handled and thrown by default to upper level
    """
    config = _get_mock_config()

    get_target_az_mock = mocker.patch(
        "mount_efs.get_target_az", return_value=DEFAULT_AZ
    )
    get_botocore_client_mock = mocker.patch(
        "mount_efs.get_botocore_client", side_effect=[MOCK_EFS_AGENT, MOCK_EC2_AGENT]
    )
    get_mount_target_az_mock = mocker.patch(
        "mount_efs.get_mount_target_in_az",
        side_effect=mount_efs.FallbackException("No mount target"),
    )

    with pytest.raises(mount_efs.FallbackException) as excinfo:
        mount_efs.get_fallback_mount_target_ip_address_helper(config, {}, FS_ID)
    assert "No mount target" in str(excinfo)

    utils.assert_called_once(get_target_az_mock)
    utils.assert_called_n_times(get_botocore_client_mock, 2)
    utils.assert_called_once(get_mount_target_az_mock)


def test_get_fallback_mount_target_ip_address_mount_target_ip(mocker):
    config = _get_mock_config()
    mount_efs.BOTOCORE_PRESENT = True

    get_target_az_mock = mocker.patch(
        "mount_efs.get_target_az", return_value=DEFAULT_AZ
    )
    get_botocore_client_mock = mocker.patch(
        "mount_efs.get_botocore_client", side_effect=[None, None]
    )
    get_mount_target_mock = mocker.patch(
        "mount_efs.get_mount_target_in_az",
        return_value={"IpAddress": FALLBACK_IP_ADDRESS},
    )

    assert FALLBACK_IP_ADDRESS == mount_efs.get_fallback_mount_target_ip_address_helper(
        config, {}, FS_ID
    )

    utils.assert_called_once(get_target_az_mock)
    utils.assert_called_once(get_mount_target_mock)
    utils.assert_called_n_times(get_botocore_client_mock, 2)


def test_get_fall_back_ip_address_success(mocker):
    """
    When the fallback to mount target ip address is enabled, the mount target ip address is retrieved and can be connected
    """
    config = _get_mock_config()

    check_fallback_enabled_mock = mocker.patch(
        "mount_efs.check_if_fall_back_to_mount_target_ip_address_is_enabled",
        return_value=True,
    )
    get_fallback_mount_target_ip_mock = mocker.patch(
        "mount_efs.get_fallback_mount_target_ip_address_helper",
        return_value=FALLBACK_IP_ADDRESS,
    )
    check_ip_resolve_mock = mocker.patch(
        "mount_efs.mount_target_ip_address_can_be_resolved", return_value=True
    )

    ip_address = mount_efs.get_fallback_mount_target_ip_address(
        config, FS_ID, DEFAULT_NFS_OPTIONS, DNS_NAME
    )

    assert FALLBACK_IP_ADDRESS == ip_address

    utils.assert_called(check_fallback_enabled_mock)
    utils.assert_called(get_fallback_mount_target_ip_mock)
    utils.assert_called(check_ip_resolve_mock)


def test_get_fall_back_ip_address_feature_not_enabled(mocker):
    """
    When the fallback to mount target ip address is not enabled
    """
    config = _get_mock_config()

    check_fallback_enabled_mock = mocker.patch(
        "mount_efs.check_if_fall_back_to_mount_target_ip_address_is_enabled",
        return_value=False,
    )
    get_fallback_mount_target_ip_mock = mocker.patch(
        "mount_efs.get_fallback_mount_target_ip_address_helper"
    )
    check_ip_resolve_mock = mocker.patch(
        "mount_efs.mount_target_ip_address_can_be_resolved"
    )

    with pytest.raises(mount_efs.FallbackException) as excinfo:
        mount_efs.get_fallback_mount_target_ip_address(
            config, FS_ID, DEFAULT_NFS_OPTIONS, DNS_NAME
        )

    assert "not enabled" in str(excinfo)

    utils.assert_called(check_fallback_enabled_mock)
    utils.assert_not_called(get_fallback_mount_target_ip_mock)
    utils.assert_not_called(check_ip_resolve_mock)


def test_get_fall_back_ip_address_when_crossaccount_enabled(mocker):
    """
    When the crossacount feature is enabled this should throw an Exception
    """
    config = _get_mock_config()

    get_fallback_mount_target_ip_mock = mocker.patch(
        "mount_efs.get_fallback_mount_target_ip_address_helper"
    )
    check_ip_resolve_mock = mocker.patch(
        "mount_efs.mount_target_ip_address_can_be_resolved"
    )

    with pytest.raises(mount_efs.FallbackException) as excinfo:
        mount_efs.get_fallback_mount_target_ip_address(
            config, OPTIONS_WITH_CROSSACCOUNT, FS_ID, DNS_NAME
        )

    assert "crossaccount option" in str(excinfo)

    utils.assert_not_called(get_fallback_mount_target_ip_mock)
    utils.assert_not_called(check_ip_resolve_mock)


def test_get_dns_name_and_fall_back_ip_address_is_none_botocore_not_present(mocker):
    """
    When the fallback to mount target ip address is enabled, botocore is not present
    """
    config = _get_mock_config()

    mount_efs.BOTOCORE_PRESENT = False

    check_fallback_enabled_mock = mocker.patch(
        "mount_efs.check_if_fall_back_to_mount_target_ip_address_is_enabled",
        return_value=True,
    )
    get_fallback_mount_target_ip_mock = mocker.patch(
        "mount_efs.get_fallback_mount_target_ip_address_helper"
    )
    check_ip_resolve_mock = mocker.patch(
        "mount_efs.mount_target_ip_address_can_be_resolved"
    )

    with pytest.raises(mount_efs.FallbackException) as excinfo:
        mount_efs.get_fallback_mount_target_ip_address(
            config, FS_ID, DEFAULT_NFS_OPTIONS, DNS_NAME
        )

    assert "necessary dependency botocore" in str(excinfo)

    utils.assert_called(check_fallback_enabled_mock)
    utils.assert_not_called(get_fallback_mount_target_ip_mock)
    utils.assert_not_called(check_ip_resolve_mock)


def test_get_dns_name_and_fall_back_ip_address_cannot_be_resolved(mocker, capsys):
    """
    When the fallback to mount target ip address is enabled, the mount target ip address is retrieved but cannot be connected
    """
    config = _get_mock_config()
    mount_efs.BOTOCORE_PRESENT = True
    check_fallback_enabled_mock = mocker.patch(
        "mount_efs.check_if_fall_back_to_mount_target_ip_address_is_enabled",
        return_value=True,
    )
    get_fallback_mount_target_ip_mock = mocker.patch(
        "mount_efs.get_fallback_mount_target_ip_address_helper",
        return_value=FALLBACK_IP_ADDRESS,
    )
    check_ip_resolve_mock = mocker.patch(
        "mount_efs.mount_target_ip_address_can_be_resolved",
        side_effect=[mount_efs.FallbackException("timeout")],
    )

    with pytest.raises(SystemExit) as ex:
        mount_efs.get_fallback_mount_target_ip_address(
            config, FS_ID, DEFAULT_NFS_OPTIONS, DNS_NAME
        )

        assert 0 != ex.value.code

        out, err = capsys.readouterr()
        assert "Failed to resolve" in err
        assert "cannot be found" in err

    utils.assert_called(check_fallback_enabled_mock)
    utils.assert_called(get_fallback_mount_target_ip_mock)
    utils.assert_called(check_ip_resolve_mock)
