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
IP_ADDRESS = "192.0.0.1"
SPECIAL_REGION_DNS_DICT = {
    "cn-north-1": "amazonaws.com.cn",
    "cn-northwest-1": "amazonaws.com.cn",
    "us-iso-east-1": "c2s.ic.gov",
    "us-iso-west-1": "c2s.ic.gov",
    "us-isob-east-1": "sc2s.sgov.gov",
    "us-isob-west-1": "sc2s.sgov.gov",
    "us-isof-south-1": "csp.hci.ic.gov",
    "us-isof-east-1": "csp.hci.ic.gov",
    "eu-isoe-west-1": "cloud.adc-e.uk"
}
SPECIAL_REGIONS = ["cn-north-1", "cn-northwest-1", "us-iso-east-1", "us-iso-west-1", "us-isob-east-1", "us-isob-west-1", "us-isof-south-1", "us-isof-east-1", "eu-isoe-west-1"]
DEFAULT_NFS_OPTIONS = {}
OPTIONS_WITH_AZ = {"az": DEFAULT_AZ}
OPTIONS_WITH_IP = {"mounttargetip": IP_ADDRESS}
OPTIONS_WITH_CROSSACCOUNT = {"crossaccount": None}
MOCK_EFS_AGENT = "fake-efs-client"
MOCK_EC2_AGENT = "fake-ec2-client"


@pytest.fixture(autouse=True)
def setup(mocker):
    mocker.patch("mount_efs.get_target_region", return_value=DEFAULT_REGION)
    mocker.patch("socket.gethostbyname")


def _get_mock_config(
    dns_name_format="{az}.{fs_id}.efs.{region}.{dns_name_suffix}",
    dns_name_suffix="amazonaws.com",
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
    config.set(mount_efs.CONFIG_SECTION, "dns_name_format", dns_name_format)
    config.set(config_section, "dns_name_suffix", dns_name_suffix)
    if has_fallback_to_mount_target_ip_address_item:
        config.set(
            mount_efs.CONFIG_SECTION,
            mount_efs.FALLBACK_TO_MOUNT_TARGET_IP_ADDRESS_ITEM,
            str(fallback_to_mount_target_ip_address),
        )

    return config


def test_get_dns_name_and_fallback_mount_target_ip_address():
    config = _get_mock_config()

    dns_name, ip_address = mount_efs.get_dns_name_and_fallback_mount_target_ip_address(
        config, FS_ID, DEFAULT_NFS_OPTIONS
    )

    assert "%s.efs.%s.amazonaws.com" % (FS_ID, DEFAULT_REGION) == dns_name
    assert None == ip_address


def test_get_dns_name_with_az_in_options():
    config = _get_mock_config("{az}.{fs_id}.efs.{region}.amazonaws.com")

    dns_name, ip_address = mount_efs.get_dns_name_and_fallback_mount_target_ip_address(
        config, FS_ID, OPTIONS_WITH_AZ
    )

    assert (
        "%s.%s.efs.%s.amazonaws.com" % (DEFAULT_AZ, FS_ID, DEFAULT_REGION) == dns_name
    )
    assert None == ip_address


def test_get_dns_name_without_az_in_options():
    config = _get_mock_config("{az}.{fs_id}.efs.{region}.amazonaws.com")

    dns_name, ip_address = mount_efs.get_dns_name_and_fallback_mount_target_ip_address(
        config, FS_ID, DEFAULT_NFS_OPTIONS
    )

    assert "%s.efs.%s.amazonaws.com" % (FS_ID, DEFAULT_REGION) == dns_name
    assert None == ip_address


def test_get_dns_name_with_ip_in_options(mocker):
    config = _get_mock_config()
    ip_address_connect_mock = mocker.patch(
        "mount_efs.mount_target_ip_address_can_be_resolved", return_value=True
    )
    dns_name, ip_address = mount_efs.get_dns_name_and_fallback_mount_target_ip_address(
        config, FS_ID, OPTIONS_WITH_IP
    )

    assert "%s.efs.%s.amazonaws.com" % (FS_ID, DEFAULT_REGION) == dns_name
    assert IP_ADDRESS == ip_address
    utils.assert_called(ip_address_connect_mock)


def test_get_dns_name_with_crossaccount_in_options(mocker):
    config = _get_mock_config("{az}.{fs_id}.efs.{region}.amazonaws.com")

    get_az_id_mock = mocker.patch(
        "mount_efs.get_az_id_from_instance_metadata", return_value=DEFAULT_AZ_ID
    )

    dns_name, ip_address = mount_efs.get_dns_name_and_fallback_mount_target_ip_address(
        config, FS_ID, OPTIONS_WITH_CROSSACCOUNT
    )

    assert (
        "%s.%s.efs.%s.amazonaws.com" % (DEFAULT_AZ_ID, FS_ID, DEFAULT_REGION)
        == dns_name
    )
    utils.assert_called(get_az_id_mock)


def test_get_dns_name_suffix_hardcoded():
    config = _get_mock_config("{az}.{fs_id}.efs.{region}.amazonaws.com")

    dns_name, ip_address = mount_efs.get_dns_name_and_fallback_mount_target_ip_address(
        config, FS_ID, DEFAULT_NFS_OPTIONS
    )

    assert "%s.efs.%s.amazonaws.com" % (FS_ID, DEFAULT_REGION) == dns_name
    assert None == ip_address


def test_get_dns_name_region_hardcoded(mocker):
    get_target_region_mock = mocker.patch("mount_efs.get_target_region")

    config = _get_mock_config("{az}.{fs_id}.efs.%s.{dns_name_suffix}" % DEFAULT_REGION)

    dns_name, ip_address = mount_efs.get_dns_name_and_fallback_mount_target_ip_address(
        config, FS_ID, DEFAULT_NFS_OPTIONS
    )

    utils.assert_not_called(get_target_region_mock)

    assert "%s.efs.%s.amazonaws.com" % (FS_ID, DEFAULT_REGION) == dns_name
    assert None == ip_address


def test_get_dns_name_region_and_suffix_hardcoded(mocker):
    get_target_region_mock = mocker.patch("mount_efs.get_target_region")

    config = _get_mock_config("{az}.{fs_id}.efs.us-west-2.amazonaws.com")

    dns_name, ip_address = mount_efs.get_dns_name_and_fallback_mount_target_ip_address(
        config, FS_ID, DEFAULT_NFS_OPTIONS
    )

    utils.assert_not_called(get_target_region_mock)

    assert "%s.efs.us-west-2.amazonaws.com" % FS_ID == dns_name
    assert None == ip_address


def test_get_dns_name_bad_format_wrong_specifiers():
    config = _get_mock_config("{foo}.efs.{bar}")

    with pytest.raises(ValueError) as ex:
        mount_efs.get_dns_name_and_fallback_mount_target_ip_address(
            config, FS_ID, DEFAULT_NFS_OPTIONS
        )

    assert "must include" in str(ex.value)


def test_get_dns_name_bad_format_too_many_specifiers_1():
    config = _get_mock_config("{fs_id}.efs.{foo}")

    with pytest.raises(ValueError) as ex:
        mount_efs.get_dns_name_and_fallback_mount_target_ip_address(
            config, FS_ID, DEFAULT_NFS_OPTIONS
        )

    assert "incorrect number" in str(ex.value)


def test_get_dns_name_bad_format_too_many_specifiers_2():
    config = _get_mock_config("{fs_id}.efs.{region}.{foo}")

    with pytest.raises(ValueError) as ex:
        mount_efs.get_dns_name_and_fallback_mount_target_ip_address(
            config, FS_ID, DEFAULT_NFS_OPTIONS
        )

    assert "incorrect number" in str(ex.value)


def test_get_dns_name_unresolvable(mocker, capsys):
    config = _get_mock_config()

    mocker.patch("socket.gethostbyname", side_effect=socket.gaierror)

    with pytest.raises(SystemExit) as ex:
        mount_efs.get_dns_name_and_fallback_mount_target_ip_address(
            config, FS_ID, DEFAULT_NFS_OPTIONS
        )

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert "Failed to resolve" in err


def test_get_dns_name_special_region(mocker):
    for special_region in SPECIAL_REGIONS:
        mocker.patch("mount_efs.get_target_region", return_value=special_region)

        config_section = "mount.%s" % special_region
        special_dns_name_suffix = SPECIAL_REGION_DNS_DICT[special_region]

        config = _get_mock_config(
            dns_name_suffix=special_dns_name_suffix, config_section=config_section
        )

        (
            dns_name,
            ip_address,
        ) = mount_efs.get_dns_name_and_fallback_mount_target_ip_address(
            config, FS_ID, DEFAULT_NFS_OPTIONS
        )

        assert (
            "%s.efs.%s.%s" % (FS_ID, special_region, special_dns_name_suffix)
            == dns_name
        )
        assert ip_address == None


def test_get_dns_name_region_in_suffix(mocker):
    get_target_region_mock = mocker.patch("mount_efs.get_target_region")

    for special_region in SPECIAL_REGIONS:
        special_dns_name_suffix = SPECIAL_REGION_DNS_DICT[special_region]
        dns_name_suffix = "%s.%s" % (special_region, special_dns_name_suffix)

        config = _get_mock_config(
            "{fs_id}.efs.{dns_name_suffix}", dns_name_suffix=dns_name_suffix
        )

        (
            dns_name,
            ip_address,
        ) = mount_efs.get_dns_name_and_fallback_mount_target_ip_address(
            config, FS_ID, DEFAULT_NFS_OPTIONS
        )

        utils.assert_not_called(get_target_region_mock)

        assert (
            "%s.efs.%s.%s" % (FS_ID, special_region, special_dns_name_suffix)
            == dns_name
        )
        assert None == ip_address


def test_dns_name_can_be_resolved_dns_resolve_failure(mocker):
    dns_mock = mocker.patch("socket.gethostbyname", side_effect=socket.gaierror)
    result = mount_efs.dns_name_can_be_resolved(DNS_NAME)
    assert False == result
    utils.assert_called(dns_mock)


def test_dns_name_can_be_resolved_dns_resolve_succeed(mocker):
    dns_mock = mocker.patch("socket.gethostbyname")
    result = mount_efs.dns_name_can_be_resolved(DNS_NAME)
    assert True == result
    utils.assert_called(dns_mock)


def test_get_dns_name_and_fall_back_ip_address_success(mocker):
    """
    When the dns name cannot be resolved, and the fallback to mount target ip address is retrieved
    """
    config = _get_mock_config()

    dns_mock = mocker.patch("socket.gethostbyname", side_effect=socket.gaierror)
    get_fallback_mount_target_ip_mock = mocker.patch(
        "mount_efs.get_fallback_mount_target_ip_address", return_value=IP_ADDRESS
    )

    dns_name, ip_address = mount_efs.get_dns_name_and_fallback_mount_target_ip_address(
        config, FS_ID, DEFAULT_NFS_OPTIONS
    )

    assert "%s.efs.%s.amazonaws.com" % (FS_ID, DEFAULT_REGION) == dns_name
    assert IP_ADDRESS == ip_address

    utils.assert_called(dns_mock)
    utils.assert_called(get_fallback_mount_target_ip_mock)


def test_get_dns_name_and_mount_target_ip_address_via_option_success(mocker):
    """
    When the mount target ip address is passed through mount options and can be connected
    """
    config = _get_mock_config()

    dns_mock = mocker.patch("socket.gethostbyname")
    get_fallback_mount_target_ip_mock = mocker.patch(
        "mount_efs.get_fallback_mount_target_ip_address"
    )
    ip_address_connect_mock = mocker.patch(
        "mount_efs.mount_target_ip_address_can_be_resolved", return_value=True
    )

    dns_name, ip_address = mount_efs.get_dns_name_and_fallback_mount_target_ip_address(
        config, FS_ID, OPTIONS_WITH_IP
    )

    assert "%s.efs.%s.amazonaws.com" % (FS_ID, DEFAULT_REGION) == dns_name
    assert IP_ADDRESS == ip_address

    utils.assert_not_called(dns_mock)
    utils.assert_not_called(get_fallback_mount_target_ip_mock)
    utils.assert_called(ip_address_connect_mock)


def test_get_dns_name_and_mount_target_ip_address_via_option_failure(mocker, capsys):
    """
    When the mount target ip address is passed through mount options and cannot be connected
    """
    config = _get_mock_config()

    dns_mock = mocker.patch("socket.gethostbyname")
    get_fallback_mount_target_ip_mock = mocker.patch(
        "mount_efs.get_fallback_mount_target_ip_address"
    )
    ip_address_connect_mock = mocker.patch(
        "mount_efs.mount_target_ip_address_can_be_resolved",
        side_effect=mount_efs.FallbackException("Timeout"),
    )

    with pytest.raises(SystemExit) as ex:
        mount_efs.get_dns_name_and_fallback_mount_target_ip_address(
            config, FS_ID, OPTIONS_WITH_IP
        )

        assert 0 != ex.value.code

        out, err = capsys.readouterr()
        assert "Failed to resolve" not in err
        assert IP_ADDRESS in err
        assert "Cannot connect" in err
        assert "Timeout" in err

    utils.assert_not_called(dns_mock)
    utils.assert_not_called(get_fallback_mount_target_ip_mock)
    utils.assert_called(ip_address_connect_mock)


def test_get_dns_name_and_fall_back_ip_address_failure(mocker, capsys):
    """
    When the dns name cannot be resolved, and the fallback to mount target ip address throw FallbackException
    """
    config = _get_mock_config()

    dns_mock = mocker.patch("socket.gethostbyname", side_effect=socket.gaierror)
    get_fallback_mount_target_ip_mock = mocker.patch(
        "mount_efs.get_fallback_mount_target_ip_address",
        side_effect=mount_efs.FallbackException("timeout"),
    )

    with pytest.raises(SystemExit) as ex:
        mount_efs.get_dns_name_and_fallback_mount_target_ip_address(
            config, FS_ID, DEFAULT_NFS_OPTIONS
        )

        assert 0 != ex.value.code

        out, err = capsys.readouterr()
        assert "cannot be retrieved" in err

    utils.assert_called(dns_mock)
    utils.assert_called(get_fallback_mount_target_ip_mock)
