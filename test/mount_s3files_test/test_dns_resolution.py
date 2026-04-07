# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.

import efs_utils_common
import mount_s3files.dns_resolver as dns_resolver

try:
    import ConfigParser
except ImportError:
    from configparser import ConfigParser

fs_id = "fs-deadbeef"
DEFAULT_REGION = "us-east-1"
DEFAULT_AZ = "us-east-1a"
DEFAULT_AZ_ID = "use1-az1"
DNS_NAME_SUFFIX = "on.aws"
IP_ADDRESS = "192.0.0.1"


def _get_mock_config(
    dns_name_format="{az_id}.{fs_id}.s3files.{region}.{dns_name_suffix}",
    dns_name_suffix=DNS_NAME_SUFFIX,
):
    try:
        config = ConfigParser.SafeConfigParser()
    except AttributeError:
        config = ConfigParser()
    config.add_section(efs_utils_common.constants.CONFIG_SECTION)
    config.set(
        efs_utils_common.constants.CONFIG_SECTION, "dns_name_format", dns_name_format
    )
    config.set(
        efs_utils_common.constants.CONFIG_SECTION, "dns_name_suffix", dns_name_suffix
    )
    return config

    def test_standard_s3files_dns_resolution_success(mocker):
        config = _get_mock_config()
        options = {}

        mock_get_az_id = mocker.patch(
            "mount_s3files.dns_resolver.get_az_id_from_instance_metadata"
        )
        mock_get_region = mocker.patch("mount_s3files.dns_resolver.get_target_region")
        mock_get_suffix = mocker.patch("mount_s3files.dns_resolver.get_dns_name_suffix")
        mock_dns_resolve = mocker.patch(
            "mount_s3files.dns_resolver.dns_name_can_be_resolved"
        )

        mock_get_az_id.return_value = DEFAULT_AZ_ID
        mock_get_region.return_value = DEFAULT_REGION
        mock_get_suffix.return_value = DNS_NAME_SUFFIX
        mock_dns_resolve.return_value = True

        dns_name, fallback_ip = dns_resolver.get_dns_name_and_mount_target_ip_address(
            config, fs_id, options
        )

        expected_dns = (
            f"{DEFAULT_AZ_ID}.{fs_id}.s3files.{DEFAULT_REGION}.{DNS_NAME_SUFFIX}"
        )
        assert dns_name == expected_dns
        assert fallback_ip is None


def test_s3files_dns_resolution_failure_no_fallback(mocker):
    config = _get_mock_config()
    options = {}

    mock_get_az_id = mocker.patch(
        "mount_s3files.dns_resolver.get_az_id_from_instance_metadata"
    )
    mock_get_region = mocker.patch("mount_s3files.dns_resolver.get_target_region")
    mock_get_suffix = mocker.patch("mount_s3files.dns_resolver.get_dns_name_suffix")
    mock_dns_resolve = mocker.patch(
        "mount_s3files.dns_resolver.dns_name_can_be_resolved"
    )
    mock_fatal_error = mocker.patch("mount_s3files.dns_resolver.fatal_error")

    mock_get_az_id.return_value = DEFAULT_AZ_ID
    mock_get_region.return_value = DEFAULT_REGION
    mock_get_suffix.return_value = DNS_NAME_SUFFIX
    mock_dns_resolve.return_value = False

    dns_resolver.get_dns_name_and_mount_target_ip_address(config, fs_id, options)

    mock_fatal_error.assert_called_once()


def test_s3files_with_mounttargetip_option(mocker):
    config = _get_mock_config()
    options = {"mounttargetip": IP_ADDRESS}

    mock_get_az_id = mocker.patch(
        "mount_s3files.dns_resolver.get_az_id_from_instance_metadata"
    )
    mock_get_region = mocker.patch("mount_s3files.dns_resolver.get_target_region")
    mock_get_suffix = mocker.patch("mount_s3files.dns_resolver.get_dns_name_suffix")
    mock_ip_resolve = mocker.patch(
        "mount_s3files.dns_resolver.mount_target_ip_address_can_be_resolved"
    )

    mock_get_az_id.return_value = DEFAULT_AZ_ID
    mock_get_region.return_value = DEFAULT_REGION
    mock_get_suffix.return_value = DNS_NAME_SUFFIX
    mock_ip_resolve.return_value = None

    dns_name, fallback_ip = dns_resolver.get_dns_name_and_mount_target_ip_address(
        config, fs_id, options
    )

    expected_dns = f"{DEFAULT_AZ_ID}.{fs_id}.s3files.{DEFAULT_REGION}.{DNS_NAME_SUFFIX}"
    assert dns_name == expected_dns
    assert fallback_ip == IP_ADDRESS


def test_s3files_with_az_id_option_override(mocker):
    config = _get_mock_config(
        dns_name_format="{az_id}.{fs_id}.s3files.{region}.{dns_name_suffix}"
    )
    options = {"azid": DEFAULT_AZ_ID}

    mock_get_az_id = mocker.patch(
        "mount_s3files.dns_resolver.get_az_id_from_instance_metadata"
    )
    mock_get_region = mocker.patch("mount_s3files.dns_resolver.get_target_region")
    mock_get_suffix = mocker.patch("mount_s3files.dns_resolver.get_dns_name_suffix")
    mock_dns_resolve = mocker.patch(
        "mount_s3files.dns_resolver.dns_name_can_be_resolved"
    )

    mock_get_az_id.return_value = DEFAULT_AZ_ID
    mock_get_region.return_value = DEFAULT_REGION
    mock_get_suffix.return_value = DNS_NAME_SUFFIX
    mock_dns_resolve.return_value = True

    dns_name, fallback_ip = dns_resolver.get_dns_name_and_mount_target_ip_address(
        config, fs_id, options
    )

    expected_dns = f"{DEFAULT_AZ_ID}.{fs_id}.s3files.{DEFAULT_REGION}.{DNS_NAME_SUFFIX}"
    assert dns_name == expected_dns
    assert fallback_ip is None


def test_s3files_minimal_dns_format(mocker):
    config = _get_mock_config(
        dns_name_format="{fs_id}.s3files.{region}.{dns_name_suffix}"
    )
    options = {}

    mock_get_region = mocker.patch("mount_s3files.dns_resolver.get_target_region")
    mock_get_suffix = mocker.patch("mount_s3files.dns_resolver.get_dns_name_suffix")
    mock_dns_resolve = mocker.patch(
        "mount_s3files.dns_resolver.dns_name_can_be_resolved"
    )

    mock_get_region.return_value = DEFAULT_REGION
    mock_get_suffix.return_value = DNS_NAME_SUFFIX
    mock_dns_resolve.return_value = True

    dns_name, fallback_ip = dns_resolver.get_dns_name_and_mount_target_ip_address(
        config, fs_id, options
    )

    expected_dns = f"{fs_id}.s3files.{DEFAULT_REGION}.{DNS_NAME_SUFFIX}"
    assert dns_name == expected_dns
    assert fallback_ip is None


def test_s3files_match_device_with_fs_id(mocker):
    """Test match_device function with direct filesystem ID"""
    config = _get_mock_config()
    options = {}

    mock_context = mocker.patch("mount_s3files.dns_resolver.MountContext")
    mock_context_instance = mock_context.return_value

    result_fs_id, path, az = dns_resolver.match_device(config, fs_id, options)

    assert result_fs_id == fs_id
    assert path == "/"
    assert az is None


def test_s3files_match_device_with_path(mocker):
    """Test match_device function with filesystem ID and path"""
    config = _get_mock_config()
    options = {}
    device = f"{fs_id}:/some/path"

    mock_context = mocker.patch("mount_s3files.dns_resolver.MountContext")
    mock_context_instance = mock_context.return_value

    result_fs_id, path, az = dns_resolver.match_device(config, device, options)

    assert result_fs_id == fs_id
    assert path == "/some/path"
    assert az is None
