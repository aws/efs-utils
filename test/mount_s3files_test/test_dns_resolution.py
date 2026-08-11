# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.

import socket

import pytest

import efs_utils_common
import efs_utils_common.context as context
import mount_s3files
import mount_s3files.dns_resolver as dns_resolver
from efs_utils_common.constants import MOUNT_TYPE_S3FILES

from .. import utils

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

# S3Files FQDN form: {az_id}.{fs_id}.s3files.{region}.{dns_name_suffix}
S3FILES_DNS_NAME = f"{DEFAULT_AZ_ID}.{fs_id}.s3files.{DEFAULT_REGION}.{DNS_NAME_SUFFIX}"
CUSTOM_CNAME = "custom-cname.example.com"
CORRECT_DEVICE_DESCRIPTORS_CNAME_DNS = [
    (CUSTOM_CNAME, (fs_id, "/")),
    (f"{CUSTOM_CNAME}:/", (fs_id, "/")),
    (f"{CUSTOM_CNAME}:/some/subpath", (fs_id, "/some/subpath")),
    (
        f"{CUSTOM_CNAME}:/some/subpath/with:colons",
        (fs_id, "/some/subpath/with:colons"),
    ),
]


@pytest.fixture(autouse=True)
def setup_context():
    mount_context = context.MountContext()
    mount_context.reset()
    mount_context.fqdn_regex_pattern = mount_s3files.FQDN_REGEX_PATTERN
    mount_context.mount_type = MOUNT_TYPE_S3FILES
    yield mount_context
    mount_context.reset()


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

    expected_dns = f"{DEFAULT_AZ_ID}.{fs_id}.s3files.{DEFAULT_REGION}.{DNS_NAME_SUFFIX}"
    assert dns_name == expected_dns
    assert fallback_ip is None


def test_s3files_dns_resolution_failure_no_fallback(mocker, capsys):
    """When the DNS name cannot be resolved and there is no fallback, the mount must
    REALLY abort: fatal_error is not mocked, so the process must exit non-zero (via
    SystemExit) and never return a dns_name/ip pair to the caller.
    """
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
    mock_dns_resolve.return_value = False

    with pytest.raises(SystemExit) as ex:
        dns_resolver.get_dns_name_and_mount_target_ip_address(config, fs_id, options)

    # A real abort: non-zero exit code and the user-facing failure message on stderr.
    assert ex.value.code != 0
    _out, err = capsys.readouterr()
    assert "Failed to resolve" in err
    expected_dns = f"{DEFAULT_AZ_ID}.{fs_id}.s3files.{DEFAULT_REGION}.{DNS_NAME_SUFFIX}"
    assert expected_dns in err


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


def test_s3files_dns_resolution_china_region(mocker):
    """Test that S3 Files uses on.amazonwebservices.com.cn in China, not amazonaws.com.cn"""
    config = _get_mock_config(dns_name_suffix="on.amazonwebservices.com.cn")
    options = {}

    mock_get_az_id = mocker.patch(
        "mount_s3files.dns_resolver.get_az_id_from_instance_metadata"
    )
    mock_get_region = mocker.patch("mount_s3files.dns_resolver.get_target_region")
    mock_get_suffix = mocker.patch("mount_s3files.dns_resolver.get_dns_name_suffix")
    mock_dns_resolve = mocker.patch(
        "mount_s3files.dns_resolver.dns_name_can_be_resolved"
    )

    mock_get_az_id.return_value = "cnn1-az2"
    mock_get_region.return_value = "cn-north-1"
    mock_get_suffix.return_value = "on.amazonwebservices.com.cn"
    mock_dns_resolve.return_value = True

    dns_name, fallback_ip = dns_resolver.get_dns_name_and_mount_target_ip_address(
        config, fs_id, options
    )

    assert (
        dns_name
        == "cnn1-az2.fs-deadbeef.s3files.cn-north-1.on.amazonwebservices.com.cn"
    )
    assert fallback_ip is None


# ---------------------------------------------------------------------------
# S3Files match_device CNAME tests (parity with EFS mount_common_test/test_match_device.py)
#
# S3Files match_device resolves a CNAME via socket.gethostbyname_ex and requires
# the resolved primary hostname to exactly match the expected S3Files DNS name.
# ---------------------------------------------------------------------------


def test_s3files_match_device_correct_descriptors_cname_dns(mocker):
    """A CNAME resolving to a valid S3Files DNS name returns (fs_id, path, az_id),
    for the bare CNAME and CNAME:/subpath forms."""
    get_dns_name_mock = mocker.patch(
        "mount_s3files.dns_resolver.get_dns_name_and_mount_target_ip_address",
        return_value=(S3FILES_DNS_NAME, None),
    )
    gethostbyname_mock = mocker.patch(
        "socket.gethostbyname_ex",
        return_value=(S3FILES_DNS_NAME, [], [IP_ADDRESS]),
    )
    config = _get_mock_config()
    for device, (expected_fs_id, expected_path) in CORRECT_DEVICE_DESCRIPTORS_CNAME_DNS:
        result_fs_id, path, az = dns_resolver.match_device(config, device, {})
        assert result_fs_id == expected_fs_id
        assert path == expected_path
        assert az == DEFAULT_AZ_ID
    utils.assert_called(get_dns_name_mock)
    utils.assert_called(gethostbyname_mock)


def test_s3files_match_device_cname_china_suffix(mocker):
    """CNAME resolving to an S3Files DNS name with the China suffix."""
    china_dns_name = (
        "cnn1-az2.fs-deadbeef.s3files.cn-north-1.on.amazonwebservices.com.cn"
    )
    get_dns_name_mock = mocker.patch(
        "mount_s3files.dns_resolver.get_dns_name_and_mount_target_ip_address",
        return_value=(china_dns_name, None),
    )
    gethostbyname_mock = mocker.patch(
        "socket.gethostbyname_ex",
        return_value=(china_dns_name, [], [IP_ADDRESS]),
    )
    config = _get_mock_config(dns_name_suffix="on.amazonwebservices.com.cn")
    result_fs_id, path, az = dns_resolver.match_device(config, CUSTOM_CNAME, {})
    assert result_fs_id == fs_id
    assert path == "/"
    assert az == "cnn1-az2"
    utils.assert_called(get_dns_name_mock)
    utils.assert_called(gethostbyname_mock)


def test_s3files_match_device_cname_in_secondaries(mocker):
    """The valid S3Files DNS name may be in the secondary aliases rather than the
    primary hostname; match_device must still find it."""
    get_dns_name_mock = mocker.patch(
        "mount_s3files.dns_resolver.get_dns_name_and_mount_target_ip_address",
        return_value=(S3FILES_DNS_NAME, None),
    )
    gethostbyname_mock = mocker.patch(
        "socket.gethostbyname_ex",
        return_value=("some-other-alias.example.com", [S3FILES_DNS_NAME], [IP_ADDRESS]),
    )
    config = _get_mock_config()
    result_fs_id, path, az = dns_resolver.match_device(config, CUSTOM_CNAME, {})
    assert result_fs_id == fs_id
    assert path == "/"
    assert az == DEFAULT_AZ_ID
    utils.assert_called(get_dns_name_mock)
    utils.assert_called(gethostbyname_mock)


def test_s3files_match_device_unresolvable_domain(mocker, capsys):
    """A CNAME that does not resolve at all must cause a REAL abort (SystemExit)."""
    gethostbyname_mock = mocker.patch(
        "socket.gethostbyname_ex", side_effect=socket.gaierror
    )
    config = _get_mock_config()
    with pytest.raises(SystemExit) as ex:
        dns_resolver.match_device(config, CUSTOM_CNAME, {})

    assert ex.value.code != 0
    _out, err = capsys.readouterr()
    assert "Failed to resolve" in err
    assert CUSTOM_CNAME in err
    utils.assert_called(gethostbyname_mock)


def test_s3files_match_device_no_hostnames(mocker, capsys):
    """A CNAME resolving to no usable hostnames must cause a REAL abort."""
    gethostbyname_mock = mocker.patch(
        "socket.gethostbyname_ex",
        return_value=(None, [], [IP_ADDRESS]),
    )
    config = _get_mock_config()
    with pytest.raises(SystemExit) as ex:
        dns_resolver.match_device(config, CUSTOM_CNAME, {})

    assert ex.value.code != 0
    _out, err = capsys.readouterr()
    assert "did not resolve to an S3Files mount target" in err
    utils.assert_called(gethostbyname_mock)


def test_s3files_match_device_resolve_to_invalid_dns_name(mocker, capsys):
    """A CNAME resolving to a hostname that is not a valid S3Files DNS name must
    cause a REAL abort."""
    gethostbyname_mock = mocker.patch(
        "socket.gethostbyname_ex",
        return_value=("invalid-name.example.com", [], [IP_ADDRESS]),
    )
    config = _get_mock_config()
    with pytest.raises(SystemExit) as ex:
        dns_resolver.match_device(config, CUSTOM_CNAME, {})

    assert ex.value.code != 0
    _out, err = capsys.readouterr()
    assert "did not resolve to a valid DNS name" in err
    utils.assert_called(gethostbyname_mock)


def test_s3files_match_device_resolve_to_unexpected_dns_name(mocker, capsys):
    """A CNAME resolving to an S3Files-shaped hostname that does not exactly match
    the expected mount-target DNS name must cause a REAL abort."""
    get_dns_name_mock = mocker.patch(
        "mount_s3files.dns_resolver.get_dns_name_and_mount_target_ip_address",
        return_value=(
            "use1-az1.fs-deadbeef.s3files.us-west-2.on.aws",
            None,
        ),
    )
    gethostbyname_mock = mocker.patch(
        "socket.gethostbyname_ex",
        return_value=(S3FILES_DNS_NAME, [], [IP_ADDRESS]),
    )
    config = _get_mock_config()
    with pytest.raises(SystemExit) as ex:
        dns_resolver.match_device(config, CUSTOM_CNAME, {})

    assert ex.value.code != 0
    _out, err = capsys.readouterr()
    assert "did not resolve to a valid DNS name" in err
    utils.assert_called(get_dns_name_mock)
    utils.assert_called(gethostbyname_mock)


def test_s3files_match_device_azid_mismatch_aborts(mocker, capsys):
    """When the resolved hostname's az_id does not match an azid provided in the
    mount options, match_device must REALLY abort."""
    gethostbyname_mock = mocker.patch(
        "socket.gethostbyname_ex",
        return_value=(S3FILES_DNS_NAME, [], [IP_ADDRESS]),
    )
    config = _get_mock_config()
    with pytest.raises(SystemExit) as ex:
        dns_resolver.match_device(config, CUSTOM_CNAME, {"azid": "use1-az2"})

    assert ex.value.code != 0
    _out, err = capsys.readouterr()
    assert "does not match the azid provided" in err
    utils.assert_called(gethostbyname_mock)


def test_s3files_match_device_cname_literal_attempted_before_dotted(mocker):
    """Guards COE-404021 for the S3Files match_device CNAME path: resolution must
    attempt the literal CNAME FIRST, then retry with a trailing dot only if the
    literal attempt fails. If the order were reversed, the literal form would never
    be attempted and call_count would be 1 (dotted only) instead of 2."""
    mocker.patch(
        "mount_s3files.dns_resolver.get_dns_name_and_mount_target_ip_address",
        return_value=(S3FILES_DNS_NAME, None),
    )

    def fake_gethostbyname_ex(host, *args, **kwargs):
        # Only the trailing-dot form resolves; the literal form raises NXDOMAIN.
        if host == CUSTOM_CNAME + ".":
            return (S3FILES_DNS_NAME, [], [IP_ADDRESS])
        raise socket.gaierror

    gethostbyname_mock = mocker.patch(
        "socket.gethostbyname_ex", side_effect=fake_gethostbyname_ex
    )
    config = _get_mock_config()

    result_fs_id, path, az = dns_resolver.match_device(config, CUSTOM_CNAME, {})

    assert result_fs_id == fs_id
    # Bare CNAME (no ":/subpath") must resolve to the root path, matching the other
    # S3Files CNAME tests (e.g. test_s3files_match_device_cname_in_secondaries).
    assert path == "/"
    assert az == DEFAULT_AZ_ID
    # Exactly two attempts, in order: literal CNAME first, then trailing-dot retry.
    assert gethostbyname_mock.call_count == 2
    assert gethostbyname_mock.call_args_list[0][0][0] == CUSTOM_CNAME
    assert gethostbyname_mock.call_args_list[1][0][0] == CUSTOM_CNAME + "."
