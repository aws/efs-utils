#
# Copyright 2026 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import logging
from contextlib import contextmanager

import pytest
from pytest_mock import MockFixture

import efs_utils_common.context as efs_context
import mount_s3files
from efs_utils_common.constants import PROXY_MODE_STUNNEL

from .. import utils


@contextmanager
def dummy_contextmanager(*args, **kwargs):
    yield


def _test_main(
    mocker: MockFixture,
    fake: bool = False,
    region: str = "us-west-1",
    fips: bool = False,
) -> None:
    """
    Test mount_s3files.main() with configurable fake mount behavior.
    S3 Files always uses IAM+TLS, so the mount path is always mount_with_proxy.
    """
    options = {"iam": None, "tls": None}

    mocker.patch("os.geteuid", return_value=0)
    bootstrap_logging_mock = mocker.patch("mount_s3files.bootstrap_logging")
    network_status_check_mock = mocker.patch("mount_s3files.check_network_status")
    mocker.patch(
        target="mount_s3files.get_target_region",
        return_value=region,
    )
    mocker.patch(
        target="efs_utils_common.metadata.get_fips_config",
        return_value=fips,
    )
    get_dns_mock = mocker.patch(
        "mount_s3files.get_dns_name_and_mount_target_ip_address",
        return_value=("fs-deadbeef.efs.us-west-1.amazonaws.com", None),
    )
    parse_arguments_mock = mocker.patch(
        "mount_s3files.parse_arguments",
        return_value=("fs-deadbeef", "/", "/mnt", options, fake),
    )
    bootstrap_proxy_mock = mocker.patch(
        "efs_utils_common.mount_utils.bootstrap_proxy",
        side_effect=dummy_contextmanager,
    )
    mount_mock = mocker.patch("efs_utils_common.mount_utils.mount_nfs")

    mock_context = mocker.MagicMock()
    mock_context.proxy_mode = "efs_proxy"
    mocker.patch("efs_utils_common.metadata.MountContext", return_value=mock_context)

    mocker.patch(
        "efs_utils_common.network_utils.verify_tlsport_can_be_connected",
        return_value=True,
    )
    mocker.patch("mount_s3files.bootstrap_cloudwatch_logging", return_value=None)

    mount_s3files.main()

    # Validation always runs
    utils.assert_called_once(bootstrap_logging_mock)
    utils.assert_called_once(network_status_check_mock)
    utils.assert_called_once(get_dns_mock)
    utils.assert_called_once(parse_arguments_mock)

    if fake:
        utils.assert_not_called(mount_mock)
        utils.assert_not_called(bootstrap_proxy_mock)
        return
    else:
        utils.assert_called_once(mount_mock)
        utils.assert_called_once(bootstrap_proxy_mock)


def test_main_fake_mount_s3files(mocker):
    """Test that -f/--fake skips the actual mount for s3files."""
    _test_main(mocker, fake=True)


def test_main_normal_mount_s3files(mocker):
    """Test the normal (non-fake) mount path for s3files."""
    _test_main(mocker, fake=False)


def test_main_fips_in_us_region_s3files(mocker: MockFixture) -> None:
    _test_main(
        mocker=mocker,
        region="us-east-1",
        fips=True,
    )


def test_main_fips_outside_us_and_canada_s3files(
    mocker: MockFixture,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # The mount goes ahead and logs the region warning.
    with caplog.at_level(logging.WARNING):
        _test_main(
            mocker=mocker,
            region="eu-west-2",
            fips=True,
        )

    assert "region eu-west-2 has no FIPS endpoints" in caplog.text


def test_main_macos_does_not_warn_about_legacy_stunnel_mode(mocker, capsys, caplog):
    """
    On macOS an s3files mount runs in legacy stunnel mode, but must not warn: there is
    no efs-proxy build for macOS, so it is not a choice the caller can act on. Uses the
    real MountContext so the real selection runs.
    """
    caplog.set_level(logging.WARNING)
    efs_context.MountContext().reset()

    mocker.patch("os.geteuid", return_value=0)
    mocker.patch("mount_s3files.read_config", return_value=mocker.MagicMock())
    mocker.patch("mount_s3files.bootstrap_logging")
    mocker.patch("mount_s3files.check_if_platform_is_mac", return_value=True)
    mocker.patch("mount_s3files.check_if_mac_version_is_supported", return_value=True)
    mocker.patch("mount_s3files.bootstrap_cloudwatch_logging", return_value=None)
    mocker.patch("mount_s3files.check_network_status")
    mocker.patch(
        "mount_s3files.get_dns_name_and_mount_target_ip_address",
        return_value=("fs-deadbeef.efs.us-west-1.amazonaws.com", None),
    )
    mocker.patch(
        "mount_s3files.parse_arguments",
        return_value=("fs-deadbeef", "/", "/mnt", {"iam": None}, False),
    )
    # Stub the mount entry points rather than spawning a real tunnel.
    mocker.patch("mount_s3files.mount_nfs")
    mocker.patch("mount_s3files.mount_with_proxy")

    try:
        mount_s3files.main()
        assert efs_context.MountContext().proxy_mode == PROXY_MODE_STUNNEL
    finally:
        efs_context.MountContext().reset()

    assert "stunnel" not in capsys.readouterr().err
    assert "stunnel" not in caplog.text
