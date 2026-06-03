#
# Copyright 2026 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

from contextlib import contextmanager

import mount_s3files

from .. import utils


@contextmanager
def dummy_contextmanager(*args, **kwargs):
    yield


def _test_main(mocker, fake=False):
    """
    Test mount_s3files.main() with configurable fake mount behavior.
    S3 Files always uses IAM+TLS, so the mount path is always mount_with_proxy.
    """
    options = {"iam": None, "tls": None}

    mocker.patch("os.geteuid", return_value=0)
    bootstrap_logging_mock = mocker.patch("mount_s3files.bootstrap_logging")
    network_status_check_mock = mocker.patch("mount_s3files.check_network_status")
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
