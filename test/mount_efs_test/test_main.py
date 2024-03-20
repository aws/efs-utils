# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.

from contextlib import contextmanager
from unittest.mock import MagicMock

import pytest

import mount_efs

from .. import utils

AP_ID = "fsap-0123456789abcdef0"
BAD_AP_ID_INCORRECT_START = "bad-fsap-0123456789abc"
BAD_AP_ID_TOO_SHORT = "fsap-0123456789abcdef"
BAD_AP_ID_BAD_CHAR = "fsap-0123456789abcdefg"
PORT = 3000
TLS_PORT = 10000
AWSPROFILE = "test_profile"
AWSCREDSURI = "/v2/credentials/{uuid}"
TLSPORT_INCORRECT = "incorrect"
AZ_ID = "usw1-az1"


@contextmanager
def dummy_contextmanager(*args, **kwargs):
    yield


def _test_main(
    mocker,
    tls=False,
    root=True,
    ap_id=None,
    iam=False,
    awsprofile=None,
    ocsp=False,
    noocsp=False,
    port=None,
    tlsport=None,
    awscredsuri=None,
    notls=False,
    crossaccount=False,
):
    options = {}

    if tls:
        options["tls"] = None
    if notls:
        options["notls"] = None
    if ap_id is not None:
        options["accesspoint"] = ap_id
    if iam:
        options["iam"] = None
    if awsprofile is not None:
        options["awsprofile"] = awsprofile
    if ocsp:
        options["ocsp"] = None
    if noocsp:
        options["noocsp"] = None
    if port is not None:
        options["port"] = port
    if tlsport is not None:
        options["tlsport"] = tlsport
    if awscredsuri is not None:
        options["awscredsuri"] = awscredsuri
    if crossaccount:
        options["crossaccount"] = None

    if root:
        mocker.patch("os.geteuid", return_value=0)
    else:
        mocker.patch("os.geteuid", return_value=100)

    bootstrap_logging_mock = mocker.patch("mount_efs.bootstrap_logging")
    network_status_check_mock = mocker.patch("mount_efs.check_network_status")
    if crossaccount:
        get_dns_mock = mocker.patch(
            "mount_efs.get_dns_name_and_fallback_mount_target_ip_address",
            return_value=("usw1-az1.fs-deadbeef.efs.us-west-1.amazonaws.com", None),
        )
    else:
        get_dns_mock = mocker.patch(
            "mount_efs.get_dns_name_and_fallback_mount_target_ip_address",
            return_value=("fs-deadbeef.efs.us-west-1.amazonaws.com", None),
        )
    parse_arguments_mock = mocker.patch(
        "mount_efs.parse_arguments", return_value=("fs-deadbeef", "/", "/mnt", options)
    )
    bootstrap_tls_mock = mocker.patch(
        "mount_efs.bootstrap_tls", side_effect=dummy_contextmanager
    )

    if tls:
        mocker.patch("mount_efs.verify_tlsport_can_be_connected", return_value=True)
    mount_mock = mocker.patch("mount_efs.mount_nfs")

    mount_efs.main()

    utils.assert_called_once(bootstrap_logging_mock)
    utils.assert_called_once(network_status_check_mock)
    utils.assert_called_once(get_dns_mock)
    utils.assert_called_once(parse_arguments_mock)
    utils.assert_called_once(mount_mock)

    if tls:
        utils.assert_called_once(bootstrap_tls_mock)
    else:
        utils.assert_not_called(bootstrap_tls_mock)


def _test_main_assert_error(mocker, capsys, expected_err, **kwargs):
    with pytest.raises(SystemExit) as ex:
        _test_main(mocker, **kwargs)

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert expected_err in err


def _test_main_macos(mocker, is_supported_macos_version, **kwargs):
    mocker.patch("mount_efs.check_if_platform_is_mac", return_value=True)
    mocker.patch(
        "mount_efs.check_if_mac_version_is_supported",
        return_value=is_supported_macos_version,
    )
    _test_main(mocker, **kwargs)


def _test_main_macos_assert_error(
    mocker, capsys, expected_err, is_supported_macos_version, **kwargs
):
    mocker.patch("mount_efs.check_if_platform_is_mac", return_value=True)
    mocker.patch(
        "mount_efs.check_if_mac_version_is_supported",
        return_value=is_supported_macos_version,
    )
    _test_main_assert_error(mocker, capsys, expected_err, **kwargs)


def test_main_tls(mocker):
    _test_main(mocker, tls=True, tlsport=TLS_PORT)


def test_main_no_tls(mocker):
    _test_main(mocker, tls=False)


def test_main_non_root(mocker, capsys):
    expected_err = "only root"
    _test_main_assert_error(mocker, capsys, expected_err, root=False)


def test_main_good_ap_with_tls(mocker):
    _test_main(mocker, tls=True, ap_id=AP_ID, tlsport=TLS_PORT)


def test_main_bad_ap_incorrect_start_with_tls(mocker, capsys):
    expected_err = "Access Point ID %s is malformed" % BAD_AP_ID_INCORRECT_START
    _test_main_assert_error(
        mocker,
        capsys,
        expected_err,
        tls=True,
        ap_id=BAD_AP_ID_INCORRECT_START,
        tlsport=TLS_PORT,
    )


def test_main_bad_ap_too_short_with_tls(mocker, capsys):
    expected_err = "Access Point ID %s is malformed" % BAD_AP_ID_TOO_SHORT
    _test_main_assert_error(
        mocker,
        capsys,
        expected_err,
        tls=True,
        ap_id=BAD_AP_ID_TOO_SHORT,
        tlsport=TLS_PORT,
    )


def test_main_bad_ap_bad_char_with_tls(mocker, capsys):
    expected_err = "Access Point ID %s is malformed" % BAD_AP_ID_BAD_CHAR
    _test_main_assert_error(
        mocker,
        capsys,
        expected_err,
        tls=True,
        ap_id=BAD_AP_ID_BAD_CHAR,
        tlsport=TLS_PORT,
    )


def test_main_ap_without_tls(mocker, capsys):
    expected_err = '"tls" option is required'
    _test_main_assert_error(mocker, capsys, expected_err, ap_id=AP_ID)


def test_main_iam_with_tls(mocker):
    _test_main(mocker, tls=True, iam=True, tlsport=TLS_PORT)


def test_main_iam_without_tls(mocker, capsys):
    expected_err = '"tls" option is required'
    _test_main_assert_error(mocker, capsys, expected_err, iam=True)


def test_main_awsprofile_with_iam(mocker):
    _test_main(mocker, tls=True, iam=True, awsprofile=AWSPROFILE, tlsport=TLS_PORT)


def test_main_awsprofile_without_iam(mocker, capsys):
    expected_err = 'The "iam" option is required when mounting with named profile option, "awsprofile"'
    _test_main_assert_error(
        mocker, capsys, expected_err, tls=True, awsprofile=AWSPROFILE, tlsport=TLS_PORT
    )


def test_main_awscredsuri_without_iam(mocker, capsys):
    expected_err = 'The "iam" option is required when mounting with "awscredsuri"'
    _test_main_assert_error(
        mocker,
        capsys,
        expected_err,
        tls=True,
        awscredsuri=AWSCREDSURI,
        tlsport=TLS_PORT,
    )


def test_main_tls_ocsp_option(mocker):
    _test_main(mocker, tls=True, ocsp=True, tlsport=TLS_PORT)


def test_main_tls_noocsp_option(mocker):
    _test_main(mocker, tls=True, noocsp=True, tlsport=TLS_PORT)


def test_main_tls_ocsp_and_noocsp_option(mocker, capsys):
    expected_err = 'The "ocsp" and "noocsp" options are mutually exclusive'
    _test_main_assert_error(
        mocker, capsys, expected_err, tls=True, ocsp=True, noocsp=True, tlsport=TLS_PORT
    )


def test_main_port_without_tls(mocker):
    _test_main(mocker, port=PORT)


def test_main_port_with_tls(mocker, capsys):
    expected_err = 'The "port" and "tls" options are mutually exclusive'
    _test_main_assert_error(
        mocker, capsys, expected_err, tls=True, port=PORT, tlsport=TLS_PORT
    )


def test_main_aws_creds_uri_with_aws_profile(mocker, capsys):
    expected_err = 'The "awscredsuri" and "awsprofile" options are mutually exclusive'
    _test_main_assert_error(
        mocker,
        capsys,
        expected_err,
        tls=True,
        iam=True,
        awscredsuri=AWSCREDSURI,
        awsprofile=AWSPROFILE,
        tlsport=TLS_PORT,
    )


def test_main_aws_creds_uri_malformed(mocker, capsys):
    expected_err = "is malformed"
    _test_main_assert_error(
        mocker, capsys, expected_err, tls=True, iam=True, awscredsuri=".random"
    )


def test_main_tlsport_is_integer(mocker):
    _test_main(mocker, tls=True, tlsport=TLS_PORT)


def test_main_tlsport_is_not_integer(mocker, capsys):
    expected_err = "is not an integer"
    _test_main_assert_error(
        mocker, capsys, expected_err, tls=True, tlsport=TLSPORT_INCORRECT
    )


def test_main_tls_mount_point_mounted_with_non_nfs(mocker):
    mocker.patch("os.path.ismount", return_value=True)
    mocker.patch("mount_efs.is_nfs_mount", return_value=False)
    _test_main(mocker, tls=True, tlsport=TLS_PORT)


def _mock_popen(mocker, returncode=0, stdout="stdout", stderr="stderr"):
    popen_mock = MagicMock()
    popen_mock.communicate.return_value = (
        stdout,
        stderr,
    )
    popen_mock.returncode = returncode

    return mocker.patch("subprocess.Popen", return_value=popen_mock)


def test_main_unsupported_macos(mocker, capsys):
    # Test for Catalina Client
    expected_err = "We do not support EFS on MacOS"
    _test_main_macos_assert_error(
        mocker, capsys, expected_err, root=True, is_supported_macos_version=False
    )


def test_main_supported_macos(mocker):
    _test_main_macos(
        mocker, is_supported_macos_version=True, tls=True, tlsport=TLS_PORT
    )


def test_main_tls_notls_option_macos(mocker):
    _test_main_macos(mocker, is_supported_macos_version=True, notls=True)


def test_main_tls_ocsp_and_noocsp_option(mocker, capsys):
    expected_err = 'The "tls" and "notls" options are mutually exclusive'
    _test_main_assert_error(
        mocker, capsys, expected_err, tls=True, tlsport=TLS_PORT, notls=True
    )


def test_main_crossaccount_and_tls_option(mocker):
    _test_main(mocker, crossaccount=True, tls=True, tlsport=TLS_PORT)


def test_main_crossaccount_without_tls_option(mocker):
    _test_main(mocker, crossaccount=True, tls=False)


def test_main_crossaccount_tls_and_ap_option(mocker):
    _test_main(mocker, crossaccount=True, tls=True, ap_id=AP_ID, tlsport=TLS_PORT)
