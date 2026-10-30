# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
import os
import tempfile
from unittest.mock import MagicMock

import pytest

import efs_utils_common
import efs_utils_common.certificate_utils as certificate_utils
import efs_utils_common.constants as constants
import efs_utils_common.proxy as proxy

try:
    import ConfigParser
except ImportError:
    from configparser import ConfigParser

AP_ID = "fsap-beefdead"
FS_ID = "fs-deadbeef"
CLIENT_SOURCE = "test"
DNS_NAME = "%s.efs.us-east-1.amazonaws.com" % FS_ID
MOUNT_POINT = "/mnt"
REGION = "us-east-1"

DEFAULT_TLS_PORT = 20049

EXPECTED_STUNNEL_CONFIG_FILE_BASE = "stunnel-config.fs-deadbeef.mnt."
EXPECTED_STUNNEL_CONFIG_FILE = EXPECTED_STUNNEL_CONFIG_FILE_BASE + str(DEFAULT_TLS_PORT)

INIT_SYSTEM = "upstart"

MOCK_CONFIG = MagicMock()


def setup_mocks(mocker, patch_worker_threads=True):
    mocker.patch("efs_utils_common.proxy.start_watchdog")
    # MOCK_CONFIG is a MagicMock, so any real read of it yields a MagicMock (or
    # trips a side_effect another test installed) rather than a usable value.
    # Default the optional worker-thread item to "not configured"; tests that
    # exercise it either override this patch or opt out and pass a real config.
    if patch_worker_threads:
        mocker.patch(
            "efs_utils_common.proxy.get_efs_proxy_worker_threads", return_value=None
        )
    mocker.patch(
        "efs_utils_common.proxy.get_tls_port_range",
        return_value=(DEFAULT_TLS_PORT, DEFAULT_TLS_PORT + 10),
    )
    mocker.patch("socket.socket", return_value=MagicMock())
    mocker.patch(
        "mount_efs.dns_resolver.get_dns_name_and_fallback_mount_target_ip_address",
        return_value=(DNS_NAME, None),
    )
    mocker.patch("efs_utils_common.proxy.get_target_region", return_value=REGION)
    mocker.patch(
        "efs_utils_common.proxy.write_tunnel_state_file", return_value="~mocktempfile"
    )
    mocker.patch("efs_utils_common.proxy.create_certificate")
    mocker.patch("os.rename")
    mocker.patch("os.kill")
    mocker.patch(
        "efs_utils_common.proxy.update_tunnel_temp_state_file_with_tunnel_pid",
        return_value="~mocktempfile",
    )

    mocker.patch(
        "efs_utils_common.config_utils.get_efs_proxy_log_level", return_value="info"
    )

    process_mock = MagicMock()
    process_mock.communicate.return_value = (
        "stdout",
        "stderr",
    )
    # A tunnel that is still running and listening on its port.
    process_mock.returncode = None
    mocker.patch("efs_utils_common.proxy.process_listens_on_port", return_value=True)

    popen_mock = mocker.patch("subprocess.Popen", return_value=process_mock)
    write_config_mock = mocker.patch(
        "efs_utils_common.proxy.write_stunnel_config_file",
        return_value=EXPECTED_STUNNEL_CONFIG_FILE,
    )
    return popen_mock, write_config_mock


def setup_mocks_without_popen(mocker):
    mocker.patch("efs_utils_common.proxy.start_watchdog")
    # See the note in setup_mocks: MOCK_CONFIG cannot answer a real config read.
    mocker.patch(
        "efs_utils_common.proxy.get_efs_proxy_worker_threads", return_value=None
    )
    mocker.patch(
        "efs_utils_common.proxy.get_tls_port_range",
        return_value=(DEFAULT_TLS_PORT, DEFAULT_TLS_PORT + 10),
    )
    mocker.patch("socket.gethostname", return_value=DNS_NAME)
    mocker.patch(
        "mount_efs.dns_resolver.get_dns_name_and_fallback_mount_target_ip_address",
        return_value=(DNS_NAME, None),
    )
    mocker.patch(
        "efs_utils_common.proxy.write_tunnel_state_file", return_value="~mocktempfile"
    )
    mocker.patch("os.kill")
    mocker.patch(
        "efs_utils_common.proxy.update_tunnel_temp_state_file_with_tunnel_pid",
        return_value="~mocktempfile",
    )

    write_config_mock = mocker.patch(
        "efs_utils_common.proxy.write_stunnel_config_file",
        return_value=EXPECTED_STUNNEL_CONFIG_FILE,
    )
    return write_config_mock


def test_bootstrap_proxy_state_file_dir_exists(mocker, tmpdir):
    popen_mock, _ = setup_mocks(mocker)
    state_file_dir = str(tmpdir)
    mocker.patch("efs_utils_common.proxy.is_ocsp_enabled", return_value=False)
    mocker.patch(
        "efs_utils_common.proxy._efs_proxy_bin", return_value="/usr/bin/efs-proxy"
    )
    with proxy.bootstrap_proxy(
        MOCK_CONFIG, INIT_SYSTEM, DNS_NAME, FS_ID, MOUNT_POINT, {}, state_file_dir
    ):
        pass

    args, _ = popen_mock.call_args
    args = args[0]

    assert "/usr/bin/efs-proxy" in args
    assert EXPECTED_STUNNEL_CONFIG_FILE in args


def _bootstrap(mocker, state_file_dir):
    mocker.patch("efs_utils_common.proxy.is_ocsp_enabled", return_value=False)
    mocker.patch(
        "efs_utils_common.proxy._efs_proxy_bin", return_value="/usr/bin/efs-proxy"
    )
    with proxy.bootstrap_proxy(
        MOCK_CONFIG, INIT_SYSTEM, DNS_NAME, FS_ID, MOUNT_POINT, {}, state_file_dir
    ):
        pass


def test_bootstrap_proxy_tolerates_state_file_finalized_by_watchdog(mocker, tmpdir):
    # The watchdog renamed the temp first; the record is in place.
    setup_mocks(mocker)
    mocker.patch("os.rename", side_effect=FileNotFoundError())
    tmpdir.join("mocktempfile").write("{}")

    _bootstrap(mocker, str(tmpdir))


def test_bootstrap_proxy_fails_when_state_file_is_missing(mocker, tmpdir):
    setup_mocks(mocker)
    mocker.patch("os.rename", side_effect=FileNotFoundError())

    with pytest.raises(FileNotFoundError):
        _bootstrap(mocker, str(tmpdir))


def test_bootstrap_proxy_state_file_nonexistent_dir(mocker, tmpdir):
    popen_mock, _ = setup_mocks(mocker)
    state_file_dir = str(tmpdir.join(tempfile.mkdtemp()[1]))

    def config_get_side_effect(section, field):
        if (
            section == efs_utils_common.constants.CONFIG_SECTION
            and field == "state_file_dir_mode"
        ):
            return "0755"
        elif (
            section == efs_utils_common.constants.CONFIG_SECTION
            and field == "dns_name_format"
        ):
            return "{fs_id}.efs.{region}.amazonaws.com"
        elif (
            section == efs_utils_common.constants.CLIENT_INFO_SECTION
            and field == "source"
        ):
            return CLIENT_SOURCE
        else:
            raise ValueError("Unexpected arguments")

    MOCK_CONFIG.get.side_effect = config_get_side_effect

    assert not os.path.exists(state_file_dir)

    mocker.patch("efs_utils_common.proxy.is_ocsp_enabled", return_value=False)
    mocker.patch(
        "efs_utils_common.proxy._efs_proxy_bin", return_value="/usr/bin/efs-proxy"
    )
    mocker.patch(
        "efs_utils_common.proxy.find_existing_mount_using_tls_port", return_value=None
    )
    with proxy.bootstrap_proxy(
        MOCK_CONFIG, INIT_SYSTEM, DNS_NAME, FS_ID, MOUNT_POINT, {}, state_file_dir
    ):
        pass

    assert os.path.exists(state_file_dir)


def test_bootstrap_proxy_cert_created_tls_mount(mocker, tmpdir):
    setup_mocks_without_popen(mocker)
    mocker.patch(
        "efs_utils_common.proxy.get_mount_specific_filename", return_value=DNS_NAME
    )
    mocker.patch("efs_utils_common.proxy.get_target_region", return_value=REGION)
    state_file_dir = str(tmpdir)
    tls_dict = certificate_utils.tls_paths_dictionary(DNS_NAME + "+", state_file_dir)
    mocker.patch("efs_utils_common.proxy.is_ocsp_enabled", return_value=False)
    pk_path = os.path.join(str(tmpdir), "privateKey.pem")
    mocker.patch(
        "efs_utils_common.certificate_utils.get_private_key_path", return_value=pk_path
    )

    def config_get_side_effect(section, field):
        if (
            section == efs_utils_common.constants.CONFIG_SECTION
            and field == "state_file_dir_mode"
        ):
            return "0755"
        elif (
            section == efs_utils_common.constants.CONFIG_SECTION
            and field == "dns_name_format"
        ):
            return "{fs_id}.efs.{region}.amazonaws.com"
        elif (
            section == efs_utils_common.constants.CONFIG_SECTION
            and field == "logging_level"
        ):
            return "info"
        elif (
            section == efs_utils_common.constants.CLIENT_INFO_SECTION
            and field == "source"
        ):
            return CLIENT_SOURCE
        else:
            raise ValueError("Unexpected arguments")

    MOCK_CONFIG.get.side_effect = config_get_side_effect

    mocker.patch(
        "efs_utils_common.proxy._efs_proxy_bin", return_value="/usr/bin/efs-proxy"
    )
    try:
        with proxy.bootstrap_proxy(
            MOCK_CONFIG,
            INIT_SYSTEM,
            DNS_NAME,
            FS_ID,
            MOUNT_POINT,
            {"accesspoint": AP_ID, "tls": None},
            state_file_dir,
        ):
            pass
    except OSError as e:
        assert "[Errno 2] No such file or directory" in str(e)

    assert os.path.exists(os.path.join(tls_dict["mount_dir"], "certificate.pem"))
    assert os.path.exists(os.path.join(tls_dict["mount_dir"], "request.csr"))
    assert os.path.exists(os.path.join(tls_dict["mount_dir"], "config.conf"))
    assert os.path.exists(pk_path)


def test_bootstrap_proxy_persists_credential_expiration_for_iam_mount(mocker, tmpdir):
    write_config_mock = setup_mocks_without_popen(mocker)
    write_state_mock = mocker.patch(
        "efs_utils_common.proxy.write_tunnel_state_file", return_value="~mocktempfile"
    )
    mocker.patch(
        "efs_utils_common.proxy.get_mount_specific_filename", return_value=DNS_NAME
    )
    mocker.patch("efs_utils_common.proxy.get_target_region", return_value=REGION)
    mocker.patch("efs_utils_common.proxy.is_ocsp_enabled", return_value=False)
    mocker.patch("efs_utils_common.proxy.create_certificate", return_value="dummytime")
    mocker.patch(
        "efs_utils_common.proxy._efs_proxy_bin", return_value="/usr/bin/efs-proxy"
    )
    pk_path = os.path.join(str(tmpdir), "privateKey.pem")
    mocker.patch("efs_utils_common.proxy.get_private_key_path", return_value=pk_path)

    expiration = "2026-08-06T00:38:37Z"  # whole-second ISO-8601 shape IMDS returns
    mocker.patch(
        "efs_utils_common.proxy.get_aws_security_credentials",
        return_value=(
            {
                "AccessKeyId": "AKID",
                "SecretAccessKey": "SECRET",
                "Token": "TOKEN",
                "Expiration": expiration,
            },
            "metadata:",
        ),
    )

    MOCK_CONFIG.get.side_effect = None
    MOCK_CONFIG.get.return_value = "info"
    MOCK_CONFIG.getboolean.return_value = True

    try:
        with proxy.bootstrap_proxy(
            MOCK_CONFIG,
            INIT_SYSTEM,
            DNS_NAME,
            FS_ID,
            MOUNT_POINT,
            {"tls": None, "iam": None},
            str(tmpdir),
        ):
            pass
    except OSError:
        pass

    assert write_state_mock.called
    cert_details = write_state_mock.call_args.kwargs["cert_details"]
    assert cert_details["certificateExpirationTime"] == expiration
    assert write_config_mock.called


@pytest.mark.parametrize(
    argnames="fips",
    argvalues=[
        True,
        False,
    ],
)
def test_bootstrap_proxy_records_fips_choice_for_iam_mount(
    mocker,
    tmpdir,
    fips: bool,
) -> None:
    # The watchdog refreshes the mount's credentials through the STS endpoint this
    # choice selects, so the state file must carry it.
    setup_mocks_without_popen(mocker)
    write_state_mock = mocker.patch(
        target="efs_utils_common.proxy.write_tunnel_state_file",
        return_value="~mocktempfile",
    )
    return_values: dict[str, object] = {
        "efs_utils_common.proxy.get_mount_specific_filename": DNS_NAME,
        "efs_utils_common.proxy.get_target_region": REGION,
        "efs_utils_common.proxy.is_ocsp_enabled": False,
        "efs_utils_common.proxy.create_certificate": "dummytime",
        "efs_utils_common.proxy._efs_proxy_bin": "/usr/bin/efs-proxy",
        "efs_utils_common.proxy.get_private_key_path": os.path.join(
            str(tmpdir),
            "privateKey.pem",
        ),
        "efs_utils_common.proxy.get_aws_security_credentials": (
            {
                "AccessKeyId": "AKID",
                "SecretAccessKey": "SECRET",
                "Token": "TOKEN",
            },
            "webidentity:arn:aws:iam::123456789012:role/efs,/tmp/token",
        ),
        "efs_utils_common.proxy.get_fips_config": fips,
    }
    target: str
    return_value: object
    for target, return_value in return_values.items():
        mocker.patch(
            target=target,
            return_value=return_value,
        )

    MOCK_CONFIG.get.side_effect = None
    MOCK_CONFIG.get.return_value = "info"
    MOCK_CONFIG.getboolean.return_value = True

    try:
        with proxy.bootstrap_proxy(
            config=MOCK_CONFIG,
            init_system=INIT_SYSTEM,
            dns_name=DNS_NAME,
            fs_id=FS_ID,
            mountpoint=MOUNT_POINT,
            options={
                "tls": None,
                "iam": None,
            },
            state_file_dir=str(tmpdir),
        ):
            pass
    except OSError:
        pass

    cert_details: dict[str, object] = write_state_mock.call_args.kwargs["cert_details"]
    assert cert_details[constants.USE_FIPS_ENDPOINT_STATE_KEY] is fips


def test_bootstrap_proxy_drops_malformed_credential_expiration(mocker, tmpdir, caplog):
    import logging

    caplog.set_level(logging.WARNING)
    setup_mocks_without_popen(mocker)
    write_state_mock = mocker.patch(
        "efs_utils_common.proxy.write_tunnel_state_file", return_value="~mocktempfile"
    )
    mocker.patch(
        "efs_utils_common.proxy.get_mount_specific_filename", return_value=DNS_NAME
    )
    mocker.patch("efs_utils_common.proxy.get_target_region", return_value=REGION)
    mocker.patch("efs_utils_common.proxy.is_ocsp_enabled", return_value=False)
    mocker.patch("efs_utils_common.proxy.create_certificate", return_value="dummytime")
    mocker.patch(
        "efs_utils_common.proxy._efs_proxy_bin", return_value="/usr/bin/efs-proxy"
    )
    pk_path = os.path.join(str(tmpdir), "privateKey.pem")
    mocker.patch("efs_utils_common.proxy.get_private_key_path", return_value=pk_path)

    mocker.patch(
        "efs_utils_common.proxy.get_aws_security_credentials",
        return_value=(
            {
                "AccessKeyId": "AKID",
                "SecretAccessKey": "SECRET",
                "Token": "TOKEN",
                "Expiration": "1786127616",  # epoch, not ISO-8601
            },
            "metadata:",
        ),
    )

    MOCK_CONFIG.get.side_effect = None
    MOCK_CONFIG.get.return_value = "info"
    MOCK_CONFIG.getboolean.return_value = True

    try:
        with proxy.bootstrap_proxy(
            MOCK_CONFIG,
            INIT_SYSTEM,
            DNS_NAME,
            FS_ID,
            MOUNT_POINT,
            {"tls": None, "iam": None},
            str(tmpdir),
        ):
            pass
    except OSError:
        pass

    assert write_state_mock.called
    cert_details = write_state_mock.call_args.kwargs["cert_details"]
    assert "certificateExpirationTime" not in cert_details
    assert "is not valid ISO-8601" in caplog.text


def test_bootstrap_proxy_no_expiration_logs_debug(mocker, tmpdir, caplog):
    import logging

    caplog.set_level(logging.DEBUG)
    setup_mocks_without_popen(mocker)
    write_state_mock = mocker.patch(
        "efs_utils_common.proxy.write_tunnel_state_file", return_value="~mocktempfile"
    )
    mocker.patch(
        "efs_utils_common.proxy.get_mount_specific_filename", return_value=DNS_NAME
    )
    mocker.patch("efs_utils_common.proxy.get_target_region", return_value=REGION)
    mocker.patch("efs_utils_common.proxy.is_ocsp_enabled", return_value=False)
    mocker.patch("efs_utils_common.proxy.create_certificate", return_value="dummytime")
    mocker.patch(
        "efs_utils_common.proxy._efs_proxy_bin", return_value="/usr/bin/efs-proxy"
    )
    pk_path = os.path.join(str(tmpdir), "privateKey.pem")
    mocker.patch("efs_utils_common.proxy.get_private_key_path", return_value=pk_path)

    mocker.patch(
        "efs_utils_common.proxy.get_aws_security_credentials",
        return_value=(
            {
                "AccessKeyId": "AKID",
                "SecretAccessKey": "SECRET",
                "Token": "TOKEN",
                # no Expiration key
            },
            "metadata:",
        ),
    )

    MOCK_CONFIG.get.side_effect = None
    MOCK_CONFIG.get.return_value = "info"
    MOCK_CONFIG.getboolean.return_value = True

    try:
        with proxy.bootstrap_proxy(
            MOCK_CONFIG,
            INIT_SYSTEM,
            DNS_NAME,
            FS_ID,
            MOUNT_POINT,
            {"tls": None, "iam": None},
            str(tmpdir),
        ):
            pass
    except OSError:
        pass

    assert write_state_mock.called
    cert_details = write_state_mock.call_args.kwargs["cert_details"]
    assert "certificateExpirationTime" not in cert_details
    assert "No credential expiration available" in caplog.text


def test_bootstrap_proxy_cert_not_created_non_tls_mount(mocker, tmpdir):
    setup_mocks_without_popen(mocker)
    mocker.patch(
        "efs_utils_common.proxy.get_mount_specific_filename", return_value=DNS_NAME
    )
    mocker.patch("efs_utils_common.proxy.get_target_region", return_value=REGION)
    state_file_dir = str(tmpdir)
    tls_dict = certificate_utils.tls_paths_dictionary(DNS_NAME + "+", state_file_dir)

    pk_path = os.path.join(str(tmpdir), "privateKey.pem")
    mocker.patch(
        "efs_utils_common.certificate_utils.get_private_key_path", return_value=pk_path
    )

    def config_get_side_effect(section, field):
        if (
            section == efs_utils_common.constants.CONFIG_SECTION
            and field == "state_file_dir_mode"
        ):
            return "0755"
        elif (
            section == efs_utils_common.constants.CONFIG_SECTION
            and field == "dns_name_format"
        ):
            return "{fs_id}.efs.{region}.amazonaws.com"
        elif (
            section == efs_utils_common.constants.CONFIG_SECTION
            and field == "logging_level"
        ):
            return "info"
        elif (
            section == efs_utils_common.constants.CLIENT_INFO_SECTION
            and field == "source"
        ):
            return CLIENT_SOURCE
        else:
            raise ValueError("Unexpected arguments")

    MOCK_CONFIG.get.side_effect = config_get_side_effect

    mocker.patch("efs_utils_common.proxy.is_ocsp_enabled", return_value=False)
    mocker.patch(
        "efs_utils_common.proxy._efs_proxy_bin", return_value="/usr/bin/efs-proxy"
    )
    try:
        with proxy.bootstrap_proxy(
            MOCK_CONFIG,
            INIT_SYSTEM,
            DNS_NAME,
            FS_ID,
            MOUNT_POINT,
            {"accesspoint": AP_ID},
            state_file_dir,
        ):
            pass
    except OSError as e:
        assert "[Errno 2] No such file or directory" in str(e)

    assert not os.path.exists(os.path.join(tls_dict["mount_dir"], "certificate.pem"))
    assert not os.path.exists(os.path.join(tls_dict["mount_dir"], "request.csr"))
    assert not os.path.exists(os.path.join(tls_dict["mount_dir"], "config.conf"))
    assert not os.path.exists(pk_path)


def test_bootstrap_proxy_non_default_port(mocker, tmpdir):
    popen_mock, write_config_mock = setup_mocks(mocker)
    mocker.patch("os.rename")
    state_file_dir = str(tmpdir)

    tls_port = 1000
    tls_port_sock_mock = MagicMock()
    tls_port_sock_mock.getsockname.return_value = ("local_host", tls_port)
    tls_port_sock_mock.close.side_effect = None
    mocker.patch("socket.socket", return_value=tls_port_sock_mock)
    mocker.patch("efs_utils_common.proxy.is_ocsp_enabled", return_value=False)
    mocker.patch(
        "efs_utils_common.proxy._efs_proxy_bin", return_value="/usr/bin/efs-proxy"
    )
    with proxy.bootstrap_proxy(
        MOCK_CONFIG,
        INIT_SYSTEM,
        DNS_NAME,
        FS_ID,
        MOUNT_POINT,
        {"tlsport": tls_port},
        state_file_dir,
    ):
        pass

    popen_args, _ = popen_mock.call_args
    popen_args = popen_args[0]
    write_config_args, _ = write_config_mock.call_args

    assert "/usr/bin/efs-proxy" in popen_args
    assert EXPECTED_STUNNEL_CONFIG_FILE in popen_args
    assert tls_port == write_config_args[4]  # positional argument for tls_port
    # Ensure the socket used to choose the tls port is closed in bootstrap_proxy. The
    # tunnel's readiness is read from its own listener, so no socket is opened to
    # connect to the port.
    assert 1 == tls_port_sock_mock.close.call_count


def test_bootstrap_proxy_non_tls_verify_ignored(mocker, tmpdir):
    popen_mock, write_config_mock = setup_mocks(mocker)
    state_file_dir = str(tmpdir)
    mocker.patch("efs_utils_common.proxy.is_ocsp_enabled", return_value=False)
    mocker.patch(
        "efs_utils_common.proxy._efs_proxy_bin", return_value="/usr/bin/efs-proxy"
    )
    with proxy.bootstrap_proxy(
        MOCK_CONFIG,
        INIT_SYSTEM,
        DNS_NAME,
        FS_ID,
        MOUNT_POINT,
        {},
        state_file_dir,
    ):
        pass

    popen_args, _ = popen_mock.call_args
    popen_args = popen_args[0]
    write_config_args, _ = write_config_mock.call_args

    assert "/usr/bin/efs-proxy" in popen_args
    assert EXPECTED_STUNNEL_CONFIG_FILE in popen_args
    assert None == write_config_args[6]  # positional argument for verify_level


def test_bootstrap_proxy_non_default_verify_level_stunnel(mocker, tmpdir):
    popen_mock, write_config_mock = setup_mocks(mocker)
    state_file_dir = str(tmpdir)
    mocker.patch("efs_utils_common.proxy.is_ocsp_enabled", return_value=False)
    verify = 0
    mocker.patch("efs_utils_common.proxy._stunnel_bin", return_value="/usr/bin/stunnel")
    with proxy.bootstrap_proxy(
        MOCK_CONFIG,
        INIT_SYSTEM,
        DNS_NAME,
        FS_ID,
        MOUNT_POINT,
        {"verify": verify, "tls": None},
        state_file_dir,
        efs_proxy_enabled=False,
    ):
        pass

    popen_args, _ = popen_mock.call_args
    popen_args = popen_args[0]
    write_config_args, _ = write_config_mock.call_args

    assert "/usr/bin/stunnel" in popen_args
    assert EXPECTED_STUNNEL_CONFIG_FILE in popen_args
    assert 0 == write_config_args[6]  # positional argument for verify_level


def test_bootstrap_proxy_ocsp_option(mocker, tmpdir):
    popen_mock, write_config_mock = setup_mocks(mocker)
    state_file_dir = str(tmpdir)
    mocker.patch("efs_utils_common.proxy._stunnel_bin", return_value="/usr/bin/stunnel")
    with proxy.bootstrap_proxy(
        MOCK_CONFIG,
        INIT_SYSTEM,
        DNS_NAME,
        FS_ID,
        MOUNT_POINT,
        {"ocsp": None},
        state_file_dir,
        efs_proxy_enabled=False,
    ):
        pass

    popen_args, _ = popen_mock.call_args
    popen_args = popen_args[0]
    write_config_args, _ = write_config_mock.call_args

    assert "/usr/bin/stunnel" in popen_args
    assert EXPECTED_STUNNEL_CONFIG_FILE in popen_args
    # positional argument for ocsp_override
    assert write_config_args[7] is True


def test_bootstrap_proxy_noocsp_option(mocker, tmpdir):
    popen_mock, write_config_mock = setup_mocks(mocker)
    state_file_dir = str(tmpdir)
    mocker.patch("efs_utils_common.proxy._stunnel_bin", return_value="/usr/bin/stunnel")
    with proxy.bootstrap_proxy(
        MOCK_CONFIG,
        INIT_SYSTEM,
        DNS_NAME,
        FS_ID,
        MOUNT_POINT,
        {"noocsp": None},
        state_file_dir,
        efs_proxy_enabled=False,
    ):
        pass

    popen_args, _ = popen_mock.call_args
    popen_args = popen_args[0]
    write_config_args, _ = write_config_mock.call_args

    assert "/usr/bin/stunnel" in popen_args
    assert EXPECTED_STUNNEL_CONFIG_FILE in popen_args
    # positional argument for ocsp_override
    assert write_config_args[7] is False


def test_bootstrap_proxy_efs_proxy_enabled_tls(mocker, tmpdir):
    popen_mock, _ = setup_mocks(mocker)
    mocker.patch("os.rename")
    state_file_dir = str(tmpdir)
    mocker.patch("efs_utils_common.proxy.is_ocsp_enabled", return_value=False)
    mocker.patch(
        "efs_utils_common.proxy._efs_proxy_bin", return_value="/usr/bin/efs-proxy"
    )
    with proxy.bootstrap_proxy(
        MOCK_CONFIG,
        INIT_SYSTEM,
        DNS_NAME,
        FS_ID,
        MOUNT_POINT,
        {"tls": None},
        state_file_dir,
        efs_proxy_enabled=True,
    ):
        pass

    popen_args, _ = popen_mock.call_args
    popen_args = popen_args[0]

    assert "/usr/bin/efs-proxy" in popen_args
    assert "--tls" in popen_args
    assert EXPECTED_STUNNEL_CONFIG_FILE in popen_args


def test_bootstrap_proxy_efs_proxy_enabled_non_tls(mocker, tmpdir):
    popen_mock, _ = setup_mocks(mocker)
    mocker.patch("os.rename")
    state_file_dir = str(tmpdir)
    mocker.patch("efs_utils_common.proxy.is_ocsp_enabled", return_value=False)
    mocker.patch(
        "efs_utils_common.proxy._efs_proxy_bin", return_value="/usr/bin/efs-proxy"
    )
    with proxy.bootstrap_proxy(
        MOCK_CONFIG,
        INIT_SYSTEM,
        DNS_NAME,
        FS_ID,
        MOUNT_POINT,
        {},
        state_file_dir,
        efs_proxy_enabled=True,
    ):
        pass

    popen_args, _ = popen_mock.call_args
    popen_args = popen_args[0]

    assert "/usr/bin/stunnel" not in popen_args
    assert "--tls" not in popen_args

    assert "/usr/bin/efs-proxy" in popen_args
    assert EXPECTED_STUNNEL_CONFIG_FILE in popen_args


def test_bootstrap_proxy_stunnel_enabled(mocker, tmpdir):
    popen_mock, _ = setup_mocks(mocker)
    mocker.patch("os.rename")
    state_file_dir = str(tmpdir)

    mocker.patch("efs_utils_common.proxy._stunnel_bin", return_value="/usr/bin/stunnel")
    with proxy.bootstrap_proxy(
        MOCK_CONFIG,
        INIT_SYSTEM,
        DNS_NAME,
        FS_ID,
        MOUNT_POINT,
        {},
        state_file_dir,
        efs_proxy_enabled=False,
    ):
        pass

    popen_args, _ = popen_mock.call_args
    popen_args = popen_args[0]

    assert "/usr/bin/efs-proxy" not in popen_args
    assert "info" not in popen_args

    assert "/usr/bin/stunnel" in popen_args
    assert EXPECTED_STUNNEL_CONFIG_FILE in popen_args


def test_bootstrap_proxy_netns_option(mocker, tmpdir):
    popen_mock, write_config_mock = setup_mocks(mocker)
    state_file_dir = str(tmpdir)

    netns = "/proc/1/net/ns"
    mocker.patch(
        "efs_utils_common.proxy._efs_proxy_bin", return_value="/usr/bin/efs-proxy"
    )
    mocker.patch("efs_utils_common.proxy.NetNS")
    mocker.patch("efs_utils_common.proxy.is_ocsp_enabled", return_value=False)
    with proxy.bootstrap_proxy(
        MOCK_CONFIG,
        INIT_SYSTEM,
        DNS_NAME,
        FS_ID,
        MOUNT_POINT,
        {"netns": netns},
        state_file_dir,
    ):
        pass

    popen_args, _ = popen_mock.call_args
    popen_args = popen_args[0]
    write_config_args, _ = write_config_mock.call_args

    assert "/usr/bin/efs-proxy" in popen_args
    assert EXPECTED_STUNNEL_CONFIG_FILE in popen_args
    assert "nsenter" in popen_args
    assert "--net=" + netns in popen_args


def test_bootstrap_proxy_efs_mount_disables_readbypass(mocker, tmpdir):
    """EFS (non-s3files) mounts should always pass --no-direct-s3-read."""
    popen_mock, _ = setup_mocks(mocker)
    mocker.patch("os.rename")
    state_file_dir = str(tmpdir)
    mocker.patch("efs_utils_common.proxy.is_ocsp_enabled", return_value=False)
    mocker.patch(
        "efs_utils_common.proxy._efs_proxy_bin", return_value="/usr/bin/efs-proxy"
    )
    mock_context = mocker.patch("efs_utils_common.proxy.MountContext")
    mock_context.return_value.mount_type = "EFS"

    with proxy.bootstrap_proxy(
        MOCK_CONFIG,
        INIT_SYSTEM,
        DNS_NAME,
        FS_ID,
        MOUNT_POINT,
        {"tls": None},
        state_file_dir,
        efs_proxy_enabled=True,
    ):
        pass

    popen_args, _ = popen_mock.call_args
    popen_args = popen_args[0]

    assert "--no-direct-s3-read" in popen_args


def test_bootstrap_proxy_s3files_mount_allows_readbypass(mocker, tmpdir):
    """S3Files mounts should NOT pass --no-direct-s3-read unless explicitly requested."""
    popen_mock, _ = setup_mocks(mocker)
    mocker.patch("os.rename")
    state_file_dir = str(tmpdir)
    mocker.patch("efs_utils_common.proxy.is_ocsp_enabled", return_value=False)
    mocker.patch(
        "efs_utils_common.proxy._efs_proxy_bin", return_value="/usr/bin/efs-proxy"
    )
    mock_context = mocker.patch("efs_utils_common.proxy.MountContext")
    mock_context.return_value.mount_type = "S3Files"

    with proxy.bootstrap_proxy(
        MOCK_CONFIG,
        INIT_SYSTEM,
        DNS_NAME,
        FS_ID,
        MOUNT_POINT,
        {"tls": None},
        state_file_dir,
        efs_proxy_enabled=True,
    ):
        pass

    popen_args, _ = popen_mock.call_args
    popen_args = popen_args[0]

    assert "--no-direct-s3-read" not in popen_args


def test_bootstrap_proxy_s3files_mount_with_nodirects3read(mocker, tmpdir):
    """S3Files mounts with nodirects3read option should pass --no-direct-s3-read."""
    popen_mock, _ = setup_mocks(mocker)
    mocker.patch("os.rename")
    state_file_dir = str(tmpdir)
    mocker.patch("efs_utils_common.proxy.is_ocsp_enabled", return_value=False)
    mocker.patch(
        "efs_utils_common.proxy._efs_proxy_bin", return_value="/usr/bin/efs-proxy"
    )
    mock_context = mocker.patch("efs_utils_common.proxy.MountContext")
    mock_context.return_value.mount_type = "S3Files"

    with proxy.bootstrap_proxy(
        MOCK_CONFIG,
        INIT_SYSTEM,
        DNS_NAME,
        FS_ID,
        MOUNT_POINT,
        {"tls": None, "nodirects3read": None},
        state_file_dir,
        efs_proxy_enabled=True,
    ):
        pass

    popen_args, _ = popen_mock.call_args
    popen_args = popen_args[0]

    assert "--no-direct-s3-read" in popen_args


def test_bootstrap_proxy_omits_worker_threads_when_not_configured(mocker, tmpdir):
    """With the config item unset, no --worker-threads argument is passed and
    efs-proxy keeps its own one-worker-per-CPU default."""
    popen_mock, _ = setup_mocks(mocker)
    mocker.patch("os.rename")
    state_file_dir = str(tmpdir)
    mocker.patch("efs_utils_common.proxy.is_ocsp_enabled", return_value=False)
    mocker.patch(
        "efs_utils_common.proxy._efs_proxy_bin", return_value="/usr/bin/efs-proxy"
    )

    with proxy.bootstrap_proxy(
        MOCK_CONFIG,
        INIT_SYSTEM,
        DNS_NAME,
        FS_ID,
        MOUNT_POINT,
        {"tls": None},
        state_file_dir,
        efs_proxy_enabled=True,
    ):
        pass

    popen_args, _ = popen_mock.call_args
    popen_args = popen_args[0]

    assert "--worker-threads" not in popen_args


def test_bootstrap_proxy_passes_configured_worker_threads(mocker, tmpdir):
    """A configured worker count reaches efs-proxy as `--worker-threads N`."""
    popen_mock, _ = setup_mocks(mocker)
    mocker.patch("os.rename")
    state_file_dir = str(tmpdir)
    mocker.patch("efs_utils_common.proxy.is_ocsp_enabled", return_value=False)
    mocker.patch(
        "efs_utils_common.proxy._efs_proxy_bin", return_value="/usr/bin/efs-proxy"
    )
    mocker.patch("efs_utils_common.proxy.get_efs_proxy_worker_threads", return_value=8)

    with proxy.bootstrap_proxy(
        MOCK_CONFIG,
        INIT_SYSTEM,
        DNS_NAME,
        FS_ID,
        MOUNT_POINT,
        {"tls": None},
        state_file_dir,
        efs_proxy_enabled=True,
    ):
        pass

    popen_args, _ = popen_mock.call_args
    popen_args = popen_args[0]

    assert "--worker-threads" in popen_args
    assert popen_args[popen_args.index("--worker-threads") + 1] == "8"


def test_bootstrap_proxy_worker_threads_read_from_real_config(mocker, tmpdir):
    """End-to-end: the [mount] config item alone produces the CLI argument, with
    no patching of the reader, and the value lands in the watchdog state command."""
    popen_mock, _ = setup_mocks(mocker, patch_worker_threads=False)
    mocker.patch("os.rename")
    state_file_dir = str(tmpdir)
    mocker.patch("efs_utils_common.proxy.is_ocsp_enabled", return_value=False)
    mocker.patch(
        "efs_utils_common.proxy._efs_proxy_bin", return_value="/usr/bin/efs-proxy"
    )
    state_file_mock = mocker.patch(
        "efs_utils_common.proxy.write_tunnel_state_file", return_value="~mocktempfile"
    )

    try:
        config = ConfigParser.SafeConfigParser()
    except AttributeError:
        config = ConfigParser()
    config.add_section(efs_utils_common.constants.CONFIG_SECTION)
    config.set(
        efs_utils_common.constants.CONFIG_SECTION,
        efs_utils_common.constants.EFS_PROXY_WORKER_THREADS_ITEM,
        "4",
    )

    with proxy.bootstrap_proxy(
        config,
        INIT_SYSTEM,
        DNS_NAME,
        FS_ID,
        MOUNT_POINT,
        {"tls": None},
        state_file_dir,
        efs_proxy_enabled=True,
    ):
        pass

    popen_args, _ = popen_mock.call_args
    popen_args = popen_args[0]
    assert popen_args[popen_args.index("--worker-threads") + 1] == "4"

    # The watchdog restarts the exact command persisted in the state file, so an
    # explicit worker count must survive a proxy restart.
    state_args, _ = state_file_mock.call_args
    persisted_command = state_args[4]
    assert persisted_command[persisted_command.index("--worker-threads") + 1] == "4"


def _bootstrap_and_track_order(mocker, tmpdir, efs_proxy_enabled):
    """Run bootstrap_proxy, recording the probe socket close and the Popen in order."""
    import socket

    popen_mock, _ = setup_mocks(mocker)
    mocker.patch("efs_utils_common.proxy.is_ocsp_enabled", return_value=False)
    mocker.patch(
        "efs_utils_common.proxy._efs_proxy_bin", return_value="/usr/bin/efs-proxy"
    )
    mocker.patch("efs_utils_common.proxy._stunnel_bin", return_value="/usr/bin/stunnel")
    sock = socket.socket.return_value
    sock.fileno.return_value = 7
    events = MagicMock()
    events.attach_mock(popen_mock, "popen")
    events.attach_mock(sock.close, "close")
    with proxy.bootstrap_proxy(
        MOCK_CONFIG,
        INIT_SYSTEM,
        DNS_NAME,
        FS_ID,
        MOUNT_POINT,
        {"tls": None},
        str(tmpdir),
        efs_proxy_enabled=efs_proxy_enabled,
    ):
        pass
    order = [name for name, _, _ in events.mock_calls]
    return popen_mock, order


def test_bootstrap_proxy_hands_listen_socket_to_efs_proxy(mocker, tmpdir):
    popen_mock, order = _bootstrap_and_track_order(mocker, tmpdir, True)

    popen_args, popen_kwargs = popen_mock.call_args
    assert popen_args[0][-2:] == ["--listen-fd", "7"]
    assert popen_kwargs["pass_fds"] == (7,)
    # The probe socket stays open until efs-proxy has inherited it.
    assert order.index("popen") < order.index("close")


def test_bootstrap_proxy_state_file_command_has_no_listen_fd(mocker, tmpdir):
    """The watchdog restarts a dead proxy from the saved command, with no socket to inherit."""
    _bootstrap_and_track_order(mocker, tmpdir, True)

    saved_command = proxy.write_tunnel_state_file.call_args[0][4]
    assert "/usr/bin/efs-proxy" in saved_command
    assert "--listen-fd" not in saved_command


def test_bootstrap_proxy_stunnel_frees_port_before_start(mocker, tmpdir):
    popen_mock, order = _bootstrap_and_track_order(mocker, tmpdir, False)

    popen_args, popen_kwargs = popen_mock.call_args
    assert "/usr/bin/stunnel" in popen_args[0]
    assert "--listen-fd" not in popen_args[0]
    assert popen_kwargs["pass_fds"] == ()
    # stunnel binds the port itself, so the probe socket is closed first.
    assert order.index("close") < order.index("popen")


def test_bootstrap_proxy_closes_listen_socket_when_setup_fails(mocker, tmpdir):
    import socket

    setup_mocks(mocker)
    mocker.patch("efs_utils_common.proxy.is_ocsp_enabled", return_value=False)
    mocker.patch(
        "efs_utils_common.proxy.write_stunnel_config_file",
        side_effect=RuntimeError("config write failed"),
    )
    sock = socket.socket.return_value
    with pytest.raises(RuntimeError):
        with proxy.bootstrap_proxy(
            MOCK_CONFIG,
            INIT_SYSTEM,
            DNS_NAME,
            FS_ID,
            MOUNT_POINT,
            {},
            str(tmpdir),
            efs_proxy_enabled=True,
        ):
            pass
    sock.close.assert_called_once_with()
    proxy.subprocess.Popen.assert_not_called()
