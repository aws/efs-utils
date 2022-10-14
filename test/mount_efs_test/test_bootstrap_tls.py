# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.

import os
import tempfile
from unittest.mock import MagicMock

import mount_efs

AP_ID = "fsap-beefdead"
FS_ID = "fs-deadbeef"
CLIENT_SOURCE = "test"
DNS_NAME = "%s.efs.us-east-1.amazonaws.com" % FS_ID
MOUNT_POINT = "/mnt"
REGION = "us-east-1"

NON_AL2_RELEASE_ID_VAL = "FAKE_NON_AL2_RELEASE_ID_VAL"

DEFAULT_TLS_PORT = 20049

EXPECTED_STUNNEL_CONFIG_FILE_BASE = "stunnel-config.fs-deadbeef.mnt."
EXPECTED_STUNNEL_CONFIG_FILE = EXPECTED_STUNNEL_CONFIG_FILE_BASE + str(DEFAULT_TLS_PORT)

INIT_SYSTEM = "upstart"

MOCK_CONFIG = MagicMock()


def setup_mocks(mocker):
    mocker.patch("mount_efs.start_watchdog")
    mocker.patch(
        "mount_efs.get_tls_port_range",
        return_value=(DEFAULT_TLS_PORT, DEFAULT_TLS_PORT + 10),
    )
    mocker.patch("socket.socket", return_value=MagicMock())
    mocker.patch(
        "mount_efs.get_dns_name_and_fallback_mount_target_ip_address",
        return_value=(DNS_NAME, None),
    )
    mocker.patch("mount_efs.get_target_region", return_value=REGION)
    mocker.patch("mount_efs.write_tls_tunnel_state_file", return_value="~mocktempfile")
    mocker.patch("mount_efs.create_certificate")
    mocker.patch("os.rename")
    mocker.patch("os.kill")

    process_mock = MagicMock()
    process_mock.communicate.return_value = (
        "stdout",
        "stderr",
    )
    process_mock.returncode = 0

    popen_mock = mocker.patch("subprocess.Popen", return_value=process_mock)
    write_config_mock = mocker.patch(
        "mount_efs.write_stunnel_config_file", return_value=EXPECTED_STUNNEL_CONFIG_FILE
    )
    return popen_mock, write_config_mock


def setup_mocks_without_popen(mocker):
    mocker.patch("mount_efs.start_watchdog")
    mocker.patch(
        "mount_efs.get_tls_port_range",
        return_value=(DEFAULT_TLS_PORT, DEFAULT_TLS_PORT + 10),
    )
    mocker.patch("socket.gethostname", return_value=DNS_NAME)
    mocker.patch(
        "mount_efs.get_dns_name_and_fallback_mount_target_ip_address",
        return_value=(DNS_NAME, None),
    )
    mocker.patch("mount_efs.write_tls_tunnel_state_file", return_value="~mocktempfile")
    mocker.patch("os.kill")

    write_config_mock = mocker.patch(
        "mount_efs.write_stunnel_config_file", return_value=EXPECTED_STUNNEL_CONFIG_FILE
    )
    return write_config_mock


def test_bootstrap_tls_state_file_dir_exists(mocker, tmpdir):
    popen_mock, _ = setup_mocks(mocker)
    state_file_dir = str(tmpdir)

    mocker.patch("mount_efs._stunnel_bin", return_value="/usr/bin/stunnel")
    with mount_efs.bootstrap_tls(
        MOCK_CONFIG, INIT_SYSTEM, DNS_NAME, FS_ID, MOUNT_POINT, {}, state_file_dir
    ):
        pass

    args, _ = popen_mock.call_args
    args = args[0]

    assert "/usr/bin/stunnel" in args
    assert EXPECTED_STUNNEL_CONFIG_FILE in args


def test_stunnel5_al2(mocker):
    process_mock = MagicMock()
    check_output_mock = mocker.patch(
        "subprocess.check_output", return_value=process_mock
    )
    mocker.patch(
        "mount_efs.get_system_release_version",
        return_value=mount_efs.AMAZON_LINUX_2_RELEASE_ID,
    )
    mount_efs._stunnel_bin()
    args, _ = check_output_mock.call_args
    args = args[0]
    assert "stunnel5" in args[1]


def test_stunnel5_non_al2(mocker):
    process_mock = MagicMock()
    check_output_mock = mocker.patch(
        "subprocess.check_output", return_value=process_mock
    )
    mocker.patch(
        "mount_efs.get_system_release_version", return_value=NON_AL2_RELEASE_ID_VAL
    )
    mount_efs._stunnel_bin()
    args, _ = check_output_mock.call_args
    args = args[0]
    assert "stunnel" in args[1]


def test_bootstrap_tls_state_file_nonexistent_dir(mocker, tmpdir):
    popen_mock, _ = setup_mocks(mocker)
    state_file_dir = str(tmpdir.join(tempfile.mkdtemp()[1]))

    def config_get_side_effect(section, field):
        if section == mount_efs.CONFIG_SECTION and field == "state_file_dir_mode":
            return "0755"
        elif section == mount_efs.CONFIG_SECTION and field == "dns_name_format":
            return "{fs_id}.efs.{region}.amazonaws.com"
        elif section == mount_efs.CLIENT_INFO_SECTION and field == "source":
            return CLIENT_SOURCE
        else:
            raise ValueError("Unexpected arguments")

    MOCK_CONFIG.get.side_effect = config_get_side_effect

    assert not os.path.exists(state_file_dir)

    mocker.patch("mount_efs._stunnel_bin", return_value="/usr/bin/stunnel")
    with mount_efs.bootstrap_tls(
        MOCK_CONFIG, INIT_SYSTEM, DNS_NAME, FS_ID, MOUNT_POINT, {}, state_file_dir
    ):
        pass

    assert os.path.exists(state_file_dir)


def test_bootstrap_tls_cert_created(mocker, tmpdir):
    setup_mocks_without_popen(mocker)
    mocker.patch("mount_efs.get_mount_specific_filename", return_value=DNS_NAME)
    mocker.patch("mount_efs.get_target_region", return_value=REGION)
    state_file_dir = str(tmpdir)
    tls_dict = mount_efs.tls_paths_dictionary(DNS_NAME + "+", state_file_dir)

    pk_path = os.path.join(str(tmpdir), "privateKey.pem")
    mocker.patch("mount_efs.get_private_key_path", return_value=pk_path)

    def config_get_side_effect(section, field):
        if section == mount_efs.CONFIG_SECTION and field == "state_file_dir_mode":
            return "0755"
        elif section == mount_efs.CONFIG_SECTION and field == "dns_name_format":
            return "{fs_id}.efs.{region}.amazonaws.com"
        elif section == mount_efs.CLIENT_INFO_SECTION and field == "source":
            return CLIENT_SOURCE
        else:
            raise ValueError("Unexpected arguments")

    MOCK_CONFIG.get.side_effect = config_get_side_effect

    mocker.patch("mount_efs._stunnel_bin", return_value="/usr/bin/stunnel")
    try:
        with mount_efs.bootstrap_tls(
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

    assert os.path.exists(os.path.join(tls_dict["mount_dir"], "certificate.pem"))
    assert os.path.exists(os.path.join(tls_dict["mount_dir"], "request.csr"))
    assert os.path.exists(os.path.join(tls_dict["mount_dir"], "config.conf"))
    assert os.path.exists(pk_path)


def test_bootstrap_tls_non_default_port(mocker, tmpdir):
    popen_mock, write_config_mock = setup_mocks(mocker)
    mocker.patch("os.rename")
    state_file_dir = str(tmpdir)

    tls_port = 1000
    mocker.patch("mount_efs._stunnel_bin", return_value="/usr/bin/stunnel")
    with mount_efs.bootstrap_tls(
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

    assert "/usr/bin/stunnel" in popen_args
    assert EXPECTED_STUNNEL_CONFIG_FILE in popen_args
    assert 1000 == write_config_args[4]  # positional argument for tls_port


def test_bootstrap_tls_non_default_verify_level(mocker, tmpdir):
    popen_mock, write_config_mock = setup_mocks(mocker)
    state_file_dir = str(tmpdir)

    verify = 0
    mocker.patch("mount_efs._stunnel_bin", return_value="/usr/bin/stunnel")
    with mount_efs.bootstrap_tls(
        MOCK_CONFIG,
        INIT_SYSTEM,
        DNS_NAME,
        FS_ID,
        MOUNT_POINT,
        {"verify": verify},
        state_file_dir,
    ):
        pass

    popen_args, _ = popen_mock.call_args
    popen_args = popen_args[0]
    write_config_args, _ = write_config_mock.call_args

    assert "/usr/bin/stunnel" in popen_args
    assert EXPECTED_STUNNEL_CONFIG_FILE in popen_args
    assert 0 == write_config_args[6]  # positional argument for verify_level


def test_bootstrap_tls_ocsp_option(mocker, tmpdir):
    popen_mock, write_config_mock = setup_mocks(mocker)
    state_file_dir = str(tmpdir)

    mocker.patch("mount_efs._stunnel_bin", return_value="/usr/bin/stunnel")
    with mount_efs.bootstrap_tls(
        MOCK_CONFIG,
        INIT_SYSTEM,
        DNS_NAME,
        FS_ID,
        MOUNT_POINT,
        {"ocsp": None},
        state_file_dir,
    ):
        pass

    popen_args, _ = popen_mock.call_args
    popen_args = popen_args[0]
    write_config_args, _ = write_config_mock.call_args

    assert "/usr/bin/stunnel" in popen_args
    assert EXPECTED_STUNNEL_CONFIG_FILE in popen_args
    # positional argument for ocsp_override
    assert write_config_args[7] is True


def test_bootstrap_tls_noocsp_option(mocker, tmpdir):
    popen_mock, write_config_mock = setup_mocks(mocker)
    state_file_dir = str(tmpdir)

    mocker.patch("mount_efs._stunnel_bin", return_value="/usr/bin/stunnel")
    with mount_efs.bootstrap_tls(
        MOCK_CONFIG,
        INIT_SYSTEM,
        DNS_NAME,
        FS_ID,
        MOUNT_POINT,
        {"noocsp": None},
        state_file_dir,
    ):
        pass

    popen_args, _ = popen_mock.call_args
    popen_args = popen_args[0]
    write_config_args, _ = write_config_mock.call_args

    assert "/usr/bin/stunnel" in popen_args
    assert EXPECTED_STUNNEL_CONFIG_FILE in popen_args
    # positional argument for ocsp_override
    assert write_config_args[7] is False
