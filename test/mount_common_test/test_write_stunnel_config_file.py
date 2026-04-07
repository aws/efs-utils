# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
import os

import pytest

import efs_utils_common
import efs_utils_common.constants as constants
import efs_utils_common.context as context
import efs_utils_common.platform_utils as platform_utils
import efs_utils_common.proxy as proxy

from .. import utils

try:
    import ConfigParser
except ImportError:
    from configparser import ConfigParser

FS_ID = "fs-deadbeef"
DNS_NAME = "fs-deadbeef.com"
DNS_NAME_WITH_AZ = "us-east-1a.fs-deadbeef.com"
FALLBACK_IP_ADDRESS = "192.0.0.1"
MOUNT_POINT = "/mnt"
PORT = 12345
VERIFY_LEVEL = 2
OCSP_ENABLED = False
DEFAULT_REGION = "us-east-1"
STUNNEL_LOGS_FILE = "/var/log/amazon/efs/%s.stunnel.log" % FS_ID
PROXY_LOGS_FILE = "/var/log/amazon/efs/%s.efs-proxy.log" % FS_ID


@pytest.fixture(autouse=True)
def setup_test():
    mount_context = context.MountContext()
    mount_context.reset()
    mount_context.mount_type = constants.MOUNT_TYPE_EFS
    mount_context.config_file_path = constants.CONFIG_FILE
    yield mount_context
    mount_context.reset()


def _get_config(
    mocker,
    stunnel_debug_enabled=False,
    stunnel_check_cert_hostname_supported=True,
    stunnel_check_cert_validity_supported=True,
    stunnel_foreground_quiet_supported=False,
    stunnel_check_cert_hostname=None,
    stunnel_check_cert_validity=False,
    stunnel_logs_file=None,
    stunnel_libwrap_option_supported=True,
    fips_mode_enabled=False,
):
    options = []
    if stunnel_check_cert_hostname_supported:
        options.append(b"checkHost              = peer certificate host name pattern")
    if stunnel_check_cert_validity_supported:
        options.append(
            b"OCSPaia                = yes|no check the AIA responders from certificates"
        )
    if stunnel_libwrap_option_supported:
        options.append(
            b"libwrap                = yes|no use /etc/hosts.allow and /etc/hosts.deny"
        )
    if stunnel_foreground_quiet_supported:
        options.append(
            b"foreground             = yes|quiet|no foreground mode (don't fork, log to stderr)"
        )

    mocker.patch(
        "efs_utils_common.proxy.get_stunnel_options",
        return_value=options,
    )

    if stunnel_check_cert_hostname is None:
        stunnel_check_cert_hostname = stunnel_check_cert_hostname_supported

    if stunnel_check_cert_validity is None:
        stunnel_check_cert_validity = stunnel_check_cert_validity_supported

    try:
        config = ConfigParser.SafeConfigParser()
    except AttributeError:
        config = ConfigParser()
    config.add_section(efs_utils_common.constants.CONFIG_SECTION)
    config.set(
        efs_utils_common.constants.CONFIG_SECTION,
        "stunnel_debug_enabled",
        str(stunnel_debug_enabled),
    )
    config.set(
        efs_utils_common.constants.CONFIG_SECTION,
        "stunnel_check_cert_hostname",
        str(stunnel_check_cert_hostname),
    )
    config.set(
        efs_utils_common.constants.CONFIG_SECTION,
        "stunnel_check_cert_validity",
        str(stunnel_check_cert_validity),
    )

    # This option is only written if stunnel debug logs are enabled and a log file is specified
    if stunnel_debug_enabled and stunnel_logs_file:
        config.set(
            efs_utils_common.constants.CONFIG_SECTION,
            "stunnel_logs_file",
            str(stunnel_logs_file),
        )

    config.set(
        efs_utils_common.constants.CONFIG_SECTION,
        "fips_mode_enabled",
        str(fips_mode_enabled),
    )

    return config


def _get_mount_options_tls_and_iam(port=PORT):
    options = {"tlsport": port, "tls": None, "iam": None}
    return options


def _get_mount_options_tls(port=PORT):
    options = {"tlsport": port, "tls": None}
    return options


def _get_mount_options_non_tls(port=PORT):
    options = {
        "tlsport": port,
    }
    return options


def _get_expected_global_config(
    fs_id,
    mountpoint,
    tls_port,
    state_file_dir,
    global_config=efs_utils_common.metadata.STUNNEL_GLOBAL_CONFIG,
):
    global_config = dict(global_config)
    mount_filename = proxy.get_mount_specific_filename(fs_id, mountpoint, tls_port)
    pid_file_path = os.path.join(state_file_dir, mount_filename + "+", "stunnel.pid")
    global_config["pid"] = pid_file_path
    return global_config


def _validate_config(stunnel_config_file, expected_global_config, expected_efs_config):
    actual_global_config = {}
    actual_efs_config = {}

    # This assumes efs-specific config comes after global config
    global_config = True
    with open(stunnel_config_file) as f:
        for line in f:
            line = line.strip()

            if line == "[efs]":
                global_config = False
                continue

            conf = actual_global_config if global_config else actual_efs_config

            assert "=" in line
            parts = line.split("=", 1)

            key = parts[0].strip()
            val = parts[1].strip()

            if key in conf:
                if type(conf[key]) is not list:
                    conf[key] = [conf[key]]
                conf[key].append(val)
            else:
                conf[key] = val

    assert expected_global_config == actual_global_config
    assert expected_efs_config == actual_efs_config


def _get_expected_efs_config_tls(
    fs_id=FS_ID,
    port=PORT,
    dns_name=DNS_NAME,
    verify=efs_utils_common.constants.DEFAULT_STUNNEL_VERIFY_LEVEL,
    ocsp_override=True,
    check_cert_hostname=True,
    check_cert_validity=False,
    disable_libwrap=True,
    fallback_ip_address=None,
    efs_proxy_enabled=True,
):
    expected_efs_config = dict(efs_utils_common.metadata.STUNNEL_EFS_CONFIG)
    expected_efs_config["accept"] = expected_efs_config["accept"] % port
    if not fallback_ip_address:
        expected_efs_config["connect"] = expected_efs_config["connect"] % dns_name
    else:
        expected_efs_config["connect"] = (
            expected_efs_config["connect"] % fallback_ip_address
        )

    expected_efs_config["verify"] = str(verify)

    if efs_proxy_enabled:
        expected_efs_config["retry_nfs_mount_command_timeout_sec"] = str(
            proxy.DEFAULT_NFS_MOUNT_COMMAND_TIMEOUT_SEC
        )
        expected_efs_config["fs_id"] = fs_id
        expected_efs_config["region"] = DEFAULT_REGION

    if check_cert_hostname or efs_proxy_enabled:
        expected_efs_config["checkHost"] = dns_name[dns_name.index(fs_id) :]

    if not efs_proxy_enabled and platform_utils.is_ipv6_address(fallback_ip_address):
        expected_efs_config["sni"] = dns_name[dns_name.index(fs_id) :]

    if check_cert_validity and ocsp_override and (not efs_proxy_enabled):
        expected_efs_config["OCSPaia"] = "yes"

    if disable_libwrap and (not efs_proxy_enabled):
        expected_efs_config["libwrap"] = "no"

    return expected_efs_config


def _get_expected_efs_config_non_tls(
    fs_id=FS_ID,
    port=PORT,
    dns_name=DNS_NAME,
    fallback_ip_address=None,
    efs_proxy_enabled=True,
):
    expected_efs_config = dict(efs_utils_common.metadata.STUNNEL_EFS_CONFIG)
    expected_efs_config["accept"] = expected_efs_config["accept"] % port
    if not fallback_ip_address:
        expected_efs_config["connect"] = expected_efs_config["connect"] % dns_name
    else:
        expected_efs_config["connect"] = (
            expected_efs_config["connect"] % fallback_ip_address
        )

    expected_efs_config["retry_nfs_mount_command_timeout_sec"] = str(
        proxy.DEFAULT_NFS_MOUNT_COMMAND_TIMEOUT_SEC
    )

    if efs_proxy_enabled:
        expected_efs_config["fs_id"] = fs_id
        expected_efs_config["region"] = DEFAULT_REGION

    return expected_efs_config


# Check the hostname behavior when using stunnel instead of efs-proxy.
def _test_check_cert_hostname_stunnel(
    mocker,
    tmpdir,
    stunnel_check_cert_hostname_supported,
    stunnel_check_cert_hostname,
    expected_check_cert_hostname_config_value,
):
    ca_mocker = mocker.patch("efs_utils_common.proxy.add_tunnel_ca_options")
    state_file_dir = str(tmpdir)
    config_file = proxy.write_stunnel_config_file(
        _get_config(
            mocker,
            stunnel_check_cert_hostname_supported=stunnel_check_cert_hostname_supported,
            stunnel_check_cert_hostname=stunnel_check_cert_hostname,
        ),
        state_file_dir,
        FS_ID,
        MOUNT_POINT,
        PORT,
        DNS_NAME,
        VERIFY_LEVEL,
        OCSP_ENABLED,
        _get_mount_options_tls(),
        DEFAULT_REGION,
        efs_proxy_enabled=False,
    )

    utils.assert_called_once(ca_mocker)

    _validate_config(
        config_file,
        _get_expected_global_config(FS_ID, MOUNT_POINT, PORT, state_file_dir),
        _get_expected_efs_config_tls(
            check_cert_hostname=expected_check_cert_hostname_config_value,
            efs_proxy_enabled=False,
        ),
    )


def _test_check_cert_validity(
    mocker,
    tmpdir,
    stunnel_check_cert_validity_supported,
    stunnel_check_cert_validity,
    expected_check_cert_validity_config_value,
):
    ca_mocker = mocker.patch("efs_utils_common.proxy.add_tunnel_ca_options")
    state_file_dir = str(tmpdir)
    config_file = proxy.write_stunnel_config_file(
        _get_config(
            mocker,
            stunnel_check_cert_validity_supported=stunnel_check_cert_validity_supported,
        ),
        state_file_dir,
        FS_ID,
        MOUNT_POINT,
        PORT,
        DNS_NAME,
        VERIFY_LEVEL,
        stunnel_check_cert_validity,
        _get_mount_options_tls(),
        DEFAULT_REGION,
        efs_proxy_enabled=True,
    )

    utils.assert_called_once(ca_mocker)

    _validate_config(
        config_file,
        _get_expected_global_config(FS_ID, MOUNT_POINT, PORT, state_file_dir),
        _get_expected_efs_config_tls(
            check_cert_validity=expected_check_cert_validity_config_value
        ),
    )


def test_write_stunnel_config_file(mocker, tmpdir):
    ca_mocker = mocker.patch("efs_utils_common.proxy.add_tunnel_ca_options")
    state_file_dir = str(tmpdir)

    config_file = proxy.write_stunnel_config_file(
        _get_config(mocker),
        state_file_dir,
        FS_ID,
        MOUNT_POINT,
        PORT,
        DNS_NAME,
        VERIFY_LEVEL,
        OCSP_ENABLED,
        _get_mount_options_tls(),
        DEFAULT_REGION,
        efs_proxy_enabled=True,
    )
    utils.assert_called_once(ca_mocker)

    _validate_config(
        config_file,
        _get_expected_global_config(FS_ID, MOUNT_POINT, PORT, state_file_dir),
        _get_expected_efs_config_tls(),
    )


def test_write_stunnel_config_file_with_az_as_dns_name(mocker, tmpdir):
    ca_mocker = mocker.patch("efs_utils_common.proxy.add_tunnel_ca_options")
    state_file_dir = str(tmpdir)

    config_file = proxy.write_stunnel_config_file(
        _get_config(mocker),
        state_file_dir,
        FS_ID,
        MOUNT_POINT,
        PORT,
        DNS_NAME_WITH_AZ,
        VERIFY_LEVEL,
        OCSP_ENABLED,
        _get_mount_options_tls(),
        DEFAULT_REGION,
        efs_proxy_enabled=True,
    )
    utils.assert_called_once(ca_mocker)

    _validate_config(
        config_file,
        _get_expected_global_config(FS_ID, MOUNT_POINT, PORT, state_file_dir),
        _get_expected_efs_config_tls(dns_name=DNS_NAME_WITH_AZ),
    )


def _test_enable_disable_libwrap(
    mocker,
    tmpdir,
    system_release="unknown",
    libwrap_supported=True,
):
    mocker.patch("efs_utils_common.proxy.add_tunnel_ca_options")
    state_file_dir = str(tmpdir)
    ver_mocker = mocker.patch(
        "efs_utils_common.proxy.get_system_release_version", return_value=system_release
    )

    config_file = proxy.write_stunnel_config_file(
        _get_config(mocker, stunnel_libwrap_option_supported=libwrap_supported),
        state_file_dir,
        FS_ID,
        MOUNT_POINT,
        PORT,
        DNS_NAME,
        VERIFY_LEVEL,
        OCSP_ENABLED,
        _get_mount_options_tls(),
        DEFAULT_REGION,
        efs_proxy_enabled=True,
    )

    utils.assert_called_once(ver_mocker)
    _validate_config(
        config_file,
        _get_expected_global_config(FS_ID, MOUNT_POINT, PORT, state_file_dir),
        _get_expected_efs_config_tls(disable_libwrap=libwrap_supported),
    )


def test_write_stunnel_config_with_debug(mocker, tmpdir):
    ca_mocker = mocker.patch("efs_utils_common.proxy.add_tunnel_ca_options")
    state_file_dir = str(tmpdir)

    config_file = proxy.write_stunnel_config_file(
        _get_config(mocker, stunnel_debug_enabled=True),
        state_file_dir,
        FS_ID,
        MOUNT_POINT,
        PORT,
        DNS_NAME,
        VERIFY_LEVEL,
        OCSP_ENABLED,
        _get_mount_options_tls(),
        DEFAULT_REGION,
        efs_proxy_enabled=True,
    )
    utils.assert_called_once(ca_mocker)

    expected_global_config = dict(
        _get_expected_global_config(FS_ID, MOUNT_POINT, PORT, state_file_dir)
    )
    expected_global_config["debug"] = "debug"
    expected_global_config["output"] = os.path.join(
        efs_utils_common.constants.LOG_DIR,
        "%s.efs-proxy.log"
        % proxy.get_mount_specific_filename(FS_ID, MOUNT_POINT, PORT),
    )

    _validate_config(
        config_file, expected_global_config, _get_expected_efs_config_tls()
    )


def test_write_stunnel_config_with_debug_and_logs_file(mocker, tmpdir):
    ca_mocker = mocker.patch("efs_utils_common.proxy.add_tunnel_ca_options")
    state_file_dir = str(tmpdir)
    config_file = proxy.write_stunnel_config_file(
        _get_config(
            mocker, stunnel_debug_enabled=True, stunnel_logs_file=PROXY_LOGS_FILE
        ),
        state_file_dir,
        FS_ID,
        MOUNT_POINT,
        PORT,
        DNS_NAME,
        VERIFY_LEVEL,
        OCSP_ENABLED,
        _get_mount_options_tls(),
        DEFAULT_REGION,
        efs_proxy_enabled=True,
    )
    utils.assert_called_once(ca_mocker)

    expected_global_config = dict(
        _get_expected_global_config(FS_ID, MOUNT_POINT, PORT, state_file_dir)
    )
    expected_global_config["debug"] = "debug"
    expected_global_config["output"] = PROXY_LOGS_FILE

    _validate_config(
        config_file, expected_global_config, _get_expected_efs_config_tls()
    )


def test_write_stunnel_config_s3files_mount_type_always_configures_logs_output(
    mocker, tmpdir, setup_test
):
    ca_mocker = mocker.patch("efs_utils_common.proxy.add_tunnel_ca_options")
    state_file_dir = str(tmpdir)
    setup_test.mount_type = constants.MOUNT_TYPE_S3FILES

    config_file = proxy.write_stunnel_config_file(
        _get_config(mocker, stunnel_debug_enabled=False),
        state_file_dir,
        FS_ID,
        MOUNT_POINT,
        PORT,
        DNS_NAME,
        VERIFY_LEVEL,
        OCSP_ENABLED,
        _get_mount_options_tls(),
        DEFAULT_REGION,
        efs_proxy_enabled=True,
    )
    utils.assert_called_once(ca_mocker)

    expected_global_config = dict(
        _get_expected_global_config(FS_ID, MOUNT_POINT, PORT, state_file_dir)
    )
    expected_global_config["output"] = os.path.join(
        efs_utils_common.constants.LOG_DIR,
        "%s.efs-proxy.log"
        % proxy.get_mount_specific_filename(FS_ID, MOUNT_POINT, PORT),
    )

    _validate_config(
        config_file, expected_global_config, _get_expected_efs_config_tls()
    )


# We should always write "checkHost" into the stunnel config when using efs-proxy for TLS mounts.
def test_write_stunnel_config_efs_proxy_check_cert_hostname_tls(mocker, tmpdir):
    ca_mocker = mocker.patch("efs_utils_common.proxy.add_tunnel_ca_options")
    supported_opt_mock = mocker.patch(
        "efs_utils_common.proxy.is_stunnel_option_supported"
    )
    state_file_dir = str(tmpdir)
    config_file = proxy.write_stunnel_config_file(
        _get_config(mocker),
        state_file_dir,
        FS_ID,
        MOUNT_POINT,
        PORT,
        DNS_NAME,
        VERIFY_LEVEL,
        OCSP_ENABLED,
        _get_mount_options_tls(),
        DEFAULT_REGION,
        efs_proxy_enabled=True,
    )

    utils.assert_called_once(ca_mocker)
    utils.assert_not_called(supported_opt_mock)

    _validate_config(
        config_file,
        _get_expected_global_config(FS_ID, MOUNT_POINT, PORT, state_file_dir),
        _get_expected_efs_config_tls(
            efs_proxy_enabled=True,
        ),
    )


def test_write_stunnel_config_check_cert_hostname_supported_flag_not_set(
    mocker, tmpdir
):
    _test_check_cert_hostname_stunnel(
        mocker,
        tmpdir,
        stunnel_check_cert_hostname_supported=True,
        stunnel_check_cert_hostname=None,
        expected_check_cert_hostname_config_value=True,
    )


def test_write_stunnel_config_check_cert_hostname_supported_flag_set_false(
    mocker, capsys, tmpdir
):
    _test_check_cert_hostname_stunnel(
        mocker,
        tmpdir,
        stunnel_check_cert_hostname_supported=True,
        stunnel_check_cert_hostname=False,
        expected_check_cert_hostname_config_value=False,
    )


def test_write_stunnel_config_check_cert_hostname_supported_flag_set_true(
    mocker, tmpdir
):
    _test_check_cert_hostname_stunnel(
        mocker,
        tmpdir,
        stunnel_check_cert_hostname_supported=True,
        stunnel_check_cert_hostname=True,
        expected_check_cert_hostname_config_value=True,
    )


def test_write_stunnel_config_check_cert_hostname_not_supported_flag_not_specified(
    mocker, capsys, tmpdir
):
    _test_check_cert_hostname_stunnel(
        mocker,
        tmpdir,
        stunnel_check_cert_hostname_supported=False,
        stunnel_check_cert_hostname=None,
        expected_check_cert_hostname_config_value=False,
    )


def test_write_stunnel_config_check_cert_hostname_not_supported_flag_set_false(
    mocker, capsys, tmpdir
):
    _test_check_cert_hostname_stunnel(
        mocker,
        tmpdir,
        stunnel_check_cert_hostname_supported=False,
        stunnel_check_cert_hostname=False,
        expected_check_cert_hostname_config_value=False,
    )


def test_write_stunnel_config_check_cert_hostname_not_supported_flag_set_true(
    mocker, capsys, tmpdir
):
    mocker.patch("efs_utils_common.proxy.add_tunnel_ca_options")

    with pytest.raises(SystemExit) as ex:
        proxy.write_stunnel_config_file(
            _get_config(
                mocker,
                stunnel_check_cert_hostname_supported=False,
                stunnel_check_cert_hostname=True,
            ),
            str(tmpdir),
            FS_ID,
            MOUNT_POINT,
            PORT,
            DNS_NAME,
            VERIFY_LEVEL,
            OCSP_ENABLED,
            _get_mount_options_tls(),
            DEFAULT_REGION,
            efs_proxy_enabled=False,
        )

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert "WARNING: Your client lacks sufficient controls" in err
    assert "stunnel_check_cert_hostname" in err


def test_write_stunnel_config_check_cert_validity_supported_ocsp_enabled(
    mocker, capsys, tmpdir
):
    _test_check_cert_validity(
        mocker,
        tmpdir,
        stunnel_check_cert_validity_supported=True,
        stunnel_check_cert_validity=True,
        expected_check_cert_validity_config_value=True,
    )


def test_write_stunnel_config_check_cert_validity_supported_ocsp_disabled(
    mocker, capsys, tmpdir
):
    _test_check_cert_validity(
        mocker,
        tmpdir,
        stunnel_check_cert_validity_supported=True,
        stunnel_check_cert_validity=False,
        expected_check_cert_validity_config_value=False,
    )


def test_write_stunnel_config_check_cert_validity_not_supported_ocsp_disabled(
    mocker, capsys, tmpdir
):
    _test_check_cert_validity(
        mocker,
        tmpdir,
        stunnel_check_cert_validity_supported=True,
        stunnel_check_cert_validity=False,
        expected_check_cert_validity_config_value=False,
    )


def test_write_stunnel_config_check_cert_validity_not_supported_ocsp_enabled(
    mocker, capsys, tmpdir
):
    mocker.patch("efs_utils_common.proxy.add_tunnel_ca_options")

    with pytest.raises(SystemExit) as ex:
        proxy.write_stunnel_config_file(
            _get_config(
                mocker,
                stunnel_check_cert_validity_supported=False,
                stunnel_check_cert_validity=True,
            ),
            str(tmpdir),
            FS_ID,
            MOUNT_POINT,
            PORT,
            DNS_NAME,
            VERIFY_LEVEL,
            True,
            _get_mount_options_tls(),
            DEFAULT_REGION,
            efs_proxy_enabled=False,
        )

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert "WARNING: Your client lacks sufficient controls" in err
    assert "stunnel_check_cert_validity" in err


def test_write_stunnel_config_with_verify_level(mocker, tmpdir):
    ca_mocker = mocker.patch("efs_utils_common.proxy.add_tunnel_ca_options")
    state_file_dir = str(tmpdir)
    verify = 0
    config_file = proxy.write_stunnel_config_file(
        _get_config(mocker, stunnel_check_cert_validity=True),
        state_file_dir,
        FS_ID,
        MOUNT_POINT,
        PORT,
        DNS_NAME,
        verify,
        OCSP_ENABLED,
        _get_mount_options_tls(),
        DEFAULT_REGION,
    )
    utils.assert_not_called(ca_mocker)

    _validate_config(
        config_file,
        _get_expected_global_config(FS_ID, MOUNT_POINT, PORT, state_file_dir),
        _get_expected_efs_config_tls(check_cert_validity=False, verify=verify),
    )


def test_write_stunnel_config_libwrap_not_supported(mocker, tmpdir):
    _test_enable_disable_libwrap(mocker, tmpdir, libwrap_supported=False)


def test_write_stunnel_config_libwrap_supported(mocker, tmpdir):
    _test_enable_disable_libwrap(mocker, tmpdir, libwrap_supported=True)


def test_write_stunnel_config_with_fall_back_ip_address(mocker, tmpdir):
    ca_mocker = mocker.patch("efs_utils_common.proxy.add_tunnel_ca_options")
    state_file_dir = str(tmpdir)

    config_file = proxy.write_stunnel_config_file(
        _get_config(mocker),
        state_file_dir,
        FS_ID,
        MOUNT_POINT,
        PORT,
        DNS_NAME,
        VERIFY_LEVEL,
        OCSP_ENABLED,
        _get_mount_options_tls(),
        DEFAULT_REGION,
        fallback_ip_address=FALLBACK_IP_ADDRESS,
    )

    utils.assert_called_once(ca_mocker)

    _validate_config(
        config_file,
        _get_expected_global_config(FS_ID, MOUNT_POINT, PORT, state_file_dir),
        _get_expected_efs_config_tls(fallback_ip_address=FALLBACK_IP_ADDRESS),
    )


def test_write_stunnel_config_foreground_quiet_not_supported(mocker, tmpdir):
    _test_stunnel_config_foreground_quiet_helper(
        mocker, tmpdir, foreground_quiet_supported=False, stunnel_debug_enabled=False
    )


def test_write_stunnel_config_foreground_quiet_supported(mocker, tmpdir):
    _test_stunnel_config_foreground_quiet_helper(
        mocker, tmpdir, foreground_quiet_supported=True, stunnel_debug_enabled=False
    )


def test_write_stunnel_config_foreground_quiet_supported_debug_enabled(mocker, tmpdir):
    _test_stunnel_config_foreground_quiet_helper(
        mocker, tmpdir, foreground_quiet_supported=True, stunnel_debug_enabled=True
    )


def test_write_stunnel_config_foreground_quiet_supported_debug_enabled(mocker, tmpdir):
    _test_stunnel_config_foreground_quiet_helper(
        mocker, tmpdir, foreground_quiet_supported=True, stunnel_debug_enabled=True
    )


def _test_stunnel_config_foreground_quiet_helper(
    mocker, tmpdir, foreground_quiet_supported, stunnel_debug_enabled
):
    ca_mocker = mocker.patch("efs_utils_common.proxy.add_tunnel_ca_options")
    state_file_dir = str(tmpdir)

    config_file = proxy.write_stunnel_config_file(
        _get_config(
            mocker,
            stunnel_debug_enabled=stunnel_debug_enabled,
            stunnel_foreground_quiet_supported=foreground_quiet_supported,
        ),
        state_file_dir,
        FS_ID,
        MOUNT_POINT,
        PORT,
        DNS_NAME,
        VERIFY_LEVEL,
        OCSP_ENABLED,
        _get_mount_options_tls(),
        DEFAULT_REGION,
        efs_proxy_enabled=False,
    )
    utils.assert_called_once(ca_mocker)

    expected_global_config = dict(
        _get_expected_global_config(FS_ID, MOUNT_POINT, PORT, state_file_dir)
    )
    expected_global_config["foreground"] = (
        "quiet" if foreground_quiet_supported and not stunnel_debug_enabled else "yes"
    )
    if stunnel_debug_enabled:
        expected_global_config["debug"] = "debug"
        expected_global_config["output"] = os.path.join(
            efs_utils_common.constants.LOG_DIR,
            "%s.stunnel.log"
            % proxy.get_mount_specific_filename(FS_ID, MOUNT_POINT, PORT),
        )
    _validate_config(
        config_file,
        expected_global_config,
        _get_expected_efs_config_tls(efs_proxy_enabled=False),
    )


def test_write_stunnel_config_fips_enabled(mocker, tmpdir):
    ca_mocker = mocker.patch("efs_utils_common.proxy.add_tunnel_ca_options")
    state_file_dir = str(tmpdir)

    config_file = proxy.write_stunnel_config_file(
        _get_config(mocker, fips_mode_enabled=True),
        state_file_dir,
        FS_ID,
        MOUNT_POINT,
        PORT,
        DNS_NAME,
        VERIFY_LEVEL,
        OCSP_ENABLED,
        _get_mount_options_tls(),
        DEFAULT_REGION,
    )
    utils.assert_called_once(ca_mocker)

    expected_global_config = dict(
        _get_expected_global_config(FS_ID, MOUNT_POINT, PORT, state_file_dir)
    )
    expected_global_config["fips"] = "yes"

    _validate_config(
        config_file,
        expected_global_config,
        _get_expected_efs_config_tls(),
    )


def test_non_tls_mount_with_proxy(mocker, tmpdir):
    ca_mocker = mocker.patch("efs_utils_common.proxy.add_tunnel_ca_options")
    state_file_dir = str(tmpdir)

    config_file = proxy.write_stunnel_config_file(
        _get_config(mocker),
        state_file_dir,
        FS_ID,
        MOUNT_POINT,
        PORT,
        DNS_NAME,
        VERIFY_LEVEL,
        OCSP_ENABLED,
        _get_mount_options_non_tls(),
        DEFAULT_REGION,
        efs_proxy_enabled=True,
    )
    utils.assert_not_called(ca_mocker)

    expected_global_config = dict(
        _get_expected_global_config(FS_ID, MOUNT_POINT, PORT, state_file_dir)
    )

    _validate_config(
        config_file,
        expected_global_config,
        _get_expected_efs_config_non_tls(),
    )


def test_write_stunnel_config_with_ipv6_and_legacy_stunnel(mocker, tmpdir):
    ca_mocker = mocker.patch("efs_utils_common.proxy.add_tunnel_ca_options")
    state_file_dir = str(tmpdir)

    test_ipv6_address = "2001:db8:3333:4444:5555:6666:7777:8888"

    config_file = proxy.write_stunnel_config_file(
        _get_config(mocker),
        state_file_dir,
        FS_ID,
        MOUNT_POINT,
        PORT,
        DNS_NAME,
        VERIFY_LEVEL,
        OCSP_ENABLED,
        _get_mount_options_tls(),
        DEFAULT_REGION,
        fallback_ip_address=test_ipv6_address,
        efs_proxy_enabled=False,
    )

    utils.assert_called_once(ca_mocker)

    _validate_config(
        config_file,
        _get_expected_global_config(FS_ID, MOUNT_POINT, PORT, state_file_dir),
        _get_expected_efs_config_tls(
            dns_name=DNS_NAME,
            fallback_ip_address=test_ipv6_address,
            efs_proxy_enabled=False,
        ),
    )


def test_write_stunnel_config_efs_proxy_skips_stunnel_options(mocker, tmpdir):
    get_stunnel_options_mock = mocker.patch(
        "efs_utils_common.proxy.get_stunnel_options"
    )
    mocker.patch("efs_utils_common.proxy.add_tunnel_ca_options")

    proxy.write_stunnel_config_file(
        _get_config(mocker),
        str(tmpdir),
        FS_ID,
        MOUNT_POINT,
        PORT,
        DNS_NAME,
        VERIFY_LEVEL,
        OCSP_ENABLED,
        _get_mount_options_tls(),
        DEFAULT_REGION,
        efs_proxy_enabled=True,
    )

    get_stunnel_options_mock.assert_not_called()


def test_write_stunnel_config_with_readbypass_configs(mocker, tmpdir):
    mocker.patch("efs_utils_common.proxy.add_tunnel_ca_options")
    mocker.patch("efs_utils_common.proxy.get_aws_profile", return_value="default")
    state_file_dir = str(tmpdir)

    config_parser = _get_config(mocker)
    config_parser.add_section(efs_utils_common.constants.PROXY_CONFIG_SECTION)
    config_parser.set(
        efs_utils_common.constants.PROXY_CONFIG_SECTION,
        "read_bypass_denylist_size",
        "100",
    )
    config_parser.set(
        efs_utils_common.constants.PROXY_CONFIG_SECTION,
        "read_bypass_denylist_ttl_seconds",
        "300",
    )
    config_parser.set(
        efs_utils_common.constants.PROXY_CONFIG_SECTION,
        "s3_read_chunk_size_bytes",
        "1048576",
    )

    config_file = proxy.write_stunnel_config_file(
        config_parser,
        state_file_dir,
        FS_ID,
        MOUNT_POINT,
        PORT,
        DNS_NAME,
        VERIFY_LEVEL,
        OCSP_ENABLED,
        _get_mount_options_tls_and_iam(),
        DEFAULT_REGION,
        efs_proxy_enabled=True,
    )

    expected_config = _get_expected_efs_config_tls()
    expected_config["read_bypass_denylist_size"] = "100"
    expected_config["read_bypass_denylist_ttl_seconds"] = "300"
    expected_config["s3_read_chunk_size_bytes"] = "1048576"
    expected_config["proxy_logging_level"] = "INFO"
    expected_config["proxy_logging_max_bytes"] = "1048576"
    expected_config["proxy_logging_file_count"] = "10"
    expected_config["profile"] = "default"

    _validate_config(
        config_file,
        _get_expected_global_config(FS_ID, MOUNT_POINT, PORT, state_file_dir),
        expected_config,
    )


def test_write_stunnel_config_with_readbypass_and_rolearn(mocker, tmpdir):
    mocker.patch("efs_utils_common.proxy.add_tunnel_ca_options")
    mocker.patch("efs_utils_common.proxy.get_aws_profile", return_value="custom")
    state_file_dir = str(tmpdir)

    config_parser = _get_config(mocker)
    config_parser.add_section(efs_utils_common.constants.PROXY_CONFIG_SECTION)
    config_parser.set(
        efs_utils_common.constants.PROXY_CONFIG_SECTION,
        "readahead_cache_max_memory_size_mb",
        "50",
    )

    options = _get_mount_options_tls_and_iam()
    options["rolearn"] = "arn:aws:iam::123456789012:role/MyRole"

    config_file = proxy.write_stunnel_config_file(
        config_parser,
        state_file_dir,
        FS_ID,
        MOUNT_POINT,
        PORT,
        DNS_NAME,
        VERIFY_LEVEL,
        OCSP_ENABLED,
        options,
        DEFAULT_REGION,
        efs_proxy_enabled=True,
    )

    expected_config = _get_expected_efs_config_tls()
    expected_config["readahead_cache_max_memory_size_mb"] = "50"
    expected_config["role_arn"] = "arn:aws:iam::123456789012:role/MyRole"
    expected_config["proxy_logging_level"] = "INFO"
    expected_config["proxy_logging_max_bytes"] = "1048576"
    expected_config["proxy_logging_file_count"] = "10"
    expected_config["profile"] = "custom"

    _validate_config(
        config_file,
        _get_expected_global_config(FS_ID, MOUNT_POINT, PORT, state_file_dir),
        expected_config,
    )


def test_write_stunnel_config_with_nodirects3read_option(mocker, tmpdir):
    mocker.patch("efs_utils_common.proxy.add_tunnel_ca_options")
    state_file_dir = str(tmpdir)

    config_parser = _get_config(mocker)
    config_parser.add_section(efs_utils_common.constants.PROXY_CONFIG_SECTION)
    config_parser.set(
        efs_utils_common.constants.PROXY_CONFIG_SECTION,
        "read_bypass_denylist_size",
        "100",
    )

    options = _get_mount_options_tls_and_iam()
    options["nodirects3read"] = None

    config_file = proxy.write_stunnel_config_file(
        config_parser,
        state_file_dir,
        FS_ID,
        MOUNT_POINT,
        PORT,
        DNS_NAME,
        VERIFY_LEVEL,
        OCSP_ENABLED,
        options,
        DEFAULT_REGION,
        efs_proxy_enabled=True,
    )

    expected_config = _get_expected_efs_config_tls()
    # readbypass configs should NOT be present when nodirects3read option is set
    assert "read_bypass_denylist_size" not in expected_config
    expected_config["proxy_logging_level"] = "INFO"
    expected_config["proxy_logging_max_bytes"] = "1048576"
    expected_config["proxy_logging_file_count"] = "10"

    _validate_config(
        config_file,
        _get_expected_global_config(FS_ID, MOUNT_POINT, PORT, state_file_dir),
        expected_config,
    )


def test_write_stunnel_config_with_nos3readcache_option(mocker, tmpdir):
    mocker.patch("efs_utils_common.proxy.add_tunnel_ca_options")
    mocker.patch("efs_utils_common.proxy.get_aws_profile", return_value="default")
    state_file_dir = str(tmpdir)

    config_parser = _get_config(mocker)
    config_parser.add_section(efs_utils_common.constants.PROXY_CONFIG_SECTION)
    config_parser.set(
        efs_utils_common.constants.PROXY_CONFIG_SECTION,
        "readahead_cache_enabled",
        "true",
    )
    config_parser.set(
        efs_utils_common.constants.PROXY_CONFIG_SECTION,
        "read_bypass_denylist_size",
        "100",
    )

    options = _get_mount_options_tls_and_iam()
    options["nos3readcache"] = None

    config_file = proxy.write_stunnel_config_file(
        config_parser,
        state_file_dir,
        FS_ID,
        MOUNT_POINT,
        PORT,
        DNS_NAME,
        VERIFY_LEVEL,
        OCSP_ENABLED,
        options,
        DEFAULT_REGION,
        efs_proxy_enabled=True,
    )

    expected_config = _get_expected_efs_config_tls()
    # readbypass configs should still be present (unlike nodirects3read)
    expected_config["read_bypass_denylist_size"] = "100"
    # nos3readcache should force readahead_cache_enabled to "no" despite config saying "true"
    expected_config["readahead_cache_enabled"] = "no"
    expected_config["proxy_logging_level"] = "INFO"
    expected_config["proxy_logging_max_bytes"] = "1048576"
    expected_config["proxy_logging_file_count"] = "10"
    expected_config["profile"] = "default"

    _validate_config(
        config_file,
        _get_expected_global_config(FS_ID, MOUNT_POINT, PORT, state_file_dir),
        expected_config,
    )


def test_write_stunnel_config_with_nos3readcache_and_nodirects3read(mocker, tmpdir):
    mocker.patch("efs_utils_common.proxy.add_tunnel_ca_options")
    state_file_dir = str(tmpdir)

    config_parser = _get_config(mocker)
    config_parser.add_section(efs_utils_common.constants.PROXY_CONFIG_SECTION)
    config_parser.set(
        efs_utils_common.constants.PROXY_CONFIG_SECTION,
        "readahead_cache_enabled",
        "true",
    )

    options = _get_mount_options_tls_and_iam()
    options["nodirects3read"] = None
    options["nos3readcache"] = None

    config_file = proxy.write_stunnel_config_file(
        config_parser,
        state_file_dir,
        FS_ID,
        MOUNT_POINT,
        PORT,
        DNS_NAME,
        VERIFY_LEVEL,
        OCSP_ENABLED,
        options,
        DEFAULT_REGION,
        efs_proxy_enabled=True,
    )

    expected_config = _get_expected_efs_config_tls()
    # nodirects3read skips readbypass config entirely, but nos3readcache still forces cache off
    expected_config["readahead_cache_enabled"] = "no"
    expected_config["proxy_logging_level"] = "INFO"
    expected_config["proxy_logging_max_bytes"] = "1048576"
    expected_config["proxy_logging_file_count"] = "10"

    _validate_config(
        config_file,
        _get_expected_global_config(FS_ID, MOUNT_POINT, PORT, state_file_dir),
        expected_config,
    )


def test_write_stunnel_config_with_telemetry_configs(mocker, tmpdir):
    mocker.patch("efs_utils_common.proxy.add_tunnel_ca_options")
    mocker.patch("efs_utils_common.proxy.get_aws_profile", return_value="default")
    state_file_dir = str(tmpdir)

    config_parser = _get_config(mocker)
    config_parser.add_section(efs_utils_common.constants.PROXY_CONFIG_SECTION)
    config_parser.set(
        efs_utils_common.constants.PROXY_CONFIG_SECTION, "metrics_enabled", "true"
    )
    config_parser.add_section("cloudwatch-log")
    config_parser.set("cloudwatch-log", "enabled", "true")
    config_parser.set("cloudwatch-log", "log_group_name", "/aws/efs/custom")
    config_parser.set("cloudwatch-log", "retention_in_days", "30")

    config_file = proxy.write_stunnel_config_file(
        config_parser,
        state_file_dir,
        FS_ID,
        MOUNT_POINT,
        PORT,
        DNS_NAME,
        VERIFY_LEVEL,
        OCSP_ENABLED,
        _get_mount_options_tls_and_iam(),
        DEFAULT_REGION,
        efs_proxy_enabled=True,
    )

    expected_config = _get_expected_efs_config_tls(FS_ID)
    expected_config["cloud_watch_metrics"] = "True"
    expected_config["cloud_watch_logs"] = "True"
    expected_config["log_group_name"] = "/aws/efs/custom"
    expected_config["cloud_watch_logs_retention_days"] = "30"
    expected_config["profile"] = "default"
    expected_config["proxy_logging_level"] = (
        efs_utils_common.constants.DEFAULT_PROXY_LOGGING_LEVEL
    )
    expected_config["proxy_logging_max_bytes"] = str(
        efs_utils_common.constants.DEFAULT_PROXY_LOGGING_MAX_BYTES
    )
    expected_config["proxy_logging_file_count"] = str(
        efs_utils_common.constants.DEFAULT_PROXY_LOGGING_FILE_COUNT
    )

    _validate_config(
        config_file,
        _get_expected_global_config(FS_ID, MOUNT_POINT, PORT, state_file_dir),
        expected_config,
    )


def test_write_stunnel_config_with_proxy_logging_configs(mocker, tmpdir):
    mocker.patch("efs_utils_common.proxy.add_tunnel_ca_options")
    state_file_dir = str(tmpdir)

    config_parser = _get_config(mocker)
    config_parser.add_section("proxy")
    config_parser.set("proxy", "proxy_logging_level", "DEBUG")
    config_parser.set("proxy", "proxy_logging_max_bytes", "2097152")
    config_parser.set("proxy", "proxy_logging_file_count", "5")

    config_file = proxy.write_stunnel_config_file(
        config_parser,
        state_file_dir,
        FS_ID,
        MOUNT_POINT,
        PORT,
        DNS_NAME,
        VERIFY_LEVEL,
        OCSP_ENABLED,
        _get_mount_options_tls(),
        DEFAULT_REGION,
        efs_proxy_enabled=True,
    )

    expected_config = _get_expected_efs_config_tls()
    expected_config["proxy_logging_level"] = "DEBUG"
    expected_config["proxy_logging_max_bytes"] = "2097152"
    expected_config["proxy_logging_file_count"] = "5"

    _validate_config(
        config_file,
        _get_expected_global_config(FS_ID, MOUNT_POINT, PORT, state_file_dir),
        expected_config,
    )


def test_write_stunnel_config_without_proxy_section_omits_logging_configs(
    mocker, tmpdir
):
    """EFS mounts use efs-utils.conf which has no [proxy] section. Verify no proxy logging keys are written."""
    mocker.patch("efs_utils_common.proxy.add_tunnel_ca_options")
    state_file_dir = str(tmpdir)

    config_parser = _get_config(mocker)

    config_file = proxy.write_stunnel_config_file(
        config_parser,
        state_file_dir,
        FS_ID,
        MOUNT_POINT,
        PORT,
        DNS_NAME,
        VERIFY_LEVEL,
        OCSP_ENABLED,
        _get_mount_options_tls(),
        DEFAULT_REGION,
        efs_proxy_enabled=True,
    )

    expected_config = _get_expected_efs_config_tls()

    _validate_config(
        config_file,
        _get_expected_global_config(FS_ID, MOUNT_POINT, PORT, state_file_dir),
        expected_config,
    )
