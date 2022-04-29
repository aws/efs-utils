# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.

import os

import mount_efs
import pytest

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


def _get_config(
    mocker,
    stunnel_debug_enabled=False,
    stunnel_check_cert_hostname_supported=True,
    stunnel_check_cert_validity_supported=True,
    stunnel_check_cert_hostname=None,
    stunnel_check_cert_validity=False,
    stunnel_logs_file=None,
    stunnel_libwrap_option_supported=True,
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

    mocker.patch(
        "mount_efs.get_stunnel_options",
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
    config.add_section(mount_efs.CONFIG_SECTION)
    config.set(
        mount_efs.CONFIG_SECTION, "stunnel_debug_enabled", str(stunnel_debug_enabled)
    )
    config.set(
        mount_efs.CONFIG_SECTION,
        "stunnel_check_cert_hostname",
        str(stunnel_check_cert_hostname),
    )
    config.set(
        mount_efs.CONFIG_SECTION,
        "stunnel_check_cert_validity",
        str(stunnel_check_cert_validity),
    )

    # This option is only written if stunnel debug logs are enabled and a log file is specified
    if stunnel_debug_enabled and stunnel_logs_file:
        config.set(
            mount_efs.CONFIG_SECTION, "stunnel_logs_file", str(stunnel_logs_file)
        )

    return config


def _get_mount_options(port=PORT):
    options = {
        "tlsport": port,
    }
    return options


def _get_expected_global_config(
    fs_id,
    mountpoint,
    tls_port,
    state_file_dir,
    global_config=mount_efs.STUNNEL_GLOBAL_CONFIG,
):
    global_config = dict(global_config)
    mount_filename = mount_efs.get_mount_specific_filename(fs_id, mountpoint, tls_port)
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


def _get_expected_efs_config(
    port=PORT,
    dns_name=DNS_NAME,
    verify=mount_efs.DEFAULT_STUNNEL_VERIFY_LEVEL,
    ocsp_override=True,
    check_cert_hostname=True,
    check_cert_validity=False,
    disable_libwrap=True,
    fallback_ip_address=None,
):

    expected_efs_config = dict(mount_efs.STUNNEL_EFS_CONFIG)
    expected_efs_config["accept"] = expected_efs_config["accept"] % port
    if not fallback_ip_address:
        expected_efs_config["connect"] = expected_efs_config["connect"] % dns_name
    else:
        expected_efs_config["connect"] = (
            expected_efs_config["connect"] % fallback_ip_address
        )
    expected_efs_config["verify"] = str(verify)

    if check_cert_hostname:
        expected_efs_config["checkHost"] = dns_name[dns_name.index(FS_ID) :]

    if check_cert_validity and ocsp_override:
        expected_efs_config["OCSPaia"] = "yes"

    if disable_libwrap:
        expected_efs_config["libwrap"] = "no"

    return expected_efs_config


def _test_check_cert_hostname(
    mocker,
    tmpdir,
    stunnel_check_cert_hostname_supported,
    stunnel_check_cert_hostname,
    expected_check_cert_hostname_config_value,
):
    ca_mocker = mocker.patch("mount_efs.add_stunnel_ca_options")
    state_file_dir = str(tmpdir)
    config_file = mount_efs.write_stunnel_config_file(
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
        _get_mount_options(),
        DEFAULT_REGION,
    )

    utils.assert_called_once(ca_mocker)

    _validate_config(
        config_file,
        _get_expected_global_config(FS_ID, MOUNT_POINT, PORT, state_file_dir),
        _get_expected_efs_config(
            check_cert_hostname=expected_check_cert_hostname_config_value
        ),
    )


def _test_check_cert_validity(
    mocker,
    tmpdir,
    stunnel_check_cert_validity_supported,
    stunnel_check_cert_validity,
    expected_check_cert_validity_config_value,
):
    ca_mocker = mocker.patch("mount_efs.add_stunnel_ca_options")
    state_file_dir = str(tmpdir)
    config_file = mount_efs.write_stunnel_config_file(
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
        _get_mount_options(),
        DEFAULT_REGION,
    )

    utils.assert_called_once(ca_mocker)

    _validate_config(
        config_file,
        _get_expected_global_config(FS_ID, MOUNT_POINT, PORT, state_file_dir),
        _get_expected_efs_config(
            check_cert_validity=expected_check_cert_validity_config_value
        ),
    )


def test_write_stunnel_config_file(mocker, tmpdir):
    ca_mocker = mocker.patch("mount_efs.add_stunnel_ca_options")
    state_file_dir = str(tmpdir)

    config_file = mount_efs.write_stunnel_config_file(
        _get_config(mocker),
        state_file_dir,
        FS_ID,
        MOUNT_POINT,
        PORT,
        DNS_NAME,
        VERIFY_LEVEL,
        OCSP_ENABLED,
        _get_mount_options(),
        DEFAULT_REGION,
    )
    utils.assert_called_once(ca_mocker)

    _validate_config(
        config_file,
        _get_expected_global_config(FS_ID, MOUNT_POINT, PORT, state_file_dir),
        _get_expected_efs_config(),
    )


def test_write_stunnel_config_file_with_az_as_dns_name(mocker, tmpdir):
    ca_mocker = mocker.patch("mount_efs.add_stunnel_ca_options")
    state_file_dir = str(tmpdir)

    config_file = mount_efs.write_stunnel_config_file(
        _get_config(mocker),
        state_file_dir,
        FS_ID,
        MOUNT_POINT,
        PORT,
        DNS_NAME_WITH_AZ,
        VERIFY_LEVEL,
        OCSP_ENABLED,
        _get_mount_options(),
        DEFAULT_REGION,
    )
    utils.assert_called_once(ca_mocker)

    _validate_config(
        config_file,
        _get_expected_global_config(FS_ID, MOUNT_POINT, PORT, state_file_dir),
        _get_expected_efs_config(dns_name=DNS_NAME_WITH_AZ),
    )


def _test_enable_disable_libwrap(
    mocker,
    tmpdir,
    system_release="unknown",
    libwrap_supported=True,
):
    mocker.patch("mount_efs.add_stunnel_ca_options")
    state_file_dir = str(tmpdir)
    ver_mocker = mocker.patch(
        "mount_efs.get_system_release_version", return_value=system_release
    )

    config_file = mount_efs.write_stunnel_config_file(
        _get_config(mocker, stunnel_libwrap_option_supported=libwrap_supported),
        state_file_dir,
        FS_ID,
        MOUNT_POINT,
        PORT,
        DNS_NAME,
        VERIFY_LEVEL,
        OCSP_ENABLED,
        _get_mount_options(),
        DEFAULT_REGION,
    )

    utils.assert_called_once(ver_mocker)
    _validate_config(
        config_file,
        _get_expected_global_config(FS_ID, MOUNT_POINT, PORT, state_file_dir),
        _get_expected_efs_config(disable_libwrap=libwrap_supported),
    )


def test_write_stunnel_config_with_debug(mocker, tmpdir):
    ca_mocker = mocker.patch("mount_efs.add_stunnel_ca_options")
    state_file_dir = str(tmpdir)

    config_file = mount_efs.write_stunnel_config_file(
        _get_config(mocker, stunnel_debug_enabled=True),
        state_file_dir,
        FS_ID,
        MOUNT_POINT,
        PORT,
        DNS_NAME,
        VERIFY_LEVEL,
        OCSP_ENABLED,
        _get_mount_options(),
        DEFAULT_REGION,
    )
    utils.assert_called_once(ca_mocker)

    expected_global_config = dict(
        _get_expected_global_config(FS_ID, MOUNT_POINT, PORT, state_file_dir)
    )
    expected_global_config["debug"] = "debug"
    expected_global_config["output"] = os.path.join(
        mount_efs.LOG_DIR,
        "%s.stunnel.log"
        % mount_efs.get_mount_specific_filename(FS_ID, MOUNT_POINT, PORT),
    )

    _validate_config(config_file, expected_global_config, _get_expected_efs_config())


def test_write_stunnel_config_with_debug_and_logs_file(mocker, tmpdir):
    ca_mocker = mocker.patch("mount_efs.add_stunnel_ca_options")
    state_file_dir = str(tmpdir)
    config_file = mount_efs.write_stunnel_config_file(
        _get_config(
            mocker, stunnel_debug_enabled=True, stunnel_logs_file=STUNNEL_LOGS_FILE
        ),
        state_file_dir,
        FS_ID,
        MOUNT_POINT,
        PORT,
        DNS_NAME,
        VERIFY_LEVEL,
        OCSP_ENABLED,
        _get_mount_options(),
        DEFAULT_REGION,
    )
    utils.assert_called_once(ca_mocker)

    expected_global_config = dict(
        _get_expected_global_config(FS_ID, MOUNT_POINT, PORT, state_file_dir)
    )
    expected_global_config["debug"] = "debug"
    expected_global_config["output"] = STUNNEL_LOGS_FILE

    _validate_config(config_file, expected_global_config, _get_expected_efs_config())


def test_write_stunnel_config_check_cert_hostname_supported_flag_not_set(
    mocker, tmpdir
):
    _test_check_cert_hostname(
        mocker,
        tmpdir,
        stunnel_check_cert_hostname_supported=True,
        stunnel_check_cert_hostname=None,
        expected_check_cert_hostname_config_value=True,
    )


def test_write_stunnel_config_check_cert_hostname_supported_flag_set_false(
    mocker, capsys, tmpdir
):
    _test_check_cert_hostname(
        mocker,
        tmpdir,
        stunnel_check_cert_hostname_supported=True,
        stunnel_check_cert_hostname=False,
        expected_check_cert_hostname_config_value=False,
    )


def test_write_stunnel_config_check_cert_hostname_supported_flag_set_true(
    mocker, tmpdir
):
    _test_check_cert_hostname(
        mocker,
        tmpdir,
        stunnel_check_cert_hostname_supported=True,
        stunnel_check_cert_hostname=True,
        expected_check_cert_hostname_config_value=True,
    )


def test_write_stunnel_config_check_cert_hostname_not_supported_flag_not_specified(
    mocker, capsys, tmpdir
):
    _test_check_cert_hostname(
        mocker,
        tmpdir,
        stunnel_check_cert_hostname_supported=False,
        stunnel_check_cert_hostname=None,
        expected_check_cert_hostname_config_value=False,
    )


def test_write_stunnel_config_check_cert_hostname_not_supported_flag_set_false(
    mocker, capsys, tmpdir
):
    _test_check_cert_hostname(
        mocker,
        tmpdir,
        stunnel_check_cert_hostname_supported=False,
        stunnel_check_cert_hostname=False,
        expected_check_cert_hostname_config_value=False,
    )


def test_write_stunnel_config_check_cert_hostname_not_supported_flag_set_true(
    mocker, capsys, tmpdir
):
    mocker.patch("mount_efs.add_stunnel_ca_options")

    with pytest.raises(SystemExit) as ex:
        mount_efs.write_stunnel_config_file(
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
            _get_mount_options(),
            DEFAULT_REGION,
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
    mocker.patch("mount_efs.add_stunnel_ca_options")

    with pytest.raises(SystemExit) as ex:
        mount_efs.write_stunnel_config_file(
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
            _get_mount_options(),
            DEFAULT_REGION,
        )

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert "WARNING: Your client lacks sufficient controls" in err
    assert "stunnel_check_cert_validity" in err


def test_write_stunnel_config_with_verify_level(mocker, tmpdir):
    ca_mocker = mocker.patch("mount_efs.add_stunnel_ca_options")
    state_file_dir = str(tmpdir)
    verify = 0
    config_file = mount_efs.write_stunnel_config_file(
        _get_config(mocker, stunnel_check_cert_validity=True),
        state_file_dir,
        FS_ID,
        MOUNT_POINT,
        PORT,
        DNS_NAME,
        verify,
        OCSP_ENABLED,
        _get_mount_options(),
        DEFAULT_REGION,
    )
    utils.assert_not_called(ca_mocker)

    _validate_config(
        config_file,
        _get_expected_global_config(FS_ID, MOUNT_POINT, PORT, state_file_dir),
        _get_expected_efs_config(check_cert_validity=False, verify=verify),
    )


def test_write_stunnel_config_libwrap_not_supported(mocker, tmpdir):
    _test_enable_disable_libwrap(mocker, tmpdir, libwrap_supported=False)


def test_write_stunnel_config_libwrap_supported(mocker, tmpdir):
    _test_enable_disable_libwrap(mocker, tmpdir, libwrap_supported=True)


def test_write_stunnel_config_with_fall_back_ip_address(mocker, tmpdir):
    ca_mocker = mocker.patch("mount_efs.add_stunnel_ca_options")
    state_file_dir = str(tmpdir)

    config_file = mount_efs.write_stunnel_config_file(
        _get_config(mocker),
        state_file_dir,
        FS_ID,
        MOUNT_POINT,
        PORT,
        DNS_NAME,
        VERIFY_LEVEL,
        OCSP_ENABLED,
        _get_mount_options(),
        DEFAULT_REGION,
        fallback_ip_address=FALLBACK_IP_ADDRESS,
    )

    utils.assert_called_once(ca_mocker)

    _validate_config(
        config_file,
        _get_expected_global_config(FS_ID, MOUNT_POINT, PORT, state_file_dir),
        _get_expected_efs_config(fallback_ip_address=FALLBACK_IP_ADDRESS),
    )
