#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import mount_efs
import ConfigParser
import os

import pytest

FS_ID = 'fs-deadbeef'
DNS_NAME = 'fs-deadbeef.com'
MOUNT_POINT = '/mnt'
PORT = 12345
VERIFY_LEVEL = 2
OCSP_ENABLED = False


def _get_config(mocker, stunnel_debug_enabled=False, stunnel_check_cert_hostname_supported=True,
                stunnel_check_cert_validity_supported=True, stunnel_check_cert_hostname=None,
                stunnel_check_cert_validity=False):

    mocker.patch('mount_efs.get_version_specific_stunnel_options',
                 return_value=(stunnel_check_cert_hostname_supported, stunnel_check_cert_validity_supported, ))

    if stunnel_check_cert_hostname is None:
        stunnel_check_cert_hostname = stunnel_check_cert_hostname_supported

    if stunnel_check_cert_validity is None:
        stunnel_check_cert_validity = stunnel_check_cert_validity_supported

    config = ConfigParser.SafeConfigParser()
    config.add_section(mount_efs.CONFIG_SECTION)
    config.set(mount_efs.CONFIG_SECTION, 'stunnel_debug_enabled', str(stunnel_debug_enabled))
    config.set(mount_efs.CONFIG_SECTION, 'stunnel_check_cert_hostname', str(stunnel_check_cert_hostname))
    config.set(mount_efs.CONFIG_SECTION, 'stunnel_check_cert_validity', str(stunnel_check_cert_validity))
    return config


def _get_mount_options(port=PORT):
    options = {
        'tlsport': port,
    }
    return options


def _validate_config(stunnel_config_file, expected_global_config, expected_efs_config):
    actual_global_config = {}
    actual_efs_config = {}

    # This assumes efs-specific config comes after global config
    global_config = True
    with open(stunnel_config_file) as f:
        for line in f:
            line = line.strip()

            if line == '[efs]':
                global_config = False
                continue

            conf = actual_global_config if global_config else actual_efs_config

            assert '=' in line
            parts = line.split('=', 1)

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


def _get_expected_efs_config(port=PORT, dns_name=DNS_NAME, verify=mount_efs.DEFAULT_STUNNEL_VERIFY_LEVEL,
                             ocsp_override=True, check_cert_hostname=True, check_cert_validity=False):

    expected_efs_config = dict(mount_efs.STUNNEL_EFS_CONFIG)
    expected_efs_config['accept'] = expected_efs_config['accept'] % port
    expected_efs_config['connect'] = expected_efs_config['connect'] % dns_name
    expected_efs_config['verify'] = str(verify)

    if check_cert_hostname:
        expected_efs_config['checkHost'] = dns_name

    if check_cert_validity and ocsp_override:
        expected_efs_config['OCSPaia'] = 'yes'

    return expected_efs_config


def _test_check_cert_hostname(mocker, tmpdir, stunnel_check_cert_hostname_supported, stunnel_check_cert_hostname,
                              expected_check_cert_hostname_config_value):
    ca_mocker = mocker.patch('mount_efs.add_stunnel_ca_options')

    config_file = mount_efs.write_stunnel_config_file(
        _get_config(mocker, stunnel_check_cert_hostname_supported=stunnel_check_cert_hostname_supported,
                    stunnel_check_cert_hostname=stunnel_check_cert_hostname),
        str(tmpdir), FS_ID, MOUNT_POINT, PORT, DNS_NAME, VERIFY_LEVEL, OCSP_ENABLED)

    ca_mocker.assert_called_once()

    _validate_config(config_file, mount_efs.STUNNEL_GLOBAL_CONFIG,
                     _get_expected_efs_config(check_cert_hostname=expected_check_cert_hostname_config_value))


def _test_check_cert_validity(mocker, tmpdir, stunnel_check_cert_validity_supported, stunnel_check_cert_validity,
                              expected_check_cert_validity_config_value):
    ca_mocker = mocker.patch('mount_efs.add_stunnel_ca_options')

    config_file = mount_efs.write_stunnel_config_file(
        _get_config(mocker, stunnel_check_cert_validity_supported=stunnel_check_cert_validity_supported),
        str(tmpdir), FS_ID, MOUNT_POINT, PORT, DNS_NAME, VERIFY_LEVEL, stunnel_check_cert_validity)

    ca_mocker.assert_called_once()

    _validate_config(config_file, mount_efs.STUNNEL_GLOBAL_CONFIG,
                     _get_expected_efs_config(check_cert_validity=expected_check_cert_validity_config_value))


def _test_write_stunnel_config_file(mocker, tmpdir):
    ca_mocker = mocker.patch('mount_efs.add_stunnel_ca_options')
    state_file_dir = str(tmpdir)

    config_file = mount_efs.write_stunnel_config_file(_get_config(mocker), state_file_dir, FS_ID, MOUNT_POINT, PORT, DNS_NAME,
                                                      VERIFY_LEVEL, OCSP_ENABLED)
    ca_mocker.assert_called_once()

    _validate_config(config_file, mount_efs.STUNNEL_GLOBAL_CONFIG, _get_expected_efs_config())


def test_write_stunnel_config_with_debug(mocker, tmpdir):
    ca_mocker = mocker.patch('mount_efs.add_stunnel_ca_options')
    state_file_dir = str(tmpdir)

    config_file = mount_efs.write_stunnel_config_file(_get_config(mocker, stunnel_debug_enabled=True), state_file_dir, FS_ID,
                                                      MOUNT_POINT, PORT, DNS_NAME, VERIFY_LEVEL, OCSP_ENABLED)
    ca_mocker.assert_called_once()

    expected_global_config = dict(mount_efs.STUNNEL_GLOBAL_CONFIG)
    expected_global_config['debug'] = 'debug'
    expected_global_config['output'] = os.path.join(mount_efs.LOG_DIR,
                                                    '%s.stunnel.log' % mount_efs.get_mount_specific_filename(FS_ID, MOUNT_POINT,
                                                                                                             PORT))

    _validate_config(config_file, expected_global_config, _get_expected_efs_config())


def test_write_stunnel_config_check_cert_hostname_supported_flag_not_set(mocker, tmpdir):
    _test_check_cert_hostname(mocker, tmpdir, stunnel_check_cert_hostname_supported=True, stunnel_check_cert_hostname=None,
                              expected_check_cert_hostname_config_value=True)


def test_write_stunnel_config_check_cert_hostname_supported_flag_set_false(mocker, capsys, tmpdir):
    _test_check_cert_hostname(mocker, tmpdir, stunnel_check_cert_hostname_supported=True, stunnel_check_cert_hostname=False,
                              expected_check_cert_hostname_config_value=False)


def test_write_stunnel_config_check_cert_hostname_supported_flag_set_true(mocker, tmpdir):
    _test_check_cert_hostname(mocker, tmpdir, stunnel_check_cert_hostname_supported=True, stunnel_check_cert_hostname=True,
                              expected_check_cert_hostname_config_value=True)


def test_write_stunnel_config_check_cert_hostname_not_supported_flag_not_specified(mocker, capsys, tmpdir):
    _test_check_cert_hostname(mocker, tmpdir, stunnel_check_cert_hostname_supported=False, stunnel_check_cert_hostname=None,
                              expected_check_cert_hostname_config_value=False)


def test_write_stunnel_config_check_cert_hostname_not_supported_flag_set_false(mocker, capsys, tmpdir):
    _test_check_cert_hostname(mocker, tmpdir, stunnel_check_cert_hostname_supported=False, stunnel_check_cert_hostname=False,
                              expected_check_cert_hostname_config_value=False)


def test_write_stunnel_config_check_cert_hostname_not_supported_flag_set_true(mocker, capsys, tmpdir):
    mocker.patch('mount_efs.add_stunnel_ca_options')

    with pytest.raises(SystemExit) as ex:
        mount_efs.write_stunnel_config_file(_get_config(mocker, stunnel_check_cert_hostname_supported=False,
                                            stunnel_check_cert_hostname=True), str(tmpdir), FS_ID, MOUNT_POINT, PORT, DNS_NAME,
                                            VERIFY_LEVEL, OCSP_ENABLED)

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert 'WARNING: Your client lacks sufficient controls' in err
    assert 'stunnel_check_cert_hostname' in err


def test_write_stunnel_config_check_cert_validity_supported_ocsp_enabled(mocker, capsys, tmpdir):
    _test_check_cert_validity(mocker, tmpdir, stunnel_check_cert_validity_supported=True, stunnel_check_cert_validity=True,
                              expected_check_cert_validity_config_value=True)


def test_write_stunnel_config_check_cert_validity_supported_ocsp_disabled(mocker, capsys, tmpdir):
    _test_check_cert_validity(mocker, tmpdir, stunnel_check_cert_validity_supported=True, stunnel_check_cert_validity=False,
                              expected_check_cert_validity_config_value=False)


def test_write_stunnel_config_check_cert_validity_not_supported_ocsp_disabled(mocker, capsys, tmpdir):
    _test_check_cert_validity(mocker, tmpdir, stunnel_check_cert_validity_supported=True, stunnel_check_cert_validity=False,
                              expected_check_cert_validity_config_value=False)


def test_write_stunnel_config_check_cert_validity_not_supported_ocsp_enabled(mocker, capsys, tmpdir):
    mocker.patch('mount_efs.add_stunnel_ca_options')

    with pytest.raises(SystemExit) as ex:
        mount_efs.write_stunnel_config_file(_get_config(mocker, stunnel_check_cert_validity_supported=False,
                                            stunnel_check_cert_validity=True), str(tmpdir), FS_ID, MOUNT_POINT, PORT, DNS_NAME,
                                            VERIFY_LEVEL, ocsp_enabled=True)

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert 'WARNING: Your client lacks sufficient controls' in err
    assert 'stunnel_check_cert_validity' in err


def test_write_stunnel_config_with_verify_level(mocker, tmpdir):
    ca_mocker = mocker.patch('mount_efs.add_stunnel_ca_options')

    verify = 0
    config_file = mount_efs.write_stunnel_config_file(_get_config(mocker, stunnel_check_cert_validity=True), str(tmpdir), FS_ID,
                                                      MOUNT_POINT, PORT, DNS_NAME, verify, OCSP_ENABLED)
    ca_mocker.assert_not_called()

    _validate_config(config_file, mount_efs.STUNNEL_GLOBAL_CONFIG,
                     _get_expected_efs_config(check_cert_validity=False, verify=verify))
