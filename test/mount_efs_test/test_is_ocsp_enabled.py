#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import mount_efs

import pytest

try:
    import ConfigParser
except ImportError:
    from configparser import ConfigParser

def _get_config(stunnel_check_cert_validity):
    try:
        config = ConfigParser.SafeConfigParser()
    except AttributeError:
        config = ConfigParser()
    config.add_section(mount_efs.CONFIG_SECTION)
    if stunnel_check_cert_validity is not None:
        config.set(mount_efs.CONFIG_SECTION, 'stunnel_check_cert_validity', str(stunnel_check_cert_validity))
    return config


def test_is_ocsp_enabled_config_false_no_cli():
    options = {}

    ocsp_enabled = mount_efs.is_ocsp_enabled(_get_config(False), options)

    assert ocsp_enabled is False


def test_is_ocsp_enabled_config_true_no_cli():
    options = {}

    ocsp_enabled = mount_efs.is_ocsp_enabled(_get_config(True), options)

    assert ocsp_enabled is True


def test_is_ocsp_enabled_config_false_cli_true():
    options = {'ocsp': None}

    ocsp_enabled = mount_efs.is_ocsp_enabled(_get_config(False), options)

    assert ocsp_enabled is True


def test_is_ocsp_enabled_config_true_cli_true():
    options = {'ocsp': None}

    ocsp_enabled = mount_efs.is_ocsp_enabled(_get_config(True), options)

    assert ocsp_enabled is True


def test_is_ocsp_enabled_config_false_cli_false():
    options = {'noocsp': None}

    ocsp_enabled = mount_efs.is_ocsp_enabled(_get_config(False), options)

    assert ocsp_enabled is False


def test_is_ocsp_enabled_config_true_cli_false():
    options = {'noocsp': None}

    ocsp_enabled = mount_efs.is_ocsp_enabled(_get_config(True), options)

    assert ocsp_enabled is False


def test_is_ocsp_enabled_cli_both_options(capsys):
    options = {'noocsp': None, 'ocsp': None}

    with pytest.raises(SystemExit) as ex:
        mount_efs.is_ocsp_enabled(_get_config(True), options)

    assert 0 != ex.value.code
    out, err = capsys.readouterr()
    assert 'The "ocsp" and "noocsp" options are mutually exclusive' in err
