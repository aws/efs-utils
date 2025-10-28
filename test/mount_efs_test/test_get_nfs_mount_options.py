# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.

from unittest.mock import MagicMock

try:
    import ConfigParser
except ImportError:
    from configparser import ConfigParser

import pytest

import mount_efs

DEFAULT_OPTIONS = {"tlsport": "3030"}


def _get_config(ocsp_enabled=False):
    try:
        config = ConfigParser.SafeConfigParser()
    except AttributeError:
        config = ConfigParser()

    mount_nfs_command_retry_count = 4
    mount_nfs_command_retry_timeout = 10
    mount_nfs_command_retry = "false"
    config.add_section(mount_efs.CONFIG_SECTION)
    config.set(
        mount_efs.CONFIG_SECTION, "retry_nfs_mount_command", mount_nfs_command_retry
    )
    config.set(
        mount_efs.CONFIG_SECTION,
        "retry_nfs_mount_command_count",
        str(mount_nfs_command_retry_count),
    )
    config.set(
        mount_efs.CONFIG_SECTION,
        "retry_nfs_mount_command_timeout_sec",
        str(mount_nfs_command_retry_timeout),
    )
    if ocsp_enabled:
        config.set(
            mount_efs.CONFIG_SECTION,
            "stunnel_check_cert_validity",
            "true",
        )
    return config


def _mock_popen(mocker, returncode=0, stdout="stdout", stderr="stderr"):
    popen_mock = MagicMock()
    popen_mock.communicate.return_value = (
        stdout,
        stderr,
    )
    popen_mock.returncode = returncode

    return mocker.patch("subprocess.Popen", return_value=popen_mock)


def test_get_default_nfs_mount_options():
    nfs_opts = mount_efs.get_nfs_mount_options(dict(DEFAULT_OPTIONS), _get_config())

    assert "nfsvers=4.1" in nfs_opts
    assert "rsize=1048576" in nfs_opts
    assert "wsize=1048576" in nfs_opts
    assert "hard" in nfs_opts
    assert "timeo=600" in nfs_opts
    assert "retrans=2" in nfs_opts
    assert "port=3030" in nfs_opts


def test_override_nfs_version():
    options = dict(DEFAULT_OPTIONS)
    options["nfsvers"] = 4.0
    nfs_opts = mount_efs.get_nfs_mount_options(options, _get_config())

    assert "nfsvers=4.0" in nfs_opts
    assert "nfsvers=4.1" not in nfs_opts


def test_override_nfs_version_alternate_option():
    options = dict(DEFAULT_OPTIONS)
    options["vers"] = 4.0
    nfs_opts = mount_efs.get_nfs_mount_options(options, _get_config())

    assert "vers=4.0" in nfs_opts
    assert "nfsvers=4.0" not in nfs_opts
    assert "nfsvers=4.1" not in nfs_opts


def test_override_rsize():
    options = dict(DEFAULT_OPTIONS)
    options["rsize"] = 1
    nfs_opts = mount_efs.get_nfs_mount_options(options, _get_config())

    assert "rsize=1" in nfs_opts
    assert "rsize=1048576" not in nfs_opts


def test_override_wsize():
    options = dict(DEFAULT_OPTIONS)
    options["wsize"] = 1
    nfs_opts = mount_efs.get_nfs_mount_options(options, _get_config())

    assert "wsize=1" in nfs_opts
    assert "wsize=1048576" not in nfs_opts


def test_override_recovery_soft():
    options = dict(DEFAULT_OPTIONS)
    options["soft"] = None
    nfs_opts = mount_efs.get_nfs_mount_options(options, _get_config())

    assert "soft" in nfs_opts
    assert "soft=" not in nfs_opts
    assert "hard" not in nfs_opts


def test_override_timeo():
    options = dict(DEFAULT_OPTIONS)
    options["timeo"] = 1
    nfs_opts = mount_efs.get_nfs_mount_options(options, _get_config())

    assert "timeo=1" in nfs_opts
    assert "timeo=600" not in nfs_opts


def test_override_retrans():
    options = dict(DEFAULT_OPTIONS)
    options["retrans"] = 1
    nfs_opts = mount_efs.get_nfs_mount_options(options, _get_config())

    assert "retrans=1" in nfs_opts
    assert "retrans=2" not in nfs_opts


def test_tlsport():
    options = dict(DEFAULT_OPTIONS)
    options["tls"] = None
    nfs_opts = mount_efs.get_nfs_mount_options(options, _get_config())

    assert "port=3030" in nfs_opts
    assert "tls" not in nfs_opts


def test_get_default_nfs_mount_options_macos(mocker):
    mocker.patch("mount_efs.check_if_platform_is_mac", return_value=True)
    nfs_opts = mount_efs.get_nfs_mount_options(dict(DEFAULT_OPTIONS), _get_config())

    assert "nfsvers=4.0" in nfs_opts
    assert "rsize=1048576" in nfs_opts
    assert "wsize=1048576" in nfs_opts
    assert "hard" in nfs_opts
    assert "timeo=600" in nfs_opts
    assert "retrans=2" in nfs_opts
    assert "mountport=2049" in nfs_opts
    assert not "port=3030" in nfs_opts


def _test_unsupported_mount_options_macos(mocker, capsys, options={}):
    mocker.patch("mount_efs.check_if_platform_is_mac", return_value=True)
    _mock_popen(mocker, stdout="nfs")
    with pytest.raises(SystemExit) as ex:
        mount_efs.get_nfs_mount_options(options, _get_config())

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert "NFSv4.1 is not supported on MacOS" in err


def test_unsupported_nfsvers_mount_options_macos(mocker, capsys):
    _test_unsupported_mount_options_macos(mocker, capsys, {"nfsvers": "4.1"})


def test_unsupported_vers_mount_options_macos(mocker, capsys):
    _test_unsupported_mount_options_macos(mocker, capsys, {"vers": "4.1"})


def test_unsupported_minorversion_mount_options_macos(mocker, capsys):
    _test_unsupported_mount_options_macos(mocker, capsys, {"minorversion": 1})
