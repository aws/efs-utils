import subprocess
from unittest.mock import MagicMock

import pytest

import mount_efs

from .. import common, utils

try:
    import ConfigParser
except ImportError:
    from configparser import ConfigParser

try:
    import ConfigParser
except ImportError:
    from configparser import ConfigParser

DNS_NAME = "fs-deadbeef.efs.us-east-1.amazonaws.com"
FS_ID = "fs-deadbeef"
INIT_SYSTEM = "upstart"
FALLBACK_IP_ADDRESS = "192.0.0.1"
MOUNT_POINT = "/mnt"
PATH = "/"

DEFAULT_OPTIONS = {
    "nfsvers": 4.1,
    "rsize": 1048576,
    "wsize": 1048576,
    "hard": None,
    "timeo": 600,
    "retrans": 2,
    "tlsport": 3049,
}

# indices of different arguments to the NFS call
NFS_BIN_ARG_IDX = 0
NFS_MOUNT_PATH_IDX = 1
NFS_MOUNT_POINT_IDX = 2
NFS_OPTION_FLAG_IDX = 3
NFS_OPTIONS_IDX = 4

# indices of different arguments to the NFS call to certain network namespace
NETNS_NSENTER_ARG_IDX = 0
NETNS_PATH_ARG_IDX = 1
NETNS_NFS_OFFSET = 2

# indices of different arguments to the NFS call for MACOS
NFS_MOUNT_PATH_IDX_MACOS = -2
NFS_MOUNT_POINT_IDX_MACOS = -1

NETNS = "/proc/1/net/ns"


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


def test_mount_with_proxy_efs_proxy_enabled(mocker, capsys):
    options = dict(DEFAULT_OPTIONS)
    options["tls"] = None

    bootstrap_proxy_mock = mocker.patch("mount_efs.bootstrap_proxy")
    mocker.patch("os.path.ismount", return_value=False)
    mocker.patch("threading.Thread.start")
    mocker.patch("threading.Thread.join")
    mocker.patch("mount_efs.mount_nfs")
    _mock_popen(mocker, stdout="nfs")
    mount_efs.mount_with_proxy(
        _get_config(),
        INIT_SYSTEM,
        DNS_NAME,
        PATH,
        FS_ID,
        MOUNT_POINT,
        options,
    )
    utils.assert_called_once(bootstrap_proxy_mock)

    kwargs = bootstrap_proxy_mock.call_args[1]
    assert kwargs["efs_proxy_enabled"] == True


def test_mount_with_proxy_ocsp_config_enabled(mocker, capsys):
    options = dict(DEFAULT_OPTIONS)
    options["tls"] = None

    bootstrap_proxy_mock = mocker.patch("mount_efs.bootstrap_proxy")
    mocker.patch("os.path.ismount", return_value=False)
    mocker.patch("threading.Thread.start")
    mocker.patch("threading.Thread.join")
    mocker.patch("mount_efs.mount_nfs")
    _mock_popen(mocker, stdout="nfs")
    mount_efs.mount_with_proxy(
        _get_config(ocsp_enabled=True),
        INIT_SYSTEM,
        DNS_NAME,
        PATH,
        FS_ID,
        MOUNT_POINT,
        options,
    )
    utils.assert_called_once(bootstrap_proxy_mock)

    kwargs = bootstrap_proxy_mock.call_args[1]
    assert kwargs["efs_proxy_enabled"] == False


def test_mount_with_proxy_ocsp_option_enabled(mocker, capsys):
    options = dict(DEFAULT_OPTIONS)
    options["tls"] = None
    options["ocsp"] = None

    bootstrap_proxy_mock = mocker.patch("mount_efs.bootstrap_proxy")
    mocker.patch("os.path.ismount", return_value=False)
    mocker.patch("threading.Thread.start")
    mocker.patch("threading.Thread.join")
    mocker.patch("mount_efs.mount_nfs")
    _mock_popen(mocker, stdout="nfs")
    mount_efs.mount_with_proxy(
        _get_config(),
        INIT_SYSTEM,
        DNS_NAME,
        PATH,
        FS_ID,
        MOUNT_POINT,
        options,
    )
    utils.assert_called_once(bootstrap_proxy_mock)

    kwargs = bootstrap_proxy_mock.call_args[1]
    assert kwargs["efs_proxy_enabled"] == False


def test_mount_with_proxy_efs_proxy_enabled_non_tls_mount(mocker, capsys):
    options = dict(DEFAULT_OPTIONS)

    bootstrap_proxy_mock = mocker.patch("mount_efs.bootstrap_proxy")
    mocker.patch("os.path.ismount", return_value=False)
    mocker.patch("threading.Thread.start")
    mocker.patch("threading.Thread.join")
    mocker.patch("mount_efs.mount_nfs")
    _mock_popen(mocker, stdout="nfs")
    mount_efs.mount_with_proxy(
        _get_config(),
        INIT_SYSTEM,
        DNS_NAME,
        PATH,
        FS_ID,
        MOUNT_POINT,
        options,
    )
    utils.assert_called_once(bootstrap_proxy_mock)

    kwargs = bootstrap_proxy_mock.call_args[1]
    assert kwargs["efs_proxy_enabled"] == True


def test_mount_with_proxy_stunnel_enabled(mocker, capsys):
    options = dict(DEFAULT_OPTIONS)
    options["stunnel"] = None

    bootstrap_proxy_mock = mocker.patch("mount_efs.bootstrap_proxy")
    mocker.patch("os.path.ismount", return_value=False)
    mocker.patch("threading.Thread.start")
    mocker.patch("threading.Thread.join")
    mocker.patch("mount_efs.mount_nfs")
    _mock_popen(mocker, stdout="nfs")
    mount_efs.mount_with_proxy(
        _get_config(),
        INIT_SYSTEM,
        DNS_NAME,
        PATH,
        FS_ID,
        MOUNT_POINT,
        options,
    )
    utils.assert_called_once(bootstrap_proxy_mock)

    kwargs = bootstrap_proxy_mock.call_args[1]
    assert kwargs["efs_proxy_enabled"] == False
