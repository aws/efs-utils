# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.

import subprocess
from unittest.mock import MagicMock

import pytest

import mount_efs

from .. import common, utils

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

LOCAL_HOST = "127.0.0.1"


def _get_config(
    mount_nfs_command_retry="true",
    mount_nfs_command_retry_count=4,
    mount_nfs_command_retry_timeout=10,
):
    try:
        config = ConfigParser.SafeConfigParser()
    except AttributeError:
        config = ConfigParser()
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
    return config


def _mock_popen(mocker, returncode=0, stdout="stdout", stderr="stderr"):
    popen_mock = MagicMock()
    popen_mock.communicate.return_value = (
        stdout,
        stderr,
    )
    popen_mock.returncode = returncode

    return mocker.patch("subprocess.Popen", return_value=popen_mock)


def test_mount_nfs(mocker):
    mock = _mock_popen(mocker)
    optimize_readahead_window_mock = mocker.patch("mount_efs.optimize_readahead_window")

    mount_efs.mount_nfs(
        _get_config(mount_nfs_command_retry="false"),
        DNS_NAME,
        "/",
        "/mnt",
        DEFAULT_OPTIONS,
    )

    args, _ = mock.call_args
    args = args[0]

    assert "/sbin/mount.nfs4" == args[NFS_BIN_ARG_IDX]
    assert LOCAL_HOST in args[NFS_MOUNT_PATH_IDX]
    assert "/mnt" == args[NFS_MOUNT_POINT_IDX]

    utils.assert_called_once(optimize_readahead_window_mock)


def test_mount_nfs_stunnel_enabled(mocker):
    mock = _mock_popen(mocker)
    optimize_readahead_window_mock = mocker.patch("mount_efs.optimize_readahead_window")
    options = dict(DEFAULT_OPTIONS)
    options["stunnel"] = None

    mount_efs.mount_nfs(
        _get_config(mount_nfs_command_retry="false"),
        DNS_NAME,
        "/",
        "/mnt",
        options,
    )

    args, _ = mock.call_args
    args = args[0]

    assert "/sbin/mount.nfs4" == args[NFS_BIN_ARG_IDX]
    assert DNS_NAME in args[NFS_MOUNT_PATH_IDX]
    assert "/mnt" == args[NFS_MOUNT_POINT_IDX]

    utils.assert_called_once(optimize_readahead_window_mock)


def test_mount_nfs_stunnel_with_fallback_ip_address(mocker):
    mock = _mock_popen(mocker)
    optimize_readahead_window_mock = mocker.patch("mount_efs.optimize_readahead_window")
    options = dict(DEFAULT_OPTIONS)
    options["stunnel"] = None

    mount_efs.mount_nfs(
        _get_config(mount_nfs_command_retry="false"),
        DNS_NAME,
        "/",
        "/mnt",
        options,
        fallback_ip_address=FALLBACK_IP_ADDRESS,
    )

    args, _ = mock.call_args
    args = args[0]

    assert "/sbin/mount.nfs4" == args[NFS_BIN_ARG_IDX]
    assert DNS_NAME not in args[NFS_MOUNT_PATH_IDX]
    assert FALLBACK_IP_ADDRESS in args[NFS_MOUNT_PATH_IDX]
    assert "/mnt" == args[NFS_MOUNT_POINT_IDX]

    utils.assert_called_once(optimize_readahead_window_mock)


def test_mount_nfs_tls_stunnel_enabled(mocker):
    mock = _mock_popen(mocker)
    optimize_readahead_window_mock = mocker.patch("mount_efs.optimize_readahead_window")

    options = dict(DEFAULT_OPTIONS)
    options["tls"] = None
    options["stunnel"] = None

    mount_efs.mount_nfs(
        _get_config(mount_nfs_command_retry="false"), DNS_NAME, "/", "/mnt", options
    )

    args, _ = mock.call_args
    args = args[0]

    assert DNS_NAME not in args[NFS_MOUNT_PATH_IDX]
    assert "127.0.0.1" in args[NFS_MOUNT_PATH_IDX]

    utils.assert_called_once(optimize_readahead_window_mock)


def test_mount_nfs_failure(mocker):
    _mock_popen(mocker, returncode=1)
    optimize_readahead_window_mock = mocker.patch("mount_efs.optimize_readahead_window")

    with pytest.raises(SystemExit) as ex:
        mount_efs.mount_nfs(
            _get_config(mount_nfs_command_retry="false"),
            DNS_NAME,
            "/",
            "/mnt",
            DEFAULT_OPTIONS,
        )

    assert 0 != ex.value.code

    utils.assert_not_called(optimize_readahead_window_mock)


def test_mount_nfs_tls_netns(mocker):
    mock = _mock_popen(mocker)
    optimize_readahead_window_mock = mocker.patch("mount_efs.optimize_readahead_window")

    options = dict(DEFAULT_OPTIONS)
    options["tls"] = None
    options["netns"] = NETNS

    mount_efs.mount_nfs(
        _get_config(mount_nfs_command_retry="false"), DNS_NAME, "/", "/mnt", options
    )

    args, _ = mock.call_args
    args = args[0]

    assert "nsenter" == args[NETNS_NSENTER_ARG_IDX]
    assert "--net=" + NETNS == args[NETNS_PATH_ARG_IDX]
    assert "/sbin/mount.nfs4" == args[NFS_BIN_ARG_IDX + NETNS_NFS_OFFSET]
    assert DNS_NAME not in args[NFS_MOUNT_PATH_IDX + NETNS_NFS_OFFSET]
    assert "127.0.0.1" in args[NFS_MOUNT_PATH_IDX + NETNS_NFS_OFFSET]
    assert "/mnt" in args[NFS_MOUNT_POINT_IDX + NETNS_NFS_OFFSET]

    utils.assert_called_once(optimize_readahead_window_mock)


def test_mount_tls_mountpoint_mounted_with_nfs(mocker, capsys):
    options = dict(DEFAULT_OPTIONS)
    options["tls"] = None

    bootstrap_proxy_mock = mocker.patch("mount_efs.bootstrap_proxy")
    optimize_readahead_window_mock = mocker.patch("mount_efs.optimize_readahead_window")
    mocker.patch("os.path.ismount", return_value=True)
    _mock_popen(mocker, stdout="nfs")
    mount_efs.mount_with_proxy(
        _get_config(mount_nfs_command_retry="false"),
        INIT_SYSTEM,
        DNS_NAME,
        PATH,
        FS_ID,
        MOUNT_POINT,
        options,
    )
    out, err = capsys.readouterr()
    assert "is already mounted" in out
    utils.assert_not_called(bootstrap_proxy_mock)

    utils.assert_not_called(optimize_readahead_window_mock)


def test_mount_nfs_macos(mocker):
    mock = _mock_popen(mocker)
    mocker.patch("mount_efs.check_if_platform_is_mac", return_value=True)
    optimize_readahead_window_mock = mocker.patch("mount_efs.optimize_readahead_window")
    DEFAULT_OPTIONS["nfsvers"] = 4.0
    mount_efs.mount_nfs(
        _get_config(mount_nfs_command_retry="false"),
        DNS_NAME,
        "/",
        "/mnt",
        DEFAULT_OPTIONS,
    )

    args, _ = mock.call_args
    args = args[0]

    assert "/sbin/mount_nfs" == args[NFS_BIN_ARG_IDX]
    assert DNS_NAME in args[-2]
    assert "/mnt" == args[-1]

    utils.assert_called_once(optimize_readahead_window_mock)


def test_mount_nfs_tls_macos(mocker):
    mock = _mock_popen(mocker)
    mocker.patch("mount_efs.check_if_platform_is_mac", return_value=True)
    optimize_readahead_window_mock = mocker.patch("mount_efs.optimize_readahead_window")
    DEFAULT_OPTIONS["nfsvers"] = 4.0
    options = dict(DEFAULT_OPTIONS)
    options["tls"] = None

    mount_efs.mount_nfs(
        _get_config(mount_nfs_command_retry="false"), DNS_NAME, "/", "/mnt", options
    )

    args, _ = mock.call_args
    args = args[0]

    assert DNS_NAME not in args[NFS_MOUNT_PATH_IDX_MACOS]
    assert "127.0.0.1" in args[NFS_MOUNT_PATH_IDX_MACOS]

    utils.assert_called_once(optimize_readahead_window_mock)


def test_mount_nfs_retry_succeed_after_one_retryable_failure(mocker):
    optimize_readahead_window_mock = mocker.patch("mount_efs.optimize_readahead_window")
    mocker.patch(
        "subprocess.Popen",
        side_effect=[
            common.DEFAULT_RETRYABLE_FAILURE_POPEN.mock,
            common.DEFAULT_SUCCESS_POPEN.mock,
        ],
    )
    mount_efs.mount_nfs(_get_config(), DNS_NAME, "/", "/mnt", DEFAULT_OPTIONS)
    utils.assert_called(optimize_readahead_window_mock)


def test_mount_nfs_not_retry_on_non_retryable_failure(mocker):
    optimize_readahead_window_mock = mocker.patch("mount_efs.optimize_readahead_window")
    mocker.patch(
        "subprocess.Popen",
        side_effect=[common.DEFAULT_NON_RETRYABLE_FAILURE_POPEN.mock],
    )

    with pytest.raises(SystemExit) as ex:
        mount_efs.mount_nfs(
            _get_config(),
            DNS_NAME,
            "/",
            "/mnt",
            DEFAULT_OPTIONS,
        )

    assert 0 != ex.value.code
    utils.assert_not_called(optimize_readahead_window_mock)


def test_mount_nfs_not_retry_access_denied_without_access_point(mocker):
    optimize_readahead_window_mock = mocker.patch("mount_efs.optimize_readahead_window")

    mocker.patch(
        "subprocess.Popen", side_effect=[common.ACCESS_DENIED_FAILURE_POPEN.mock]
    )

    with pytest.raises(SystemExit) as ex:
        mount_efs.mount_nfs(
            _get_config(),
            DNS_NAME,
            "/",
            "/mnt",
            DEFAULT_OPTIONS,
        )

    assert 0 != ex.value.code
    utils.assert_not_called(optimize_readahead_window_mock)


def test_mount_nfs_retry_access_denied_with_access_point(mocker):
    optimize_readahead_window_mock = mocker.patch("mount_efs.optimize_readahead_window")

    mocker.patch(
        "subprocess.Popen", return_value=common.ACCESS_DENIED_FAILURE_POPEN.mock
    )

    options = dict(DEFAULT_OPTIONS)
    options["accesspoint"] = "fsap-12345"

    with pytest.raises(SystemExit) as ex:
        mount_efs.mount_nfs(
            _get_config(),
            DNS_NAME,
            "/",
            "/mnt",
            options,
        )

    assert 0 != ex.value.code
    assert subprocess.Popen.call_count > 1
    utils.assert_not_called(optimize_readahead_window_mock)


def test_mount_nfs_failure_after_all_attempts_fail(mocker):
    optimize_readahead_window_mock = mocker.patch("mount_efs.optimize_readahead_window")
    mocker.patch(
        "subprocess.Popen",
        side_effect=[
            common.DEFAULT_RETRYABLE_FAILURE_POPEN.mock,
            common.DEFAULT_RETRYABLE_FAILURE_POPEN.mock,
        ],
    )

    with pytest.raises(SystemExit) as ex:
        mount_efs.mount_nfs(
            _get_config(mount_nfs_command_retry_count=2),
            DNS_NAME,
            "/",
            "/mnt",
            DEFAULT_OPTIONS,
        )

    assert 0 != ex.value.code
    utils.assert_not_called(optimize_readahead_window_mock)


def test_mount_nfs_retry_succeed_after_one_timeout(mocker):
    optimize_readahead_window_mock = mocker.patch("mount_efs.optimize_readahead_window")
    mocker.patch(
        "subprocess.Popen",
        side_effect=[
            common.DEFAULT_TIMEOUT_POPEN.mock,
            common.DEFAULT_SUCCESS_POPEN.mock,
        ],
    )
    mount_efs.mount_nfs(
        _get_config(mount_nfs_command_retry_timeout=1),
        DNS_NAME,
        "/",
        "/mnt",
        DEFAULT_OPTIONS,
    )
    utils.assert_called(optimize_readahead_window_mock)


def test_mount_nfs_retry_succeed_after_one_timeout_proc_kill_error(mocker):
    optimize_readahead_window_mock = mocker.patch("mount_efs.optimize_readahead_window")
    kill_failure_process = common.PopenMock(
        return_code=1,
        poll_result=1,
        communicate_side_effect=subprocess.TimeoutExpired("cmd", timeout=1),
        kill_side_effect=OSError("Process does not exist"),
    )
    mocker.patch(
        "subprocess.Popen",
        side_effect=[kill_failure_process.mock, common.DEFAULT_SUCCESS_POPEN.mock],
    )
    mount_efs.mount_nfs(
        _get_config(mount_nfs_command_retry_timeout=1),
        DNS_NAME,
        "/",
        "/mnt",
        DEFAULT_OPTIONS,
    )
    utils.assert_called(optimize_readahead_window_mock)


def test_mount_nfs_not_retry_after_one_unknown_exception(mocker):
    optimize_readahead_window_mock = mocker.patch("mount_efs.optimize_readahead_window")
    mocker.patch(
        "subprocess.Popen",
        side_effect=[common.DEFAULT_UNKNOWN_EXCEPTION_POPEN.mock],
    )

    with pytest.raises(SystemExit) as ex:
        mount_efs.mount_nfs(
            _get_config(),
            DNS_NAME,
            "/",
            "/mnt",
            DEFAULT_OPTIONS,
        )

    assert 0 != ex.value.code
    utils.assert_not_called(optimize_readahead_window_mock)
