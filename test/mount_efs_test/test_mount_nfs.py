# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.

import mount_efs
import pytest
from mock import MagicMock, patch

from .. import utils

CONFIG = MagicMock()
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

    mount_efs.mount_nfs(CONFIG, DNS_NAME, "/", "/mnt", DEFAULT_OPTIONS)

    args, _ = mock.call_args
    args = args[0]

    assert "/sbin/mount.nfs4" == args[NFS_BIN_ARG_IDX]
    assert DNS_NAME in args[NFS_MOUNT_PATH_IDX]
    assert "/mnt" == args[NFS_MOUNT_POINT_IDX]

    utils.assert_called_once(optimize_readahead_window_mock)


def test_mount_nfs_with_fallback_ip_address(mocker):
    mock = _mock_popen(mocker)
    optimize_readahead_window_mock = mocker.patch("mount_efs.optimize_readahead_window")

    mount_efs.mount_nfs(
        CONFIG,
        DNS_NAME,
        "/",
        "/mnt",
        DEFAULT_OPTIONS,
        fallback_ip_address=FALLBACK_IP_ADDRESS,
    )

    args, _ = mock.call_args
    args = args[0]

    assert "/sbin/mount.nfs4" == args[NFS_BIN_ARG_IDX]
    assert DNS_NAME not in args[NFS_MOUNT_PATH_IDX]
    assert FALLBACK_IP_ADDRESS in args[NFS_MOUNT_PATH_IDX]
    assert "/mnt" == args[NFS_MOUNT_POINT_IDX]

    utils.assert_called_once(optimize_readahead_window_mock)


def test_mount_nfs_tls(mocker):
    mock = _mock_popen(mocker)
    optimize_readahead_window_mock = mocker.patch("mount_efs.optimize_readahead_window")

    options = dict(DEFAULT_OPTIONS)
    options["tls"] = None

    mount_efs.mount_nfs(CONFIG, DNS_NAME, "/", "/mnt", options)

    args, _ = mock.call_args
    args = args[0]

    assert DNS_NAME not in args[NFS_MOUNT_PATH_IDX]
    assert "127.0.0.1" in args[NFS_MOUNT_PATH_IDX]

    utils.assert_called_once(optimize_readahead_window_mock)


def test_mount_nfs_failure(mocker):
    _mock_popen(mocker, returncode=1)
    optimize_readahead_window_mock = mocker.patch("mount_efs.optimize_readahead_window")

    with pytest.raises(SystemExit) as ex:
        mount_efs.mount_nfs(CONFIG, DNS_NAME, "/", "/mnt", DEFAULT_OPTIONS)

    assert 0 != ex.value.code

    utils.assert_not_called(optimize_readahead_window_mock)


def test_mount_nfs_tls_netns(mocker):
    mock = _mock_popen(mocker)
    optimize_readahead_window_mock = mocker.patch("mount_efs.optimize_readahead_window")

    options = dict(DEFAULT_OPTIONS)
    options["tls"] = None
    options["netns"] = NETNS

    mount_efs.mount_nfs(CONFIG, DNS_NAME, "/", "/mnt", options)

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

    bootstrap_tls_mock = mocker.patch("mount_efs.bootstrap_tls")
    optimize_readahead_window_mock = mocker.patch("mount_efs.optimize_readahead_window")
    mocker.patch("os.path.ismount", return_value=True)
    _mock_popen(mocker, stdout="nfs")
    mount_efs.mount_tls(
        CONFIG, INIT_SYSTEM, DNS_NAME, PATH, FS_ID, MOUNT_POINT, options
    )
    out, err = capsys.readouterr()
    assert "is already mounted" in out
    utils.assert_not_called(bootstrap_tls_mock)

    utils.assert_not_called(optimize_readahead_window_mock)


def test_mount_nfs_macos(mocker):
    mock = _mock_popen(mocker)
    mocker.patch("mount_efs.check_if_platform_is_mac", return_value=True)
    optimize_readahead_window_mock = mocker.patch("mount_efs.optimize_readahead_window")
    DEFAULT_OPTIONS["nfsvers"] = 4.0
    mount_efs.mount_nfs(CONFIG, DNS_NAME, "/", "/mnt", DEFAULT_OPTIONS)

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

    mount_efs.mount_nfs(CONFIG, DNS_NAME, "/", "/mnt", options)

    args, _ = mock.call_args
    args = args[0]

    assert DNS_NAME not in args[NFS_MOUNT_PATH_IDX_MACOS]
    assert "127.0.0.1" in args[NFS_MOUNT_PATH_IDX_MACOS]

    utils.assert_called_once(optimize_readahead_window_mock)
