# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.

import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock

import pytest

import watchdog

from .. import utils

PID = 1234


def _get_popen_mock(pid=PID):
    popen_mock = MagicMock()
    popen_mock.pid = pid
    return popen_mock


def _mock_popen(mocker):
    return mocker.patch("subprocess.Popen", return_value=_get_popen_mock())


def _initiate_state_file(tmpdir, cmd=None):
    state = {
        "pid": PID - 1,
        "cmd": cmd
        if cmd
        else [
            "/usr/bin/stunnel",
            "/var/run/efs/stunnel-config.fs-deadbeef.mnt.21007",
        ],
    }
    state_file = tempfile.mkstemp(prefix="state", dir=str(tmpdir))[1]
    with open(state_file, "w") as f:
        f.write(json.dumps(state))
    return state, state_file


def test_start_tls_tunnel(mocker, tmpdir):
    _mock_popen(mocker)
    mocker.patch("watchdog.is_pid_running", return_value=True)

    state, state_file = _initiate_state_file(tmpdir)
    procs = []
    pid = watchdog.start_tls_tunnel(procs, state, str(tmpdir), state_file)

    assert PID == pid
    assert 1 == len(procs)


def test_start_tls_tunnel_fails(mocker, capsys, tmpdir):
    _mock_popen(mocker)
    mocker.patch("watchdog.is_pid_running", return_value=False)

    state, state_file = _initiate_state_file(tmpdir)
    procs = []
    with pytest.raises(SystemExit) as ex:
        watchdog.start_tls_tunnel(procs, state, str(tmpdir), state_file)

    assert 0 == len(procs)
    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert "Failed to initialize TLS tunnel" in err


# https://github.com/kubernetes-sigs/aws-efs-csi-driver/issues/812 The watchdog is trying to launch stunnel on AL2 for
# mounts using older version of efs-utils based on old state file command, while somehow the stunnel bin is removed
# after updating driver with new efs-utils(using stunnel5 bin). Watchdog should handle the case when the stunnel cannot
# be found, and fallback to use stunnel5 on AL2.
#
def _test_start_tls_tunnel_for_mount_via_older_version_of_efs_utils_on_amazon_linux_2_helper(
    mocker, tmpdir, release_version
):
    popen_mocker = mocker.patch(
        "subprocess.Popen", side_effect=[FileNotFoundError, _get_popen_mock()]
    )
    mocker.patch("watchdog.is_pid_running", return_value=True)
    mocker.patch(
        "watchdog.get_system_release_version",
        return_value=release_version,
    )
    mocker.patch("watchdog.find_command_path", return_value="/usr/sbin/stunnel5")

    state, state_file = _initiate_state_file(tmpdir)
    procs = []
    pid = watchdog.start_tls_tunnel(
        procs, state, str(tmpdir), state_file.split("/")[-1]
    )
    assert PID == pid
    assert 1 == len(procs)
    utils.assert_called_n_times(popen_mocker, 2)

    with open(state_file) as f:
        state = json.load(f)

    assert "/usr/sbin/stunnel5" == state["cmd"][0]


def test_start_tls_tunnel_for_mount_via_older_version_of_efs_utils_on_amazon_linux_2_with_release_id(
    mocker, tmpdir
):
    _test_start_tls_tunnel_for_mount_via_older_version_of_efs_utils_on_amazon_linux_2_helper(
        mocker, tmpdir, watchdog.AMAZON_LINUX_2_RELEASE_ID
    )


def test_start_tls_tunnel_for_mount_via_older_version_of_efs_utils_on_amazon_linux_2_with_pretty_name(
    mocker, tmpdir
):
    _test_start_tls_tunnel_for_mount_via_older_version_of_efs_utils_on_amazon_linux_2_helper(
        mocker, tmpdir, watchdog.AMAZON_LINUX_2_PRETTY_NAME
    )


# On ECS AL2, the stunnel is started in the given network namespace, i.e. the command to start stunnel is different.
# e.g. nsenter --net=/proc/1234/ns/net /usr/bin/stunnel /var/run/efs/stunnel-config.fs-deadbeef.12345
# Need to make sure after we detect the stunnel is not found, we update the old mount to use stunnel5, and command is
# nsenter --net=/proc/1234/ns/net /usr/bin/stunnel5 /var/run/efs/stunnel-config.fs-deadbeef.12345
#
def test_start_tls_tunnel_for_mount_via_older_version_of_efs_utils_on_ecs_amazon_linux_2(
    mocker, tmpdir
):
    _mock_popen(mocker)
    mocker.patch("watchdog.is_pid_running", return_value=True)
    mocker.patch(
        "watchdog.get_system_release_version",
        return_value=watchdog.AMAZON_LINUX_2_RELEASE_ID,
    )
    mocker.patch("watchdog.find_command_path", return_value="/usr/sbin/stunnel5")

    namespace = "--net=/proc/1234/ns/net"
    cmd = [
        "nsenter",
        namespace,
        "/usr/bin/stunnel",
        "/var/run/efs/stunnel-config.fs-deadbeef.mnt.21007",
    ]
    state, state_file = _initiate_state_file(tmpdir, cmd=cmd)
    procs = []
    pid = watchdog.start_tls_tunnel(
        procs, state, str(tmpdir), state_file.split("/")[-1]
    )
    assert PID == pid
    assert 1 == len(procs)

    with open(state_file) as f:
        state = json.load(f)

    assert " ".join(["nsenter", namespace, "/usr/sbin/stunnel5"]) in " ".join(
        state["cmd"]
    )
