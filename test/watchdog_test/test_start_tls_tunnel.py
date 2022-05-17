# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.

from unittest.mock import MagicMock

import pytest

import watchdog

PID = 1234


def _mock_popen(mocker, returncode=0):
    popen_mock = MagicMock()
    popen_mock.communicate.return_value = (
        "stdout",
        "stderr",
    )
    popen_mock.pid = PID
    popen_mock.returncode = returncode

    return mocker.patch("subprocess.Popen", return_value=popen_mock)


def test_start_tls_tunnel(mocker):
    _mock_popen(mocker)
    mocker.patch("watchdog.is_pid_running", return_value=True)

    procs = []
    pid = watchdog.start_tls_tunnel(procs, "fs-deadbeef", "stunnel")

    assert PID == pid
    assert 1 == len(procs)


def test_start_tls_tunnel_fails(mocker, capsys):
    _mock_popen(mocker)
    mocker.patch("watchdog.is_pid_running", return_value=False)

    procs = []

    with pytest.raises(SystemExit) as ex:
        watchdog.start_tls_tunnel(procs, "fs-deadbeef", "stunnel")

    assert 0 == len(procs)

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert "Failed to initialize TLS tunnel" in err
