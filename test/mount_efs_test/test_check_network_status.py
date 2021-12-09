# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.

import mount_efs
import pytest
from mock import MagicMock

from .. import utils

FS_ID = "fs-deadbeef"


def _mock_subprocess_call(mocker, returncode=0):
    call_mock = MagicMock(return_value=returncode)
    return mocker.patch("subprocess.call", side_effect=call_mock)


def test_non_systemd(mocker):
    call_mock = _mock_subprocess_call(mocker)

    mount_efs.check_network_status(FS_ID, "init")

    utils.assert_not_called(call_mock)


def test_systemd_network_up(mocker):
    call_mock = _mock_subprocess_call(mocker)

    mount_efs.check_network_status(FS_ID, "systemd")

    utils.assert_called_once(call_mock)


def test_systemd_network_down(mocker):
    call_mock = _mock_subprocess_call(mocker, returncode=1)

    with pytest.raises(SystemExit) as ex:
        mount_efs.check_network_status(FS_ID, "systemd")

    utils.assert_called_once(call_mock)
    assert 0 == ex.value.code
