#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import subprocess

from mock import MagicMock


# The process mock can be retrieved by calling PopenMock(<init params>).mock
class PopenMock:
    def __init__(
        self,
        return_code=0,
        poll_result=0,
        communicate_return_value=None,
        communicate_side_effect=None,
        kill_side_effect=None,
    ):
        self.return_code = return_code
        self.poll_result = poll_result
        self.communicate_return_value = communicate_return_value
        self.communicate_side_effect = communicate_side_effect
        self.kill_side_effect = kill_side_effect
        self.mock = self._create_mock()

    def _create_mock(self):
        popen_mock = MagicMock()
        if self.communicate_return_value:
            popen_mock.communicate.return_value = self.communicate_return_value
        elif self.communicate_side_effect:
            popen_mock.communicate.side_effect = self.communicate_side_effect
        if self.kill_side_effect:
            popen_mock.kill.side_effect = self.kill_side_effect
        popen_mock.returncode = self.return_code
        popen_mock.poll.return_value = self.poll_result
        return popen_mock


DEFAULT_RETRYABLE_FAILURE_POPEN = PopenMock(
    return_code=1,
    poll_result=1,
    communicate_return_value=(b"", b"mount.nfs4: Connection reset by peer"),
)
DEFAULT_NON_RETRYABLE_FAILURE_POPEN = PopenMock(
    return_code=1,
    poll_result=1,
    communicate_return_value=(
        b"",
        b"mount.nfs4: Protocol not supported",
    ),
)
ACCESS_DENIED_FAILURE_POPEN = PopenMock(
    return_code=1,
    poll_result=1,
    communicate_return_value=(
        b"",
        b"mount.nfs4: access denied by server while mounting 127.0.0.1:/",
    ),
)
DEFAULT_SUCCESS_POPEN = PopenMock(communicate_return_value=(b"", b""))
DEFAULT_TIMEOUT_POPEN = PopenMock(
    return_code=1,
    poll_result=1,
    communicate_side_effect=subprocess.TimeoutExpired("cmd", timeout=1),
)
DEFAULT_UNKNOWN_EXCEPTION_POPEN = PopenMock(
    return_code=1, poll_result=1, communicate_side_effect=Exception("Unknown error")
)
