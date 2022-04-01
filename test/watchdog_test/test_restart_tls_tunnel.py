#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import json
import tempfile

import watchdog

from .. import utils

PID = 1234


def test_restart_tls_tunnel_without_certificate_path(mocker, tmpdir):
    mocker.patch("watchdog.start_tls_tunnel", return_value=PID)

    state = {"pid": 9999, "cmd": ""}

    state_file = tmpdir.join(tempfile.mkstemp()[1])
    state_file.write(json.dumps(state), ensure=True)

    watchdog.restart_tls_tunnel([], state, state_file.dirname, state_file.basename)

    assert PID == state["pid"]

    with state_file.open() as f:
        new_state = json.load(f)

    assert PID == new_state["pid"]


def test_restart_tls_tunnel_with_certificate_path(mocker, tmpdir):
    start_tls_tunnel_call = mocker.patch("watchdog.start_tls_tunnel", return_value=PID)

    state = {"pid": 9999, "cmd": "", "certificate": "foo/bar/certificate.pem"}

    state_file = tmpdir.join(tempfile.mkstemp()[1])
    state_file.write(json.dumps(state), ensure=True)

    watchdog.restart_tls_tunnel([], state, state_file.dirname, state_file.basename)

    utils.assert_not_called(start_tls_tunnel_call)
