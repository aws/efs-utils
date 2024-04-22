#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import watchdog
import json
import tempfile

PID = 1234


def test_restart_tls_tunnel(mocker, tmpdir):
    mocker.patch('watchdog.start_tls_tunnel', return_value=PID)

    state = {
        'pid': 9999,
        'cmd': ''
    }

    state_file = tmpdir.join(tempfile.mktemp())
    state_file.write(json.dumps(state), ensure=True)

    watchdog.restart_tls_tunnel([], state, state_file.dirname, state_file.basename)

    assert PID == state['pid']

    with state_file.open() as f:
        new_state = json.load(f)

    assert PID == new_state['pid']
