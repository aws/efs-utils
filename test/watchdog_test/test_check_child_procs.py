#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import watchdog

from mock import MagicMock

from .. import utils


def test_child_procs_empty():
    watchdog.check_child_procs([])

    # nothing to assert, this just verifies that empty child procs doesn't crash


def test_child_procs():
    live_proc = MagicMock(returncode=None)
    dead_proc = MagicMock(returncode=1)

    children = [live_proc, dead_proc]

    watchdog.check_child_procs(children)

    assert 1 == len(children)
    assert dead_proc not in children
    utils.assert_called_once(dead_proc.poll)
    assert live_proc in children
    utils.assert_called_once(live_proc.poll)
