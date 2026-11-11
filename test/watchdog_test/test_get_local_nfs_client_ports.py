#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import watchdog

SERVERS = """NV SERVER   PORT USE HOSTNAME
v4 7f000001  4e51   1 127.0.0.1
v4 7F000001  4e52   2 127.0.0.1
v4 0a000005  0801   1 10.0.0.5
v4 00000000000000000000000000000001  4e53   1 ::1
v4 7f000001  zzzz   1 127.0.0.1
v4 7f000001
"""


def test_parses_localhost_clients(tmpdir):
    proc_file = tmpdir.join("servers")
    proc_file.write(SERVERS)

    assert watchdog.get_local_nfs_client_ports(str(proc_file)) == {0x4E51, 0x4E52}


def test_missing_proc_file(tmpdir):
    assert watchdog.get_local_nfs_client_ports(str(tmpdir.join("missing"))) is None


def test_no_clients(tmpdir):
    proc_file = tmpdir.join("servers")
    proc_file.write("NV SERVER   PORT USE HOSTNAME\n")

    assert watchdog.get_local_nfs_client_ports(str(proc_file)) == set()


def test_port_from_state_file_name():
    assert (
        watchdog.get_port_from_state_file_name("fs-deadbeef.home.user.mnt.20049")
        == 20049
    )
    assert watchdog.get_port_from_state_file_name("fs-deadbeef.home.user.mnt") is None
