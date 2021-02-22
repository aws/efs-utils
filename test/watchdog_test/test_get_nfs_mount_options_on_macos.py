#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import watchdog

import pytest

import sys

import json

from mock import MagicMock

NFSSTAT_DEFAULT_OUTPUT = {
    "127.0.0.1:/": {
        "Current mount parameters": {
            "File system locations": [
                {
                    "Export": "/",
                    "Locations": [
                        "127.0.0.1"
                    ],
                    "Server": "127.0.0.1"
                }
            ],
            "NFS parameters": [
                "port=12345",
                "rw"
            ]
        },
        "Original mount options": {
            "File system locations": [
                {
                    "Export": "/",
                    "Locations": [
                        "127.0.0.1"
                    ],
                    "Server": "127.0.0.1"
                }
            ],
            "NFS parameters": [
                "port=12345",
                "rw"
            ]
        },
        "Server": "/Users/ec2-user/efs"
    }
}

@pytest.mark.skipif(sys.version_info < (3,5),
                    reason="requires python3.5")
def test_get_nfs_mount_options_on_macos(mocker):
    mount_point = "/mnt"
    process_mock = MagicMock()
    process_mock.stdout = str(json.dumps(NFSSTAT_DEFAULT_OUTPUT))
    process_mock.returncode = 0

    mocker.patch('subprocess.run', return_value=process_mock)
    nfs_options = watchdog.get_nfs_mount_options_on_macos(mount_point)
    assert 'port=12345' in nfs_options
