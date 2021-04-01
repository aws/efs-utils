#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import mount_efs
import socket

import pytest


def test_validate_dns_resolves_unresolvable(mocker, capsys):
    mocker.patch('socket.gethostbyname', side_effect=socket.gaierror)

    with pytest.raises(SystemExit) as ex:
        mount_efs.validate_dns_resolves("fs-deadbeef.efs.us-west-2.amazonaws.com")

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert 'Failed to resolve' in err
