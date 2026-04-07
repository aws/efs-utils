#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import pytest

import efs_utils_common.context as context
import efs_utils_common.mount_options as mount_options


@pytest.fixture(autouse=True)
def setup_test():
    mount_context = context.MountContext()
    mount_context.reset()
    yield mount_context
    mount_context.reset()


def test_azid_option_unsupported(capsys):
    options = {"azid": "use1-az1"}
    mount_context = context.MountContext()
    mount_context.unsupported_options = ["azid"]

    with pytest.raises(SystemExit):
        mount_options.check_unsupported_options(options)

    out, err = capsys.readouterr()
    assert "Unsupported mount options detected" in err
    assert "azid" in err


def test_no_efs_unsupported_options(capsys):
    options = {"tls": None}
    mount_context = context.MountContext()
    mount_context.unsupported_options = ["azid"]

    mount_options.check_unsupported_options(options)

    out, err = capsys.readouterr()
    assert not out
    assert "tls" in options
