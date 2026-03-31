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
import mount_s3files


@pytest.fixture(autouse=True)
def setup_test():
    """
    Setup fixture that runs before each test function.
    Instantiate and reset the MountContext singleton for clean test state.
    """
    mount_context = context.MountContext()
    mount_context.reset()
    yield mount_context
    mount_context.reset()


def test_az_option_unsupported(capsys):
    options = {"az": "us-east-1a"}
    mount_context = context.MountContext()
    mount_context.unsupported_options = ["az", "notls"]

    with pytest.raises(SystemExit):
        mount_options.check_unsupported_options(options)

    out, err = capsys.readouterr()
    assert "Unsupported mount options detected" in err
    assert "az" in err


def test_notls_option_unsupported(capsys):
    options = {"notls": None}
    mount_context = context.MountContext()
    mount_context.unsupported_options = ["az", "notls"]

    with pytest.raises(SystemExit):
        mount_options.check_unsupported_options(options)

    out, err = capsys.readouterr()
    assert "Unsupported mount options detected" in err
    assert "notls" in err


def test_both_s3files_unsupported_options(capsys):
    options = {"az": "us-east-1a", "notls": None}
    mount_context = context.MountContext()
    mount_context.unsupported_options = (
        mount_s3files.MOUNT_TYPE_SPECIFIC_UNSUPPORTED_OPTIONS
    )

    assert len(mount_s3files.MOUNT_TYPE_SPECIFIC_UNSUPPORTED_OPTIONS) == 4

    with pytest.raises(SystemExit):
        mount_options.check_unsupported_options(options)

    out, err = capsys.readouterr()
    assert "Unsupported mount options detected" in err
    assert "az" in err
    assert "notls" in err


def test_stunnel_option_unsupported(capsys):
    options = {"stunnel": None}
    mount_context = context.MountContext()
    mount_context.unsupported_options = (
        mount_s3files.MOUNT_TYPE_SPECIFIC_UNSUPPORTED_OPTIONS
    )

    with pytest.raises(SystemExit):
        mount_options.check_unsupported_options(options)

    out, err = capsys.readouterr()
    assert "Unsupported mount options detected" in err
    assert "stunnel" in err


def test_no_s3files_unsupported_options(capsys):
    options = {"crossaccount": None}
    mount_context = context.MountContext()
    mount_context.unsupported_options = ["az", "notls"]

    mount_options.check_unsupported_options(options)

    out, err = capsys.readouterr()
    assert not out
    assert "crossaccount" in options
