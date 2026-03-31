#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import pytest

import efs_utils_common.constants as constants
import efs_utils_common.context as context
import efs_utils_common.mount_options as mount_options


@pytest.fixture(autouse=True)
def setup_test():
    mount_context = context.MountContext()
    mount_context.reset()
    mount_context.mount_type = constants.MOUNT_TYPE_EFS
    mount_context.config_file_path = constants.CONFIG_FILE
    yield mount_context
    mount_context.reset()


def test_no_unsupported_options(capsys):
    options = {}

    mount_options.check_unsupported_options(options)

    out, err = capsys.readouterr()
    assert not out


def test_capath_unsupported(capsys):
    options = {"capath": "/capath"}

    with pytest.raises(SystemExit):
        mount_options.check_unsupported_options(options)

    out, err = capsys.readouterr()
    assert "Unsupported mount options detected" in err
    assert "capath" in err


def test_no_unsupported_options_with_additional_list(capsys):
    options = {}
    mount_context = context.MountContext()
    mount_context.unsupported_options = ["custom_option"]

    mount_options.check_unsupported_options(options)

    out, err = capsys.readouterr()
    assert not out


def test_additional_unsupported_option(capsys):
    options = {"custom_option": "value"}
    mount_context = context.MountContext()
    mount_context.unsupported_options = ["custom_option"]

    with pytest.raises(SystemExit):
        mount_options.check_unsupported_options(options)

    out, err = capsys.readouterr()
    assert "Unsupported mount options detected" in err
    assert "custom_option" in err


def test_additional_unsupported_options_includes_default(capsys):
    options = {"capath": "/capath", "custom_option": "value"}
    mount_context = context.MountContext()
    mount_context.unsupported_options = ["custom_option"]

    with pytest.raises(SystemExit):
        mount_options.check_unsupported_options(options)

    out, err = capsys.readouterr()
    assert "Unsupported mount options detected" in err
    assert "custom_option" in err
    assert "capath" in err


def test_empty_additional_unsupported_list(capsys):
    options = {"capath": "/capath"}

    with pytest.raises(SystemExit):
        mount_options.check_unsupported_options(options)

    out, err = capsys.readouterr()
    assert "Unsupported mount options detected" in err
    assert "capath" in err
