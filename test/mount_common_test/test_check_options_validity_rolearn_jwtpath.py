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


# ---- rolearn: valid values pass ----


@pytest.mark.parametrize(
    "rolearn",
    [
        "arn:aws:iam::123456789012:role/legit-role",
        "arn:aws:iam::123456789012:role/path/to/role_name",
        "arn:aws-cn:iam::123456789012:role/role",
        "arn:aws-us-gov:iam::123456789012:role/Admin+Role=1,x.y@z_-",
    ],
)
def test_valid_rolearn_passes(capsys, rolearn):
    mount_options.check_options_validity({"rolearn": rolearn})
    out, err = capsys.readouterr()
    assert not err


# ---- rolearn: malformed values are rejected ----


@pytest.mark.parametrize(
    "rolearn",
    [
        "arn:aws:iam::123456789012:role/legit-role\nsecond-line",  # embedded newline
        "arn:aws:iam::123456789012:role/legit-role\n",  # trailing newline
        "arn:aws:iam::123:role/short-account",  # account id not 12 digits
        "arn:aws:iam::123456789012:role/",  # empty role name
        "not-an-arn",
        "",  # empty string
    ],
)
def test_malformed_rolearn_rejected(capsys, rolearn):
    with pytest.raises(SystemExit):
        mount_options.check_options_validity({"rolearn": rolearn})
    out, err = capsys.readouterr()
    assert "rolearn" in err
    assert "malformed" in err


# ---- jwtpath: valid values pass ----


@pytest.mark.parametrize(
    "jwtpath",
    [
        "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
        "/etc/eks/pod-identity/jwt",
        "/a",
    ],
)
def test_valid_jwtpath_passes(capsys, jwtpath):
    mount_options.check_options_validity({"jwtpath": jwtpath})
    out, err = capsys.readouterr()
    assert not err


# ---- jwtpath: malformed values are rejected ----


@pytest.mark.parametrize(
    "jwtpath",
    [
        "/var/run/token\nsecond-line",  # embedded newline
        "/var/run/token\n",  # trailing newline
        "relative/path",  # not absolute
        "/etc/x y",  # whitespace
        "/etc/x,y",  # comma (option separator)
        "/tok=1",  # equals (kv separator)
        "",  # empty string
    ],
)
def test_malformed_jwtpath_rejected(capsys, jwtpath):
    with pytest.raises(SystemExit):
        mount_options.check_options_validity({"jwtpath": jwtpath})
    out, err = capsys.readouterr()
    assert "jwtpath" in err
    assert "malformed" in err


def test_absent_rolearn_jwtpath_pass(capsys):
    # Neither option present -> no validation error from this check.
    mount_options.check_options_validity({})
    out, err = capsys.readouterr()
    assert not err
