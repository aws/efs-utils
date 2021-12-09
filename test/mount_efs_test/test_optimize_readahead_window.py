#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import subprocess

import mount_efs

from .. import utils

try:
    import ConfigParser
except ImportError:
    from configparser import ConfigParser

MOUNT_POINT = "/mnt"
DEFAULT_OPTIONS = {
    "nfsvers": 4.1,
    "rsize": 1048576,
    "wsize": 1048576,
    "hard": None,
    "timeo": 600,
    "retrans": 2,
    "tlsport": 3049,
}

EXPECTED_MOUNT_POINT_DEV_NUMBER = 54
EXPECTED_READAHEAD_KB_PATH = (
    mount_efs.NFS_READAHEAD_CONFIG_PATH_FORMAT % EXPECTED_MOUNT_POINT_DEV_NUMBER
)
EXPECTED_CALL_FORMAT = "echo %s > %s"


def _get_new_mock_config(
    enable_optimize_readahead, has_readahead_optimization_item_in_config=True
):
    try:
        config = ConfigParser.SafeConfigParser()
    except AttributeError:
        config = ConfigParser()
    config.add_section(mount_efs.CONFIG_SECTION)
    if has_readahead_optimization_item_in_config:
        config.set(
            mount_efs.CONFIG_SECTION,
            "optimize_readahead",
            str(enable_optimize_readahead),
        )
    return config


def _mock_subprocess_call(mocker, throw_exception=False):
    def _side_effect_raise_exception(cmd, shell):
        raise subprocess.CalledProcessError(1, cmd)

    if throw_exception:
        return mocker.patch(
            "subprocess.check_call", side_effect=_side_effect_raise_exception
        )
    else:
        return mocker.patch("subprocess.check_call")


def _mock_conditions(
    mocker,
    system="Linux",
    kernel_version=mount_efs.NFS_READAHEAD_OPTIMIZE_LINUX_KERNEL_MIN_VERSION,
):
    mocker.patch("platform.system", return_value=system)
    mocker.patch("mount_efs.get_linux_kernel_version", return_value=kernel_version)


def _mock_should_revise_readahead(mocker, should_apply):
    mocker.patch("mount_efs.should_revise_readahead", return_value=should_apply)


def test_should_revise_readahead_disable_in_config(mocker):
    mock_config = _get_new_mock_config(False)
    assert False == mount_efs.should_revise_readahead(mock_config)


def test_should_revise_readahead_on_none_linux(mocker):
    mock_config = _get_new_mock_config(True)
    _mock_conditions(mocker, system="Unknown")
    assert False == mount_efs.should_revise_readahead(mock_config)


def test_should_revise_readahead_on_linux_lower_54(mocker):
    mock_config = _get_new_mock_config(True)
    _mock_conditions(mocker, kernel_version=[5, 3])
    assert False == mount_efs.should_revise_readahead(mock_config)


def test_should_revise_readahead_on_linux_eq_min_version(mocker):
    mock_config = _get_new_mock_config(True)
    _mock_conditions(mocker, kernel_version=[5, 4])
    assert True == mount_efs.should_revise_readahead(mock_config)


def test_should_revise_readahead_on_linux_gt_min_version(mocker):
    mock_config = _get_new_mock_config(True)
    _mock_conditions(mocker, kernel_version=[6, 5])
    assert True == mount_efs.should_revise_readahead(mock_config)


def test_should_revise_readahead_when_config_not_present(mocker, capsys):
    mock_config = _get_new_mock_config(
        True, has_readahead_optimization_item_in_config=False
    )
    _mock_conditions(mocker)
    assert False == mount_efs.should_revise_readahead(mock_config)

    out, err = capsys.readouterr()
    assert "config file does not have" in out


def test_optimize_readahead_should_not_apply(mocker):
    mock_subprocess_call = _mock_subprocess_call(mocker)
    mock_config = _get_new_mock_config(True)
    _mock_should_revise_readahead(mocker, False)
    mount_efs.optimize_readahead_window(MOUNT_POINT, DEFAULT_OPTIONS, mock_config)
    utils.assert_not_called(mock_subprocess_call)


def test_optimize_readahead_should_apply(mocker):
    mock_subprocess_call = _mock_subprocess_call(mocker)
    mock_config = _get_new_mock_config(True)
    _mock_should_revise_readahead(mocker, True)

    mocker.patch(
        "subprocess.check_output",
        return_value='"' + str(EXPECTED_MOUNT_POINT_DEV_NUMBER) + '"\n',
    )

    mount_efs.optimize_readahead_window(MOUNT_POINT, DEFAULT_OPTIONS, mock_config)

    utils.assert_called_once(mock_subprocess_call)

    args, _ = mock_subprocess_call.call_args

    readahead_kb_value = int(
        mount_efs.DEFAULT_NFS_MAX_READAHEAD_MULTIPLIER
        * int(DEFAULT_OPTIONS["rsize"])
        / 1024
    )
    expected_subprocess_call = EXPECTED_CALL_FORMAT % (
        readahead_kb_value,
        EXPECTED_READAHEAD_KB_PATH,
    )
    assert expected_subprocess_call == args[0]


def test_optimize_readahead_should_apply_failed_with_exception(mocker):
    mock_subprocess_call = _mock_subprocess_call(mocker, True)
    mock_config = _get_new_mock_config(True)
    mock_log_warning = mocker.patch("logging.warning")
    _mock_should_revise_readahead(mocker, True)

    mocker.patch(
        "subprocess.check_output",
        return_value='"' + str(EXPECTED_MOUNT_POINT_DEV_NUMBER) + '"\n',
    )

    mount_efs.optimize_readahead_window(MOUNT_POINT, DEFAULT_OPTIONS, mock_config)

    utils.assert_called_once(mock_subprocess_call)

    args, _ = mock_subprocess_call.call_args

    readahead_kb_value = int(
        mount_efs.DEFAULT_NFS_MAX_READAHEAD_MULTIPLIER
        * int(DEFAULT_OPTIONS["rsize"])
        / 1024
    )
    expected_subprocess_call = EXPECTED_CALL_FORMAT % (
        readahead_kb_value,
        EXPECTED_READAHEAD_KB_PATH,
    )
    assert expected_subprocess_call == args[0]

    assert "failed to modify read_ahead_kb" in mock_log_warning.call_args[0][0]
