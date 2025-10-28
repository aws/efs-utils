#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#
import os
import subprocess
import time

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

DEFAULT_MOUNT_DEVICE_NUMBER = 1048761


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
    def _side_effect_raise_exception(cmd):
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


def test_should_revise_readahead_disable_in_config():
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


def test_device_number_parsing():
    device_number_parsing_helper(2097372, expect_major=0, expect_minor=732)
    device_number_parsing_helper(1048761, expect_major=0, expect_minor=441)
    device_number_parsing_helper(2097198, expect_major=0, expect_minor=558)
    device_number_parsing_helper(40, expect_major=0, expect_minor=40)


def test_optimize_readahead_should_not_apply(mocker):
    mock_config = _get_new_mock_config(True)
    _mock_should_revise_readahead(mocker, False)
    stat_mock_call = mocker.patch("os.stat")
    mount_efs.optimize_readahead_window(MOUNT_POINT, DEFAULT_OPTIONS, mock_config)
    utils.assert_not_called(stat_mock_call)


def test_optimize_readahead_should_apply(mocker, tmpdir):
    mock_config = _get_new_mock_config(enable_optimize_readahead=True)
    _mock_should_revise_readahead(mocker, True)
    # Modify the config path to verify in the test temporary folder
    mocker.patch(
        "mount_efs.NFS_READAHEAD_CONFIG_PATH_FORMAT",
        str(tmpdir) + "/%s:%s/read_ahead_kb",
    )
    mocker.patch(
        "os.stat",
        return_value=generate_os_stat_result(st_dev=DEFAULT_MOUNT_DEVICE_NUMBER),
    )
    expected_major, expected_minor = mount_efs.decode_device_number(
        DEFAULT_MOUNT_DEVICE_NUMBER
    )
    os.mkdir(str(tmpdir) + "/%s:%s" % (expected_major, expected_minor))

    mount_efs.optimize_readahead_window(MOUNT_POINT, DEFAULT_OPTIONS, mock_config)

    expected_readahead_kb_value = int(
        mount_efs.DEFAULT_NFS_MAX_READAHEAD_MULTIPLIER
        * int(DEFAULT_OPTIONS["rsize"])
        / 1024
    )
    with open(
        str(tmpdir) + "/%s:%s/read_ahead_kb" % (expected_major, expected_minor)
    ) as file:
        a = file.read()
        print(a)
        assert expected_readahead_kb_value == int(a)


def test_optimize_readahead_should_apply_failed_with_exception(mocker, tmpdir):
    mock_config = _get_new_mock_config(True)
    mock_log_warning = mocker.patch("logging.warning")
    _mock_should_revise_readahead(mocker, True)

    # Modify the config path to verify in the test temporary folder
    mocker.patch(
        "mount_efs.NFS_READAHEAD_CONFIG_PATH_FORMAT",
        str(tmpdir) + "/%s:%s/read_ahead_kb",
    )
    mocker.patch(
        "os.stat",
        return_value=generate_os_stat_result(st_dev=DEFAULT_MOUNT_DEVICE_NUMBER),
    )

    mount_efs.optimize_readahead_window(MOUNT_POINT, DEFAULT_OPTIONS, mock_config)

    warning_log = mock_log_warning.call_args[0][0]
    assert "Failed to modify read_ahead_kb" in warning_log
    assert (
        "No such file or directory" in warning_log
        or "Directory nonexistent" in warning_log
    )


def test_optimize_readahead_ubuntu_24(mocker, tmpdir):
    mock_config = _get_new_mock_config(enable_optimize_readahead=True)
    _mock_should_revise_readahead(mocker, True)
    mocker.patch(
        "mount_efs.get_system_release_version", return_value="Ubuntu 24.04 LTS"
    )
    mocker.patch(
        "mount_efs.NFS_READAHEAD_CONFIG_PATH_FORMAT",
        str(tmpdir) + "/%s:%s/read_ahead_kb",
    )
    mocker.patch(
        "os.stat",
        return_value=generate_os_stat_result(st_dev=DEFAULT_MOUNT_DEVICE_NUMBER),
    )

    expected_major, expected_minor = mount_efs.decode_device_number(
        DEFAULT_MOUNT_DEVICE_NUMBER
    )
    os.mkdir(str(tmpdir) + "/%s:%s" % (expected_major, expected_minor))

    mount_efs.optimize_readahead_window(MOUNT_POINT, DEFAULT_OPTIONS, mock_config)

    expected_readahead_kb_value = int(
        mount_efs.DEFAULT_NFS_MAX_READAHEAD_MULTIPLIER
        * int(DEFAULT_OPTIONS["rsize"])
        / 1024
    )

    # Check if the value was set correctly after the delay
    time.sleep(3)
    with open(
        str(tmpdir) + "/%s:%s/read_ahead_kb" % (expected_major, expected_minor)
    ) as file:
        assert expected_readahead_kb_value == int(file.read().strip())


def generate_os_stat_result(
    st_mode=0,
    st_ino=0,
    st_dev=0,
    st_nlink=0,
    st_uid=0,
    st_gid=0,
    st_size=0,
    st_atime=0,
    st_mtime=0,
    st_ctime=0,
):
    return os.stat_result(
        (
            st_mode,
            st_ino,
            st_dev,
            st_nlink,
            st_uid,
            st_gid,
            st_size,
            st_atime,
            st_mtime,
            st_ctime,
        )
    )


def device_number_parsing_helper(device_number, expect_major, expect_minor):
    major, minor = mount_efs.decode_device_number(device_number)
    assert expect_major == major
    assert expect_minor == minor
