import os
import subprocess
from collections import namedtuple
from unittest.mock import MagicMock, patch

import watchdog

# Constants
MOUNT_POINT = "/mnt/efs"
UBUNTU_24_RELEASE = "Ubuntu 24"
DEFAULT_RSIZE = 1048576
DEFAULT_MOUNT_DEVICE_NUMBER = 1048761
DEFAULT_NFS_MAX_READAHEAD_MULTIPLIER = 15
NFS_READAHEAD_CONFIG_PATH_FORMAT = "/sys/class/bdi/%s:%s/read_ahead_kb"
MOUNT_CONFIG_SECTION = "mount"
OPTIMIZE_READAHEAD_ITEM = "optimize_readahead"

# Mock Mount namedtuple
Mount = namedtuple(
    "Mount", ["server", "mountpoint", "type", "options", "freq", "passno"]
)


def test_verify_and_update_readahead_ubuntu_24(mocker, tmpdir):
    # Mock necessary functions and objects
    mock_config = MagicMock()
    mock_mount_info = Mount("server", MOUNT_POINT, "nfs4", "rsize=1048576", "0", "0")

    mocker.patch("watchdog.get_boolean_config_item_value", return_value=True)
    mocker.patch("watchdog.get_system_release_version", return_value=UBUNTU_24_RELEASE)
    mocker.patch(
        "watchdog.NFS_READAHEAD_CONFIG_PATH_FORMAT",
        str(tmpdir) + "/%s:%s/read_ahead_kb",
    )

    expected_major, expected_minor = watchdog.decode_device_number(
        DEFAULT_MOUNT_DEVICE_NUMBER
    )
    os.mkdir(str(tmpdir) + "/%s:%s" % (expected_major, expected_minor))

    # Set up mock file for read_ahead_kb
    read_ahead_file = tmpdir.join(
        "/%s:%s/read_ahead_kb" % (expected_major, expected_minor)
    )
    read_ahead_file.write("128")  # Initial incorrect value

    # Call the function
    mock_stat_process = MagicMock()
    mock_stat_process.communicate.return_value = (
        str(DEFAULT_MOUNT_DEVICE_NUMBER).encode(),
        b"",
    )
    mock_stat_process.returncode = 0

    mock_cat_process = MagicMock()
    mock_cat_process.communicate.return_value = (b"128", b"")
    mock_cat_process.returncode = 0

    mock_echo_process = MagicMock()
    mock_echo_process.returncode = 0

    def echo_communicate(*args, **kwargs):
        read_ahead_file.write("15360")
        return (b"", b"")

    mock_echo_process.communicate = echo_communicate

    def mock_popen(*args, **kwargs):
        if len(args) > 0 and len(args[0]) > 0 and args[0][0] == "stat":
            return mock_stat_process
        elif len(args) > 0 and len(args[0]) > 0 and args[0][0] == "cat":
            return mock_cat_process
        elif kwargs.get("shell"):
            return mock_echo_process
        return MagicMock()

    mocker.patch("subprocess.Popen", side_effect=mock_popen)
    watchdog.verify_and_update_readahead(MOUNT_POINT, mock_config, mock_mount_info)

    # Assert that the value was updated
    assert read_ahead_file.read().strip() == "15360"  # Expected value for 1048576 rsize


def test_verify_and_update_readahead_non_ubuntu_24(mocker, tmpdir):
    # Mock necessary functions and objects
    mock_config = MagicMock()
    mock_mount_info = Mount("server", MOUNT_POINT, "nfs4", "rsize=1048576", "0", "0")

    mocker.patch("watchdog.get_boolean_config_item_value", return_value=True)
    mocker.patch("watchdog.get_system_release_version", return_value="Ubuntu 22.04")
    mocker.patch(
        "watchdog.NFS_READAHEAD_CONFIG_PATH_FORMAT",
        str(tmpdir) + "/%s:%s/read_ahead_kb",
    )

    expected_major, expected_minor = watchdog.decode_device_number(
        DEFAULT_MOUNT_DEVICE_NUMBER
    )
    os.mkdir(str(tmpdir) + "/%s:%s" % (expected_major, expected_minor))

    # Set up mock file for read_ahead_kb
    read_ahead_file = tmpdir.join(
        "/%s:%s/read_ahead_kb" % (expected_major, expected_minor)
    )
    read_ahead_file.write("128")  # Initial incorrect value

    # Call the function
    watchdog.verify_and_update_readahead(MOUNT_POINT, mock_config, mock_mount_info)

    # Assert that the value was not updated
    assert read_ahead_file.read().strip() == "128"


def test_verify_and_update_readahead_optimization_disabled(mocker, tmpdir):
    # Mock necessary functions and objects
    mock_config = MagicMock()
    mock_mount_info = Mount("server", MOUNT_POINT, "nfs4", "rsize=1048576", "0", "0")

    mocker.patch("watchdog.get_boolean_config_item_value", return_value=False)
    mocker.patch("watchdog.get_system_release_version", return_value=UBUNTU_24_RELEASE)
    mocker.patch(
        "watchdog.NFS_READAHEAD_CONFIG_PATH_FORMAT",
        str(tmpdir) + "/%s:%s/read_ahead_kb",
    )

    expected_major, expected_minor = watchdog.decode_device_number(
        DEFAULT_MOUNT_DEVICE_NUMBER
    )
    os.mkdir(str(tmpdir) + "/%s:%s" % (expected_major, expected_minor))

    # Set up mock file for read_ahead_kb
    read_ahead_file = tmpdir.join(
        "/%s:%s/read_ahead_kb" % (expected_major, expected_minor)
    )
    read_ahead_file.write("128")  # Initial incorrect value

    # Call the function
    watchdog.verify_and_update_readahead(MOUNT_POINT, mock_config, mock_mount_info)

    # Assert that the value was not updated
    assert read_ahead_file.read().strip() == "128"


def test_verify_and_update_readahead_exception_handling(mocker, tmpdir, caplog):
    # Mock necessary functions and objects
    mock_config = MagicMock()
    mock_mount_info = Mount("server", MOUNT_POINT, "nfs4", "rsize=1048576", "0", "0")

    mocker.patch("watchdog.get_boolean_config_item_value", return_value=True)
    mocker.patch("watchdog.get_system_release_version", return_value=UBUNTU_24_RELEASE)
    mocker.patch(
        "watchdog.NFS_READAHEAD_CONFIG_PATH_FORMAT",
        str(tmpdir) + "/%s:%s/read_ahead_kb",
    )
    mocker.patch("subprocess.Popen", side_effect=Exception("Test exception"))

    # Call the function
    watchdog.verify_and_update_readahead(MOUNT_POINT, mock_config, mock_mount_info)

    # Assert that the exception was logged
    assert (
        "Failed to verify/update readahead for /mnt/efs: Test exception" in caplog.text
    )


def test_verify_and_update_readahead_stat_timeout(mocker, caplog):
    # Mock necessary functions and objects
    mock_config = MagicMock()
    mock_mount_info = Mount("server", MOUNT_POINT, "nfs4", "rsize=1048576", "0", "0")

    mocker.patch("watchdog.get_boolean_config_item_value", return_value=True)
    mocker.patch("watchdog.get_system_release_version", return_value=UBUNTU_24_RELEASE)

    # Mock subprocess.Popen to raise TimeoutExpired for stat command
    mock_process = MagicMock()
    mock_process.communicate.side_effect = subprocess.TimeoutExpired("stat", 2)
    mocker.patch("subprocess.Popen", return_value=mock_process)

    # Call the function
    watchdog.verify_and_update_readahead(MOUNT_POINT, mock_config, mock_mount_info)

    # Assert that timeout was logged and process was killed
    assert (
        "Timeout getting device number for /mnt/efs, skipping readahead check"
        in caplog.text
    )
    mock_process.kill.assert_called_once()


def test_verify_and_update_readahead_stat_exception(mocker, caplog):
    # Mock necessary functions and objects
    mock_config = MagicMock()
    mock_mount_info = Mount("server", MOUNT_POINT, "nfs4", "rsize=1048576", "0", "0")

    mocker.patch("watchdog.get_boolean_config_item_value", return_value=True)
    mocker.patch("watchdog.get_system_release_version", return_value=UBUNTU_24_RELEASE)

    # Mock subprocess.Popen to raise exception for stat command
    mock_process = MagicMock()
    mock_process.communicate.side_effect = ValueError("Invalid device")
    mocker.patch("subprocess.Popen", return_value=mock_process)

    # Call the function
    watchdog.verify_and_update_readahead(MOUNT_POINT, mock_config, mock_mount_info)

    # Assert that exception was logged
    assert "Failed to get device number for /mnt/efs: Invalid device" in caplog.text


def test_verify_and_update_readahead_cat_timeout(mocker, tmpdir, caplog):
    # Mock necessary functions and objects
    mock_config = MagicMock()
    mock_mount_info = Mount("server", MOUNT_POINT, "nfs4", "rsize=1048576", "0", "0")

    mocker.patch("watchdog.get_boolean_config_item_value", return_value=True)
    mocker.patch("watchdog.get_system_release_version", return_value=UBUNTU_24_RELEASE)

    # Mock stat command to succeed, cat command to timeout
    mock_stat_process = MagicMock()
    mock_stat_process.communicate.return_value = (
        str(DEFAULT_MOUNT_DEVICE_NUMBER).encode(),
        b"",
    )
    mock_stat_process.returncode = 0

    mock_cat_process = MagicMock()
    mock_cat_process.communicate.side_effect = subprocess.TimeoutExpired("cat", 2)

    def mock_popen(*args, **kwargs):
        if len(args) > 0 and len(args[0]) > 0 and args[0][0] == "stat":
            return mock_stat_process
        elif len(args) > 0 and len(args[0]) > 0 and args[0][0] == "cat":
            return mock_cat_process
        return MagicMock()

    mocker.patch("subprocess.Popen", side_effect=mock_popen)

    # Call the function
    watchdog.verify_and_update_readahead(MOUNT_POINT, mock_config, mock_mount_info)

    # Assert that timeout was logged and process was killed
    assert "Timeout reading readahead for /mnt/efs, skipping" in caplog.text
    mock_cat_process.kill.assert_called_once()


def test_verify_and_update_readahead_cat_exception(mocker, tmpdir, caplog):
    # Mock necessary functions and objects
    mock_config = MagicMock()
    mock_mount_info = Mount("server", MOUNT_POINT, "nfs4", "rsize=1048576", "0", "0")

    mocker.patch("watchdog.get_boolean_config_item_value", return_value=True)
    mocker.patch("watchdog.get_system_release_version", return_value=UBUNTU_24_RELEASE)

    # Mock stat command to succeed, cat command to raise exception
    mock_stat_process = MagicMock()
    mock_stat_process.communicate.return_value = (
        str(DEFAULT_MOUNT_DEVICE_NUMBER).encode(),
        b"",
    )
    mock_stat_process.returncode = 0

    mock_cat_process = MagicMock()
    mock_cat_process.communicate.side_effect = IOError("Permission denied")

    def mock_popen(*args, **kwargs):
        if len(args) > 0 and len(args[0]) > 0 and args[0][0] == "stat":
            return mock_stat_process
        elif len(args) > 0 and len(args[0]) > 0 and args[0][0] == "cat":
            return mock_cat_process
        return MagicMock()

    mocker.patch("subprocess.Popen", side_effect=mock_popen)

    # Call the function
    watchdog.verify_and_update_readahead(MOUNT_POINT, mock_config, mock_mount_info)

    # Assert that exception was logged
    assert "Failed to read readahead for /mnt/efs: Permission denied" in caplog.text


def test_verify_and_update_readahead_custom_rsize(mocker, tmpdir):
    # Mock necessary functions and objects
    mock_config = MagicMock()
    mock_mount_info = Mount(
        "server", MOUNT_POINT, "nfs4", "rsize=2097152", "0", "0"
    )  # Custom rsize

    mocker.patch("watchdog.get_boolean_config_item_value", return_value=True)
    mocker.patch("watchdog.get_system_release_version", return_value=UBUNTU_24_RELEASE)
    mocker.patch(
        "watchdog.NFS_READAHEAD_CONFIG_PATH_FORMAT",
        str(tmpdir) + "/%s:%s/read_ahead_kb",
    )

    expected_major, expected_minor = watchdog.decode_device_number(
        DEFAULT_MOUNT_DEVICE_NUMBER
    )
    os.mkdir(str(tmpdir) + "/%s:%s" % (expected_major, expected_minor))

    # Set up mock file for read_ahead_kb
    read_ahead_file = tmpdir.join(
        "/%s:%s/read_ahead_kb" % (expected_major, expected_minor)
    )
    read_ahead_file.write("128")  # Initial incorrect value

    # Mock processes
    mock_stat_process = MagicMock()
    mock_stat_process.communicate.return_value = (
        str(DEFAULT_MOUNT_DEVICE_NUMBER).encode(),
        b"",
    )
    mock_stat_process.returncode = 0

    mock_cat_process = MagicMock()
    mock_cat_process.communicate.return_value = (b"128", b"")
    mock_cat_process.returncode = 0

    mock_echo_process = MagicMock()
    mock_echo_process.returncode = 0

    def echo_communicate(*args, **kwargs):
        # Expected readahead for rsize=2097152: 15 * 2097152 / 1024 = 30720
        read_ahead_file.write("30720")
        return (b"", b"")

    mock_echo_process.communicate = echo_communicate

    def mock_popen(*args, **kwargs):
        if len(args) > 0 and len(args[0]) > 0 and args[0][0] == "stat":
            return mock_stat_process
        elif len(args) > 0 and len(args[0]) > 0 and args[0][0] == "cat":
            return mock_cat_process
        elif kwargs.get("shell"):
            return mock_echo_process
        return MagicMock()

    mocker.patch("subprocess.Popen", side_effect=mock_popen)
    watchdog.verify_and_update_readahead(MOUNT_POINT, mock_config, mock_mount_info)

    # Assert that the value was updated to correct value for custom rsize
    assert read_ahead_file.read().strip() == "30720"  # Expected value for 2097152 rsize


def test_verify_and_update_readahead_no_rsize_option(mocker, tmpdir):
    # Mock necessary functions and objects
    mock_config = MagicMock()
    mock_mount_info = Mount(
        "server", MOUNT_POINT, "nfs4", "proto=tcp,vers=4.1", "0", "0"
    )  # No rsize

    mocker.patch("watchdog.get_boolean_config_item_value", return_value=True)
    mocker.patch("watchdog.get_system_release_version", return_value=UBUNTU_24_RELEASE)
    mocker.patch(
        "watchdog.NFS_READAHEAD_CONFIG_PATH_FORMAT",
        str(tmpdir) + "/%s:%s/read_ahead_kb",
    )

    expected_major, expected_minor = watchdog.decode_device_number(
        DEFAULT_MOUNT_DEVICE_NUMBER
    )
    os.mkdir(str(tmpdir) + "/%s:%s" % (expected_major, expected_minor))

    # Set up mock file for read_ahead_kb
    read_ahead_file = tmpdir.join(
        "/%s:%s/read_ahead_kb" % (expected_major, expected_minor)
    )
    read_ahead_file.write("128")  # Initial incorrect value

    # Mock processes
    mock_stat_process = MagicMock()
    mock_stat_process.communicate.return_value = (
        str(DEFAULT_MOUNT_DEVICE_NUMBER).encode(),
        b"",
    )
    mock_stat_process.returncode = 0

    mock_cat_process = MagicMock()
    mock_cat_process.communicate.return_value = (b"128", b"")
    mock_cat_process.returncode = 0

    mock_echo_process = MagicMock()
    mock_echo_process.returncode = 0

    def echo_communicate(*args, **kwargs):
        # Expected readahead for default rsize=1048576: 15 * 1048576 / 1024 = 15360
        read_ahead_file.write("15360")
        return (b"", b"")

    mock_echo_process.communicate = echo_communicate

    def mock_popen(*args, **kwargs):
        if len(args) > 0 and len(args[0]) > 0 and args[0][0] == "stat":
            return mock_stat_process
        elif len(args) > 0 and len(args[0]) > 0 and args[0][0] == "cat":
            return mock_cat_process
        elif kwargs.get("shell"):
            return mock_echo_process
        return MagicMock()

    mocker.patch("subprocess.Popen", side_effect=mock_popen)
    watchdog.verify_and_update_readahead(MOUNT_POINT, mock_config, mock_mount_info)

    # Assert that the value was updated using default rsize
    assert read_ahead_file.read().strip() == "15360"  # Expected value for default rsize


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
