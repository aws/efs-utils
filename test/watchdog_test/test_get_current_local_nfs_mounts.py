#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import logging
from unittest.mock import MagicMock

import watchdog

MOUNT_FMT_LINE = "{address}:/ {mountpoint} {fs_type} {options} 0 0"
DEFAULT_OPTS = "rw,port=12345"


def _create_mount_file(tmpdir, lines):
    mount_file = tmpdir.join("mounts")
    mount_file.write("\n".join(lines))
    return str(mount_file)


def test_no_mounts(tmpdir):
    mount_file = _create_mount_file(tmpdir, [])

    mounts = watchdog.get_current_local_nfs_mounts(mount_file)

    assert {} == mounts


def test_no_local_mounts(tmpdir):
    mount_file = _create_mount_file(
        tmpdir,
        [
            MOUNT_FMT_LINE.format(
                address="10.1.0.1",
                mountpoint="/mnt",
                fs_type="nfs4",
                options=DEFAULT_OPTS,
            )
        ],
    )

    mounts = watchdog.get_current_local_nfs_mounts(mount_file)

    assert {} == mounts


def test_no_local_nfs_mounts(tmpdir):
    mount_file = _create_mount_file(
        tmpdir,
        [
            MOUNT_FMT_LINE.format(
                address="127.0.0.1",
                mountpoint="/mnt",
                fs_type="ext4",
                options=DEFAULT_OPTS,
            )
        ],
    )

    mounts = watchdog.get_current_local_nfs_mounts(mount_file)

    assert {} == mounts


def test_invalid_mount_with_nfs(tmpdir, caplog):
    mount_file = _create_mount_file(
        tmpdir,
        [
            MOUNT_FMT_LINE.format(
                address="127.0.0.1",
                mountpoint="/ mnt",
                fs_type="nfs4",
                options=DEFAULT_OPTS,
            )
        ],
    )
    with caplog.at_level(logging.WARNING):
        mounts = watchdog.get_current_local_nfs_mounts(mount_file)
    assert "Watchdog ignoring malformed nfs4 mount" in caplog.text


def test_invalid_mount_without_nfs(tmpdir, caplog):
    mount_file = _create_mount_file(
        tmpdir,
        [
            MOUNT_FMT_LINE.format(
                address="127.0.0.1",
                mountpoint="/ mnt",
                fs_type="overlay",
                options=DEFAULT_OPTS,
            )
        ],
    )
    with caplog.at_level(logging.DEBUG):
        mounts = watchdog.get_current_local_nfs_mounts(mount_file)
    assert "Watchdog ignoring malformed mount" in caplog.text


def test_invalid_mount_arguments_without_nfs(tmpdir, caplog):
    mount_file = _create_mount_file(
        tmpdir,
        [
            MOUNT_FMT_LINE.format(
                address="127.0.0.1",
                mountpoint="/ mnt",
                fs_type="overlay",
                options="rw,port= 12345",
            )
        ],
    )
    with caplog.at_level(logging.DEBUG):
        mounts = watchdog.get_current_local_nfs_mounts(mount_file)
    assert "Watchdog ignoring malformed mount" in caplog.text


def test_local_nfs_mount(tmpdir):
    mount_file = _create_mount_file(
        tmpdir,
        [
            MOUNT_FMT_LINE.format(
                address="127.0.0.1",
                mountpoint="/mnt",
                fs_type="nfs4",
                options=DEFAULT_OPTS,
            )
        ],
    )

    mounts = watchdog.get_current_local_nfs_mounts(mount_file)

    assert 1 == len(mounts)
    assert "mnt.12345" in mounts


def test_macos_local_nfs_mount(mocker):
    """
    macOS branch: mounts are discovered via `mount -t nfs` output (not /proc/mounts),
    and per-mount options come from get_nfs_mount_options_on_macos.
    """
    mocker.patch("watchdog.check_if_running_on_macos", return_value=True)
    process_mock = MagicMock()
    process_mock.stdout = "127.0.0.1:/ on /Users/ec2-user/efs (nfs)\n"
    run_mock = mocker.patch("subprocess.run", return_value=process_mock)
    mocker.patch(
        "watchdog.get_nfs_mount_options_on_macos", return_value="rw,port=12345"
    )

    mounts = watchdog.get_current_local_nfs_mounts()

    # Verify the macOS code path (mount -t nfs) was used, not /proc/mounts.
    run_mock.assert_called_once()
    assert ["mount", "-t", "nfs"] == run_mock.call_args[0][0]
    assert 1 == len(mounts)
    assert "Users.ec2-user.efs.12345" in mounts


def test_macos_no_nfs_mounts_logs_warning(mocker, caplog):
    """macOS branch: empty `mount -t nfs` output logs a warning and returns no mounts."""
    mocker.patch("watchdog.check_if_running_on_macos", return_value=True)
    process_mock = MagicMock()
    process_mock.stdout = ""
    mocker.patch("subprocess.run", return_value=process_mock)

    with caplog.at_level(logging.WARNING):
        mounts = watchdog.get_current_local_nfs_mounts()

    assert {} == mounts
    assert "No nfs mounts found" in caplog.text


def test_local_nfs_mount_default_nfs_port(tmpdir):
    mount_file = _create_mount_file(
        tmpdir,
        [
            MOUNT_FMT_LINE.format(
                address="127.0.0.1",
                mountpoint="/mnt",
                fs_type="nfs4",
                options="rw,noresvport",
            )
        ],
    )

    mounts = watchdog.get_current_local_nfs_mounts(mount_file)

    assert 1 == len(mounts)
    assert "mnt.2049" in mounts


def test_local_nfs_mount_noresvport(tmpdir):
    mount_file = _create_mount_file(
        tmpdir,
        [
            MOUNT_FMT_LINE.format(
                address="127.0.0.1",
                mountpoint="/mnt",
                fs_type="nfs4",
                options="rw,noresvport,port=12345",
            )
        ],
    )

    mounts = watchdog.get_current_local_nfs_mounts(mount_file)

    assert 1 == len(mounts)
    assert "mnt.12345" in mounts
