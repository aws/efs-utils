#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import watchdog

DEFAULT_OPTIONS = "rw,port=12345"
NO_PORT_OPTIONS = "rw,noresvport"


def _mount(mountpoint, options=DEFAULT_OPTIONS):
    """Build a Mount namedtuple with localhost defaults for concise test setup."""
    return watchdog.Mount(
        server="127.0.0.1:/",
        mountpoint=mountpoint,
        type="nfs4",
        options=options,
        freq="0",
        passno="0",
    )


# --- Standard mount paths (regression tests) ---
# These verify that the lstrip(".") change doesn't alter behavior for normal
# (non-dot-prefixed) paths, where the old [1:] and new lstrip produce the same result.


def test_standard_mount(mocker):
    """/mnt -> .mnt -> mnt -> mnt.12345"""
    mocker.patch("watchdog.check_if_running_on_macos", return_value=False)
    assert "mnt.12345" == watchdog.get_file_safe_mountpoint(_mount("/mnt"))


def test_nested_mount(mocker):
    """/mnt/efs/data -> .mnt.efs.data -> mnt.efs.data -> mnt.efs.data.12345"""
    mocker.patch("watchdog.check_if_running_on_macos", return_value=False)
    assert "mnt.efs.data.12345" == watchdog.get_file_safe_mountpoint(
        _mount("/mnt/efs/data")
    )


def test_root_mount(mocker):
    """/ -> . -> '' (empty after lstrip) -> .12345
    Edge case: nobody mounts EFS at root, but confirms behavior matches proxy.py."""
    mocker.patch("watchdog.check_if_running_on_macos", return_value=False)
    assert ".12345" == watchdog.get_file_safe_mountpoint(_mount("/"))


# --- Hidden directory (leading dot) mount paths ---
# These are the bug-fix cases. The old code used mountpoint[1:] which only stripped
# one character, leaving a residual dot from the directory name. The fix uses
# lstrip(".") to strip all leading dots, matching proxy.py's get_mount_specific_filename().


def test_hidden_directory_mount(mocker):
    """/.efs -> ..efs -> efs -> efs.12345
    The exact case from GitHub issue #218. Old code produced .efs.12345, causing
    the watchdog to fail to match the state file and kill the TLS tunnel."""
    mocker.patch("watchdog.check_if_running_on_macos", return_value=False)
    assert "efs.12345" == watchdog.get_file_safe_mountpoint(_mount("/.efs"))


def test_hidden_directory_nested_mount(mocker):
    """/.hidden/data -> ..hidden.data -> hidden.data -> hidden.data.12345
    Hidden first component with a normal child directory."""
    mocker.patch("watchdog.check_if_running_on_macos", return_value=False)
    assert "hidden.data.12345" == watchdog.get_file_safe_mountpoint(
        _mount("/.hidden/data")
    )


def test_hidden_directory_deep_nested_mount(mocker):
    """/.hidden/.secret/data -> ..hidden..secret.data -> hidden..secret.data.12345
    The mid-path dot in .secret is NOT stripped — lstrip only affects leading dots.
    This confirms we don't accidentally mangle dots in the middle of the path."""
    mocker.patch("watchdog.check_if_running_on_macos", return_value=False)
    assert "hidden..secret.data.12345" == watchdog.get_file_safe_mountpoint(
        _mount("/.hidden/.secret/data")
    )


def test_hidden_directory_only_dots(mocker):
    """/...efs -> ....efs -> efs -> efs.12345
    Directory name with multiple leading dots. Confirms lstrip handles consecutive dots.
    """
    mocker.patch("watchdog.check_if_running_on_macos", return_value=False)
    assert "efs.12345" == watchdog.get_file_safe_mountpoint(_mount("/...efs"))


# --- Default NFS port (no port in mount options) ---
# When port is missing from options on Linux, the function falls back to DEFAULT_NFS_PORT (2049).


def test_no_port_uses_default_nfs_port(mocker):
    mocker.patch("watchdog.check_if_running_on_macos", return_value=False)
    assert "mnt.2049" == watchdog.get_file_safe_mountpoint(
        _mount("/mnt", NO_PORT_OPTIONS)
    )


def test_hidden_directory_no_port_uses_default_nfs_port(mocker):
    """Combines the dot-stripping fix with the default port fallback path."""
    mocker.patch("watchdog.check_if_running_on_macos", return_value=False)
    assert "efs.2049" == watchdog.get_file_safe_mountpoint(
        _mount("/.efs", NO_PORT_OPTIONS)
    )


# --- macOS behavior ---
# macOS uses nfsstat instead of /proc/mounts. When port is missing on macOS,
# the function returns just the mountpoint without a port suffix (rather than
# falling back to 2049 like Linux).


def test_macos_with_port(mocker):
    mocker.patch("watchdog.check_if_running_on_macos", return_value=True)
    assert "mnt.12345" == watchdog.get_file_safe_mountpoint(_mount("/mnt"))


def test_macos_no_port_returns_mountpoint_only(mocker):
    """On macOS, missing port returns mountpoint without port suffix."""
    mocker.patch("watchdog.check_if_running_on_macos", return_value=True)
    assert "mnt" == watchdog.get_file_safe_mountpoint(_mount("/mnt", NO_PORT_OPTIONS))


def test_macos_hidden_directory_with_port(mocker):
    """Confirms the dot-stripping fix works on macOS too."""
    mocker.patch("watchdog.check_if_running_on_macos", return_value=True)
    assert "efs.12345" == watchdog.get_file_safe_mountpoint(_mount("/.efs"))


def test_macos_hidden_directory_no_port(mocker):
    """Combines the fix with the macOS no-port path: just 'efs'."""
    mocker.patch("watchdog.check_if_running_on_macos", return_value=True)
    assert "efs" == watchdog.get_file_safe_mountpoint(_mount("/.efs", NO_PORT_OPTIONS))
