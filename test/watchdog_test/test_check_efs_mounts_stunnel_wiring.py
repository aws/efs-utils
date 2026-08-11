#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import json
from datetime import datetime

import efs_utils_common
import watchdog

from .. import utils

try:
    import ConfigParser
except ImportError:
    from configparser import ConfigParser

TIME = 1514764800
GRACE_PERIOD = 30
PID = 1234
UNMOUNT_COUNT = 5
STATE = {
    "pid": PID,
    "commonName": "deadbeef.com",
    "certificate": "/tmp/foobar",
    "certificateCreationTime": datetime.utcnow().strftime(
        watchdog.CERT_DATETIME_FORMAT
    ),
    "mountStateDir": "fs-deadbeef.mount.dir.12345",
    "privateKey": "/tmp/foobarbaz",
    "accessPoint": "fsap-fedcba9876543210",
    "mount_time": TIME,
    "service_type": "elasticfilesystem",
}
MOUNTS = {"mnt": watchdog.Mount("127.0.0.1", "/mnt", "nfs4", "", "0", "0")}


def _get_config(stunnel_health_check_enabled=True):
    """Build a config where the stunnel health check feature is ENABLED, unlike
    the existing check_efs_mounts tests which hard-code it to 'false'. Mirrors
    the parameterized pattern in test_check_stunnel_health.py."""
    try:
        config = ConfigParser.SafeConfigParser()
    except AttributeError:
        config = ConfigParser()

    config.add_section(efs_utils_common.constants.CONFIG_SECTION)
    config.set(efs_utils_common.constants.CONFIG_SECTION, "state_file_dir_mode", "750")
    config.add_section(watchdog.CONFIG_SECTION)
    config.set(
        watchdog.CONFIG_SECTION,
        "stunnel_health_check_enabled",
        "true" if stunnel_health_check_enabled else "false",
    )
    return config


def _setup_common_mocks(mocker, state_files, is_stunnel_process_running):
    mocker.patch("watchdog.get_current_local_nfs_mounts", return_value=MOUNTS)
    mocker.patch("watchdog.get_state_files", return_value=state_files)
    mocker.patch("watchdog.is_pid_running", return_value=True)
    mocker.patch("time.time", return_value=TIME + 1)
    mocker.patch("watchdog.check_certificate")
    mocker.patch("watchdog.rewrite_state_file")
    mocker.patch("watchdog.verify_and_update_readahead")
    mocker.patch(
        "watchdog.is_mount_stunnel_proc_running",
        return_value=is_stunnel_process_running,
    )


def create_state_file(tmpdir, content=json.dumps(STATE)):
    state_file = tmpdir.join("fs-deadbeef.mount.dir.12345")
    state_file.write(content, ensure=True)
    return state_file.dirname, state_file.basename


def test_check_stunnel_health_wired_when_stunnel_proc_running(mocker, tmpdir):
    """When the mount's stunnel proc is running, check_efs_mounts must delegate
    to check_stunnel_health with the full expected arg tuple, and must NOT
    restart the tunnel. Guards the call-site wiring (not the health check
    internals, which live in test_check_stunnel_health.py)."""
    state_file_dir, state_file = create_state_file(tmpdir)

    _setup_common_mocks(
        mocker, state_files={"mnt": state_file}, is_stunnel_process_running=True
    )
    check_stunnel_health_mock = mocker.patch("watchdog.check_stunnel_health")
    restart_tls_mock = mocker.patch("watchdog.restart_tls_tunnel")

    config = _get_config(stunnel_health_check_enabled=True)
    child_procs = []
    watchdog.check_efs_mounts(
        config,
        child_procs,
        GRACE_PERIOD,
        UNMOUNT_COUNT,
        state_file_dir=state_file_dir,
    )

    utils.assert_called_once(check_stunnel_health_mock)
    utils.assert_not_called(restart_tls_mock)

    # Signature: (config, state, state_file_dir, state_file, child_procs, nfs_mounts)
    # Note: check_efs_mounts mutates the state dict in place (e.g. resets
    # unmount_count) before delegating, so assert on identifying fields rather
    # than exact equality with the original STATE.
    args, kwargs = check_stunnel_health_mock.call_args
    assert args[0] is config
    assert args[1]["pid"] == PID
    assert args[1]["mountStateDir"] == STATE["mountStateDir"]
    assert args[2] == state_file_dir
    assert args[3] == state_file
    assert args[4] is child_procs
    assert args[5] == MOUNTS


def test_restart_tls_tunnel_when_stunnel_proc_not_running(mocker, tmpdir):
    """Companion: when the stunnel proc is not running, check_efs_mounts must
    restart the tunnel and must NOT call check_stunnel_health."""
    state_file_dir, state_file = create_state_file(tmpdir)

    _setup_common_mocks(
        mocker, state_files={"mnt": state_file}, is_stunnel_process_running=False
    )
    check_stunnel_health_mock = mocker.patch("watchdog.check_stunnel_health")
    restart_tls_mock = mocker.patch("watchdog.restart_tls_tunnel")

    watchdog.check_efs_mounts(
        _get_config(stunnel_health_check_enabled=True),
        [],
        GRACE_PERIOD,
        UNMOUNT_COUNT,
        state_file_dir=state_file_dir,
    )

    utils.assert_called_once(restart_tls_mock)
    utils.assert_not_called(check_stunnel_health_mock)
