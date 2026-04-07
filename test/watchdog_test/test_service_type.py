#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import json
import tempfile

import efs_utils_common
import watchdog
from efs_utils_common.constants import EFS_SERVICE_NAME

from .. import utils

try:
    import ConfigParser
except ImportError:
    from configparser import ConfigParser

TIME = 1514764800
GRACE_PERIOD = 30
PID = 1234

BASE_STATE = {
    "pid": PID,
    "mount_time": TIME,
    "mountpoint": "/mnt/efs",
    "certificate": "/tmp/cert.pem",  # Add certificate to trigger check_certificate
    "certificateCreationTime": "251201120000Z",
}


def _get_config():
    try:
        config = ConfigParser.SafeConfigParser()
    except AttributeError:
        config = ConfigParser()
    config.add_section(efs_utils_common.constants.CONFIG_SECTION)
    config.set(efs_utils_common.constants.CONFIG_SECTION, "state_file_dir_mode", "750")
    config.add_section(watchdog.CONFIG_SECTION)
    config.set(watchdog.CONFIG_SECTION, "stunnel_health_check_enabled", "false")
    return config


def create_state_file_with_service_type(tmpdir, service_type=None):
    state = dict(BASE_STATE)
    if service_type:
        state["service_type"] = service_type

    state_file = tmpdir.join(tempfile.mkstemp(prefix="fs-")[1])
    state_file.write(json.dumps(state), ensure=True)
    return state_file.dirname, state_file.basename


def test_service_type_efs_from_json(mocker, tmpdir):
    """Test that EFS service type is read from JSON state file"""
    state_file_dir, state_file = create_state_file_with_service_type(
        tmpdir, "elasticfilesystem"
    )

    # Create a mock mount object
    mock_mount = mocker.MagicMock()
    mock_mount.mountpoint = "/mnt/efs"

    mocker.patch(
        "watchdog.get_current_local_nfs_mounts",
        return_value={"mount.dir.12345": mock_mount},
    )
    mocker.patch(
        "watchdog.get_state_files", return_value={"mount.dir.12345": state_file}
    )
    mocker.patch("watchdog.is_mount_stunnel_proc_running", return_value=True)
    mocker.patch("time.time", return_value=TIME)
    mocker.patch("watchdog.verify_and_update_readahead")

    check_certificate_mock = mocker.patch("watchdog.check_certificate")

    config = _get_config()
    watchdog.check_efs_mounts(config, [], GRACE_PERIOD, 5, state_file_dir)

    # Verify check_certificate was called with EFS service
    check_certificate_mock.assert_called_once()
    args = check_certificate_mock.call_args[0]
    assert args[4] == "elasticfilesystem"  # service parameter


def test_service_type_s3files_from_json(mocker, tmpdir):
    """Test that S3Files service type is read from JSON state file"""
    state_file_dir, state_file = create_state_file_with_service_type(tmpdir, "s3files")

    # Create a mock mount object
    mock_mount = mocker.MagicMock()
    mock_mount.mountpoint = "/mnt/efs"

    mocker.patch(
        "watchdog.get_current_local_nfs_mounts",
        return_value={"mount.dir.12345": mock_mount},
    )
    mocker.patch(
        "watchdog.get_state_files", return_value={"mount.dir.12345": state_file}
    )
    mocker.patch("watchdog.is_mount_stunnel_proc_running", return_value=True)
    mocker.patch("time.time", return_value=TIME)
    mocker.patch("watchdog.verify_and_update_readahead")

    check_certificate_mock = mocker.patch("watchdog.check_certificate")

    config = _get_config()
    watchdog.check_efs_mounts(config, [], GRACE_PERIOD, 5, state_file_dir)

    # Verify check_certificate was called with S3Files service
    check_certificate_mock.assert_called_once()
    args = check_certificate_mock.call_args[0]
    assert args[4] == "s3files"  # service parameter


def test_service_type_defaults_to_efs(mocker, tmpdir):
    """Test that missing service_type defaults to EFS for backwards compatibility"""
    state_file_dir, state_file = create_state_file_with_service_type(
        tmpdir
    )  # No service_type

    # Create a mock mount object
    mock_mount = mocker.MagicMock()
    mock_mount.mountpoint = "/mnt/efs"

    mocker.patch(
        "watchdog.get_current_local_nfs_mounts",
        return_value={"mount.dir.12345": mock_mount},
    )
    mocker.patch(
        "watchdog.get_state_files", return_value={"mount.dir.12345": state_file}
    )
    mocker.patch("watchdog.is_mount_stunnel_proc_running", return_value=True)
    mocker.patch("time.time", return_value=TIME)
    mocker.patch("watchdog.verify_and_update_readahead")

    check_certificate_mock = mocker.patch("watchdog.check_certificate")

    config = _get_config()
    watchdog.check_efs_mounts(config, [], GRACE_PERIOD, 5, state_file_dir)

    # Verify check_certificate was called with default EFS service
    check_certificate_mock.assert_called_once()
    args = check_certificate_mock.call_args[0]
    assert args[4] == EFS_SERVICE_NAME  # service parameter
