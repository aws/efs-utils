from unittest.mock import MagicMock, patch

import pytest

from efs_utils_common.config_utils import get_config_file_path
from efs_utils_common.constants import (
    CONFIG_FILE,
    MOUNT_TYPE_EFS,
    MOUNT_TYPE_S3FILES,
    S3FILES_CONFIG_FILE,
)


@patch("efs_utils_common.config_utils.MountContext")
def test_get_config_file_path_with_explicit_path(mock_mount_context):
    mock_context = MagicMock()
    mock_context.config_file_path = "/custom/config/path"
    mock_context.mount_type = MOUNT_TYPE_EFS
    mock_mount_context.return_value = mock_context

    result = get_config_file_path()

    assert result == "/custom/config/path"


@patch("efs_utils_common.config_utils.MountContext")
def test_get_config_file_path_auto_detect_s3files(mock_mount_context):
    mock_context = MagicMock()
    mock_context.config_file_path = None
    mock_context.mount_type = MOUNT_TYPE_S3FILES
    mock_mount_context.return_value = mock_context

    result = get_config_file_path()

    assert result == S3FILES_CONFIG_FILE


@patch("efs_utils_common.config_utils.MountContext")
def test_get_config_file_path_auto_detect_efs(mock_mount_context):
    mock_context = MagicMock()
    mock_context.config_file_path = None
    mock_context.mount_type = MOUNT_TYPE_EFS
    mock_mount_context.return_value = mock_context

    result = get_config_file_path()

    assert result == CONFIG_FILE


@patch("efs_utils_common.config_utils.MountContext")
def test_get_config_file_path_unknown_mount_type(mock_mount_context):
    mock_context = MagicMock()
    mock_context.config_file_path = None
    mock_context.mount_type = "UNKNOWN"
    mock_mount_context.return_value = mock_context

    with pytest.raises(ValueError, match="Unable to determine config file path"):
        get_config_file_path()
