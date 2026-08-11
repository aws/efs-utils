import logging
from unittest.mock import MagicMock, patch

import pytest

from efs_utils_common.config_utils import (
    bootstrap_logging,
    get_config_file_path,
    get_efs_proxy_log_level,
    get_log_level_from_config,
    read_config,
)
from efs_utils_common.constants import (
    CONFIG_FILE,
    CONFIG_SECTION,
    MOUNT_TYPE_EFS,
    MOUNT_TYPE_S3FILES,
    S3FILES_CONFIG_FILE,
)

try:
    import ConfigParser
except ImportError:
    from configparser import ConfigParser


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


def _make_config(
    logging_level="info", max_bytes="1048576", file_count="10", omit_level=False
):
    try:
        config = ConfigParser.SafeConfigParser()
    except AttributeError:
        config = ConfigParser()
    config.add_section(CONFIG_SECTION)
    if not omit_level:
        config.set(CONFIG_SECTION, "logging_level", logging_level)
    config.set(CONFIG_SECTION, "logging_max_bytes", max_bytes)
    config.set(CONFIG_SECTION, "logging_file_count", file_count)
    return config


def test_read_config_parses_file(tmpdir):
    """read_config returns a parser reflecting the on-disk config file contents."""
    config_file = tmpdir.join("efs-utils.conf")
    config_file.write("[mount]\nlogging_level = debug\n")

    parser = read_config(str(config_file))

    assert parser.get(CONFIG_SECTION, "logging_level") == "debug"


def test_get_log_level_from_config_valid_level():
    """A recognized level string maps to the logging module level, no error flagged."""
    level, raw_level, level_error = get_log_level_from_config(
        _make_config(logging_level="debug")
    )
    assert level == logging.DEBUG
    assert raw_level == "debug"
    assert level_error is False


def test_get_log_level_from_config_malformed_defaults_to_info_with_error():
    """A malformed level string defaults to INFO and flags level_error=True."""
    level, raw_level, level_error = get_log_level_from_config(
        _make_config(logging_level="notalevel")
    )
    assert level == logging.INFO
    assert raw_level == "notalevel"
    assert level_error is True


def test_get_efs_proxy_log_level_maps_critical_to_error():
    """efs-proxy has no CRITICAL level, so CRITICAL must map to 'error'."""
    assert get_efs_proxy_log_level(_make_config(logging_level="critical")) == "error"


def test_get_efs_proxy_log_level_passes_through_normal_level():
    """A normal level is passed through lowercased for efs-proxy."""
    assert get_efs_proxy_log_level(_make_config(logging_level="DEBUG")) == "debug"


def test_get_efs_proxy_log_level_malformed_returns_info():
    """A malformed config level makes efs-proxy fall back to 'info'."""
    assert get_efs_proxy_log_level(_make_config(logging_level="bogus")) == "info"


def test_bootstrap_logging_sets_level_and_adds_handler(tmpdir):
    """bootstrap_logging configures the root logger level and attaches a handler."""
    logger = logging.getLogger()
    original_level = logger.level
    original_handlers = list(logger.handlers)
    try:
        bootstrap_logging(_make_config(logging_level="debug"), log_dir=str(tmpdir))
        assert logger.level == logging.DEBUG
        assert len(logger.handlers) == len(original_handlers) + 1
    finally:
        # Restore the root logger to avoid leaking handlers into other tests.
        logger.handlers = original_handlers
        logger.setLevel(original_level)


def test_bootstrap_logging_malformed_level_logs_error(tmpdir, caplog):
    """
    bootstrap_logging with a malformed level defaults to INFO and, once logging is
    configured, emits the 'Malformed logging level' error (the level_error branch).
    """
    logger = logging.getLogger()
    original_level = logger.level
    original_handlers = list(logger.handlers)
    try:
        with caplog.at_level(logging.ERROR):
            bootstrap_logging(
                _make_config(logging_level="notalevel"), log_dir=str(tmpdir)
            )
            assert logger.level == logging.INFO
            assert "Malformed logging level" in caplog.text
    finally:
        logger.handlers = original_handlers
        logger.setLevel(original_level)
