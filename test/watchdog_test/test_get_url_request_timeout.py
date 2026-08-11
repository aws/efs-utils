import logging

import pytest

from watchdog import (
    DEFAULT_URL_REQUEST_TIMEOUT_SEC,
    MOUNT_CONFIG_SECTION,
    URL_REQUEST_TIMEOUT_ITEM,
    get_url_request_timeout,
)

try:
    import ConfigParser
except ImportError:
    from configparser import ConfigParser


def _make_config_with_timeout(value=None):
    """Create a config parser with an optional url_request_timeout_sec value."""
    try:
        config = ConfigParser.SafeConfigParser()
    except AttributeError:
        config = ConfigParser()
    config.add_section(MOUNT_CONFIG_SECTION)
    if value is not None:
        config.set(MOUNT_CONFIG_SECTION, URL_REQUEST_TIMEOUT_ITEM, str(value))
    return config


def test_get_url_request_timeout_reads_valid_value():
    """When a valid numeric value is set in config, it should be returned."""
    config = _make_config_with_timeout("2.0")
    result = get_url_request_timeout(config)
    assert result == 2.0


def test_get_url_request_timeout_reads_integer_value():
    """An integer value should be read and returned as float."""
    config = _make_config_with_timeout("3")
    result = get_url_request_timeout(config)
    assert result == 3.0


def test_get_url_request_timeout_fallback_when_not_set():
    """When the config option is not set, should fall back to DEFAULT_URL_REQUEST_TIMEOUT_SEC."""
    config = _make_config_with_timeout(None)
    result = get_url_request_timeout(config)
    assert result == DEFAULT_URL_REQUEST_TIMEOUT_SEC


def test_get_url_request_timeout_fallback_on_invalid_value(caplog):
    """When the config value is non-numeric, should log warning and fall back to default."""
    config = _make_config_with_timeout("abc")
    with caplog.at_level(logging.WARNING):
        result = get_url_request_timeout(config)
    assert result == DEFAULT_URL_REQUEST_TIMEOUT_SEC
    assert "Invalid (non-numeric) value" in caplog.text
    assert URL_REQUEST_TIMEOUT_ITEM in caplog.text


def test_get_url_request_timeout_fallback_on_empty_value(caplog):
    """When the config value is empty string, should log warning and fall back to default."""
    config = _make_config_with_timeout("")
    with caplog.at_level(logging.WARNING):
        result = get_url_request_timeout(config)
    assert result == DEFAULT_URL_REQUEST_TIMEOUT_SEC
    assert "Invalid (non-numeric) value" in caplog.text


def test_get_url_request_timeout_reads_small_value():
    """A small fractional value like 0.05 should be read correctly."""
    config = _make_config_with_timeout("0.05")
    result = get_url_request_timeout(config)
    assert result == 0.05


def test_get_url_request_timeout_missing_section():
    """When the mount config section doesn't exist, should fall back to default."""
    try:
        config = ConfigParser.SafeConfigParser()
    except AttributeError:
        config = ConfigParser()
    # Don't add the mount section
    result = get_url_request_timeout(config)
    assert result == DEFAULT_URL_REQUEST_TIMEOUT_SEC


def test_get_url_request_timeout_fallback_on_zero_value(caplog):
    """When the config value is zero, should log warning and fall back to default."""
    config = _make_config_with_timeout("0")
    with caplog.at_level(logging.WARNING):
        result = get_url_request_timeout(config)
    assert result == DEFAULT_URL_REQUEST_TIMEOUT_SEC
    assert "must be positive" in caplog.text


def test_get_url_request_timeout_fallback_on_negative_value(caplog):
    """When the config value is negative, should log warning and fall back to default."""
    config = _make_config_with_timeout("-1")
    with caplog.at_level(logging.WARNING):
        result = get_url_request_timeout(config)
    assert result == DEFAULT_URL_REQUEST_TIMEOUT_SEC
    assert "must be positive" in caplog.text
