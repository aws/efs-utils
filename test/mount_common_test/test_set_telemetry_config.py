# Copyright 2026 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.

import pytest

import efs_utils_common.proxy as proxy

try:
    import ConfigParser
except ImportError:
    from configparser import ConfigParser


def _get_config_with_telemetry_settings(
    metrics_enabled=None,
    cloudwatch_logs_enabled=None,
    log_group_name=None,
    retention_in_days=None,
):
    try:
        config = ConfigParser.SafeConfigParser()
    except AttributeError:
        config = ConfigParser()
    config.add_section("proxy")
    config.add_section("cloudwatch-log")

    if metrics_enabled is not None:
        config.set("proxy", "metrics_enabled", str(metrics_enabled).lower())
    if cloudwatch_logs_enabled is not None:
        config.set("cloudwatch-log", "enabled", str(cloudwatch_logs_enabled).lower())
    if log_group_name is not None:
        config.set("cloudwatch-log", "log_group_name", log_group_name)
    if retention_in_days is not None:
        config.set("cloudwatch-log", "retention_in_days", str(retention_in_days))

    return config


def test_set_telemetry_config_all_enabled():
    tunnel_config = {}
    config = _get_config_with_telemetry_settings(
        metrics_enabled=True,
        cloudwatch_logs_enabled=True,
        log_group_name="/aws/efs/custom",
        retention_in_days=30,
    )

    proxy.set_telemetry_config(tunnel_config, config)

    assert tunnel_config["cloud_watch_metrics"] is True
    assert tunnel_config["cloud_watch_logs"] is True
    assert tunnel_config["log_group_name"] == "/aws/efs/custom"
    assert tunnel_config["cloud_watch_logs_retention_days"] == 30


def test_set_telemetry_config_all_disabled():
    tunnel_config = {}
    config = _get_config_with_telemetry_settings(
        metrics_enabled=False, cloudwatch_logs_enabled=False
    )

    proxy.set_telemetry_config(tunnel_config, config)

    assert tunnel_config["cloud_watch_metrics"] is False
    assert tunnel_config["cloud_watch_logs"] is False
    assert "log_group_name" not in tunnel_config
    assert "cloud_watch_logs_retention_days" not in tunnel_config


def test_set_telemetry_config_defaults():
    tunnel_config = {}
    config = _get_config_with_telemetry_settings()

    proxy.set_telemetry_config(tunnel_config, config)

    assert "cloud_watch_metrics" not in tunnel_config
    assert "cloud_watch_logs" not in tunnel_config
    assert "log_group_name" not in tunnel_config
    assert "cloud_watch_logs_retention_days" not in tunnel_config


def test_set_telemetry_config_partial_settings():
    tunnel_config = {}
    config = _get_config_with_telemetry_settings(
        metrics_enabled=True, log_group_name="/aws/efs/test"
    )

    proxy.set_telemetry_config(tunnel_config, config)

    assert "cloud_watch_logs" not in tunnel_config
    assert tunnel_config["cloud_watch_metrics"] is True
    assert tunnel_config["log_group_name"] == "/aws/efs/test"
    assert "cloud_watch_logs_retention_days" not in tunnel_config


def test_set_telemetry_config_logs_enabled_with_retention():
    tunnel_config = {}
    config = _get_config_with_telemetry_settings(
        cloudwatch_logs_enabled=True, retention_in_days=14
    )

    proxy.set_telemetry_config(tunnel_config, config)

    assert "cloud_watch_metrics" not in tunnel_config
    assert tunnel_config["cloud_watch_logs"] is True
    assert "log_group_name" not in tunnel_config
    assert tunnel_config["cloud_watch_logs_retention_days"] == 14
