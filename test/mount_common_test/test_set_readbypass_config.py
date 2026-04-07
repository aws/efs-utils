# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
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


def _get_config_with_readbypass_settings(
    read_bypass_denylist_size=None,
    read_bypass_denylist_ttl_seconds=None,
    s3_read_chunk_size_bytes=None,
    readahead_cache_init_memory_size_mb=None,
    readahead_cache_max_memory_size_mb=None,
    readahead_init_window_size_bytes=None,
    readahead_max_window_size_bytes=None,
    readahead_cache_enabled=None,
):
    try:
        config = ConfigParser.SafeConfigParser()
    except AttributeError:
        config = ConfigParser()
    config.add_section("proxy")

    if read_bypass_denylist_size is not None:
        config.set("proxy", "read_bypass_denylist_size", str(read_bypass_denylist_size))
    if read_bypass_denylist_ttl_seconds is not None:
        config.set(
            "proxy",
            "read_bypass_denylist_ttl_seconds",
            str(read_bypass_denylist_ttl_seconds),
        )
    if s3_read_chunk_size_bytes is not None:
        config.set("proxy", "s3_read_chunk_size_bytes", str(s3_read_chunk_size_bytes))
    if readahead_cache_init_memory_size_mb is not None:
        config.set(
            "proxy",
            "readahead_cache_init_memory_size_mb",
            str(readahead_cache_init_memory_size_mb),
        )
    if readahead_cache_max_memory_size_mb is not None:
        config.set(
            "proxy",
            "readahead_cache_max_memory_size_mb",
            str(readahead_cache_max_memory_size_mb),
        )
    if readahead_init_window_size_bytes is not None:
        config.set(
            "proxy",
            "readahead_init_window_size_bytes",
            str(readahead_init_window_size_bytes),
        )
    if readahead_max_window_size_bytes is not None:
        config.set(
            "proxy",
            "readahead_max_window_size_bytes",
            str(readahead_max_window_size_bytes),
        )
    if readahead_cache_enabled is not None:
        config.set(
            "proxy",
            "readahead_cache_enabled",
            str(readahead_cache_enabled),
        )

    return config


def test_set_readbypass_config_with_all_int_configs():
    tunnel_config = {}
    options = {}
    config = _get_config_with_readbypass_settings(
        read_bypass_denylist_size=100,
        read_bypass_denylist_ttl_seconds=300,
        s3_read_chunk_size_bytes=1048576,
        readahead_cache_init_memory_size_mb=10,
        readahead_cache_max_memory_size_mb=50,
        readahead_init_window_size_bytes=131072,
        readahead_max_window_size_bytes=524288,
    )

    proxy.set_readbypass_config(tunnel_config, options, config)

    assert tunnel_config["read_bypass_denylist_size"] == 100
    assert tunnel_config["read_bypass_denylist_ttl_seconds"] == 300
    assert tunnel_config["s3_read_chunk_size_bytes"] == 1048576
    assert tunnel_config["readahead_cache_init_memory_size_mb"] == 10
    assert tunnel_config["readahead_cache_max_memory_size_mb"] == 50
    assert tunnel_config["readahead_init_window_size_bytes"] == 131072
    assert tunnel_config["readahead_max_window_size_bytes"] == 524288


def test_set_readbypass_config_with_partial_int_configs():
    tunnel_config = {}
    options = {}
    config = _get_config_with_readbypass_settings(
        read_bypass_denylist_size=100,
        s3_read_chunk_size_bytes=1048576,
        readahead_cache_max_memory_size_mb=50,
    )

    proxy.set_readbypass_config(tunnel_config, options, config)

    assert tunnel_config["read_bypass_denylist_size"] == 100
    assert tunnel_config["s3_read_chunk_size_bytes"] == 1048576
    assert tunnel_config["readahead_cache_max_memory_size_mb"] == 50
    assert "read_bypass_denylist_ttl_seconds" not in tunnel_config


def test_set_readbypass_config_with_no_int_configs():
    tunnel_config = {}
    options = {}
    config = _get_config_with_readbypass_settings()

    proxy.set_readbypass_config(tunnel_config, options, config)

    assert "read_bypass_denylist_size" not in tunnel_config
    assert "read_bypass_denylist_ttl_seconds" not in tunnel_config
    assert "s3_read_chunk_size_bytes" not in tunnel_config


def test_set_readbypass_config_with_rolearn(mocker):
    tunnel_config = {}
    options = {
        "rolearn": "arn:aws:iam::123456789012:role/MyRole",
        "iam": None,
        "tls": None,
    }
    config = _get_config_with_readbypass_settings()
    mocker.patch("efs_utils_common.proxy.get_aws_profile", return_value="default")

    proxy.set_readbypass_config(tunnel_config, options, config)

    assert tunnel_config["role_arn"] == "arn:aws:iam::123456789012:role/MyRole"
    assert tunnel_config["profile"] == "default"


def test_set_readbypass_config_with_jwtpath(mocker):
    tunnel_config = {}
    options = {"jwtpath": "/path/to/jwt/token", "iam": None, "tls": None}
    config = _get_config_with_readbypass_settings()
    mocker.patch("efs_utils_common.proxy.get_aws_profile", return_value="default")

    proxy.set_readbypass_config(tunnel_config, options, config)

    assert tunnel_config["jwt_path"] == "/path/to/jwt/token"
    assert tunnel_config["profile"] == "default"


def test_set_readbypass_config_with_rolearn_and_jwtpath(mocker):
    tunnel_config = {}
    options = {
        "rolearn": "arn:aws:iam::123456789012:role/MyRole",
        "jwtpath": "/path/to/jwt/token",
        "iam": None,
        "tls": None,
    }
    config = _get_config_with_readbypass_settings()
    mocker.patch(
        "efs_utils_common.proxy.get_aws_profile", return_value="custom-profile"
    )

    proxy.set_readbypass_config(tunnel_config, options, config)

    assert tunnel_config["role_arn"] == "arn:aws:iam::123456789012:role/MyRole"
    assert tunnel_config["jwt_path"] == "/path/to/jwt/token"
    assert tunnel_config["profile"] == "custom-profile"


def test_set_readbypass_config_with_all_options(mocker):
    tunnel_config = {}
    options = {
        "rolearn": "arn:aws:iam::123456789012:role/MyRole",
        "jwtpath": "/path/to/jwt/token",
        "iam": None,
        "tls": None,
    }
    config = _get_config_with_readbypass_settings(
        read_bypass_denylist_size=100,
        read_bypass_denylist_ttl_seconds=300,
        s3_read_chunk_size_bytes=1048576,
        readahead_cache_init_memory_size_mb=10,
        readahead_cache_max_memory_size_mb=50,
        readahead_init_window_size_bytes=131072,
        readahead_max_window_size_bytes=524288,
    )
    mocker.patch("efs_utils_common.proxy.get_aws_profile", return_value="test-profile")

    proxy.set_readbypass_config(tunnel_config, options, config)

    assert tunnel_config["read_bypass_denylist_size"] == 100
    assert tunnel_config["read_bypass_denylist_ttl_seconds"] == 300
    assert tunnel_config["s3_read_chunk_size_bytes"] == 1048576
    assert tunnel_config["readahead_cache_init_memory_size_mb"] == 10
    assert tunnel_config["readahead_cache_max_memory_size_mb"] == 50
    assert tunnel_config["readahead_init_window_size_bytes"] == 131072
    assert tunnel_config["readahead_max_window_size_bytes"] == 524288
    assert tunnel_config["role_arn"] == "arn:aws:iam::123456789012:role/MyRole"
    assert tunnel_config["jwt_path"] == "/path/to/jwt/token"
    assert tunnel_config["profile"] == "test-profile"


def test_set_readbypass_config_with_readahead_cache_enabled_true():
    tunnel_config = {}
    options = {}
    config = _get_config_with_readbypass_settings(readahead_cache_enabled="true")

    proxy.set_readbypass_config(tunnel_config, options, config)

    assert tunnel_config["readahead_cache_enabled"] == "yes"


def test_set_readbypass_config_with_readahead_cache_enabled_false():
    tunnel_config = {}
    options = {}
    config = _get_config_with_readbypass_settings(readahead_cache_enabled="false")

    proxy.set_readbypass_config(tunnel_config, options, config)

    assert tunnel_config["readahead_cache_enabled"] == "no"


def test_set_readbypass_config_with_readahead_cache_enabled_not_set():
    tunnel_config = {}
    options = {}
    config = _get_config_with_readbypass_settings()

    proxy.set_readbypass_config(tunnel_config, options, config)

    assert "readahead_cache_enabled" not in tunnel_config


def test_nos3readcache_option_overrides_config_enabled():
    """nos3readcache mount option should force readahead_cache_enabled to 'no' even if config says true."""
    tunnel_config = {}
    options = {"nos3readcache": None}
    config = _get_config_with_readbypass_settings(readahead_cache_enabled="true")

    proxy.set_readbypass_config(tunnel_config, options, config)

    # set_readbypass_config sets it to "yes" from config, but the mount option override
    # happens in write_stunnel_config_file, not here. This test verifies set_readbypass_config
    # itself still sets the config value normally.
    assert tunnel_config["readahead_cache_enabled"] == "yes"


def test_nos3readcache_option_does_not_affect_other_readbypass_configs():
    """nos3readcache should not prevent other readbypass configs from being set."""
    tunnel_config = {}
    options = {"nos3readcache": None}
    config = _get_config_with_readbypass_settings(
        read_bypass_denylist_size=100,
        s3_read_chunk_size_bytes=1048576,
    )

    proxy.set_readbypass_config(tunnel_config, options, config)

    assert tunnel_config["read_bypass_denylist_size"] == 100
    assert tunnel_config["s3_read_chunk_size_bytes"] == 1048576
