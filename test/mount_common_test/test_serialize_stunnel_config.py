#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#
"""Central control-character guard in serialize_stunnel_config.

Every stunnel / efs-proxy config value is emitted as an unescaped "key = value"
line, so no value may contain a control character (a newline in particular).
serialize_stunnel_config is the single chokepoint every value flows through, so
the guard here covers all sources --
mount options like rolearn / jwtpath / awscredsuri / awsprofile / cafile as well
as config-file and derived values -- on top of the per-option format checks.
"""

import pytest

import efs_utils_common.proxy as proxy

# ---- clean configs serialize unchanged ----


def test_clean_config_serializes():
    lines = proxy.serialize_stunnel_config(
        {"accept": "127.0.0.1:20449", "verify": "2"}, header="efs"
    )
    assert lines == ["[efs]", "accept = 127.0.0.1:20449", "verify = 2"]


def test_clean_list_value_serializes():
    lines = proxy.serialize_stunnel_config({"socket": ["a:1", "b:2"]})
    assert lines == ["socket = a:1", "socket = b:2"]


def test_non_string_values_serialize():
    # ints/bools flow through as before (e.g. proxy_logging_max_bytes, fs_id ints).
    lines = proxy.serialize_stunnel_config({"proxy_logging_max_bytes": 1048576})
    assert lines == ["proxy_logging_max_bytes = 1048576"]


# ---- control chars in a VALUE are rejected ----


@pytest.mark.parametrize(
    "bad_value",
    [
        "/x\nsecond-line",  # embedded newline
        "arn:aws:iam::123456789012:role/r\nsecond-line",  # rolearn with a second line
        "/var/run/token\r\nsecond-line",  # CRLF
        "value\x00null",  # NUL
        "value\x7fdel",  # DEL
    ],
)
def test_control_char_in_value_rejected(bad_value):
    with pytest.raises(SystemExit):
        proxy.serialize_stunnel_config({"CAfile": bad_value}, header="efs")


def test_control_char_in_list_value_rejected():
    with pytest.raises(SystemExit):
        proxy.serialize_stunnel_config({"socket": ["ok:1", "bad\nsecond-line"]})


# ---- control char in a KEY is rejected ----


def test_control_char_in_key_rejected():
    with pytest.raises(SystemExit):
        proxy.serialize_stunnel_config({"key\nsecond-line": "0"}, header="efs")
