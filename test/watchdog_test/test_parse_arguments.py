# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.

import pytest

import watchdog


def _test_parse_arguments_help(capsys, help):
    with pytest.raises(SystemExit) as ex:
        watchdog.parse_arguments(["watchdog", "foo", "bar", help])

    assert 0 == ex.value.code

    out, err = capsys.readouterr()
    assert "Usage:" in out


def test_parse_arguments_help_long(capsys):
    _test_parse_arguments_help(capsys, "--help")


def test_parse_arguments_help_short(capsys):
    _test_parse_arguments_help(capsys, "-h")


def test_parse_arguments_version(capsys):
    with pytest.raises(SystemExit) as ex:
        watchdog.parse_arguments(["watchdog", "foo", "bar", "--version"])

    assert 0 == ex.value.code

    out, err = capsys.readouterr()
    assert "Version: %s" % watchdog.VERSION in out
