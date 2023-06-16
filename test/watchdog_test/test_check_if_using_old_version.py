# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.

import json
import logging
import tempfile
from datetime import date, datetime

import pytest

import watchdog

try:
    import ConfigParser
except ImportError:
    from configparser import ConfigParser

OLD_VERSION = "1.34.3"
GITHUB_VERSION = "1.35.9"
YUM_VERSION = "1.35.8"

CERT_DATETIME_FORMAT = "%y%m%d%H%M%SZ"


def test_check_if_using_old_version_yum_works(mocker, caplog):
    mocker.patch(
        "watchdog.EFSUtilsVersionChecker.get_latest_version_by_yum",
        return_value=YUM_VERSION,
    )
    mocker.patch(
        "watchdog.EFSUtilsVersionChecker.get_latest_version_by_github",
        return_value=GITHUB_VERSION,
    )
    mocker.patch("watchdog.EFSUtilsVersionChecker.update_version_check_file")

    with caplog.at_level(logging.INFO):
        watchdog.EFSUtilsVersionChecker.check_if_using_old_version(OLD_VERSION)
    assert (
        "We recommend you upgrade to the latest version of efs-utils by running 'yum update amazon-efs-utils'."
        in caplog.text
    )
    assert YUM_VERSION in caplog.text


def test_check_if_using_old_version_yum_fails(mocker, caplog):
    mocker.patch(
        "watchdog.EFSUtilsVersionChecker.get_latest_version_by_yum",
        side_effect=TimeoutError,
    )
    mocker.patch(
        "watchdog.EFSUtilsVersionChecker.get_latest_version_by_github",
        return_value=GITHUB_VERSION,
    )
    mocker.patch("watchdog.EFSUtilsVersionChecker.update_version_check_file")

    with caplog.at_level(logging.INFO):
        watchdog.EFSUtilsVersionChecker.check_if_using_old_version(OLD_VERSION)

    assert (
        "We recommend you install the latest version of efs-utils from github"
        in caplog.text
    )
    assert GITHUB_VERSION in caplog.text


def test_check_if_using_old_version_yum_github_fail(mocker, caplog):
    mocker.patch(
        "watchdog.EFSUtilsVersionChecker.get_latest_version_by_yum",
        side_effect=FileNotFoundError("No such file or directory: 'yum'"),
    )
    mocker.patch(
        "watchdog.EFSUtilsVersionChecker.get_latest_version_by_github",
        side_effect=TimeoutError,
    )
    mocker.patch("watchdog.EFSUtilsVersionChecker.update_version_check_file")

    with caplog.at_level(logging.WARNING):
        watchdog.EFSUtilsVersionChecker.check_if_using_old_version(OLD_VERSION)

    assert not caplog.text


def test_get_last_version_check_date(mocker, tmp_path):
    current_time_str = datetime.utcnow().strftime(CERT_DATETIME_FORMAT)
    dictionary = {
        "time": current_time_str,
    }
    version_check_file = tempfile.NamedTemporaryFile(mode="w+", dir=str(tmp_path))
    json.dump(dictionary, version_check_file)
    version_check_file.flush()

    mocker.patch("os.path.join", return_value=version_check_file.name)
    last_version_check_date = (
        watchdog.EFSUtilsVersionChecker.get_last_version_check_time()
    )
    assert last_version_check_date.strftime(CERT_DATETIME_FORMAT) == current_time_str

    version_check_file.close()


def test_get_last_version_check_bad_format(mocker, tmp_path):
    """Make sure that watchdog does not crash if the version check file does not have a format we expect"""
    current_time_str = datetime.utcnow().strftime(CERT_DATETIME_FORMAT)
    dictionary = {
        "bad_key": current_time_str,
    }
    version_check_file = tempfile.NamedTemporaryFile(mode="w+", dir=str(tmp_path))
    json.dump(dictionary, version_check_file)
    version_check_file.flush()

    mocker.patch("os.path.join", return_value=version_check_file.name)
    last_version_check_date = (
        watchdog.EFSUtilsVersionChecker.get_last_version_check_time()
    )
    assert not last_version_check_date

    version_check_file.close()


def test_version_check_ready(mocker):
    old_datetime = datetime(2000, 2, 3, 5, 35, 2)
    mocker.patch(
        "watchdog.EFSUtilsVersionChecker.get_last_version_check_time",
        return_value=old_datetime,
    )
    assert watchdog.EFSUtilsVersionChecker.version_check_ready()


def test_update_version_check_file(mocker, tmp_path):
    """Write current time into the version check file"""
    current_time = datetime.utcnow()
    mocker.patch("watchdog.get_utc_now", return_value=current_time)
    version_check_file = tempfile.NamedTemporaryFile(mode="w+", dir=str(tmp_path))
    mocker.patch("os.path.join", return_value=version_check_file.name)
    mocker.patch("os.path.exists", return_value=True)

    watchdog.EFSUtilsVersionChecker.update_version_check_file()
    version_check_file.flush()

    with open(version_check_file.name, "r") as f:
        data = json.load(f)

    assert current_time.strftime(CERT_DATETIME_FORMAT) == data["time"]


def test_version_gt():
    assert watchdog.Version("1.34.5") > watchdog.Version("0.34.5")
    assert watchdog.Version("1.35.5") > watchdog.Version("1.34.5")
    assert watchdog.Version("1.34.5") > watchdog.Version("1.34.4")

    assert not watchdog.Version("0.34.5") > watchdog.Version("1.34.5")
    assert not watchdog.Version("1.34.5") > watchdog.Version("1.35.5")
    assert not watchdog.Version("1.34.4") > watchdog.Version("1.34.5")


def test_version_lt():
    assert watchdog.Version("0.34.5") < watchdog.Version("1.34.5")
    assert watchdog.Version("1.34.5") < watchdog.Version("1.35.5")
    assert watchdog.Version("1.34.4") < watchdog.Version("1.34.5")

    assert not watchdog.Version("1.34.5") < watchdog.Version("0.34.5")
    assert not watchdog.Version("1.35.5") < watchdog.Version("1.34.5")
    assert not watchdog.Version("1.34.5") < watchdog.Version("1.34.4")


def test_version_eq():
    assert watchdog.Version("0.34.5") == watchdog.Version("0.34.5")
    assert not watchdog.Version("0.34.5") > watchdog.Version("0.34.5")
    assert not watchdog.Version("0.34.5") < watchdog.Version("0.34.5")


def test_version_empty_version_str():
    """Assert that an Exception is thrown when we try to construct a Version instance with an empty string"""
    with pytest.raises(Exception):
        watchdog.Version("")


def test_should_check_efs_utils_version(mocker):
    mocker.patch("watchdog.get_boolean_config_item_value", return_value=True)
    mocker.patch(
        "watchdog.EFSUtilsVersionChecker.version_check_ready", return_value=True
    )
    config = ConfigParser()
    assert watchdog.EFSUtilsVersionChecker.should_check_efs_utils_version(config)

    mocker.patch("watchdog.get_boolean_config_item_value", return_value=False)
    assert not watchdog.EFSUtilsVersionChecker.should_check_efs_utils_version(config)

    mocker.patch(
        "watchdog.EFSUtilsVersionChecker.version_check_ready", return_value=False
    )
    mocker.patch("watchdog.get_boolean_config_item_value", return_value=True)
    assert not watchdog.EFSUtilsVersionChecker.should_check_efs_utils_version(config)
