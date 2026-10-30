# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
import logging
from unittest.mock import MagicMock

import pytest
from pytest_mock import MockFixture

import efs_utils_common
import efs_utils_common.constants as constants
import efs_utils_common.metadata as metadata

MOCK_CONFIG = MagicMock()


def test_get_fips_config_env_var_enabled(mocker):
    mocker.patch("os.getenv", return_value="true")
    mocker.patch(
        "efs_utils_common.metadata.get_boolean_config_item_value", return_value=False
    )

    result = metadata.get_fips_config(None)
    assert result == True


def test_get_fips_config_env_var_disabled(mocker):
    mocker.patch("os.getenv", return_value="False")
    mocker.patch(
        "efs_utils_common.metadata.get_boolean_config_item_value", return_value=False
    )

    result = metadata.get_fips_config(None)
    assert result == False
    assert efs_utils_common.metadata.STUNNEL_GLOBAL_CONFIG["fips"] == "no"


def test_get_fips_config_enabled_in_file(mocker):
    mocker.patch("os.getenv", return_value="False")
    mocker.patch(
        "efs_utils_common.metadata.get_boolean_config_item_value", return_value=True
    )

    result = metadata.get_fips_config(None)
    assert result == True


def mock_fips(
    mocker: MockFixture,
    enabled: bool,
) -> None:
    mocker.patch(
        target="os.getenv",
        return_value="False",
    )
    mocker.patch(
        target="efs_utils_common.metadata.get_boolean_config_item_value",
        return_value=enabled,
    )


@pytest.mark.parametrize(
    argnames="region",
    argvalues=[
        "us-east-1",
        "us-gov-west-1",
        "ca-central-1",
    ],
)
def test_has_fips_endpoints_in_us_and_canada(region: str) -> None:
    assert metadata.has_fips_endpoints(region)


@pytest.mark.parametrize(
    argnames="region",
    argvalues=[
        "eu-west-2",
        "ap-southeast-1",
        "cn-north-1",
    ],
)
def test_has_fips_endpoints_elsewhere(region: str) -> None:
    assert not metadata.has_fips_endpoints(region)


def test_warn_if_region_has_no_fips_endpoints_warns_outside_us_and_canada(
    mocker: MockFixture,
    caplog: pytest.LogCaptureFixture,
) -> None:
    # The mount goes ahead: the check logs a warning naming the region and the FIPS
    # regions page, and does not exit.
    mock_fips(
        mocker=mocker,
        enabled=True,
    )

    with caplog.at_level(logging.WARNING):
        metadata.warn_if_region_has_no_fips_endpoints(
            config=MOCK_CONFIG,
            region="eu-west-2",
        )

    assert "region eu-west-2 has no FIPS endpoints" in caplog.text
    assert constants.FIPS_REGIONS_HELP_URL in caplog.text


@pytest.mark.parametrize(
    argnames="region",
    argvalues=[
        "us-east-1",
        "us-gov-west-1",
        "ca-central-1",
    ],
)
def test_warn_if_region_has_no_fips_endpoints_is_silent_in_us_and_canada(
    mocker: MockFixture,
    caplog: pytest.LogCaptureFixture,
    region: str,
) -> None:
    mock_fips(
        mocker=mocker,
        enabled=True,
    )

    with caplog.at_level(logging.WARNING):
        metadata.warn_if_region_has_no_fips_endpoints(
            config=MOCK_CONFIG,
            region=region,
        )

    assert "has no FIPS endpoints" not in caplog.text


def test_warn_if_region_has_no_fips_endpoints_is_silent_with_fips_off(
    mocker: MockFixture,
    caplog: pytest.LogCaptureFixture,
) -> None:
    mock_fips(
        mocker=mocker,
        enabled=False,
    )

    with caplog.at_level(logging.WARNING):
        metadata.warn_if_region_has_no_fips_endpoints(
            config=MOCK_CONFIG,
            region="eu-west-2",
        )

    assert "has no FIPS endpoints" not in caplog.text
