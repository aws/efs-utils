# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.

import os
from unittest.mock import MagicMock

import mount_efs

MOCK_CONFIG = MagicMock()


def test_get_fips_config_env_var_enabled(mocker):
    mocker.patch("os.getenv", return_value="true")
    mocker.patch("mount_efs.get_boolean_config_item_value", return_value=False)

    result = mount_efs.get_fips_config(None)
    assert result == True


def test_get_fips_config_env_var_disabled(mocker):
    mocker.patch("os.getenv", return_value="False")
    mocker.patch("mount_efs.get_boolean_config_item_value", return_value=False)

    result = mount_efs.get_fips_config(None)
    assert result == False
    assert mount_efs.STUNNEL_GLOBAL_CONFIG["fips"] == "no"


def test_get_fips_config_enabled_in_file(mocker):
    mocker.patch("os.getenv", return_value="False")
    mocker.patch("mount_efs.get_boolean_config_item_value", return_value=True)

    result = mount_efs.get_fips_config(None)
    assert result == True
