# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.

import os

import pytest

import mount_efs

from .. import utils

try:
    import ConfigParser
except ImportError:
    from configparser import ConfigParser


def test_get_aws_profile_with_env_variable(mocker):
    """Test that AWS_PROFILE environment variable is used when no mount option is provided"""
    options = {}
    use_iam = True

    # Mock environment variable
    mocker.patch.dict(os.environ, {"AWS_PROFILE": "test-profile"})

    # Mock file reading to return empty configs
    mocker.patch("mount_efs.read_config", return_value=ConfigParser())

    result = mount_efs.get_aws_profile(options, use_iam)
    assert result == "test-profile"


def test_get_aws_profile_mount_option_takes_precedence(mocker):
    """Test that mount option takes precedence over environment variable"""
    options = {"awsprofile": "mount-profile"}
    use_iam = True

    # Mock environment variable
    mocker.patch.dict(os.environ, {"AWS_PROFILE": "env-profile"})

    result = mount_efs.get_aws_profile(options, use_iam)
    assert result == "mount-profile"


def test_get_aws_profile_no_env_variable(mocker):
    """Test fallback behavior when no environment variable is set"""
    options = {}
    use_iam = True

    # Ensure AWS_PROFILE is not set
    env_vars = {k: v for k, v in os.environ.items() if k != "AWS_PROFILE"}
    mocker.patch.dict(os.environ, env_vars, clear=True)

    # Mock config file to have default profile
    mock_config = mocker.MagicMock()
    mock_config.get.return_value = "fake_access_key"
    mocker.patch("mount_efs.read_config", return_value=mock_config)

    result = mount_efs.get_aws_profile(options, use_iam)
    assert result == "default"


def test_get_target_region_with_aws_region_env(mocker):
    """Test that AWS_REGION environment variable is used"""
    config = mocker.MagicMock()
    options = {}

    # Mock environment variable
    mocker.patch.dict(os.environ, {"AWS_REGION": "us-west-2"})

    result = mount_efs.get_target_region(config, options)
    assert result == "us-west-2"


def test_get_target_region_with_aws_default_region_env(mocker):
    """Test that AWS_DEFAULT_REGION environment variable is used"""
    config = mocker.MagicMock()
    options = {}

    # Mock environment variables (AWS_REGION not set, AWS_DEFAULT_REGION set)
    env_vars = {k: v for k, v in os.environ.items() if k != "AWS_REGION"}
    env_vars["AWS_DEFAULT_REGION"] = "eu-central-1"
    mocker.patch.dict(os.environ, env_vars, clear=True)

    result = mount_efs.get_target_region(config, options)
    assert result == "eu-central-1"


def test_get_target_region_mount_option_takes_precedence(mocker):
    """Test that region mount option takes precedence over environment variables"""
    config = mocker.MagicMock()
    options = {"region": "ap-southeast-1"}

    # Mock environment variables
    mocker.patch.dict(
        os.environ, {"AWS_REGION": "us-west-2", "AWS_DEFAULT_REGION": "eu-central-1"}
    )

    result = mount_efs.get_target_region(config, options)
    assert result == "ap-southeast-1"


def test_get_target_region_aws_region_precedence_over_default(mocker):
    """Test that AWS_REGION takes precedence over AWS_DEFAULT_REGION"""
    config = mocker.MagicMock()
    options = {}

    # Mock both environment variables
    mocker.patch.dict(
        os.environ, {"AWS_REGION": "us-west-2", "AWS_DEFAULT_REGION": "eu-central-1"}
    )

    result = mount_efs.get_target_region(config, options)
    assert result == "us-west-2"


def test_get_target_region_fallback_to_config_file(mocker):
    """Test fallback to config file when no environment variables are set"""
    config = mocker.MagicMock()
    config.get.return_value = "us-east-1"
    options = {}

    # Ensure environment variables are not set
    env_vars = {
        k: v
        for k, v in os.environ.items()
        if k not in ["AWS_REGION", "AWS_DEFAULT_REGION"]
    }
    mocker.patch.dict(os.environ, env_vars, clear=True)

    result = mount_efs.get_target_region(config, options)
    assert result == "us-east-1"


def test_get_target_region_fallback_to_metadata_service(mocker):
    """Test fallback to instance metadata when config file fails"""
    config = mocker.MagicMock()
    config.get.side_effect = mount_efs.NoOptionError("region", "section")
    options = {}

    # Ensure environment variables are not set
    env_vars = {
        k: v
        for k, v in os.environ.items()
        if k not in ["AWS_REGION", "AWS_DEFAULT_REGION"]
    }
    mocker.patch.dict(os.environ, env_vars, clear=True)

    # Mock metadata service
    mocker.patch(
        "mount_efs.get_region_from_instance_metadata", return_value="us-west-1"
    )

    result = mount_efs.get_target_region(config, options)
    assert result == "us-west-1"
