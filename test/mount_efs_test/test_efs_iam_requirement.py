#!/usr/bin/env python3

import pytest

import efs_utils_common.context as context
import efs_utils_common.metadata as metadata
import efs_utils_common.mount_options as mount_options
import mount_efs
from efs_utils_common.constants import MOUNT_TYPE_EFS


@pytest.fixture(autouse=True)
def setup_test():
    # Get the singleton instance and reset it to clean state
    mount_context = context.MountContext()
    mount_context.reset()
    mount_context.fqdn_regex_pattern = mount_efs.FQDN_REGEX_PATTERN
    mount_context.mount_type = MOUNT_TYPE_EFS
    yield mount_context
    mount_context.reset()


def test_mount_type_does_not_require_iam_for_efs():
    """Test that EFS mount type does not require IAM"""
    assert not metadata.mount_type_requires_iam(), "EFS should not require IAM"


def test_efs_mount_options_do_not_require_iam():
    """Test that EFS mount options validation does not require IAM option"""

    # Test that EFS mount without iam option succeeds
    options_without_iam = {}

    # This should not raise an exception
    try:
        mount_options.check_options_validity(options_without_iam)
    except SystemExit:
        pytest.fail("EFS mount without iam option should not fail validation")


def test_efs_mount_options_with_iam_require_tls():
    """Test that EFS mount options with IAM still require TLS (existing behavior)"""

    # Test that EFS mount with iam but without tls option fails (existing validation)
    options_with_iam_no_tls = {"iam": None}

    with pytest.raises(SystemExit) as exc_info:
        mount_options.check_options_validity(options_with_iam_no_tls)

    # The fatal_error function calls sys.exit(1)
    assert exc_info.value.code == 1


def test_efs_mount_options_with_iam_and_tls_succeed():
    """Test that EFS mount options validation succeeds with both iam and tls"""

    # Test that EFS mount with both iam and tls options succeeds
    options_with_iam_and_tls = {"iam": None, "tls": None}

    # This should not raise an exception
    try:
        mount_options.check_options_validity(options_with_iam_and_tls)
    except SystemExit:
        pytest.fail("EFS mount with iam and tls options should not fail validation")
