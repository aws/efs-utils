#!/usr/bin/env python3

import pytest

import efs_utils_common.context as context
import efs_utils_common.metadata as metadata
import efs_utils_common.mount_options as mount_options
import mount_s3files
from efs_utils_common.constants import MOUNT_TYPE_S3FILES


@pytest.fixture(autouse=True)
def setup_test():
    # Get the singleton instance and reset it to clean state
    mount_context = context.MountContext()
    mount_context.reset()
    mount_context.fqdn_regex_pattern = mount_s3files.FQDN_REGEX_PATTERN
    mount_context.mount_type = MOUNT_TYPE_S3FILES
    yield mount_context
    mount_context.reset()


def test_mount_type_requires_iam_for_s3files():
    assert metadata.mount_type_requires_iam(), "S3Files should require IAM"


def test_s3files_mount_options_require_iam():
    options_without_iam = {}

    mount_options.check_options_validity(options_without_iam)

    assert "iam" in options_without_iam


def test_s3files_mount_options_require_tls():
    options_with_iam_no_tls = {"iam": None}

    mount_options.check_options_validity(options_with_iam_no_tls)

    assert "tls" in options_with_iam_no_tls


def test_s3files_mount_options_with_iam_and_tls_succeed():
    options_with_iam_and_tls = {"iam": None, "tls": None}

    # This should not raise an exception
    try:
        mount_options.check_options_validity(options_with_iam_and_tls)
    except SystemExit:
        pytest.fail("S3Files mount with iam and tls options should not fail validation")
