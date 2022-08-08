#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import mount_efs

STUNNEL_OPTION = "stunnelOption"
STUNNEL_VALUES = "value1|value2|value3"
STUNNEL_OPTION_VALUE = "{}: {}".format(STUNNEL_OPTION, STUNNEL_VALUES)

STUNNEL_OUTPUT_WITHOUT_OPTION = ["foo", "bar", "baz"]
STUNNEL_OUTPUT_WITH_OPTION = STUNNEL_OUTPUT_WITHOUT_OPTION + [STUNNEL_OPTION]
STUNNEL_OUTPUT_WITH_OPTION_AND_VALUE = STUNNEL_OUTPUT_WITHOUT_OPTION + [
    STUNNEL_OPTION_VALUE
]


def test_supported_option():
    enabled = mount_efs.is_stunnel_option_supported(
        STUNNEL_OUTPUT_WITH_OPTION, STUNNEL_OPTION
    )

    assert enabled


def test_supported_option_value():
    enabled = mount_efs.is_stunnel_option_supported(
        STUNNEL_OUTPUT_WITH_OPTION_AND_VALUE, STUNNEL_OPTION, "value1"
    )

    assert enabled


def test_unsupported_option():
    enabled = mount_efs.is_stunnel_option_supported(
        STUNNEL_OUTPUT_WITHOUT_OPTION, STUNNEL_OPTION
    )

    assert not enabled


def test_unsupported_option_value():
    enabled = mount_efs.is_stunnel_option_supported(
        STUNNEL_OUTPUT_WITHOUT_OPTION, STUNNEL_OPTION, "value1"
    )

    assert not enabled
