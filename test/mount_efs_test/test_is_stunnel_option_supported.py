#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import mount_efs

STUNNEL_OPTION = "stunnelOption"

STUNNEL_OUTPUT_WITHOUT_OPTION = ["foo", "bar", "baz"]
STUNNEL_OUTPUT_WITH_OPTION = STUNNEL_OUTPUT_WITHOUT_OPTION + [STUNNEL_OPTION]


def test_supported_option(capsys):
    enabled = mount_efs.is_stunnel_option_supported(
        STUNNEL_OUTPUT_WITH_OPTION, STUNNEL_OPTION
    )

    assert enabled


def test_unsupported_option():
    enabled = mount_efs.is_stunnel_option_supported(
        STUNNEL_OUTPUT_WITHOUT_OPTION, STUNNEL_OPTION
    )

    assert not enabled
