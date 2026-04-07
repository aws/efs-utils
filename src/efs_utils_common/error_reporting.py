#!/usr/bin/env python3
#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.


import logging
import sys

from efs_utils_common.context import MountContext


def fatal_error(user_message, log_message=None, exit_code=1):
    if log_message is None:
        log_message = user_message

    sys.stderr.write("%s\n" % user_message)
    logging.error(log_message)
    context = MountContext()

    from efs_utils_common.cloudwatch import publish_cloudwatch_log

    publish_cloudwatch_log(context.cloudwatch_agent, "Mount failed, %s" % log_message)
    sys.exit(exit_code)
