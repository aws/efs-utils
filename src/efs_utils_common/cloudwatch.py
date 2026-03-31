#!/usr/bin/env python3
#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.


import logging
import time

try:
    from botocore.exceptions import (
        ClientError,
        EndpointConnectionError,
        NoCredentialsError,
    )

    BOTOCORE_PRESENT = True
except ImportError:
    BOTOCORE_PRESENT = False

from efs_utils_common.config_utils import get_boolean_config_item_value
from efs_utils_common.constants import (
    CLOUDWATCH_LOG_SECTION,
    DEFAULT_CLOUDWATCH_LOG_GROUP,
)
from efs_utils_common.context import MountContext
from efs_utils_common.metadata import (
    get_botocore_client,
    get_instance_identity_info_from_instance_metadata,
)


def bootstrap_cloudwatch_logging(config, options, fs_id=None):
    if not check_if_cloudwatch_log_enabled(config):
        return None

    cloudwatchlog_client = get_botocore_client(config, "logs", options)

    if not cloudwatchlog_client:
        return None

    cloudwatchlog_config = get_cloudwatchlog_config(config, fs_id)

    log_group_name = cloudwatchlog_config.get("log_group_name")
    log_stream_name = cloudwatchlog_config.get("log_stream_name")
    retention_days = cloudwatchlog_config.get("retention_days")

    group_creation_completed = create_cloudwatch_log_group(
        cloudwatchlog_client, log_group_name
    )

    if not group_creation_completed:
        return None

    put_retention_policy_completed = put_cloudwatch_log_retention_policy(
        cloudwatchlog_client, log_group_name, retention_days
    )

    if not put_retention_policy_completed:
        return None

    stream_creation_completed = create_cloudwatch_log_stream(
        cloudwatchlog_client, log_group_name, log_stream_name
    )

    if not stream_creation_completed:
        return None

    return {
        "client": cloudwatchlog_client,
        "log_group_name": log_group_name,
        "log_stream_name": log_stream_name,
    }


def create_default_cloudwatchlog_agent_if_not_exist(config, options):
    if not check_if_cloudwatch_log_enabled(config):
        return None
    context = MountContext()
    if not context.cloudwatch_agent:
        context.cloudwatch_agent = bootstrap_cloudwatch_logging(config, options)


def get_cloudwatchlog_config(config, fs_id=None):
    log_group_name = DEFAULT_CLOUDWATCH_LOG_GROUP
    if config.has_option(CLOUDWATCH_LOG_SECTION, "log_group_name"):
        log_group_name = config.get(CLOUDWATCH_LOG_SECTION, "log_group_name")

        if "{fs_id}" in log_group_name:
            if fs_id:
                # Formatting the log_group_name with the fs_id.
                log_group_name = log_group_name.format(fs_id=fs_id)
            else:
                # If fs_id is None so putting the logs into the log-group by removing '/{fs_id}' in log_group_name.
                log_group_name = log_group_name.replace("/{fs_id}", "")
                logging.warning(
                    "Failed to load the File System ID, pushing logs to log group %s.",
                    log_group_name,
                )

    logging.debug("Pushing logs to log group named %s in Cloudwatch.", log_group_name)
    retention_days = None
    if config.has_option(CLOUDWATCH_LOG_SECTION, "retention_in_days"):
        retention_days = config.get(CLOUDWATCH_LOG_SECTION, "retention_in_days")

    log_stream_name = get_cloudwatch_log_stream_name(config, fs_id)

    return {
        "log_group_name": log_group_name,
        "retention_days": None if retention_days is None else int(retention_days),
        "log_stream_name": log_stream_name,
    }


def get_cloudwatch_log_stream_name(config, fs_id=None):
    instance_id = get_instance_identity_info_from_instance_metadata(
        config, "instanceId"
    )
    if instance_id and fs_id:
        log_stream_name = "%s - %s - mount.log" % (fs_id, instance_id)
    elif instance_id:
        log_stream_name = "%s - mount.log" % (instance_id)
    elif fs_id:
        log_stream_name = "%s - mount.log" % (fs_id)
    else:
        log_stream_name = "default - mount.log"

    return log_stream_name


def check_if_cloudwatch_log_enabled(config):
    # We don't emit warning message here as there will always no `enabled` config item even for a new config file. By default we
    # comment out the `enabled = true` in config file so that the cloudwatch log feature is disabled. This is not set as
    # `enabled = false` because we enable this feature by uncommenting this item for user who use System Manager Distributor
    # to install efs-utils. This gives user an opportunity to still disable the feature by setting `enabled = false`.
    return get_boolean_config_item_value(
        config,
        CLOUDWATCH_LOG_SECTION,
        "enabled",
        default_value=False,
        emit_warning_message=False,
    )


def cloudwatch_create_log_group_helper(cloudwatchlog_client, log_group_name):
    cloudwatchlog_client.create_log_group(logGroupName=log_group_name)
    logging.info("Created cloudwatch log group %s" % log_group_name)


def create_cloudwatch_log_group(cloudwatchlog_client, log_group_name):
    try:
        cloudwatch_create_log_group_helper(cloudwatchlog_client, log_group_name)
    except ClientError as e:
        exception = e.response["Error"]["Code"]

        if exception == "ResourceAlreadyExistsException":
            logging.debug(
                "Log group %s already exist, %s" % (log_group_name, e.response)
            )
            return True
        elif exception == "LimitExceededException":
            logging.error(
                "Reached the maximum number of log groups that can be created, %s"
                % e.response
            )
            return False
        elif exception == "OperationAbortedException":
            logging.debug(
                "Multiple requests to update the same log group %s were in conflict, %s"
                % (log_group_name, e.response)
            )
            return False
        elif exception == "InvalidParameterException":
            logging.error(
                "Log group name %s is specified incorrectly, %s"
                % (log_group_name, e.response)
            )
            return False
        else:
            handle_general_botocore_exceptions(e)
            return False
    except NoCredentialsError as e:
        logging.warning("Credentials are not properly configured, %s" % e)
        return False
    except EndpointConnectionError as e:
        logging.warning("Could not connect to the endpoint, %s" % e)
        return False
    except Exception as e:
        logging.warning("Unknown error, %s." % e)
        return False
    return True


def cloudwatch_put_retention_policy_helper(
    cloudwatchlog_client, log_group_name, retention_days
):
    if retention_days is not None:
        cloudwatchlog_client.put_retention_policy(
            logGroupName=log_group_name, retentionInDays=retention_days
        )
        logging.debug("Set cloudwatch log group retention days to %s" % retention_days)
    else:
        cloudwatchlog_client.delete_retention_policy(logGroupName=log_group_name)


def put_cloudwatch_log_retention_policy(
    cloudwatchlog_client, log_group_name, retention_days
):
    try:
        cloudwatch_put_retention_policy_helper(
            cloudwatchlog_client, log_group_name, retention_days
        )
    except ClientError as e:
        exception = e.response["Error"]["Code"]

        if exception == "ResourceNotFoundException":
            logging.error(
                "Log group %s does not exist, %s" % (log_group_name, e.response)
            )
            return False
        elif exception == "OperationAbortedException":
            logging.debug(
                "Multiple requests to update the same log group %s were in conflict, %s"
                % (log_group_name, e.response)
            )
            return False
        elif exception == "InvalidParameterException":
            logging.error(
                "Either parameter log group name %s or retention in days %s is specified incorrectly, %s"
                % (log_group_name, retention_days, e.response)
            )
            return False
        else:
            handle_general_botocore_exceptions(e)
            return False
    except NoCredentialsError as e:
        logging.warning("Credentials are not properly configured, %s" % e)
        return False
    except EndpointConnectionError as e:
        logging.warning("Could not connect to the endpoint, %s" % e)
        return False
    except Exception as e:
        logging.warning("Unknown error, %s." % e)
        return False
    return True


def cloudwatch_create_log_stream_helper(
    cloudwatchlog_client, log_group_name, log_stream_name
):
    cloudwatchlog_client.create_log_stream(
        logGroupName=log_group_name, logStreamName=log_stream_name
    )
    logging.info(
        "Created cloudwatch log stream %s in log group %s"
        % (log_stream_name, log_group_name)
    )


def create_cloudwatch_log_stream(cloudwatchlog_client, log_group_name, log_stream_name):
    try:
        cloudwatch_create_log_stream_helper(
            cloudwatchlog_client, log_group_name, log_stream_name
        )
    except ClientError as e:
        exception = e.response["Error"]["Code"]

        if exception == "ResourceAlreadyExistsException":
            logging.debug(
                "Log stream %s already exist in log group %s, %s"
                % (log_stream_name, log_group_name, e.response)
            )
            return True
        elif exception == "InvalidParameterException":
            logging.error(
                "Either parameter log group name %s or log stream name %s is specified incorrectly, %s"
                % (log_group_name, log_stream_name, e.response)
            )
            return False
        elif exception == "ResourceNotFoundException":
            logging.error(
                "Log group %s does not exist, %s" % (log_group_name, e.response)
            )
            return False
        else:
            handle_general_botocore_exceptions(e)
            return False
    except NoCredentialsError as e:
        logging.warning("Credentials are not properly configured, %s" % e)
        return False
    except EndpointConnectionError as e:
        logging.warning("Could not connect to the endpoint, %s" % e)
        return False
    except Exception as e:
        logging.warning("Unknown error, %s." % e)
        return False
    return True


def cloudwatch_put_log_events_helper(cloudwatchlog_agent, message, token=None):
    kwargs = {
        "logGroupName": cloudwatchlog_agent.get("log_group_name"),
        "logStreamName": cloudwatchlog_agent.get("log_stream_name"),
        "logEvents": [
            {"timestamp": int(round(time.time() * 1000)), "message": message}
        ],
    }
    if token:
        kwargs["sequenceToken"] = token
    cloudwatchlog_agent.get("client").put_log_events(**kwargs)


def publish_cloudwatch_log(cloudwatchlog_agent, message):
    if not cloudwatchlog_agent or not cloudwatchlog_agent.get("client"):
        return False

    token = get_log_stream_next_token(cloudwatchlog_agent)

    try:
        cloudwatch_put_log_events_helper(cloudwatchlog_agent, message, token)
    except ClientError as e:
        exception = e.response["Error"]["Code"]

        if exception == "InvalidSequenceTokenException":
            logging.debug("The sequence token is not valid, %s" % e.response)
            return False
        elif exception == "InvalidParameterException":
            logging.debug(
                "One of the parameter to put log events is not valid, %s" % e.response
            )
            return False
        elif exception == "DataAlreadyAcceptedException":
            logging.debug("The event %s was already logged, %s" % (message, e.response))
            return False
        elif exception == "UnrecognizedClientException":
            logging.debug(
                "The most likely cause is an invalid AWS access key ID or secret Key, %s"
                % e.response
            )
            return False
        elif exception == "ResourceNotFoundException":
            logging.error(
                "Either log group %s or log stream %s does not exist, %s"
                % (
                    cloudwatchlog_agent.get("log_group_name"),
                    cloudwatchlog_agent.get("log_stream_name"),
                    e.response,
                )
            )
            return False
        else:
            logging.debug("Unexpected error: %s" % e)
            return False
    except NoCredentialsError as e:
        logging.warning("Credentials are not properly configured, %s" % e)
        return False
    except EndpointConnectionError as e:
        logging.warning("Could not connect to the endpoint, %s" % e)
        return False
    except Exception as e:
        logging.warning("Unknown error, %s." % e)
        return False
    return True


def cloudwatch_describe_log_streams_helper(cloudwatchlog_agent):
    return cloudwatchlog_agent.get("client").describe_log_streams(
        logGroupName=cloudwatchlog_agent.get("log_group_name"),
        logStreamNamePrefix=cloudwatchlog_agent.get("log_stream_name"),
    )


def get_log_stream_next_token(cloudwatchlog_agent):
    try:
        response = cloudwatch_describe_log_streams_helper(cloudwatchlog_agent)
    except ClientError as e:
        exception = e.response["Error"]["Code"]

        if exception == "InvalidParameterException":
            logging.debug(
                "Either parameter log group name %s or log stream name %s is specified incorrectly, %s"
                % (
                    cloudwatchlog_agent.get("log_group_name"),
                    cloudwatchlog_agent.get("log_stream_name"),
                    e.response,
                )
            )
        elif exception == "ResourceNotFoundException":
            logging.debug(
                "Either log group %s or log stream %s does not exist, %s"
                % (
                    cloudwatchlog_agent.get("log_group_name"),
                    cloudwatchlog_agent.get("log_stream_name"),
                    e.response,
                )
            )
        else:
            handle_general_botocore_exceptions(e)
        return None
    except NoCredentialsError as e:
        logging.warning("Credentials are not properly configured, %s" % e)
        return None
    except EndpointConnectionError as e:
        logging.warning("Could not connect to the endpoint, %s" % e)
        return None
    except Exception as e:
        logging.warning("Unknown error, %s" % e)
        return None

    try:
        log_stream = response["logStreams"][0]
        return log_stream.get("uploadSequenceToken")
    except (IndexError, TypeError, KeyError):
        pass

    return None


def handle_general_botocore_exceptions(error):
    exception = error.response["Error"]["Code"]

    if exception == "ServiceUnavailableException":
        logging.debug("The service cannot complete the request, %s" % error.response)
    elif exception == "AccessDeniedException":
        logging.debug(
            "User is not authorized to perform the action, %s" % error.response
        )
    else:
        logging.debug("Unexpected error: %s" % error)
