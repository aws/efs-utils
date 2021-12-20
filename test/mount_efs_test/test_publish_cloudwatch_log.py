# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.

import mount_efs
from botocore.exceptions import ClientError, NoCredentialsError
from mock import MagicMock

from .. import utils

try:
    import ConfigParser
except ImportError:
    from configparser import ConfigParser

DEFAULT_CLOUDWATCH_LOG_GROUP = "/aws/efs/utils"
DEFAULT_CLOUDWATCH_ENABLED = "true"
DEFAULT_CLOUDWATCH_DISABLED = "false"
DEFAULT_RETENTION_DAYS = 14
FS_ID = "fs-deadbeef"
INSTANCE = "i-12345678"
DEFAULT_CLOUDWATCH_LOG_STREAM = "%s - %s - mount.log" % (FS_ID, INSTANCE)
MOCK_AGENT = {
    "client": "fake-agent",
    "log_group_name": DEFAULT_CLOUDWATCH_LOG_GROUP,
    "log_stream_name": "%s - %s - mount.log" % (FS_ID, INSTANCE),
}


def _get_mock_config(enabled, log_group_name, retention_in_days):
    def config_get_side_effect(section, field):
        if section == mount_efs.CLOUDWATCH_LOG_SECTION and field == "log_group_name":
            return log_group_name
        elif (
            section == mount_efs.CLOUDWATCH_LOG_SECTION and field == "retention_in_days"
        ):
            return retention_in_days
        else:
            raise ValueError("Unexpected arguments")

    def config_getboolean_side_effect(section, field):
        if section == mount_efs.CLOUDWATCH_LOG_SECTION and field == "enabled":
            return True if enabled == "true" else False
        else:
            raise ValueError("Unexpected arguments")

    mock_config = MagicMock()
    mock_config.get.side_effect = config_get_side_effect
    mock_config.getboolean.side_effect = config_getboolean_side_effect
    return mock_config


"""
cloudwatch-log config unit tests
"""


def test_get_cloudwatchlog_config_without_fsid_with_instance_id(mocker):
    config = _get_mock_config(
        DEFAULT_CLOUDWATCH_ENABLED, DEFAULT_CLOUDWATCH_LOG_GROUP, DEFAULT_RETENTION_DAYS
    )
    enabled = mount_efs.check_if_cloudwatch_log_enabled(config)
    assert enabled == True

    mocker.patch(
        "mount_efs.get_instance_identity_info_from_instance_metadata",
        return_value=INSTANCE,
    )
    cloudwatchlog_agent = mount_efs.get_cloudwatchlog_config(config)
    assert cloudwatchlog_agent.get("log_group_name") == DEFAULT_CLOUDWATCH_LOG_GROUP
    assert cloudwatchlog_agent.get("retention_days") == DEFAULT_RETENTION_DAYS
    assert cloudwatchlog_agent.get("log_stream_name") == "%s - mount.log" % INSTANCE


def test_get_cloudwatchlog_config_with_fsid_with_instance_id(mocker):
    config = _get_mock_config(
        DEFAULT_CLOUDWATCH_ENABLED, DEFAULT_CLOUDWATCH_LOG_GROUP, DEFAULT_RETENTION_DAYS
    )
    enabled = mount_efs.check_if_cloudwatch_log_enabled(config)
    assert enabled == True

    mocker.patch(
        "mount_efs.get_instance_identity_info_from_instance_metadata",
        return_value=INSTANCE,
    )
    cloudwatchlog_agent = mount_efs.get_cloudwatchlog_config(config, FS_ID)
    assert cloudwatchlog_agent.get("log_group_name") == DEFAULT_CLOUDWATCH_LOG_GROUP
    assert cloudwatchlog_agent.get("retention_days") == DEFAULT_RETENTION_DAYS
    assert cloudwatchlog_agent.get("log_stream_name") == "%s - %s - mount.log" % (
        FS_ID,
        INSTANCE,
    )


def test_get_cloudwatchlog_config_with_fsid_without_instance_id(mocker):
    config = _get_mock_config(
        DEFAULT_CLOUDWATCH_ENABLED, DEFAULT_CLOUDWATCH_LOG_GROUP, DEFAULT_RETENTION_DAYS
    )
    enabled = mount_efs.check_if_cloudwatch_log_enabled(config)
    assert enabled == True

    mocker.patch(
        "mount_efs.get_instance_identity_info_from_instance_metadata", return_value=None
    )
    cloudwatchlog_agent = mount_efs.get_cloudwatchlog_config(config, FS_ID)
    assert cloudwatchlog_agent.get("log_group_name") == DEFAULT_CLOUDWATCH_LOG_GROUP
    assert cloudwatchlog_agent.get("retention_days") == DEFAULT_RETENTION_DAYS
    assert cloudwatchlog_agent.get("log_stream_name") == "%s - mount.log" % (FS_ID)


def test_get_cloudwatchlog_config_without_fsid_without_instance_id(mocker):
    config = _get_mock_config(
        DEFAULT_CLOUDWATCH_ENABLED, DEFAULT_CLOUDWATCH_LOG_GROUP, DEFAULT_RETENTION_DAYS
    )
    enabled = mount_efs.check_if_cloudwatch_log_enabled(config)
    assert enabled == True

    mocker.patch(
        "mount_efs.get_instance_identity_info_from_instance_metadata", return_value=None
    )
    cloudwatchlog_agent = mount_efs.get_cloudwatchlog_config(config)
    assert cloudwatchlog_agent.get("log_group_name") == DEFAULT_CLOUDWATCH_LOG_GROUP
    assert cloudwatchlog_agent.get("retention_days") == DEFAULT_RETENTION_DAYS
    assert cloudwatchlog_agent.get("log_stream_name") == "default - mount.log"


# When config set enabled = false, or there is no enabled section, call the bootstrap_cloudwatch_logging, the get_botocore_client
# is not called
def test_botocore_not_called_when_feature_not_enabled(mocker):
    config = _get_mock_config(
        DEFAULT_CLOUDWATCH_DISABLED,
        DEFAULT_CLOUDWATCH_LOG_GROUP,
        DEFAULT_RETENTION_DAYS,
    )
    enabled = mount_efs.check_if_cloudwatch_log_enabled(config)
    assert enabled == False

    get_botocore_client_mock = mocker.patch("mount_efs.get_botocore_client")
    cloudwatchlog_agent = mount_efs.bootstrap_cloudwatch_logging(config, {}, FS_ID)
    utils.assert_not_called(get_botocore_client_mock)
    assert cloudwatchlog_agent == None


# When config set enabled = true, call the bootstrap_cloudwatch_logging, the get_botocore_client is called
def test_cloudwatchlog_agent_none_when_botocore_agent_is_none(mocker):
    config = _get_mock_config(
        DEFAULT_CLOUDWATCH_ENABLED, DEFAULT_CLOUDWATCH_LOG_GROUP, DEFAULT_RETENTION_DAYS
    )
    get_botocore_client_mock = mocker.patch(
        "mount_efs.get_botocore_client", return_value=None
    )
    cloudwatchlog_agent = mount_efs.bootstrap_cloudwatch_logging(config, {}, FS_ID)
    utils.assert_called_once(get_botocore_client_mock)

    assert cloudwatchlog_agent == None


"""
bootstrap cloud watch log unit tests
"""


def test_bootstrap_cloudwatch_log(mocker):
    config = _get_mock_config(
        DEFAULT_CLOUDWATCH_ENABLED, DEFAULT_CLOUDWATCH_LOG_GROUP, DEFAULT_RETENTION_DAYS
    )
    mocker.patch(
        "mount_efs.get_instance_identity_info_from_instance_metadata",
        return_value=INSTANCE,
    )
    get_botocore_client_mock = mocker.patch(
        "mount_efs.get_botocore_client", return_value="fake-agent"
    )
    create_log_group_mock = mocker.patch(
        "mount_efs.create_cloudwatch_log_group", return_value=True
    )
    put_retention_policy_mock = mocker.patch(
        "mount_efs.put_cloudwatch_log_retention_policy", return_value=True
    )
    create_log_stream_mock = mocker.patch(
        "mount_efs.create_cloudwatch_log_stream", return_value=True
    )

    cloudwatchlog_agent = mount_efs.bootstrap_cloudwatch_logging(config, {}, FS_ID)
    utils.assert_called_once(get_botocore_client_mock)
    utils.assert_called_once(create_log_group_mock)
    utils.assert_called_once(put_retention_policy_mock)
    utils.assert_called_once(create_log_stream_mock)

    assert cloudwatchlog_agent == MOCK_AGENT


def test_bootstrap_cloudwatch_log_with_fs_id_template(mocker):
    log_group = DEFAULT_CLOUDWATCH_LOG_GROUP + "/{fs_id}"
    expected_agent = {
        "client": "fake-agent",
        "log_group_name": log_group.format(fs_id=FS_ID),
        "log_stream_name": "%s - %s - mount.log" % (FS_ID, INSTANCE),
    }

    config = _get_mock_config(
        DEFAULT_CLOUDWATCH_ENABLED, log_group, DEFAULT_RETENTION_DAYS
    )
    mocker.patch(
        "mount_efs.get_instance_identity_info_from_instance_metadata",
        return_value=INSTANCE,
    )
    get_botocore_client_mock = mocker.patch(
        "mount_efs.get_botocore_client", return_value="fake-agent"
    )
    create_log_group_mock = mocker.patch(
        "mount_efs.create_cloudwatch_log_group", return_value=True
    )
    put_retention_policy_mock = mocker.patch(
        "mount_efs.put_cloudwatch_log_retention_policy", return_value=True
    )
    create_log_stream_mock = mocker.patch(
        "mount_efs.create_cloudwatch_log_stream", return_value=True
    )
    cloudwatchlog_agent = mount_efs.bootstrap_cloudwatch_logging(config, {}, FS_ID)
    utils.assert_called_once(get_botocore_client_mock)
    utils.assert_called_once(create_log_group_mock)
    utils.assert_called_once(put_retention_policy_mock)
    utils.assert_called_once(create_log_stream_mock)

    assert cloudwatchlog_agent == expected_agent


def test_bootstrap_cloudwatch_log_create_log_group_failed(mocker):
    config = _get_mock_config(
        DEFAULT_CLOUDWATCH_ENABLED, DEFAULT_CLOUDWATCH_LOG_GROUP, DEFAULT_RETENTION_DAYS
    )
    mocker.patch(
        "mount_efs.get_instance_identity_info_from_instance_metadata",
        return_value=INSTANCE,
    )
    get_botocore_client_mock = mocker.patch(
        "mount_efs.get_botocore_client", return_value="fake-agent"
    )
    create_log_group_mock = mocker.patch(
        "mount_efs.create_cloudwatch_log_group", return_value=False
    )
    put_retention_policy_mock = mocker.patch(
        "mount_efs.put_cloudwatch_log_retention_policy"
    )
    create_log_stream_mock = mocker.patch("mount_efs.create_cloudwatch_log_stream")

    cloudwatchlog_agent = mount_efs.bootstrap_cloudwatch_logging(config, {}, FS_ID)
    utils.assert_called_once(get_botocore_client_mock)
    utils.assert_called_once(create_log_group_mock)
    utils.assert_not_called(put_retention_policy_mock)
    utils.assert_not_called(create_log_stream_mock)

    assert cloudwatchlog_agent == None


def test_bootstrap_cloudwatch_log_put_retention_days_failed(mocker):
    config = _get_mock_config(
        DEFAULT_CLOUDWATCH_ENABLED, DEFAULT_CLOUDWATCH_LOG_GROUP, DEFAULT_RETENTION_DAYS
    )
    mocker.patch(
        "mount_efs.get_instance_identity_info_from_instance_metadata",
        return_value=INSTANCE,
    )
    get_botocore_client_mock = mocker.patch(
        "mount_efs.get_botocore_client", return_value="fake-agent"
    )
    create_log_group_mock = mocker.patch(
        "mount_efs.create_cloudwatch_log_group", return_value=True
    )
    put_retention_policy_mock = mocker.patch(
        "mount_efs.put_cloudwatch_log_retention_policy", return_value=False
    )
    create_log_stream_mock = mocker.patch("mount_efs.create_cloudwatch_log_stream")

    cloudwatchlog_agent = mount_efs.bootstrap_cloudwatch_logging(config, {}, FS_ID)
    utils.assert_called_once(get_botocore_client_mock)
    utils.assert_called_once(create_log_group_mock)
    utils.assert_called_once(put_retention_policy_mock)
    utils.assert_not_called(create_log_stream_mock)

    assert cloudwatchlog_agent == None


def test_bootstrap_cloudwatch_log_create_log_stream_failed(mocker):
    config = _get_mock_config(
        DEFAULT_CLOUDWATCH_ENABLED, DEFAULT_CLOUDWATCH_LOG_GROUP, DEFAULT_RETENTION_DAYS
    )
    mocker.patch(
        "mount_efs.get_instance_identity_info_from_instance_metadata",
        return_value=INSTANCE,
    )
    get_botocore_client_mock = mocker.patch(
        "mount_efs.get_botocore_client", return_value="fake-agent"
    )
    create_log_group_mock = mocker.patch(
        "mount_efs.create_cloudwatch_log_group", return_value=True
    )
    put_retention_policy_mock = mocker.patch(
        "mount_efs.put_cloudwatch_log_retention_policy", return_value=True
    )
    create_log_stream_mock = mocker.patch(
        "mount_efs.create_cloudwatch_log_stream", return_value=False
    )

    cloudwatchlog_agent = mount_efs.bootstrap_cloudwatch_logging(config, {}, FS_ID)
    utils.assert_called_once(get_botocore_client_mock)
    utils.assert_called_once(create_log_group_mock)
    utils.assert_called_once(put_retention_policy_mock)
    utils.assert_called_once(create_log_stream_mock)

    assert cloudwatchlog_agent == None


"""
botocore client unit tests
"""


def test_botocore_none_if_botocore_not_present(mocker):
    config = _get_mock_config(
        DEFAULT_CLOUDWATCH_ENABLED, DEFAULT_CLOUDWATCH_LOG_GROUP, DEFAULT_RETENTION_DAYS
    )
    mount_efs.BOTOCORE_PRESENT = False
    client = mount_efs.get_botocore_client(config, "logs", {})
    assert client == None


def _test_botocore_client_established(mocker, iam_name):
    config = _get_mock_config(
        DEFAULT_CLOUDWATCH_ENABLED, DEFAULT_CLOUDWATCH_LOG_GROUP, DEFAULT_RETENTION_DAYS
    )
    mount_efs.BOTOCORE_PRESENT = True
    mocker.patch("mount_efs.get_target_region", return_value="us-east-1")
    mocker.patch("mount_efs.get_iam_role_name", return_value=iam_name)
    mocker.patch(
        "mount_efs.get_aws_security_credentials_from_instance_metadata",
        return_value=(
            {"AccessKeyId": "123456", "SecretAccessKey": "123456", "Token": "123456"},
            "",
        ),
    )

    boto_session_mock = MagicMock()
    boto_session_mock.create_client.return_value = "fake-client"
    mocker.patch("botocore.session.get_session", return_value=boto_session_mock)

    client = mount_efs.get_botocore_client(config, "logs", {})
    assert client == "fake-client"


def test_botocore_client_established_if_iam_name_is_present(mocker):
    _test_botocore_client_established(mocker, "default")


def test_botocore_client_established_if_iam_name_is_not_present(mocker):
    _test_botocore_client_established(mocker, None)


"""
create_log_group api call exception unit tests
"""


def _test_create_log_group_client_error(mocker, exception, desired_result=False):
    operation_name = "CreateLogGroup"
    response = {"Error": {"Code": exception, "Message": exception}}
    mocker.patch(
        "mount_efs.cloudwatch_create_log_group_helper",
        side_effect=[ClientError(response, operation_name)],
    )
    is_completed = mount_efs.create_cloudwatch_log_group(
        MOCK_AGENT, DEFAULT_CLOUDWATCH_LOG_GROUP
    )
    assert is_completed == desired_result


def test_create_log_group_no_credentials_error(mocker):
    mocker.patch(
        "mount_efs.cloudwatch_create_log_group_helper",
        side_effect=[NoCredentialsError()],
    )
    is_completed = mount_efs.create_cloudwatch_log_group(
        MOCK_AGENT, DEFAULT_CLOUDWATCH_LOG_GROUP
    )
    assert is_completed == False


def test_create_log_group_resource_already_exist(mocker):
    _test_create_log_group_client_error(mocker, "ResourceAlreadyExistsException", True)


def test_create_log_group_limit_exceed(mocker):
    _test_create_log_group_client_error(mocker, "LimitExceededException")


def test_create_log_group_operation_aborted(mocker):
    _test_create_log_group_client_error(mocker, "OperationAbortedException")


def test_create_log_group_invalid_parameter(mocker):
    _test_create_log_group_client_error(mocker, "InvalidParameterException")


def test_create_log_group_service_unavailable_exception(mocker):
    _test_create_log_group_client_error(mocker, "ServiceUnavailableException")


def test_create_log_group_access_denied_exception(mocker):
    _test_create_log_group_client_error(mocker, "AccessDeniedException")


def test_create_log_group_unexpected_client_error(mocker):
    _test_create_log_group_client_error(mocker, "Unknown exception")


"""
put_retention_policy api call exception unit tests
"""


def _test_put_retention_policy_client_error(mocker, exception, desired_result=False):
    operation_name = "PutRetentionPolicy"
    response = {"Error": {"Code": exception, "Message": exception}}
    mocker.patch(
        "mount_efs.cloudwatch_put_retention_policy_helper",
        side_effect=[ClientError(response, operation_name)],
    )
    is_completed = mount_efs.put_cloudwatch_log_retention_policy(
        MOCK_AGENT["client"], DEFAULT_CLOUDWATCH_LOG_GROUP, DEFAULT_RETENTION_DAYS
    )
    assert is_completed == desired_result


def test_put_retention_policy_no_credentials_error(mocker):
    mocker.patch(
        "mount_efs.cloudwatch_put_retention_policy_helper",
        side_effect=[NoCredentialsError()],
    )
    is_completed = mount_efs.put_cloudwatch_log_retention_policy(
        MOCK_AGENT["client"], DEFAULT_CLOUDWATCH_LOG_GROUP, DEFAULT_RETENTION_DAYS
    )
    assert is_completed == False


def test_put_retention_policy_resource_not_found(mocker):
    _test_put_retention_policy_client_error(mocker, "ResourceNotFoundException")


def test_put_retention_policy_operation_aborted(mocker):
    _test_put_retention_policy_client_error(mocker, "OperationAbortedException")


def test_put_retention_policy_invalid_parameter(mocker):
    _test_put_retention_policy_client_error(mocker, "InvalidParameterException")


def test_put_retention_policy_service_unavailable_exception(mocker):
    _test_put_retention_policy_client_error(mocker, "ServiceUnavailableException")


def test_put_retention_policy_access_denied_exception(mocker):
    _test_put_retention_policy_client_error(mocker, "AccessDeniedException")


def test_put_retention_policy_unexpected_client_error(mocker):
    _test_put_retention_policy_client_error(mocker, "Unknown exception")


"""
create_log_stream api call exception unit tests
"""


def _test_create_log_stream_client_error(mocker, exception, desired_result=False):
    operation_name = "CreateLogStream"
    response = {"Error": {"Code": exception, "Message": exception}}
    mocker.patch(
        "mount_efs.cloudwatch_create_log_stream_helper",
        side_effect=[ClientError(response, operation_name)],
    )
    is_completed = mount_efs.create_cloudwatch_log_stream(
        MOCK_AGENT["client"],
        DEFAULT_CLOUDWATCH_LOG_GROUP,
        DEFAULT_CLOUDWATCH_LOG_STREAM,
    )
    assert is_completed == desired_result


def test_create_log_stream_no_credentials_error(mocker):
    mocker.patch(
        "mount_efs.cloudwatch_create_log_stream_helper",
        side_effect=[NoCredentialsError()],
    )
    is_completed = mount_efs.create_cloudwatch_log_stream(
        MOCK_AGENT["client"],
        DEFAULT_CLOUDWATCH_LOG_GROUP,
        DEFAULT_CLOUDWATCH_LOG_STREAM,
    )
    assert is_completed == False


def test_create_log_stream_resource_already_exist(mocker):
    _test_create_log_stream_client_error(mocker, "ResourceAlreadyExistsException", True)


def test_create_log_stream_resource_not_found(mocker):
    _test_create_log_stream_client_error(mocker, "ResourceNotFoundException")


def test_create_log_stream_invalid_parameter(mocker):
    _test_create_log_stream_client_error(mocker, "InvalidParameterException")


def test_create_log_stream_service_unavailable_exception(mocker):
    _test_create_log_stream_client_error(mocker, "ServiceUnavailableException")


def test_create_log_stream_access_denied_exception(mocker):
    _test_create_log_stream_client_error(mocker, "AccessDeniedException")


def test_create_log_stream_unexpected_client_error(mocker):
    _test_create_log_stream_client_error(mocker, "Unknown exception")


"""
put_log_events api call exception unit tests
"""


def _test_put_log_events_client_error(mocker, exception, desired_result=False):
    operation_name = "PutLogEvents"
    response = {"Error": {"Code": exception, "Message": exception}}

    mocker.patch("mount_efs.get_log_stream_next_token", return_value="ABCDEF")
    mocker.patch(
        "mount_efs.cloudwatch_put_log_events_helper",
        side_effect=[ClientError(response, operation_name)],
    )
    is_completed = mount_efs.publish_cloudwatch_log(MOCK_AGENT, "Test")
    assert is_completed == desired_result


def test_put_log_events_no_credentials_error(mocker):
    mocker.patch("mount_efs.get_log_stream_next_token", return_value="ABCDEF")
    mocker.patch(
        "mount_efs.cloudwatch_put_log_events_helper", side_effect=[NoCredentialsError()]
    )
    is_completed = mount_efs.publish_cloudwatch_log(MOCK_AGENT, "Test")
    assert is_completed == False


def test_put_log_events_resource_not_found(mocker):
    _test_put_log_events_client_error(mocker, "ResourceNotFoundException")


def test_put_log_events_invalid_sequence_token(mocker):
    _test_put_log_events_client_error(mocker, "InvalidSequenceTokenException")


def test_put_log_events_invalid_parameter(mocker):
    _test_put_log_events_client_error(mocker, "InvalidParameterException")


def test_put_log_events_data_already_accepted(mocker):
    _test_put_log_events_client_error(mocker, "DataAlreadyAcceptedException")


def test_put_log_events_unrecognized_client(mocker):
    _test_put_log_events_client_error(mocker, "UnrecognizedClientException")


def test_put_log_events_service_unavailable_exception(mocker):
    _test_put_log_events_client_error(mocker, "ServiceUnavailableException")


def test_put_log_events_access_denied_exception(mocker):
    _test_put_log_events_client_error(mocker, "AccessDeniedException")


def test_put_log_events_unexpected_client_error(mocker):
    _test_put_log_events_client_error(mocker, "Unknown exception")


"""
describe_log_stream api call exception unit tests
"""


def _test_get_log_stream_next_token_client_error(
    mocker, exception, desired_result=None
):
    operation_name = "DescribeLogStream"
    response = {"Error": {"Code": exception, "Message": exception}}

    mocker.patch(
        "mount_efs.cloudwatch_describe_log_streams_helper",
        side_effect=[ClientError(response, operation_name)],
    )
    token = mount_efs.get_log_stream_next_token(MOCK_AGENT)
    assert token == desired_result


def test_get_log_stream_next_token_no_credentials_error(mocker):
    mocker.patch(
        "mount_efs.cloudwatch_describe_log_streams_helper",
        side_effect=[NoCredentialsError()],
    )
    token = mount_efs.get_log_stream_next_token(MOCK_AGENT)
    assert token == None


def test_get_log_stream_next_token_resource_not_found(mocker):
    _test_put_log_events_client_error(mocker, "ResourceNotFoundException")


def test_get_log_stream_next_token_invalid_parameter(mocker):
    _test_get_log_stream_next_token_client_error(mocker, "InvalidParameterException")


def test_get_log_stream_next_token_service_unavailable_exception(mocker):
    _test_get_log_stream_next_token_client_error(mocker, "ServiceUnavailableException")


def test_get_log_stream_next_token_access_denied_exception(mocker):
    _test_get_log_stream_next_token_client_error(mocker, "AccessDeniedException")


def test_get_log_stream_next_token_unexpected_client_error(mocker):
    _test_get_log_stream_next_token_client_error(mocker, "Unknown exception")


def _test_get_log_stream_token_response(mocker, response, desired_token=None):
    mocker.patch(
        "mount_efs.cloudwatch_describe_log_streams_helper", return_value=response
    )
    token = mount_efs.get_log_stream_next_token(MOCK_AGENT)
    assert token == desired_token


def test_get_log_stream_token_index_error(mocker):
    response = {"logStreams": []}
    _test_get_log_stream_token_response(mocker, response)


def test_get_log_stream_token_key_error(mocker):
    response = {}
    _test_get_log_stream_token_response(mocker, response)


def test_get_log_stream_token_type_error(mocker):
    response = None
    _test_get_log_stream_token_response(mocker, response)


def test_get_log_stream_token_return_correct(mocker):
    token = "ABCDEF"
    response = {"logStreams": [{"uploadSequenceToken": token}]}
    _test_get_log_stream_token_response(mocker, response, token)
