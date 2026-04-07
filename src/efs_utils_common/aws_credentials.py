#!/usr/bin/env python3
#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.


import logging
import os

try:
    from configparser import NoOptionError, NoSectionError
except ImportError:
    from ConfigParser import NoOptionError, NoSectionError

try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode


try:
    import botocore.config
    import botocore.session
    from botocore.exceptions import ProfileNotFound

    BOTOCORE_PRESENT = True
except ImportError:
    BOTOCORE_PRESENT = False

from efs_utils_common.config_utils import read_config
from efs_utils_common.constants import (
    AWS_CONFIG_FILE,
    AWS_CONTAINER_AUTH_TOKEN_FILE_ENV,
    AWS_CONTAINER_CREDS_FULL_URI_ENV,
    AWS_CREDENTIALS_FILE,
    CONFIG_FILE_SETTINGS_HELP_URL,
    CREDENTIALS_KEYS,
    ECS_TASK_METADATA_API,
    ECS_URI_ENV,
    INSTANCE_IAM_URL,
    NAMED_PROFILE_HELP_URL,
    SECURITY_CREDS_ECS_URI_HELP_URL,
    SECURITY_CREDS_IAM_ROLE_HELP_URL,
    SECURITY_CREDS_WEBIDENTITY_HELP_URL,
    STS_ENDPOINT_URL_FORMAT,
    WEB_IDENTITY_ROLE_ARN_ENV,
    WEB_IDENTITY_TOKEN_FILE_ENV,
)
from efs_utils_common.error_reporting import fatal_error
from efs_utils_common.metadata import get_dns_name_suffix, url_request_helper


def get_aws_security_credentials(
    config,
    use_iam,
    region,
    awsprofile=None,
    aws_creds_uri=None,
    jwt_path=None,
    role_arn=None,
):
    """
    Lookup AWS security credentials. Adapted credentials provider chain from:
    https://boto3.amazonaws.com/v1/documentation/api/latest/guide/configuration.html and
    https://docs.aws.amazon.com/sdk-for-java/v1/developer-guide/credentials.html

    If iam is enabled, this function will return two objects, credentials and credentials_source.
    credentials is a dictionary with three keys, "AccessKeyId", "SecretAccessKey", and "Token".
    credentials_source will be a string that describes the method by which the credentials were obtained.
    """

    if not use_iam:
        return None, None

    # attempt to lookup AWS security credentials through the credentials URI the ECS agent generated
    if aws_creds_uri:
        return get_aws_security_credentials_from_ecs(config, aws_creds_uri, True)

    # attempt to lookup AWS security credentials in AWS credentials file (~/.aws/credentials)
    # and configs file (~/.aws/config) with given awsprofile
    # if the credentials are not present in above filepath, and botocore is present, attempt to assume the given awsprofile
    if awsprofile:
        return get_aws_security_credentials_from_awsprofile(awsprofile, True)

    # attempt to lookup AWS security credentials through AWS_CONTAINER_CREDENTIALS_RELATIVE_URI environment variable
    if ECS_URI_ENV in os.environ:
        credentials, credentials_source = get_aws_security_credentials_from_ecs(
            config, os.environ[ECS_URI_ENV], False
        )
        if credentials and credentials_source:
            return credentials, credentials_source

    # attempt to lookup AWS security credentials through Pod Identity
    credentials, credentials_source = get_aws_security_credentials_from_pod_identity(
        config, False
    )
    if credentials and credentials_source:
        return credentials, credentials_source

    # attempt to lookup AWS security credentials through AssumeRoleWithWebIdentity
    # (e.g. for IAM Role for Service Accounts (IRSA) approach on EKS)
    if jwt_path and role_arn:
        credentials, credentials_source = get_aws_security_credentials_from_webidentity(
            config,
            role_arn,
            jwt_path,
            region,
            False,
        )
        if credentials and credentials_source:
            return credentials, credentials_source

    if (
        WEB_IDENTITY_ROLE_ARN_ENV in os.environ
        and WEB_IDENTITY_TOKEN_FILE_ENV in os.environ
    ):
        credentials, credentials_source = get_aws_security_credentials_from_webidentity(
            config,
            os.environ[WEB_IDENTITY_ROLE_ARN_ENV],
            os.environ[WEB_IDENTITY_TOKEN_FILE_ENV],
            region,
            False,
        )
        if credentials and credentials_source:
            return credentials, credentials_source

    # attempt to lookup AWS security credentials with IAM role name attached to instance
    # through IAM role name security credentials lookup uri
    iam_role_name = get_iam_role_name(config)
    if iam_role_name:
        (
            credentials,
            credentials_source,
        ) = get_aws_security_credentials_from_instance_metadata(config, iam_role_name)
        if credentials and credentials_source:
            return credentials, credentials_source

    error_msg = (
        "AWS Access Key ID and Secret Access Key are not found in AWS credentials file (%s), config file (%s), "
        "from ECS credentials relative uri, or from the instance security credentials service"
        % (AWS_CREDENTIALS_FILE, AWS_CONFIG_FILE)
    )
    fatal_error(error_msg, error_msg)


def get_aws_security_credentials_from_awsprofile(awsprofile, is_fatal=False):
    for file_path in [AWS_CREDENTIALS_FILE, AWS_CONFIG_FILE]:
        if os.path.exists(file_path):
            credentials = credentials_file_helper(file_path, awsprofile)
            if credentials["AccessKeyId"]:
                logging.debug("Retrieved credentials from %s" % file_path)
                return credentials, os.path.basename(file_path) + ":" + awsprofile

    # If credentials are not defined in the aws credentials and config file, attempt to assume the named profile
    credentials = botocore_credentials_helper(awsprofile)
    if credentials["AccessKeyId"]:
        logging.debug("Retrieved credentials from assumed profile %s" % awsprofile)
        return credentials, "named_profile:" + awsprofile

    # Fail if credentials cannot be fetched from the given awsprofile
    if is_fatal:
        log_message = (
            "AWS security credentials not found in %s or %s under named profile [%s]"
            % (AWS_CREDENTIALS_FILE, AWS_CONFIG_FILE, awsprofile)
        )
        fatal_error(log_message)
    else:
        return None, None


def get_aws_security_credentials_from_ecs(config, aws_creds_uri, is_fatal=False):
    ecs_uri = ECS_TASK_METADATA_API + aws_creds_uri
    ecs_unsuccessful_resp = (
        "Unsuccessful retrieval of AWS security credentials at %s." % ecs_uri
    )
    ecs_url_error_msg = (
        "Unable to reach %s to retrieve AWS security credentials. See %s for more info."
        % (ecs_uri, SECURITY_CREDS_ECS_URI_HELP_URL)
    )
    ecs_security_dict = url_request_helper(
        config, ecs_uri, ecs_unsuccessful_resp, ecs_url_error_msg
    )

    if ecs_security_dict and all(k in ecs_security_dict for k in CREDENTIALS_KEYS):
        return ecs_security_dict, "ecs:" + aws_creds_uri

    # Fail if credentials cannot be fetched from the given aws_creds_uri
    if is_fatal:
        fatal_error(ecs_unsuccessful_resp, ecs_unsuccessful_resp)
    else:
        return None, None


def get_aws_security_credentials_from_webidentity(
    config, role_arn, token_file, region, is_fatal=False
):
    try:
        with open(token_file, "r") as f:
            token = f.read()
    except Exception as e:
        if is_fatal:
            unsuccessful_resp = "Error reading token file %s: %s" % (token_file, e)
            fatal_error(unsuccessful_resp, unsuccessful_resp)
        else:
            return None, None

    sts_endpoint_url = get_sts_endpoint_url(config, region)
    webidentity_url = (
        sts_endpoint_url
        + "?"
        + urlencode(
            {
                "Version": "2011-06-15",
                "Action": "AssumeRoleWithWebIdentity",
                "RoleArn": role_arn,
                "RoleSessionName": "efs-mount-helper",
                "WebIdentityToken": token,
            }
        )
    )

    unsuccessful_resp = (
        "Unsuccessful retrieval of AWS security credentials at %s." % sts_endpoint_url
    )
    url_error_msg = (
        "Unable to reach %s to retrieve AWS security credentials. See %s for more info."
        % (sts_endpoint_url, SECURITY_CREDS_WEBIDENTITY_HELP_URL)
    )
    resp = url_request_helper(
        config,
        webidentity_url,
        unsuccessful_resp,
        url_error_msg,
        headers={"Accept": "application/json"},
    )

    if resp:
        creds = (
            resp.get("AssumeRoleWithWebIdentityResponse", {})
            .get("AssumeRoleWithWebIdentityResult", {})
            .get("Credentials", {})
        )
        if all(k in creds for k in ["AccessKeyId", "SecretAccessKey", "SessionToken"]):
            return {
                "AccessKeyId": creds["AccessKeyId"],
                "SecretAccessKey": creds["SecretAccessKey"],
                "Token": creds["SessionToken"],
            }, "webidentity:" + ",".join([role_arn, token_file])

    # Fail if credentials cannot be fetched from the given aws_creds_uri
    if is_fatal:
        fatal_error(unsuccessful_resp, unsuccessful_resp)
    else:
        return None, None


def get_aws_security_credentials_from_pod_identity(config, is_fatal=False):
    if (
        AWS_CONTAINER_CREDS_FULL_URI_ENV not in os.environ
        or AWS_CONTAINER_AUTH_TOKEN_FILE_ENV not in os.environ
    ):
        return None, None

    creds_uri = os.environ[AWS_CONTAINER_CREDS_FULL_URI_ENV]
    token_file = os.environ[AWS_CONTAINER_AUTH_TOKEN_FILE_ENV]

    try:
        with open(token_file, "r") as f:
            token = f.read().strip()
            if "\r" in token or "\n" in token:
                if is_fatal:
                    unsuccessful_resp = (
                        "AWS Container Auth Token contains invalid characters"
                    )
                    fatal_error(unsuccessful_resp, unsuccessful_resp)
                return None, None
    except Exception as e:
        if is_fatal:
            unsuccessful_resp = (
                f"Error reading Aws Container Auth Token file {token_file}: {e}"
            )
            fatal_error(unsuccessful_resp, unsuccessful_resp)
        return None, None

    unsuccessful_resp = f"Unsuccessful retrieval of AWS security credentials from Container Credentials URI at {creds_uri}"
    url_error_msg = f"Unable to reach Container Credentials URI at {creds_uri}"

    pod_identity_security_dict = url_request_helper(
        config,
        creds_uri,
        unsuccessful_resp,
        url_error_msg,
        headers={"Authorization": token},
    )

    if pod_identity_security_dict and all(
        k in pod_identity_security_dict for k in CREDENTIALS_KEYS
    ):
        return pod_identity_security_dict, f"podidentity:{creds_uri},{token_file}"

    if is_fatal:
        fatal_error(unsuccessful_resp, unsuccessful_resp)
    return None, None


def get_sts_endpoint_url(config, region):
    dns_name_suffix = get_dns_name_suffix(config, region)
    return STS_ENDPOINT_URL_FORMAT.format(region, dns_name_suffix)


def get_aws_security_credentials_from_instance_metadata(config, iam_role_name):
    security_creds_lookup_url = INSTANCE_IAM_URL + iam_role_name
    unsuccessful_resp = (
        "Unsuccessful retrieval of AWS security credentials at %s."
        % security_creds_lookup_url
    )
    url_error_msg = (
        "Unable to reach %s to retrieve AWS security credentials. See %s for more info."
        % (security_creds_lookup_url, SECURITY_CREDS_IAM_ROLE_HELP_URL)
    )
    iam_security_dict = url_request_helper(
        config, security_creds_lookup_url, unsuccessful_resp, url_error_msg
    )

    if iam_security_dict and all(k in iam_security_dict for k in CREDENTIALS_KEYS):
        return iam_security_dict, "metadata:"
    else:
        return None, None


def get_iam_role_name(config):
    iam_role_unsuccessful_resp = (
        "Unsuccessful retrieval of IAM role name at %s." % INSTANCE_IAM_URL
    )
    iam_role_url_error_msg = (
        "Unable to reach %s to retrieve IAM role name. See %s for more info."
        % (INSTANCE_IAM_URL, SECURITY_CREDS_IAM_ROLE_HELP_URL)
    )
    iam_role_name = url_request_helper(
        config, INSTANCE_IAM_URL, iam_role_unsuccessful_resp, iam_role_url_error_msg
    )
    return iam_role_name


def credentials_file_helper(file_path, awsprofile):
    aws_credentials_configs = read_config(file_path)
    credentials = {"AccessKeyId": None, "SecretAccessKey": None, "Token": None}

    try:
        access_key = aws_credentials_configs.get(awsprofile, "aws_access_key_id")
        secret_key = aws_credentials_configs.get(awsprofile, "aws_secret_access_key")
        session_token = aws_credentials_configs.get(awsprofile, "aws_session_token")

        credentials["AccessKeyId"] = access_key
        credentials["SecretAccessKey"] = secret_key
        credentials["Token"] = session_token
    except NoOptionError as e:
        if "aws_access_key_id" in str(e) or "aws_secret_access_key" in str(e):
            logging.debug(
                "aws_access_key_id or aws_secret_access_key not found in %s under named profile [%s]",
                file_path,
                awsprofile,
            )
        if "aws_session_token" in str(e):
            logging.debug("aws_session_token not found in %s", file_path)
            credentials["AccessKeyId"] = aws_credentials_configs.get(
                awsprofile, "aws_access_key_id"
            )
            credentials["SecretAccessKey"] = aws_credentials_configs.get(
                awsprofile, "aws_secret_access_key"
            )
    except NoSectionError:
        logging.debug("No [%s] section found in config file %s", awsprofile, file_path)

    return credentials


def botocore_credentials_helper(awsprofile):
    # This method retrieves credentials from aws named profile using botocore, botocore will then assume that named profile, get
    # and return the credentials
    credentials = {"AccessKeyId": None, "SecretAccessKey": None, "Token": None}
    if not BOTOCORE_PRESENT:
        logging.error(
            "Cannot find credentials for %s, to assume this profile, please install botocore first."
            % awsprofile
        )
        return credentials
    session = botocore.session.get_session()
    session.set_config_variable("profile", awsprofile)

    try:
        frozen_credentials = session.get_credentials().get_frozen_credentials()
    except ProfileNotFound as e:
        fatal_error(
            "%s, please add the [profile %s] section in the aws config file following %s and %s."
            % (e, awsprofile, NAMED_PROFILE_HELP_URL, CONFIG_FILE_SETTINGS_HELP_URL)
        )

    credentials["AccessKeyId"] = frozen_credentials.access_key
    credentials["SecretAccessKey"] = frozen_credentials.secret_key
    credentials["Token"] = frozen_credentials.token
    return credentials


def get_aws_profile(options, use_iam):
    # Check mount option first
    awsprofile = options.get("awsprofile")

    # If not provided, check environment variable
    if not awsprofile:
        awsprofile = os.environ.get("AWS_PROFILE")
    if not awsprofile and use_iam:
        for file_path in [AWS_CREDENTIALS_FILE, AWS_CONFIG_FILE]:
            aws_credentials_configs = read_config(file_path)
            # check if aws access key id is found under [default] section in current file and return 'default' if so
            try:
                access_key = aws_credentials_configs.get("default", "aws_access_key_id")
                if access_key is not None:
                    return "default"
            except (NoSectionError, NoOptionError):
                continue

    return awsprofile
