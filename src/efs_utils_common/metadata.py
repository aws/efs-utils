#!/usr/bin/env python3
#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.


import json
import logging
import os
import random
import socket
import sys
import time

from efs_utils_common.context import MountContext

try:
    from configparser import NoOptionError
except ImportError:
    from ConfigParser import NoOptionError

try:
    from urllib.error import HTTPError, URLError
    from urllib.request import Request, urlopen
except ImportError:
    pass
    from urllib2 import HTTPError, HTTPHandler, Request, URLError, build_opener, urlopen

try:
    import botocore.config
    import botocore.session
    from botocore.exceptions import (
        ClientError,
        EndpointConnectionError,
        NoCredentialsError,
        ProfileNotFound,
    )

    BOTOCORE_PRESENT = True
except ImportError:
    BOTOCORE_PRESENT = False

from efs_utils_common.config_utils import (
    get_boolean_config_item_value,
    get_config_file_path,
)
from efs_utils_common.constants import (
    AWS_FIPS_ENDPOINT_CONFIG_ENV,
    CONFIG_FILE_SETTINGS_HELP_URL,
    CONFIG_SECTION,
    DEFAULT_GET_AWS_EC2_METADATA_TOKEN_RETRY_COUNT,
    DISABLE_FETCH_EC2_METADATA_TOKEN_ITEM,
    ECS_FARGATE_CLIENT_IDENTIFIER,
    ECS_FARGATE_TASK_METADATA_ENDPOINT_ENV,
    ECS_FARGATE_TASK_METADATA_ENDPOINT_URL_EXTENSION,
    INSTANCE_METADATA_SERVICE_AZ_ID_URL,
    INSTANCE_METADATA_SERVICE_URL,
    INSTANCE_METADATA_TOKEN_URL,
    MOUNT_TYPE_S3FILES,
    NAMED_PROFILE_HELP_URL,
)
from efs_utils_common.error_reporting import fatal_error
from efs_utils_common.exceptions import FallbackException
from efs_utils_common.platform_utils import get_client_info

CA_CONFIG_BODY = """dir = %s
RANDFILE = $dir/database/.rand

[ ca ]
default_ca = local_ca

[ local_ca ]
database = $dir/database/index.txt
serial = $dir/database/serial
private_key = %s
cert = $dir/certificate.pem
new_certs_dir = $dir/certs
default_md = sha256
preserve = no
policy = efsPolicy
x509_extensions = v3_ca

[ efsPolicy ]
CN = supplied

[ req ]
prompt = no
distinguished_name = req_distinguished_name

[ req_distinguished_name ]
CN = %s

%s

%s

%s
"""

# SigV4 Auth
STUNNEL_GLOBAL_CONFIG = {
    "fips": "no",
    "foreground": "yes",
    "socket": [
        "l:SO_REUSEADDR=yes",
        "a:SO_BINDTODEVICE=lo",
    ],
}

STUNNEL_EFS_CONFIG = {
    "client": "yes",
    "accept": "127.0.0.1:%s",
    "connect": "%s:2049",
    "sslVersion": "TLSv1.2",
    "renegotiation": "no",
    "TIMEOUTbusy": "20",
    "TIMEOUTclose": "0",
    "TIMEOUTidle": "70",
    "delay": "yes",
}


def get_target_region(config, options):
    def _fatal_error(message):
        fatal_error(
            'Error retrieving region. Please set the "region" parameter '
            "in the efs-utils configuration file or specify it as a "
            "mount option.",
            message,
        )

    if "region" in options:
        return options.get("region")

    # Check environment variable
    env_region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
    if env_region:
        return env_region

    try:
        return config.get(CONFIG_SECTION, "region")
    except NoOptionError:
        pass

    try:
        return get_region_from_instance_metadata(config)
    except Exception as e:
        metadata_exception = e
        logging.warning(
            "Region not found in config file and metadata service call failed, falling back "
            'to legacy "dns_name_format" check'
        )

    try:
        region = get_region_from_legacy_dns_format(config)
        sys.stdout.write(
            'Warning: region obtained from "dns_name_format" field. Please set the "region" '
            "parameter in the efs-utils configuration file."
        )
        return region
    except Exception:
        logging.warning('Legacy check for region in "dns_name_format" failed')

    _fatal_error(metadata_exception)


def get_region_from_instance_metadata(config):
    instance_identity = get_instance_identity_info_from_instance_metadata(
        config, "region"
    )

    if not instance_identity:
        raise Exception(
            "Cannot retrieve region from instance_metadata. "
            "Please set the 'region' parameter in the efs-utils configuration file."
        )

    return instance_identity


def get_az_from_instance_metadata(config):
    instance_identity = get_instance_identity_info_from_instance_metadata(
        config, "availabilityZone"
    )

    if not instance_identity:
        raise Exception("Cannot retrieve az from instance_metadata")

    return instance_identity


def get_az_id_from_instance_metadata(config, options):
    # Check if azid is provided in mount options first
    if "azid" in options:
        return options["azid"]

    az_id = get_az_id_info_from_instance_metadata(config, options)

    if not az_id:
        raise RuntimeError("Cannot retrieve az-id from instance_metadata")

    return az_id


def get_az_id_info_from_instance_metadata(config, options):
    logging.debug("Retrieve availability-zone-id from instance metadata")

    # For ECS Fargate clients, check if az_id is configured directly
    if is_ecs_fargate_client(config):
        try:
            return config.get(CONFIG_SECTION, "az_id")
        except NoOptionError:
            fatal_error(
                "Error retrieving AZ ID. This needs to be set in the config file."
            )

    instance_az_id_url = get_instance_az_id_metadata_url(config)
    metadata_unsuccessful_resp = (
        "Unsuccessful retrieval of metadata at %s." % instance_az_id_url
    )
    metadata_url_error_msg = (
        "Unable to reach %s to retrieve instance metadata." % instance_az_id_url
    )

    context = MountContext()
    if context.instance_az_id_metadata:
        logging.debug(
            "Instance az_id already retrieved in previous call, use the cached values."
        )
        az_id_metadata = context.instance_az_id_metadata
    else:
        az_id_metadata = url_request_helper(
            config,
            instance_az_id_url,
            metadata_unsuccessful_resp,
            metadata_url_error_msg,
        )
    context.instance_az_id_metadata = az_id_metadata

    if az_id_metadata:
        return az_id_metadata

    return None


def get_instance_az_id_metadata_url(config):
    instance_az_id_url = INSTANCE_METADATA_SERVICE_AZ_ID_URL
    if is_ecs_fargate_client(config):
        # ECS-Fargate Metadata Endpoint must be used for ECS-Fargate clients.
        logging.debug("ECS-Fargate client detected, use ECS-Fargate Metadata Endpoint")
        try:
            instance_az_id_url = (
                os.getenv(ECS_FARGATE_TASK_METADATA_ENDPOINT_ENV)
                + ECS_FARGATE_TASK_METADATA_ENDPOINT_URL_EXTENSION
            )
        except Exception as e:
            logging.warning("Unable to parse ECS-Fargate Metadata Endpoint: %s", e)
            instance_az_id_url = None
    return instance_az_id_url


def is_ecs_fargate_client(config):
    client_info = get_client_info(config)
    if client_info and client_info.get("source") == ECS_FARGATE_CLIENT_IDENTIFIER:
        return True
    return False


def get_instance_identity_info_from_instance_metadata(config, property):
    logging.debug("Retrieve property %s from instance metadata", property)
    ec2_metadata_unsuccessful_resp = (
        "Unsuccessful retrieval of EC2 metadata at %s." % INSTANCE_METADATA_SERVICE_URL
    )
    ec2_metadata_url_error_msg = (
        "Unable to reach %s to retrieve EC2 instance metadata."
        % INSTANCE_METADATA_SERVICE_URL
    )

    context = MountContext()
    if context.instance_identity:
        logging.debug(
            "Instance metadata already retrieved in previous call, use the cached values."
        )
        instance_identity = context.instance_identity
    else:
        instance_identity = url_request_helper(
            config,
            INSTANCE_METADATA_SERVICE_URL,
            ec2_metadata_unsuccessful_resp,
            ec2_metadata_url_error_msg,
        )
    context.instance_identity = instance_identity

    if instance_identity:
        try:
            return instance_identity[property]
        except KeyError as e:
            logging.warning(
                "%s not present in %s: %s" % (property, instance_identity, e)
            )
        except TypeError as e:
            logging.warning(
                "response %s is not a json object: %s" % (instance_identity, e)
            )

    return None


def get_region_from_legacy_dns_format(config):
    """
    For backwards compatibility check dns_name_format to obtain the target region. This functionality
    should only be used if region is not present in the config file and metadata calls fail.
    """
    dns_name_format = config.get(CONFIG_SECTION, "dns_name_format")
    if "{region}" not in dns_name_format:
        split_dns_name_format = dns_name_format.split(".")
        if "{dns_name_suffix}" in dns_name_format:
            return split_dns_name_format[-2]
        elif "amazonaws.com" in dns_name_format:
            return split_dns_name_format[-3]
    raise Exception("Region not found in dns_name_format")


def fetch_ec2_metadata_token_disabled(config):
    return get_boolean_config_item_value(
        config,
        CONFIG_SECTION,
        DISABLE_FETCH_EC2_METADATA_TOKEN_ITEM,
        default_value=False,
    )


def get_aws_ec2_metadata_token(
    request_timeout=0.5,
    max_retries=DEFAULT_GET_AWS_EC2_METADATA_TOKEN_RETRY_COUNT,
    retry_delay=0.5,
):
    """
    Retrieves the AWS EC2 metadata token. Typically, the token is fetched
    within 10ms. We set a default timeout of 0.5 seconds to prevent mount
    failures caused by slow requests.

    Args:
        max_retries (int): The maximum number of retries.
        retry_delay (int): The delay in seconds between retries.

    Returns:
        The AWS EC2 metadata token str or None if it cannot be retrieved.
    """

    def get_token(timeout):
        try:
            opener = build_opener(HTTPHandler)
            request = Request(INSTANCE_METADATA_TOKEN_URL)
            request.add_header("X-aws-ec2-metadata-token-ttl-seconds", "21600")
            request.get_method = lambda: "PUT"
            try:
                response = opener.open(request, timeout=timeout)
                return response.read()
            finally:
                opener.close()

        except NameError:
            headers = {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}
            request = Request(
                INSTANCE_METADATA_TOKEN_URL, headers=headers, method="PUT"
            )
            response = urlopen(request, timeout=timeout)
            return response.read()

    retries = 0
    while retries < max_retries:
        try:
            return get_token(timeout=request_timeout)
        except socket.timeout:
            logging.debug(
                "Timeout when getting the aws ec2 metadata token. Attempt: %s/%s"
                % (retries + 1, max_retries)
            )
        except HTTPError as e:
            logging.debug(
                "Failed to fetch token due to %s. Attempt: %s/%s"
                % (e, retries + 1, max_retries)
            )
        except Exception as e:
            logging.debug(
                "Unknown error when fetching aws ec2 metadata token, %s. Attempt: %s/%s"
                % (e, retries + 1, max_retries)
            )

        retries += 1
        if retries < max_retries:
            logging.debug("Retrying in %s seconds", retry_delay)
            time.sleep(retry_delay)
        else:
            logging.debug(
                "Unable to retrieve AWS EC2 metadata token. Maximum number of retries reached."
            )
            return None


def get_dns_name_suffix(config, region):
    return get_mount_config(config, region, "dns_name_suffix")


def get_mount_config(config, region, config_name):
    try:
        config_section = get_config_section(config, region)
        return config.get(config_section, config_name)
    except NoOptionError:
        pass

    try:
        return config.get(CONFIG_SECTION, config_name)
    except NoOptionError:
        fatal_error(
            f"Error retrieving config. Please set the {config_name} configuration "
            "in efs-utils.conf"
        )


def is_instance_metadata_url(url):
    return url.startswith("http://169.254.169.254")


def url_request_helper(config, url, unsuccessful_resp, url_error_msg, headers={}):
    try:
        req = Request(url)
        for k, v in headers.items():
            req.add_header(k, v)

        if not fetch_ec2_metadata_token_disabled(config) and is_instance_metadata_url(
            url
        ):
            # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
            # IMDSv1 is a request/response method to access instance metadata
            # IMDSv2 is a session-oriented method to access instance metadata
            # We expect the token retrieve will fail in bridge networking environment (e.g. container) since the default hop
            # limit for getting the token is 1. If the token retrieve does timeout, we fallback to use IMDSv1 instead
            token = get_aws_ec2_metadata_token()
            if token:
                req.add_header("X-aws-ec2-metadata-token", token)

        request_resp = urlopen(req, timeout=1)

        return get_resp_obj(request_resp, url, unsuccessful_resp)
    except socket.timeout:
        err_msg = "Request timeout"
    except HTTPError as e:
        # For instance enable with IMDSv2 and fetch token disabled, Unauthorized 401 error will be thrown
        if (
            e.code == 401
            and fetch_ec2_metadata_token_disabled(config)
            and is_instance_metadata_url(url)
        ):
            logging.warning(
                "Unauthorized request to instance metadata url %s, IMDSv2 is enabled on the instance, while fetching "
                "ec2 metadata token is disabled. Please set the value of config item "
                '"%s" to "false" in config file %s.'
                % (url, DISABLE_FETCH_EC2_METADATA_TOKEN_ITEM, get_config_file_path())
            )
        err_msg = "Unable to reach the url at %s: status=%d, reason is %s" % (
            url,
            e.code,
            e.reason,
        )
    except URLError as e:
        err_msg = "Unable to reach the url at %s, reason is %s" % (url, e.reason)

    if err_msg:
        logging.debug("%s %s", url_error_msg, err_msg)
    return None


def get_resp_obj(request_resp, url, unsuccessful_resp):
    """
    Parse the response of an url request

    :return: If the response result can be parsed into json object, return the json object parsed from the response.
             Otherwise return the response body in string format.
    """

    if request_resp.getcode() != 200:
        logging.debug(
            unsuccessful_resp + " %s: ResponseCode=%d", url, request_resp.getcode()
        )
        return None

    resp_body = request_resp.read()
    resp_body_type = type(resp_body)
    try:
        if resp_body_type is str:
            resp_dict = json.loads(resp_body)
        else:
            resp_dict = json.loads(
                resp_body.decode(
                    request_resp.headers.get_content_charset() or "us-ascii"
                )
            )

        return resp_dict
    except ValueError:
        return resp_body if resp_body_type is str else resp_body.decode("utf-8")


def get_config_section(config, region):
    region_specific_config_section = "%s.%s" % (CONFIG_SECTION, region)
    if config.has_section(region_specific_config_section):
        config_section = region_specific_config_section
    else:
        config_section = CONFIG_SECTION
    return config_section


def legacy_stunnel_mode_enabled(options, config):
    context = MountContext()
    if context.proxy_mode == "stunnel":
        return True
    else:
        return False


def get_fips_config(config):
    """
    Check whether FIPS is enabled either by setting the `AWS_USE_FIPS_ENDPOINT`
    environmental variable, or through the efs-utils config file.

    Enabling FIPS means that both the Botocore client and stunnel will be configured
    to use FIPS.
    """

    return os.getenv(
        AWS_FIPS_ENDPOINT_CONFIG_ENV, "False"
    ).lower() == "true" or get_boolean_config_item_value(
        config, CONFIG_SECTION, "fips_mode_enabled", default_value=False
    )


def get_botocore_client(config, service, options):
    if not BOTOCORE_PRESENT:
        logging.error("Failed to import botocore, please install botocore first.")
        return None

    botocore_config = None
    if get_fips_config(config):
        botocore_config = botocore.config.Config(use_fips_endpoint=True)

    session = botocore.session.get_session()
    region = get_target_region(config, options)

    if options and options.get("awsprofile"):
        profile = options.get("awsprofile")
        session.set_config_variable("profile", profile)
        try:
            return session.create_client(
                service, region_name=region, config=botocore_config
            )
        except ProfileNotFound as e:
            fatal_error(
                "%s, please add the [profile %s] section in the aws config file following %s and %s."
                % (e, profile, NAMED_PROFILE_HELP_URL, CONFIG_FILE_SETTINGS_HELP_URL)
            )

    return session.create_client(service, region_name=region, config=botocore_config)


def ec2_describe_availability_zones_helper(ec2_client, kwargs):
    # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_availability_zones
    return ec2_client.describe_availability_zones(**kwargs)


def get_az_id_by_az_name_helper(ec2_client, az_name, dryrun=False):
    operation = "DescribeAvailabilityZones"
    kwargs = {"ZoneNames": [az_name]}
    if dryrun:
        kwargs["DryRun"] = True

    if ec2_client is None:
        raise FallbackException(
            "EC2 client is not available - check AWS credentials and botocore installation"
        )

    try:
        az_info = ec2_describe_availability_zones_helper(ec2_client, kwargs)
        logging.debug("Found the az information for %s: %s", az_name, az_info)
        return az_info
    except ClientError as e:
        exception = e.response["Error"]["Code"]
        exception_message = e.response["Error"]["Message"]

        if exception == "DryRunOperation":
            logging.debug("Describe availability zones dryrun succeed.")
            return
        elif exception == "UnauthorizedOperation":
            fallback_message = "Unauthorized to perform operation %s." % operation
        elif exception == "InvalidParameterValue":
            fallback_message = "Invalid availability zone %s" % az_name
        elif exception == "ServiceUnavailableException":
            fallback_message = (
                "The ec2 service cannot complete the request, %s" % exception_message
            )
        elif exception == "AccessDeniedException":
            fallback_message = exception_message
        else:
            fallback_message = "Unexpected error: %s" % exception_message
    except NoCredentialsError as e:
        fallback_message = (
            "%s when performing operation %s, please confirm your aws credentials are properly configured."
            % (e, operation)
        )
    except EndpointConnectionError as e:
        fallback_message = (
            "Could not connect to the endpoint when performing operation %s, %s"
            % (operation, e)
        )
    except Exception as e:
        fallback_message = "Unknown error when performing operation %s, %s." % (
            operation,
            e,
        )
    raise FallbackException(fallback_message)


def get_az_id_by_az_name(ec2_client, az_name):
    # Perform a dryrun api call first
    get_az_id_by_az_name_helper(ec2_client, az_name, dryrun=True)
    az_info = get_az_id_by_az_name_helper(ec2_client, az_name, dryrun=False)
    if az_info and az_info.get("AvailabilityZones"):
        az_id = az_info["AvailabilityZones"][0]["ZoneId"]
        logging.debug("Found AZ mapping [AZ name: %s, AZ ID: %s]", az_name, az_id)
        return az_id
    return None


def efs_describe_mount_targets_helper(efs_client, kwargs):
    # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/efs.html#EFS.Client.describe_mount_targets
    return efs_client.describe_mount_targets(**kwargs)


def get_mount_targets_info(efs_client, fs_id):
    operation = "DescribeMountTargets"
    kwargs = {"FileSystemId": fs_id}

    try:
        mount_targets_info = efs_describe_mount_targets_helper(efs_client, kwargs)
        logging.debug(
            "Found these mount targets for file system %s: %s",
            fs_id,
            mount_targets_info,
        )
        return mount_targets_info.get("MountTargets")
    except ClientError as e:
        exception = e.response["Error"]["Code"]
        exception_message = e.response["Error"]["Message"]

        if exception == "FileSystemNotFound":
            fallback_message = "The file system %s is not found" % fs_id
        elif exception == "ServiceUnavailableException":
            fallback_message = (
                "The elasticfilesystem service cannot complete the request, %s"
                % exception_message
            )
        elif exception == "AccessDeniedException":
            fallback_message = exception_message
        else:
            fallback_message = "Unexpected error: %s" % exception_message
    except NoCredentialsError as e:
        fallback_message = (
            "%s when performing operation %s, please confirm your aws credentials are properly configured."
            % (e, operation)
        )
    except EndpointConnectionError as e:
        fallback_message = (
            "Could not connect to the endpoint when performing operation %s, %s"
            % (operation, e)
        )
    except Exception as e:
        fallback_message = "Unknown error when performing operation %s, %s." % (
            operation,
            e,
        )

    raise FallbackException(fallback_message)


def mount_type_requires_iam():
    context = MountContext()
    return context.mount_type == MOUNT_TYPE_S3FILES


def get_mount_target_in_az(efs_client, ec2_client, fs_id, az_name=None):
    if not efs_client or not ec2_client:
        raise FallbackException("Boto client cannot be null")

    mount_targets = get_mount_targets_info(efs_client, fs_id)
    if not mount_targets:
        message = (
            "Cannot find mount target for the file system %s, please create a mount target in %s."
            % (fs_id, az_name if az_name else "any availability zone.")
        )
        raise FallbackException(message)

    available_mount_targets = [
        mount_target
        for mount_target in mount_targets
        if mount_target.get("LifeCycleState") == "available"
    ]
    if not available_mount_targets:
        message = (
            "No mount target created for the file system %s is in available state yet, please retry in 5 minutes."
            % fs_id
        )
        raise FallbackException(message)

    if az_name:
        az_id = get_az_id_by_az_name(ec2_client, az_name)
    else:
        # If the az_name is None, which means the IMDS instance identity retrieve failed,
        # in that case randomly pick one available mount target
        logging.info(
            "No az info passed via options, randomly pick one available mount target."
        )
        return random.choice(available_mount_targets)

    az_names_of_available_mount_targets = [
        mount_target.get("AvailabilityZoneName")
        for mount_target in available_mount_targets
    ]
    available_mount_targets_message = (
        "Available mount target(s) are in az %s" % az_names_of_available_mount_targets
    )

    if not az_id:
        message = (
            "No matching az id for the az %s. Please check the az option passed. %s"
            % (az_name, available_mount_targets_message)
        )
        raise FallbackException(message)

    for mount_target in mount_targets:
        if mount_target["AvailabilityZoneId"] == az_id:
            mount_target_state = mount_target.get("LifeCycleState")
            if mount_target_state != "available":
                message = "Unknown mount target state"
                if mount_target_state in ["creating", "updating", "error"]:
                    message = (
                        "Mount target in the az %s is %s, please retry in 5 minutes, or use the "
                        "mount target in the other az by passing the availability zone name option. %s"
                        % (az_name, mount_target_state, available_mount_targets_message)
                    )
                elif mount_target_state in ["deleted", "deleting"]:
                    message = (
                        "Mount target in the availability zone %s is %s, "
                        'please create a new one in %s, or use the " "mount target '
                        "in the other az by passing the availability zone name option. %s"
                    ) % (
                        az_name,
                        mount_target_state,
                        az_name,
                        available_mount_targets_message,
                    )
                raise FallbackException(message)
            return mount_target

    message = (
        "No matching mount target in the az %s. Please create one mount target in %s, or try the mount target in another "
        "AZ by passing the availability zone name option. %s"
        % (az_name, az_name, available_mount_targets_message)
    )
    raise FallbackException(message)
