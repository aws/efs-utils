#!/usr/bin/env python3
#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.

import logging
import socket

from efs_utils_common.cloudwatch import create_default_cloudwatchlog_agent_if_not_exist
from efs_utils_common.config_utils import get_boolean_config_item_value
from efs_utils_common.constants import (
    CONFIG_FILE,
    CONFIG_SECTION,
    DEFAULT_FALLBACK_ENABLED,
    FALLBACK_TO_MOUNT_TARGET_IP_ADDRESS_ITEM,
    FS_ID_REGEX_PATTERN,
)
from efs_utils_common.context import MountContext
from efs_utils_common.error_reporting import fatal_error
from efs_utils_common.exceptions import FallbackException
from efs_utils_common.metadata import (
    get_az_from_instance_metadata,
    get_az_id_from_instance_metadata,
    get_botocore_client,
    get_dns_name_suffix,
    get_mount_target_in_az,
    get_target_region,
)
from efs_utils_common.network_utils import (
    dns_name_can_be_resolved,
    mount_target_ip_address_can_be_resolved,
)
from efs_utils_common.process_utils import add_field_in_options


def get_target_az(config, options):
    if "az" in options:
        return options.get("az")

    try:
        return get_az_from_instance_metadata(config)
    except Exception as e:
        logging.warning("Get AZ via metadata service call failed, %s", e)

    return None


def get_dns_name_and_fallback_mount_target_ip_address(config, fs_id, options):
    def _validate_replacement_field_count(format_str, expected_ct):
        if format_str.count("{") != expected_ct or format_str.count("}") != expected_ct:
            raise ValueError(
                "DNS name format has an incorrect number of replacement fields"
            )

    # mounts using crossaccount have a predetermined dns name format
    if options and "crossaccount" in options:
        try:
            az_id = get_az_id_from_instance_metadata(config, options)
            region = get_target_region(config, options)
            dns_name_suffix = get_dns_name_suffix(config, region)
            dns_name = "%s.%s.efs.%s.%s" % (az_id, fs_id, region, dns_name_suffix)
        except RuntimeError:
            err_msg = "Cannot retrieve AZ-ID from metadata service. This is required for the crossaccount mount option."
            fatal_error(err_msg)
    else:
        dns_name_format = config.get(CONFIG_SECTION, "dns_name_format")

        if "{fs_id}" not in dns_name_format:
            raise ValueError("DNS name format must include {fs_id}")

        format_args = {"fs_id": fs_id}

        expected_replacement_field_ct = 1

        if "{az}" in dns_name_format:
            az = options.get("az")
            if az:
                expected_replacement_field_ct += 1
                format_args["az"] = az
            else:
                dns_name_format = dns_name_format.replace("{az}.", "")

        region = None
        if "{region}" in dns_name_format:
            region = get_target_region(config, options)
            expected_replacement_field_ct += 1
            format_args["region"] = region

        if "{dns_name_suffix}" in dns_name_format:
            expected_replacement_field_ct += 1
            region = region or get_target_region(config, options)
            dns_name_suffix = get_dns_name_suffix(config, region)
            format_args["dns_name_suffix"] = dns_name_suffix
            logging.debug("Using dns_name_suffix %s", dns_name_suffix)

        _validate_replacement_field_count(
            dns_name_format, expected_replacement_field_ct
        )
        dns_name = dns_name_format.format(**format_args)

    if "mounttargetip" in options:
        if "crossaccount" in options:
            fatal_error(
                "mounttargetip option is incompatible with crossaccount option."
            )
        ip_address = options.get("mounttargetip")
        logging.info(
            "Use the mount target ip address %s provided in the mount options to mount."
            % ip_address
        )
        try:
            mount_target_ip_address_can_be_resolved(
                ip_address,
                passed_via_options=True,
                network_namespace=options.get("netns") if "netns" in options else None,
            )
            return dns_name, options.get("mounttargetip")
        except FallbackException as e:
            fallback_message = e.message
            throw_ip_address_connect_failure_with_fallback_message(
                ip_address=ip_address, fallback_message=fallback_message
            )

    if dns_name_can_be_resolved(dns_name):
        return dns_name, None

    logging.info(
        "Failed to resolve %s, attempting to lookup mount target ip address using botocore.",
        dns_name,
    )

    try:
        fallback_mount_target_ip_address = get_fallback_mount_target_ip_address(
            config, options, fs_id, dns_name
        )
        logging.info(
            "Found fall back mount target ip address %s for file system %s",
            fallback_mount_target_ip_address,
            fs_id,
        )
        return dns_name, fallback_mount_target_ip_address
    except FallbackException as e:
        fallback_message = e.message

    throw_dns_resolve_failure_with_fallback_message(dns_name, fallback_message)


def get_fallback_mount_target_ip_address(config, options, fs_id, dns_name):
    if options and "crossaccount" in options:
        fallback_message = "Fallback to mount target ip address feature is not available when the crossaccount option is used."
        raise FallbackException(fallback_message)

    fall_back_to_ip_address_enabled = (
        check_if_fall_back_to_mount_target_ip_address_is_enabled(config)
    )

    if not fall_back_to_ip_address_enabled:
        fallback_message = (
            "Fallback to mount target ip address feature is not enabled in config file %s."
            % CONFIG_FILE
        )
        raise FallbackException(fallback_message)

    mount_target_ip_address = get_fallback_mount_target_ip_address_helper(
        config, options, fs_id
    )
    try:
        mount_target_ip_address_can_be_resolved(
            mount_target_ip_address,
            network_namespace=options.get("netns") if "netns" in options else None,
        )
        return mount_target_ip_address
    except FallbackException as e:
        throw_ip_address_connect_failure_with_fallback_message(
            dns_name, mount_target_ip_address, e.message
        )


def check_if_fall_back_to_mount_target_ip_address_is_enabled(config):
    return get_boolean_config_item_value(
        config,
        CONFIG_SECTION,
        FALLBACK_TO_MOUNT_TARGET_IP_ADDRESS_ITEM,
        default_value=DEFAULT_FALLBACK_ENABLED,
    )


def get_fallback_mount_target_ip_address_helper(config, options, fs_id):
    az_name = get_target_az(config, options)

    ec2_client = get_botocore_client(config, "ec2", options)
    efs_client = get_botocore_client(config, "efs", options)

    if ec2_client is None or efs_client is None:
        raise FallbackException(
            "Failed to import necessary dependency botocore, please install botocore first."
        )

    mount_target = get_mount_target_in_az(efs_client, ec2_client, fs_id, az_name)

    if "IpAddress" in mount_target:
        return mount_target.get("IpAddress")
    elif "Ipv6Address" in mount_target:
        return mount_target.get("Ipv6Address")


def throw_dns_resolve_failure_with_fallback_message(dns_name, fallback_message=None):
    fallback_message = (
        "\nAttempting to lookup mount target ip address using botocore. %s"
        % fallback_message
        if fallback_message
        else ""
    )
    message = (
        'Failed to resolve "%s" - check that your file system ID is correct, and ensure that the VPC has an EFS mount '
        "target for this file system ID.\nSee %s for more detail.%s"
    ) % (
        dns_name,
        "https://docs.aws.amazon.com/console/efs/mount-dns-name",
        fallback_message,
    )
    fatal_error(message)


def throw_ip_address_connect_failure_with_fallback_message(
    dns_name=None, ip_address=None, fallback_message=None
):
    dns_message = 'Failed to resolve "%s". ' % dns_name if dns_name else ""
    if not ip_address:
        ip_address_message = (
            "The file system mount target ip address cannot be found, please pass mount target ip "
            "address via mount options. "
        )
    else:
        ip_address_message = (
            "Cannot connect to file system mount target ip address %s. " % ip_address
        )
    fallback_message = "\n%s" % fallback_message if fallback_message else ""
    fatal_error("%s%s%s" % (dns_message, ip_address_message, fallback_message))


def match_device(config, device, options):
    context = MountContext()
    """Return the EFS id, the remote path, and the az to mount"""

    try:
        remote, path = device.split(":", 1)
    except ValueError:
        remote = device
        path = "/"

    if FS_ID_REGEX_PATTERN.match(remote):
        return remote, path, None

    try:
        addrinfo = socket.getaddrinfo(
            remote, None, socket.AF_UNSPEC, socket.SOCK_STREAM, 0, socket.AI_CANONNAME
        )
        hostnames = list(
            set(
                filter(
                    lambda e: e is not None and e != "", [info[3] for info in addrinfo]
                )
            )
        )
        if not hostnames:
            hostnames = [remote]
    except socket.gaierror:
        create_default_cloudwatchlog_agent_if_not_exist(config, options)
        fatal_error(
            'Failed to resolve "%s" - check that the specified DNS name is a CNAME record resolving to a valid EFS DNS '
            "name" % remote,
            'Failed to resolve "%s"' % remote,
        )

    if not hostnames:
        create_default_cloudwatchlog_agent_if_not_exist(config, options)
        fatal_error(
            'The specified domain name "%s" did not resolve to an EFS mount target'
            % remote
        )

    for hostname in hostnames:
        efs_fqdn_match = context.fqdn_regex_pattern.match(hostname)

        if efs_fqdn_match:
            az = efs_fqdn_match.group("az")
            fs_id = efs_fqdn_match.group("fs_id")

            if az and "az" in options and az != options["az"]:
                fatal_error(
                    'The hostname "%s" resolved by the specified domain name "%s" does not match the az provided in the '
                    "mount options, expected = %s, given = %s"
                    % (hostname, remote, options["az"], az)
                )

            expected_dns_name, _ = get_dns_name_and_fallback_mount_target_ip_address(
                config, fs_id, add_field_in_options(options, "az", az)
            )

            # check that the DNS name of the mount target matches exactly the DNS name the CNAME resolves to
            if hostname == expected_dns_name:
                return fs_id, path, az
    else:
        create_default_cloudwatchlog_agent_if_not_exist(config, options)
        fatal_error(
            'The specified CNAME "%s" did not resolve to a valid DNS name for an EFS mount target. '
            "Please refer to the EFS documentation for mounting with DNS names for examples: %s"
            % (
                remote,
                "https://docs.aws.amazon.com/efs/latest/ug/mounting-fs-mount-cmd-dns-name.html",
            )
        )
