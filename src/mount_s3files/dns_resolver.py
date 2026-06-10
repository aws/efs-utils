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
from efs_utils_common.constants import CONFIG_SECTION, FS_ID_REGEX_PATTERN
from efs_utils_common.context import MountContext
from efs_utils_common.error_reporting import fatal_error
from efs_utils_common.exceptions import FallbackException
from efs_utils_common.metadata import (
    get_az_id_from_instance_metadata,
    get_dns_name_suffix,
    get_target_region,
)
from efs_utils_common.network_utils import (
    dns_name_can_be_resolved,
    mount_target_ip_address_can_be_resolved,
)
from efs_utils_common.process_utils import add_field_in_options


def get_dns_name_and_mount_target_ip_address(config, fs_id, options):
    def _validate_replacement_field_count(format_str, expected_ct):
        if format_str.count("{") != expected_ct or format_str.count("}") != expected_ct:
            raise ValueError(
                "DNS name format has an incorrect number of replacement fields"
            )

    dns_name_format = config.get(CONFIG_SECTION, "dns_name_format")

    if "{fs_id}" not in dns_name_format:
        raise ValueError("DNS name format must include {fs_id}")

    format_args = {"fs_id": fs_id}

    expected_replacement_field_ct = 1

    if "{az_id}" in dns_name_format:
        try:
            az_id = get_az_id_from_instance_metadata(config, options)
            expected_replacement_field_ct += 1
            format_args["az_id"] = az_id
        except RuntimeError:
            err_msg = (
                "Cannot retrieve AZ-ID from instance metadata service (IMDS). "
                "Ensure IMDS is reachable and that the instance has the correct IAM permissions. "
                "This is required for S3Files mounts using {az_id} in dns_name_format. "
                "You can also specify the AZ ID directly using the mount option: -o azid=<az-id>."
            )
            fatal_error(err_msg)
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

    _validate_replacement_field_count(dns_name_format, expected_replacement_field_ct)
    dns_name = dns_name_format.format(**format_args)

    if "mounttargetip" in options:
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
            throw_ip_address_connect_failure(
                ip_address=ip_address, fallback_message=fallback_message
            )

    if dns_name_can_be_resolved(dns_name):
        return dns_name, None

    logging.info(
        "Failed to resolve %s",
        dns_name,
    )
    throw_dns_resolve_failure(dns_name)


def throw_dns_resolve_failure(dns_name):
    message = (
        'Failed to resolve "%s" - check that your file system ID is correct, and ensure that the VPC has an S3Files mount '
        "target for this file system ID.\nSee %s for more detail."
    ) % (
        dns_name,
        "https://docs.aws.amazon.com/console/efs/mount-dns-name",
    )
    fatal_error(message)


def throw_ip_address_connect_failure(
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
    """Return the S3Files id, the remote path, and the az to mount"""

    try:
        remote, path = device.split(":", 1)
    except ValueError:
        remote = device
        path = "/"

    if FS_ID_REGEX_PATTERN.match(remote):
        return remote, path, None

    try:
        primary, secondaries, _ = socket.gethostbyname_ex(remote)
        hostnames = list(filter(lambda e: e is not None, [primary] + secondaries))
    except socket.gaierror:
        create_default_cloudwatchlog_agent_if_not_exist(config, options)
        fatal_error(
            'Failed to resolve "%s" - check that the specified DNS name is a CNAME record resolving to a valid S3Files DNS '
            "name" % remote,
            'Failed to resolve "%s"' % remote,
        )

    if not hostnames:
        create_default_cloudwatchlog_agent_if_not_exist(config, options)
        fatal_error(
            'The specified domain name "%s" did not resolve to an S3Files mount target'
            % remote
        )

    for hostname in hostnames:
        fqdn_match = context.fqdn_regex_pattern.match(hostname)

        if fqdn_match:
            az_id = fqdn_match.group("az_id")
            fs_id = fqdn_match.group("fs_id")

            if az_id and "azid" in options and az_id != options["azid"]:
                fatal_error(
                    'The hostname "%s" resolved by the specified domain name "%s" does not match the azid provided in the '
                    "mount options, expected = %s, given = %s"
                    % (hostname, remote, options["azid"], az_id)
                )

            expected_dns_name, _ = get_dns_name_and_mount_target_ip_address(
                config, fs_id, add_field_in_options(options, "azid", az_id)
            )

            # check that the DNS name of the mount target matches exactly the DNS name the CNAME resolves to
            if hostname == expected_dns_name:
                return fs_id, path, az_id
    else:
        create_default_cloudwatchlog_agent_if_not_exist(config, options)
        fatal_error(
            'The specified CNAME "%s" did not resolve to a valid DNS name for an S3Files mount target. '
            "Please refer to the documentation for mounting with DNS names for examples: %s"
            % (
                remote,
                "https://docs.aws.amazon.com/efs/latest/ug/mounting-fs-mount-cmd-dns-name.html",
            )
        )
