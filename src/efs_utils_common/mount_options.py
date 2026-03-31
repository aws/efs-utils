#!/usr/bin/env python3
#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.


from efs_utils_common.constants import (
    AP_REGEX_PATTERN,
    MOUNT_TYPE_S3FILES,
    NON_NFS_OPTIONS,
    UNSUPPORTED_OPTIONS,
)
from efs_utils_common.context import MountContext
from efs_utils_common.error_reporting import fatal_error
from efs_utils_common.metadata import (
    legacy_stunnel_mode_enabled,
    mount_type_requires_iam,
)
from efs_utils_common.platform_utils import check_if_platform_is_mac


def parse_options(options):
    """
    Parses a comma delineated string of key=value options (e.g. 'opt1,opt2=val').
    Returns a dictionary of key,value pairs, where value = None if
    it was not provided.
    """
    opts = {}
    for o in options.split(","):
        if "=" in o:
            k, v = o.split("=")
            opts[k] = v
        else:
            opts[o] = None
    return opts


def check_if_nfsvers_is_compatible_with_macos(options):
    # MacOS does not support NFSv4.1
    if (
        ("nfsvers" in options and options["nfsvers"] == "4.1")
        or ("vers" in options and options["vers"] == "4.1")
        or ("minorversion" in options and options["minorversion"] == 1)
    ):
        fatal_error("NFSv4.1 is not supported on MacOS, please switch to NFSv4.0")


def check_if_nfsvers_is_compatible_with_s3files(options):
    nfsvers = options.get("nfsvers") or options.get("vers")
    if nfsvers and str(nfsvers) == "4.0":
        fatal_error("NFSv4.0 is not supported for S3 Files mounts")


def get_nfs_mount_options(options, config):
    # If you change these options, update the man page as well at man/mount.efs.8
    context = MountContext()
    if "nfsvers" not in options and "vers" not in options:
        if context.mount_type == MOUNT_TYPE_S3FILES:
            if check_if_platform_is_mac():
                fatal_error(
                    "S3 Files is not supported on MacOS. MacOS only supports NFSv4.0, "
                    "which is not compatible with S3 Files."
                )
            options["nfsvers"] = "4.2"
        else:
            options["nfsvers"] = "4.1" if not check_if_platform_is_mac() else "4.0"

    if context.mount_type == MOUNT_TYPE_S3FILES:
        check_if_nfsvers_is_compatible_with_s3files(options)

    if check_if_platform_is_mac():
        check_if_nfsvers_is_compatible_with_macos(options)

    if "rsize" not in options:
        options["rsize"] = "1048576"
    if "wsize" not in options:
        options["wsize"] = "1048576"
    if "soft" not in options and "hard" not in options:
        options["hard"] = None
    if "timeo" not in options:
        options["timeo"] = "600"
    if "retrans" not in options:
        options["retrans"] = "2"
    if "noresvport" not in options:
        options["noresvport"] = None

    # Set mountport to 2049 for MacOS
    if check_if_platform_is_mac():
        options["mountport"] = "2049"

    if legacy_stunnel_mode_enabled(options, config):
        # Non-tls mounts in stunnel mode should not re-map the port
        if "tls" in options:
            options["port"] = options["tlsport"]
    else:
        options["port"] = options["tlsport"]

    def to_nfs_option(k, v):
        if v is None:
            return k
        return "%s=%s" % (str(k), str(v))

    nfs_options = [
        to_nfs_option(k, v) for k, v in options.items() if k not in NON_NFS_OPTIONS
    ]

    return ",".join(nfs_options)


def check_unsupported_options(options):
    all_unsupported_options = UNSUPPORTED_OPTIONS[:]
    context = MountContext()
    if len(context.unsupported_options) > 0:
        all_unsupported_options.extend(context.unsupported_options)

    unsupported_options = []
    for unsupported_option in all_unsupported_options:
        if unsupported_option in options:
            unsupported_options.append(unsupported_option)

    if unsupported_options:
        fatal_error(
            "Unsupported mount options detected: %s"
            % ", ".join('"%s"' % opt for opt in unsupported_options)
        )


def check_options_validity(options):
    context = MountContext()

    if context.mount_type == MOUNT_TYPE_S3FILES:
        check_if_nfsvers_is_compatible_with_s3files(options)

    if "tls" in options:
        if "port" in options:
            fatal_error('The "port" and "tls" options are mutually exclusive')

        if "tlsport" in options:
            try:
                int(options["tlsport"])
            except ValueError:
                fatal_error(
                    "tlsport option [%s] is not an integer" % options["tlsport"]
                )

        if "ocsp" in options and "noocsp" in options:
            fatal_error('The "ocsp" and "noocsp" options are mutually exclusive')

        if "notls" in options:
            fatal_error('The "tls" and "notls" options are mutually exclusive')

    if "accesspoint" in options:
        if "tls" not in options and context.mount_type != MOUNT_TYPE_S3FILES:
            fatal_error('The "tls" option is required when mounting via "accesspoint"')
        if not AP_REGEX_PATTERN.match(options["accesspoint"]):
            fatal_error("Access Point ID %s is malformed" % options["accesspoint"])

    # S3Files requires IAM authentication (and therefore TLS)
    if mount_type_requires_iam():
        if "iam" not in options:
            options["iam"] = None
        if "tls" not in options:
            options["tls"] = None

    if "iam" in options and "tls" not in options:
        fatal_error('The "tls" option is required when mounting via "iam"')

    if "awsprofile" in options and "iam" not in options:
        fatal_error(
            'The "iam" option is required when mounting with named profile option, "awsprofile"'
        )

    if "awscredsuri" in options:
        if "iam" not in options:
            fatal_error('The "iam" option is required when mounting with "awscredsuri"')
        if "awsprofile" in options:
            fatal_error(
                'The "awscredsuri" and "awsprofile" options are mutually exclusive'
            )
        # The URI must start with slash symbol as it will be appended to the ECS task metadata endpoint
        if not options["awscredsuri"].startswith("/"):
            fatal_error("awscredsuri %s is malformed" % options["awscredsuri"])
