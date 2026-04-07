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
import subprocess
import sys
import time
from contextlib import contextmanager

try:
    from configparser import NoOptionError
except ImportError:
    from ConfigParser import NoOptionError

from efs_utils_common.aws_credentials import (
    get_aws_profile,
    get_aws_security_credentials,
)
from efs_utils_common.certificate_utils import create_certificate, get_private_key_path
from efs_utils_common.config_utils import (
    get_boolean_config_item_value,
    get_config_file_path,
    get_int_value_from_config_file,
    is_ocsp_enabled,
)
from efs_utils_common.constants import (
    CONFIG_SECTION,
    DEFAULT_NFS_MOUNT_COMMAND_TIMEOUT_SEC,
    DEFAULT_PROXY_LOGGING_FILE_COUNT,
    DEFAULT_PROXY_LOGGING_LEVEL,
    DEFAULT_PROXY_LOGGING_MAX_BYTES,
    DEFAULT_STUNNEL_CAFILE,
    DEFAULT_STUNNEL_VERIFY_LEVEL,
    DEFAULT_UNKNOWN_VALUE,
    EFS_PROXY_NO_READ_BYPASS_OPTION,
    EFS_PROXY_TLS_OPTION,
    LOG_DIR,
    MOUNT_TYPE_S3FILES,
    PROXY_CONFIG_SECTION,
    SKIP_NO_SO_BINDTODEVICE_RELEASES,
    STATE_FILE_DIR,
    WATCHDOG_SERVICE,
    WATCHDOG_SERVICE_PLIST_PATH,
)
from efs_utils_common.context import MountContext
from efs_utils_common.error_reporting import fatal_error
from efs_utils_common.file_utils import create_required_directory
from efs_utils_common.metadata import (
    STUNNEL_EFS_CONFIG,
    STUNNEL_GLOBAL_CONFIG,
    get_config_section,
    get_fips_config,
    get_target_region,
)
from efs_utils_common.network_utils import test_tlsport
from efs_utils_common.platform_utils import (
    check_if_platform_is_mac,
    get_client_info,
    get_system_release_version,
    is_ipv6_address,
)
from efs_utils_common.process_utils import NetNS, _efs_proxy_bin, _stunnel_bin


def get_tls_port_range(config):
    lower_bound = config.getint(CONFIG_SECTION, "port_range_lower_bound")
    upper_bound = config.getint(CONFIG_SECTION, "port_range_upper_bound")

    if lower_bound >= upper_bound:
        fatal_error(
            'Configuration option "port_range_upper_bound" defined as %d '
            'must be strictly greater than "port_range_lower_bound" defined as %d.'
            % (upper_bound, lower_bound)
        )

    return lower_bound, upper_bound


def choose_tls_port_and_get_bind_sock(config, options, state_file_dir):
    if "tlsport" in options:
        ports_to_try = [int(options["tlsport"])]
    else:
        lower_bound, upper_bound = get_tls_port_range(config)

        ports_to_try = list(range(lower_bound, upper_bound))

        # shuffle the ports_to_try to reduce possibility of multiple mounts starting from same port range
        random.shuffle(ports_to_try)

    if "netns" not in options:
        tls_port_sock = find_tls_port_in_range_and_get_bind_sock(
            ports_to_try, state_file_dir
        )
    else:
        with NetNS(nspath=options["netns"]):
            tls_port_sock = find_tls_port_in_range_and_get_bind_sock(
                ports_to_try, state_file_dir
            )

    if tls_port_sock:
        return tls_port_sock

    if "tlsport" in options:
        fatal_error(
            "Specified port [%s] is unavailable. Try selecting a different port."
            % options["tlsport"]
        )
    else:
        fatal_error(
            "Failed to locate an available port in the range [%d, %d], try specifying a different port range in %s"
            % (lower_bound, upper_bound, get_config_file_path())
        )


def find_tls_port_in_range_and_get_bind_sock(ports_to_try, state_file_dir):
    sock = socket.socket()
    for tls_port in ports_to_try:
        mount = find_existing_mount_using_tls_port(state_file_dir, tls_port)
        if mount:
            logging.debug(
                "Skip binding TLS port %s as it is already assigned to %s",
                tls_port,
                mount,
            )
            continue
        try:
            logging.info("binding %s", tls_port)
            sock.bind(("localhost", tls_port))
            return sock
        except socket.error as e:
            logging.warning(e)
            continue
    sock.close()
    return None


def find_existing_mount_using_tls_port(state_file_dir, tls_port):
    if not os.path.exists(state_file_dir):
        logging.debug(
            "State file dir %s does not exist, assuming no existing mount using tls port %s",
            state_file_dir,
            tls_port,
        )
        return None

    for fname in os.listdir(state_file_dir):
        if fname.endswith(".%s" % tls_port):
            return fname

    return None


def get_mount_specific_filename(fs_id, mountpoint, tls_port):
    return "%s.%s.%d" % (
        fs_id,
        os.path.abspath(mountpoint).replace(os.sep, ".").lstrip("."),
        tls_port,
    )


def serialize_stunnel_config(config, header=None):
    lines = []

    if header:
        lines.append("[%s]" % header)

    for k, v in config.items():
        if type(v) is list:
            for item in v:
                lines.append("%s = %s" % (k, item))
        else:
            lines.append("%s = %s" % (k, v))

    return lines


# These options are used by both stunnel and efs-proxy for TLS mounts
def add_tunnel_ca_options(efs_config, config, options, region):
    if "cafile" in options:
        stunnel_cafile = options["cafile"]
    else:
        try:
            config_section = get_config_section(config, region)
            stunnel_cafile = config.get(config_section, "stunnel_cafile")
            logging.debug(
                "Using stunnel_cafile %s in config section [%s]",
                stunnel_cafile,
                config_section,
            )
        except NoOptionError:
            logging.debug(
                "No CA file configured, using default CA file %s",
                DEFAULT_STUNNEL_CAFILE,
            )
            stunnel_cafile = DEFAULT_STUNNEL_CAFILE

    if not os.path.exists(stunnel_cafile):
        fatal_error(
            "Failed to find certificate authority file for verification",
            'Failed to find CAfile "%s"' % stunnel_cafile,
        )

    efs_config["CAfile"] = stunnel_cafile


def is_stunnel_option_supported(
    stunnel_output,
    stunnel_option_name,
    stunnel_option_value=None,
    emit_warning_log=True,
):
    supported = False
    for line in stunnel_output:
        if line.startswith(stunnel_option_name):
            if not stunnel_option_value:
                supported = True
                break
            elif stunnel_option_value and stunnel_option_value in line:
                supported = True
                break

    if not supported and emit_warning_log:
        if not stunnel_option_value:
            logging.warning('stunnel does not support "%s"', stunnel_option_name)
        else:
            logging.warning(
                'stunnel does not support "%s" as value of "%s"',
                stunnel_option_value,
                stunnel_option_name,
            )

    return supported


def get_stunnel_options():
    stunnel_command = [_stunnel_bin(), "-help"]
    proc = subprocess.Popen(
        stunnel_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True
    )
    proc.wait()
    _, err = proc.communicate()

    return err.splitlines()


def write_stunnel_config_file(
    config,
    state_file_dir,
    fs_id,
    mountpoint,
    tls_port,
    dns_name,
    verify_level,
    ocsp_enabled,
    options,
    region,
    log_dir=LOG_DIR,
    cert_details=None,
    fallback_ip_address=None,
    efs_proxy_enabled=True,
):
    """
    Serializes stunnel configuration to a file. Unfortunately this does not conform to Python's config file format, so we have to
    hand-serialize it.
    """

    stunnel_options = [] if efs_proxy_enabled else get_stunnel_options()
    mount_filename = get_mount_specific_filename(fs_id, mountpoint, tls_port)

    system_release_version = get_system_release_version()
    global_config = dict(STUNNEL_GLOBAL_CONFIG)

    if not efs_proxy_enabled and is_stunnel_option_supported(
        stunnel_options, b"foreground", b"quiet", emit_warning_log=False
    ):
        # Do not log to stderr of subprocess in addition to the destinations specified with syslog and output.
        # Only support in stunnel version 5.25+.
        global_config["foreground"] = "quiet"

    if any(
        release in system_release_version
        for release in SKIP_NO_SO_BINDTODEVICE_RELEASES
    ):
        global_config["socket"].remove("a:SO_BINDTODEVICE=lo")

    stunnel_debug_enabled = get_boolean_config_item_value(
        config, CONFIG_SECTION, "stunnel_debug_enabled", default_value=False
    )
    if stunnel_debug_enabled:
        global_config["debug"] = "debug"
        # If the stunnel debug is enabled, we also redirect stunnel log to stderr to capture any error while launching
        # the stunnel.
        global_config["foreground"] = "yes"

    if MountContext().mount_type == MOUNT_TYPE_S3FILES or stunnel_debug_enabled:
        if config.has_option(CONFIG_SECTION, "stunnel_logs_file"):
            global_config["output"] = config.get(
                CONFIG_SECTION, "stunnel_logs_file"
            ).replace("{fs_id}", fs_id)
        else:
            proxy_log_file = (
                "%s.efs-proxy.log" if efs_proxy_enabled else "%s.stunnel.log"
            )
            global_config["output"] = os.path.join(
                log_dir, proxy_log_file % mount_filename
            )

    global_config["pid"] = os.path.join(
        state_file_dir, mount_filename + "+", "stunnel.pid"
    )

    if get_fips_config(config):
        global_config["fips"] = "yes"

    efs_config = dict(STUNNEL_EFS_CONFIG)
    efs_config["accept"] = efs_config["accept"] % tls_port

    if fallback_ip_address:
        efs_config["connect"] = efs_config["connect"] % fallback_ip_address
    else:
        efs_config["connect"] = efs_config["connect"] % dns_name

    # Verify level is only valid for tls mounts
    if (verify_level is not None) and tls_enabled(options):
        efs_config["verify"] = verify_level
        if verify_level > 0:
            add_tunnel_ca_options(efs_config, config, options, region)

    if cert_details:
        efs_config["cert"] = cert_details["certificate"]
        efs_config["key"] = cert_details["privateKey"]

    tls_controls_message = (
        "WARNING: Your client lacks sufficient controls to properly enforce TLS. Please upgrade stunnel, "
        'or disable "%%s" in %s.\nSee %s for more detail.'
        % (
            get_config_file_path(),
            "https://docs.aws.amazon.com/console/efs/troubleshooting-tls",
        )
    )

    if tls_enabled(options):
        # These config options are not applicable to non-tls mounts with efs-proxy
        if get_boolean_config_item_value(
            config, CONFIG_SECTION, "stunnel_check_cert_hostname", default_value=True
        ):
            if (not efs_proxy_enabled) and (
                not is_stunnel_option_supported(stunnel_options, b"checkHost")
            ):
                fatal_error(tls_controls_message % "stunnel_check_cert_hostname")
            else:
                efs_config["checkHost"] = dns_name[dns_name.index(fs_id) :]

        if not efs_proxy_enabled and is_ipv6_address(fallback_ip_address):
            efs_config["sni"] = dns_name[dns_name.index(fs_id) :]

        # Only use the config setting if the override is not set
        if not efs_proxy_enabled and ocsp_enabled:
            if is_stunnel_option_supported(stunnel_options, b"OCSPaia"):
                efs_config["OCSPaia"] = "yes"
            else:
                fatal_error(tls_controls_message % "stunnel_check_cert_validity")

    # If the stunnel libwrap option is supported, we disable the usage of /etc/hosts.allow and /etc/hosts.deny by
    # setting the option to no
    if not efs_proxy_enabled and is_stunnel_option_supported(
        stunnel_options, b"libwrap"
    ):
        efs_config["libwrap"] = "no"

    if efs_proxy_enabled:
        efs_config["retry_nfs_mount_command_timeout_sec"] = (
            get_int_value_from_config_file(
                config,
                "retry_nfs_mount_command_timeout_sec",
                DEFAULT_NFS_MOUNT_COMMAND_TIMEOUT_SEC,
            )
        )
        # Only write proxy logging configs when [proxy] section is present
        if config.has_section(PROXY_CONFIG_SECTION):
            proxy_logging_level = config.get(
                PROXY_CONFIG_SECTION,
                "proxy_logging_level",
                fallback=DEFAULT_PROXY_LOGGING_LEVEL,
            )
            efs_config["proxy_logging_level"] = proxy_logging_level

            proxy_logging_max_bytes = config.getint(
                PROXY_CONFIG_SECTION,
                "proxy_logging_max_bytes",
                fallback=DEFAULT_PROXY_LOGGING_MAX_BYTES,
            )
            efs_config["proxy_logging_max_bytes"] = proxy_logging_max_bytes

            proxy_logging_file_count = config.getint(
                PROXY_CONFIG_SECTION,
                "proxy_logging_file_count",
                fallback=DEFAULT_PROXY_LOGGING_FILE_COUNT,
            )
            efs_config["proxy_logging_file_count"] = proxy_logging_file_count

        if "nodirects3read" not in options:
            set_readbypass_config(efs_config, options, config)
        if "nos3readcache" in options:
            efs_config["readahead_cache_enabled"] = "no"
        set_telemetry_config(efs_config, config)
        efs_config["fs_id"] = fs_id
        efs_config["region"] = region

    stunnel_config = "\n".join(
        serialize_stunnel_config(global_config)
        + serialize_stunnel_config(efs_config, "efs")
    )
    logging.debug("Writing stunnel configuration:\n%s", stunnel_config)

    stunnel_config_file = os.path.join(
        state_file_dir, "stunnel-config.%s" % mount_filename
    )

    with open(stunnel_config_file, "w") as f:
        f.write(stunnel_config)

    return stunnel_config_file


def set_readbypass_config(tunnel_config, options, main_config):
    readbypass_int_configs = [
        "read_bypass_denylist_size",
        "read_bypass_denylist_ttl_seconds",
        "s3_read_chunk_size_bytes",
        "readahead_cache_init_memory_size_mb",
        "readahead_cache_max_memory_size_mb",
        "readahead_init_window_size_bytes",
        "readahead_max_window_size_bytes",
        "readahead_cache_eviction_interval_ms",
        "readahead_cache_target_utilization_percent",
        "read_bypass_max_in_flight_s3_bytes",
    ]
    for config in readbypass_int_configs:
        option_value = main_config.getint(PROXY_CONFIG_SECTION, config, fallback=None)
        if option_value is not None:
            tunnel_config[config] = option_value

    readbypass_bool_configs = [
        "readahead_cache_enabled",
    ]
    for config in readbypass_bool_configs:
        option_value = main_config.getboolean(
            PROXY_CONFIG_SECTION, config, fallback=None
        )
        if option_value is not None:
            tunnel_config[config] = "yes" if option_value else "no"

    if options.get("rolearn"):
        tunnel_config["role_arn"] = options.get("rolearn")
    if options.get("jwtpath"):
        tunnel_config["jwt_path"] = options.get("jwtpath")
    if options.get("awscredsuri"):
        tunnel_config["aws_creds_uri"] = options.get("awscredsuri")
    if "iam" in options:
        profile = get_aws_profile(options, True)
        if profile:
            tunnel_config["profile"] = profile


def set_telemetry_config(efs_config, main_config):
    from efs_utils_common.constants import CLOUDWATCH_LOG_SECTION

    # we're using different names for properties from configuration file and for properties passed to EFS proxy
    # to preserve backward compatibility and at the same time have readable and discoverable property names at the proxy side

    metrics_enabled = main_config.getboolean(
        PROXY_CONFIG_SECTION, "metrics_enabled", fallback=None
    )
    if metrics_enabled is not None:
        efs_config["cloud_watch_metrics"] = metrics_enabled

    logs_enabled = main_config.getboolean(
        CLOUDWATCH_LOG_SECTION, "enabled", fallback=None
    )
    if logs_enabled is not None:
        efs_config["cloud_watch_logs"] = logs_enabled

    if main_config.has_option(CLOUDWATCH_LOG_SECTION, "log_group_name"):
        efs_config["log_group_name"] = main_config.get(
            CLOUDWATCH_LOG_SECTION, "log_group_name"
        )

    retention_days = main_config.getint(
        CLOUDWATCH_LOG_SECTION, "retention_in_days", fallback=None
    )
    if retention_days is not None:
        efs_config["cloud_watch_logs_retention_days"] = retention_days


def write_tunnel_state_file(
    fs_id,
    mountpoint,
    tls_port,
    tunnel_pid,
    command,
    files,
    state_file_dir,
    cert_details=None,
):
    """
    Return the name of the temporary file containing TLS tunnel state, prefixed with a '~'. This file needs to be renamed to a
    non-temporary version following a successful mount.

    The "tunnel" here refers to efs-proxy, or stunnel.
    """
    base_filename = get_mount_specific_filename(fs_id, mountpoint, tls_port)
    context = MountContext()
    state_file = "~" + base_filename

    state = {
        "pid": tunnel_pid,
        "cmd": command,
        "files": files,
        "mount_time": time.time(),
        "mountpoint": mountpoint,
        "service_type": context.service,
    }

    if cert_details:
        state.update(cert_details)

    with open(os.path.join(state_file_dir, state_file), "w") as f:
        json.dump(state, f)

    return state_file


def rewrite_tunnel_state_file(state, state_file_dir, state_file):
    with open(os.path.join(state_file_dir, state_file), "w") as f:
        json.dump(state, f)
    return state_file


def update_tunnel_temp_state_file_with_tunnel_pid(
    temp_tls_state_file, state_file_dir, stunnel_pid
):
    with open(os.path.join(state_file_dir, temp_tls_state_file), "r") as f:
        state = json.load(f)
    state["pid"] = stunnel_pid
    temp_tls_state_file = rewrite_tunnel_state_file(
        state, state_file_dir, temp_tls_state_file
    )
    return temp_tls_state_file


def test_tunnel_process(tunnel_proc, fs_id):
    tunnel_proc.poll()
    if tunnel_proc.returncode is not None:
        _, err = tunnel_proc.communicate()
        fatal_error(
            "Failed to initialize tunnel for %s, please check mount.log for the failure reason."
            % fs_id,
            'Failed to start tunnel (errno=%d), stderr="%s". If the stderr is lacking enough details, please '
            "enable stunnel debug log in efs-utils config file and retry the mount to capture more info."
            % (tunnel_proc.returncode, err.strip()),
        )


def poll_tunnel_process(tunnel_proc, fs_id, mount_completed):
    """
    poll the tunnel process health every .5s during the mount attempt to fail fast if the tunnel dies - since this is not called
    from the main thread, if the tunnel fails, exit uncleanly with os._exit
    """
    while not mount_completed.is_set():
        try:
            test_tunnel_process(tunnel_proc, fs_id)
        except SystemExit as e:
            os._exit(e.code)
        mount_completed.wait(0.5)


def get_init_system(comm_file="/proc/1/comm"):
    init_system = DEFAULT_UNKNOWN_VALUE
    if not check_if_platform_is_mac():
        try:
            with open(comm_file) as f:
                init_system = f.read().strip()
        except IOError:
            logging.warning("Unable to read %s", comm_file)
    else:
        init_system = "launchd"

    logging.debug("Identified init system: %s", init_system)
    return init_system


def start_watchdog(init_system):
    if init_system == "init":
        proc = subprocess.Popen(
            ["/sbin/status", WATCHDOG_SERVICE],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
        )
        status, _ = proc.communicate()
        if "stop" in str(status):
            subprocess.Popen(
                ["/sbin/start", WATCHDOG_SERVICE],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
            )
        elif "start" in str(status):
            logging.debug("%s is already running", WATCHDOG_SERVICE)

    elif init_system == "systemd":
        rc = subprocess.call(
            ["systemctl", "is-active", "--quiet", WATCHDOG_SERVICE], close_fds=True
        )
        if rc != 0:
            subprocess.Popen(
                ["systemctl", "start", WATCHDOG_SERVICE],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
            )
        else:
            logging.debug("%s is already running", WATCHDOG_SERVICE)

    elif init_system == "launchd":
        rc = subprocess.Popen(
            ["sudo", "launchctl", "list", WATCHDOG_SERVICE],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
        )
        if rc != 0:
            if not os.path.exists(WATCHDOG_SERVICE_PLIST_PATH):
                fatal_error(
                    "Watchdog plist file missing. Copy the watchdog plist file in directory /Library/LaunchAgents"
                )
            subprocess.Popen(
                ["sudo", "launchctl", "load", WATCHDOG_SERVICE_PLIST_PATH],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
            )
        else:
            logging.debug("%s is already running", WATCHDOG_SERVICE)

    else:
        error_message = 'Could not start %s, unrecognized init system "%s"' % (
            WATCHDOG_SERVICE,
            init_system,
        )
        sys.stderr.write("%s\n" % error_message)
        logging.warning(error_message)


# Example of a localhost bind sock: sock.bind(('localhost',12345))
# sock.getsockname() -> ('127.0.0.1', 12345)
# This function returns the port of the bind socket, in the example is 12345
def get_tls_port_from_sock(tls_port_sock):
    return tls_port_sock.getsockname()[1]


def tls_enabled(options):
    return "tls" in options


@contextmanager
def bootstrap_proxy(
    config,
    init_system,
    dns_name,
    fs_id,
    mountpoint,
    options,
    state_file_dir=STATE_FILE_DIR,
    fallback_ip_address=None,
    efs_proxy_enabled=True,
):
    """
    Generates a TLS private key and client-side certificate, a stunnel configuration file, and a state file
    that is used to pass information to the Watchdog process.

    This function will spin up a stunnel or efs-proxy process, and pass it the stunnel configuration file.
    The client-side certificate generated by this function contains IAM information that can be used by the EFS backend to enforce
    file system policies.

    The state file passes information about the mount and the associated proxy process (whether that's stunnel or efs-proxy) to
    the Watchdog daemon service. This allows Watchdog to monitor the proxy process's health.

    This function will yield a handle on the proxy process, whether it's efs-proxy or stunnel.
    """

    proxy_listen_sock = choose_tls_port_and_get_bind_sock(
        config, options, state_file_dir
    )
    proxy_listen_port = get_tls_port_from_sock(proxy_listen_sock)

    try:
        # override the tlsport option so that we can later override the port the NFS client uses to connect to stunnel.
        # if the user has specified tlsport=X at the command line this will just re-set tlsport to X.
        options["tlsport"] = proxy_listen_port

        use_iam = "iam" in options
        ap_id = options.get("accesspoint")
        cert_details = None
        security_credentials = None
        client_info = get_client_info(config)
        region = get_target_region(config, options)

        if tls_enabled(options):
            cert_details = {}
            # IAM can only be used for tls mounts
            if use_iam:
                aws_creds_uri = options.get("awscredsuri")
                role_arn = options.get("rolearn")
                jwt_path = options.get("jwtpath")
                if aws_creds_uri:
                    kwargs = {"aws_creds_uri": aws_creds_uri}
                elif role_arn and jwt_path:
                    kwargs = {"role_arn": role_arn, "jwt_path": jwt_path}
                else:
                    kwargs = {"awsprofile": get_aws_profile(options, use_iam)}

                security_credentials, credentials_source = get_aws_security_credentials(
                    config, use_iam, region, **kwargs
                )

                if credentials_source:
                    cert_details["awsCredentialsMethod"] = credentials_source
                    logging.debug(
                        "AWS credentials source used for IAM authentication: %s",
                        credentials_source,
                    )

            # Access points must be mounted over TLS
            if ap_id:
                cert_details["accessPoint"] = ap_id

            # additional symbol appended to avoid naming collisions
            cert_details["mountStateDir"] = (
                get_mount_specific_filename(fs_id, mountpoint, proxy_listen_port) + "+"
            )
            # common name for certificate signing request is max 64 characters
            cert_details["commonName"] = socket.gethostname()[0:64]
            cert_details["region"] = region
            cert_details["certificateCreationTime"] = create_certificate(
                config,
                cert_details["mountStateDir"],
                cert_details["commonName"],
                cert_details["region"],
                fs_id,
                security_credentials,
                ap_id,
                client_info,
                base_path=state_file_dir,
            )
            cert_details["certificate"] = os.path.join(
                state_file_dir, cert_details["mountStateDir"], "certificate.pem"
            )
            cert_details["privateKey"] = get_private_key_path()
            cert_details["fsId"] = fs_id

        if not os.path.exists(state_file_dir):
            create_required_directory(config, state_file_dir)

        start_watchdog(init_system)

        verify_level = (
            int(options.get("verify", DEFAULT_STUNNEL_VERIFY_LEVEL))
            if tls_enabled(options)
            else None
        )

        ocsp_enabled = is_ocsp_enabled(config, options)
        if ocsp_enabled:
            assert (
                not efs_proxy_enabled
            ), "OCSP is not supported by efs-proxy, and efs-utils failed to revert to stunnel-mode."

        stunnel_config_file = write_stunnel_config_file(
            config,
            state_file_dir,
            fs_id,
            mountpoint,
            proxy_listen_port,
            dns_name,
            verify_level,
            ocsp_enabled,
            options,
            region,
            cert_details=cert_details,
            fallback_ip_address=fallback_ip_address,
            efs_proxy_enabled=efs_proxy_enabled,
        )
        if efs_proxy_enabled:
            tunnel_args = [_efs_proxy_bin(), stunnel_config_file]
            if "tls" in options:
                tunnel_args.append(EFS_PROXY_TLS_OPTION)
            if (
                "nodirects3read" in options
                or MountContext().mount_type != MOUNT_TYPE_S3FILES
            ):
                tunnel_args.append(EFS_PROXY_NO_READ_BYPASS_OPTION)
        else:
            tunnel_args = [_stunnel_bin(), stunnel_config_file]

        if "netns" in options:
            tunnel_args = ["nsenter", "--net=" + options["netns"]] + tunnel_args

        # This temp state file is acting like a tlsport lock file, which is why pid =- 1
        temp_tls_state_file = write_tunnel_state_file(
            fs_id,
            mountpoint,
            proxy_listen_port,
            -1,
            tunnel_args,
            [stunnel_config_file],
            state_file_dir,
            cert_details=cert_details,
        )
    finally:
        # When choosing a TLS port for efs-proxy/stunnel to listen on, we open the port to ensure it is free.
        # However, we must free it again so efs-proxy/stunnel can bind to it. We make sure to only free it after
        # we write the temporary state file, which acts like a tlsport lock file. This ensures we don't encounter
        # any race conditions when choosing tls ports during concurrent mounts.
        logging.debug(
            "Closing socket used to choose proxy listen port %s.", proxy_listen_port
        )
        proxy_listen_sock.close()

    # launch the tunnel in a process group so if it has any child processes, they can be killed easily by the mount watchdog
    logging.info(
        'Starting %s: "%s"',
        "efs-proxy" if efs_proxy_enabled else "stunnel",
        " ".join(tunnel_args),
    )
    tunnel_proc = subprocess.Popen(
        tunnel_args,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        preexec_fn=os.setsid,
        close_fds=True,
    )
    try:
        logging.info(
            "Started %s, pid: %d",
            "efs-proxy" if efs_proxy_enabled else "stunnel",
            tunnel_proc.pid,
        )

        update_tunnel_temp_state_file_with_tunnel_pid(
            temp_tls_state_file, state_file_dir, tunnel_proc.pid
        )

        if "netns" not in options:
            test_tlsport(options["tlsport"])
        else:
            with NetNS(nspath=options["netns"]):
                test_tlsport(options["tlsport"])
        yield tunnel_proc
    finally:
        # The caller of this function should use this function in the context of a `with` statement
        # so that the state file is correctly renamed.
        os.rename(
            os.path.join(state_file_dir, temp_tls_state_file),
            os.path.join(state_file_dir, temp_tls_state_file[1:]),
        )
