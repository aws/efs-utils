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
    from configparser import NoOptionError, NoSectionError
except ImportError:
    from ConfigParser import NoOptionError, NoSectionError

from efs_utils_common.aws_credentials import (
    get_aws_profile,
    get_aws_security_credentials,
    is_valid_credentials_expiration,
)
from efs_utils_common.certificate_utils import create_certificate, get_private_key_path
from efs_utils_common.config_utils import (
    get_boolean_config_item_value,
    get_config_file_path,
    get_int_value_from_config_file,
    is_ocsp_enabled,
)
from efs_utils_common.constants import (
    CONFIG_CONTROL_CHAR_PATTERN,
    CONFIG_SECTION,
    DEFAULT_NFS_MOUNT_COMMAND_TIMEOUT_SEC,
    DEFAULT_PROXY_LOGGING_FILE_COUNT,
    DEFAULT_PROXY_LOGGING_LEVEL,
    DEFAULT_PROXY_LOGGING_MAX_BYTES,
    DEFAULT_STUNNEL_CAFILE,
    DEFAULT_STUNNEL_VERIFY_LEVEL,
    DEFAULT_TIMEOUT,
    DEFAULT_UNKNOWN_VALUE,
    EFS_PROXY_LISTEN_FD_OPTION,
    EFS_PROXY_NO_READ_BYPASS_OPTION,
    EFS_PROXY_TLS_OPTION,
    EFS_PROXY_WORKER_THREADS_ITEM,
    EFS_PROXY_WORKER_THREADS_OPTION,
    LOG_DIR,
    MOUNT_TYPE_S3FILES,
    PROXY_CONFIG_SECTION,
    SKIP_NO_SO_BINDTODEVICE_RELEASES,
    STATE_FILE_DIR,
    USE_FIPS_ENDPOINT_STATE_KEY,
    VERSION,
    WATCHDOG_SERVICE,
    WATCHDOG_SERVICE_PLIST_PATH,
)
from efs_utils_common.context import MountContext
from efs_utils_common.error_reporting import fatal_error
from efs_utils_common.file_utils import (
    create_required_directory,
    get_file_safe_mountpoint_name,
)
from efs_utils_common.metadata import (
    STUNNEL_EFS_CONFIG,
    STUNNEL_GLOBAL_CONFIG,
    get_config_section,
    get_fips_config,
    get_target_region,
)
from efs_utils_common.network_utils import (
    TUNNEL_LISTEN_ADDRESS,
    process_listens_on_port,
    procfs_available,
    test_tlsport,
    verify_tlsport_can_be_connected,
)
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
    """
    Return a socket bound to a TLS port that no other mount owns, or None.

    A mount owns its port from the moment its probe socket binds until its state
    file is removed: bootstrap_proxy writes the state file before it hands the probe
    socket to efs-proxy or closes it for stunnel. Ports already assigned to a mount
    are skipped without binding them, so that the probe does not hold a port its
    owner's tunnel is about to bind. That check alone is not enough: another mount
    can write its state file and release its probe between the check and the bind,
    and the two mounts would then share the port. So the state files are checked
    again while the port is held. Any mount that has released the port by then has
    written its state file, and the second check sees it.

    The probe binds TUNNEL_LISTEN_ADDRESS, the address the tunnel listens on and
    mount.nfs4 connects to, rather than a name that might resolve elsewhere: efs-proxy
    refuses an inherited socket bound to any other address.
    """
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
            sock.bind((TUNNEL_LISTEN_ADDRESS, tls_port))
        except socket.error as e:
            logging.warning(e)
            continue

        mount = find_existing_mount_using_tls_port(state_file_dir, tls_port)
        if not mount:
            return sock

        logging.info(
            "Releasing TLS port %s as it was assigned to %s while it was being bound",
            tls_port,
            mount,
        )
        # A bound socket cannot be bound again; release it and try the next port.
        sock.close()
        sock = socket.socket()
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
        get_file_safe_mountpoint_name(mountpoint),
        tls_port,
    )


def _reject_control_chars(key, value):
    """Reject a control char in any stunnel/efs-proxy config key or value.

    Lines are written unescaped as "key = value", so a key or value must not
    contain a newline or any other control character. Central backstop for every
    value reaching the config, whatever its source.
    """
    for field in (str(key), str(value)):
        if CONFIG_CONTROL_CHAR_PATTERN.search(field):
            fatal_error(
                "Refusing to write malformed stunnel config: option %r contains a "
                "disallowed control character" % key,
                "serialize_stunnel_config rejected a control character in key/value "
                "for option %r" % key,
            )


def serialize_stunnel_config(config, header=None):
    lines = []

    if header:
        lines.append("[%s]" % header)

    for k, v in config.items():
        if type(v) is list:
            for item in v:
                _reject_control_chars(k, item)
                lines.append("%s = %s" % (k, item))
        else:
            _reject_control_chars(k, v)
            lines.append("%s = %s" % (k, v))

    return lines


# These options are used by both stunnel and efs-proxy for TLS mounts
def add_tunnel_ca_options(efs_config, config, options, region):
    if "cafile" in options:
        stunnel_cafile = options["cafile"]
        if not stunnel_cafile:
            fatal_error(
                "The cafile mount option requires a path to a CA certificate file",
                "cafile= was passed with an empty value. Specify a valid path, "
                "e.g. -o tls,cafile=/path/to/ca.pem, or omit cafile to use the default EFS CA.",
            )
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
        config,
        CONFIG_SECTION,
        "stunnel_debug_enabled",
        default_value=False,
        emit_warning_message=(MountContext().mount_type != MOUNT_TYPE_S3FILES),
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
        efs_config["efs_utils_version"] = VERSION

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
        # Lets the watchdog tell a mount still in progress from one whose
        # mount helper died before renaming this file.
        "writer_pid": os.getpid(),
        "writer_start_time": get_process_start_time(os.getpid()),
    }

    if cert_details:
        state.update(cert_details)

    return rewrite_tunnel_state_file(state, state_file_dir, state_file)


# `ps -o lstart` is formatted with the caller's locale and time zone. Pin both so
# the watchdog and mount.efs produce the same string for the same process.
PS_LSTART_ENV = {"LC_ALL": "C", "TZ": "UTC", "PATH": "/bin:/usr/bin"}


def get_process_start_time(pid):
    """Return the start time of pid, or None if it is not running.

    Linux: field 22 of /proc/<pid>/stat, clock ticks since boot. macOS: the
    fixed-format `ps -o lstart` string. The watchdog compares it for equality.
    """
    if check_if_platform_is_mac():
        p = subprocess.Popen(
            ["ps", "-p", str(pid), "-o", "lstart="],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            env=PS_LSTART_ENV,
        )
        try:
            out = p.communicate(timeout=5)[0]
        except subprocess.TimeoutExpired:
            p.kill()
            p.communicate()
            return None
        return out.decode().strip() or None
    try:
        with open("/proc/%s/stat" % pid, "rb") as f:
            stat_line = f.read()
    except OSError:
        return None
    # The name in field 2 may contain spaces or parentheses; it ends at the last ")".
    fields_after_name = stat_line[stat_line.rfind(b")") + 1 :].split()
    try:
        return int(fields_after_name[19])
    except (IndexError, ValueError):
        return None


def rewrite_tunnel_state_file(state, state_file_dir, state_file):
    # Write then rename so a kill mid-write cannot leave a truncated record. The
    # scratch name matches none of the state dir scans (fs-, ~fs-, .<port>).
    state_file_path = os.path.join(state_file_dir, state_file)
    scratch_path = os.path.join(state_file_dir, "~" + state_file + ".tmp")
    try:
        with open(scratch_path, "w") as f:
            json.dump(state, f)
    except Exception:
        _remove_scratch(scratch_path)
        raise
    os.rename(scratch_path, state_file_path)
    return state_file


def _remove_scratch(scratch_path):
    try:
        os.remove(scratch_path)
    except OSError:
        pass


def update_tunnel_temp_state_file_with_tunnel_pid(
    temp_tls_state_file, state_file_dir, stunnel_pid
):
    with open(os.path.join(state_file_dir, temp_tls_state_file), "r") as f:
        state = json.load(f)
    state["pid"] = stunnel_pid
    # Lets the watchdog tell this proxy from another process that reused its pid.
    state["pid_start_time"] = get_process_start_time(stunnel_pid)
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


# How long to wait for the tunnel process (efs-proxy or stunnel) to listen on its port. When it is still not
# listening after this, the mount fails if another process answers on the port, and
# otherwise goes ahead as it did before this wait existed. A healthy tunnel listens well
# within this; a tunnel that lost its port exits as soon as its bind fails. Only a tunnel
# that is alive but slow to start waits this long, so it is generous enough for a
# heavily loaded host.
TUNNEL_LISTEN_TIMEOUT_SEC = 30


# How long to keep checking a tunnel whose listener cannot be read from procfs before
# relying on the connect check. A refused read is ambiguous, so this gives a tunnel that
# lost its port the time to finish exiting, which the liveness check then sees. The
# refusal comes from a security policy or hidepid, not from the process exiting: an
# exiting process's /proc/<pid>/fd (mode 0500) moves to root, and mount.efs is root.
TUNNEL_OWNERSHIP_UNREADABLE_GRACE_SEC = 1


def _tunnel_owns_port(tunnel_proc, fs_id, tls_port):
    """
    process_listens_on_port for the tunnel, waiting out an ambiguous None.

    Returns True or False, or None when ownership cannot be read: the host has no
    procfs, or reads are refused for the whole grace period while the tunnel stays
    alive. Fatal if the tunnel exits meanwhile.
    """
    listening = process_listens_on_port(tunnel_proc.pid, tls_port)
    if listening is not None or not procfs_available():
        return listening
    grace_deadline = time.monotonic() + TUNNEL_OWNERSHIP_UNREADABLE_GRACE_SEC
    while listening is None and time.monotonic() < grace_deadline:
        time.sleep(DEFAULT_TIMEOUT)
        # Fatal, before mount.nfs4 has run, if the tunnel was exiting.
        test_tunnel_process(tunnel_proc, fs_id)
        listening = process_listens_on_port(tunnel_proc.pid, tls_port)
    return listening


def _tls_port_answers(tls_port, options):
    if "netns" not in options:
        return verify_tlsport_can_be_connected(tls_port)
    with NetNS(nspath=options["netns"]):
        return verify_tlsport_can_be_connected(tls_port)


def wait_for_tunnel_to_listen(tunnel_proc, fs_id, options):
    """
    Wait until the tunnel process (efs-proxy or stunnel) started for this mount
    listens on its port, so that the NFS mount is attached to this mount's own tunnel.

    A successful connect to the port is not enough. If another process holds the
    port, the connect succeeds even though this mount's tunnel failed to bind and
    exited, and the NFS mount would be attached to the other process. When the
    listener's owner can be read from procfs, wait for this tunnel to own it, and
    fail the mount before running mount.nfs4 if the tunnel exits first. Elsewhere,
    fall back to the connect check.
    """
    tls_port = int(options["tlsport"])
    deadline = time.monotonic() + TUNNEL_LISTEN_TIMEOUT_SEC
    while True:
        # Fatal, before mount.nfs4 has run, if the tunnel has already exited.
        test_tunnel_process(tunnel_proc, fs_id)

        listening = _tunnel_owns_port(tunnel_proc, fs_id, tls_port)
        if listening is None:
            logging.debug(
                "Cannot read the listener of port %s, falling back to a connect check",
                tls_port,
            )
            if "netns" not in options:
                test_tlsport(tls_port)
            else:
                with NetNS(nspath=options["netns"]):
                    test_tlsport(tls_port)
            return

        if listening:
            logging.debug(
                "TLS tunnel pid %d is listening on port %s", tunnel_proc.pid, tls_port
            )
            return

        if time.monotonic() >= deadline:
            # This tunnel is not listening, so anything that answers on the port is
            # another process, and mount.nfs4 would be attached to it. The connect and
            # the procfs read above are separate, so a tunnel that started listening in
            # between would answer too: check its listener once more first.
            if _tls_port_answers(tls_port, options):
                owns_port = _tunnel_owns_port(tunnel_proc, fs_id, tls_port)
                if owns_port:
                    logging.debug(
                        "TLS tunnel pid %d is listening on port %s",
                        tunnel_proc.pid,
                        tls_port,
                    )
                    return
                if owns_port is None:
                    # Ownership can no longer be read; as in the loop, rely on the
                    # connect check rather than claim the port is held by another
                    # process.
                    logging.debug(
                        "Cannot read the listener of port %s, relying on the connect check",
                        tls_port,
                    )
                    return
                fatal_error(
                    "Failed to mount %s: port %s is held by another process. Retry the mount."
                    % (fs_id, tls_port),
                    "TLS tunnel pid %d is not listening on port %s after %s sec, and another "
                    "process accepts connections on it"
                    % (tunnel_proc.pid, tls_port, TUNNEL_LISTEN_TIMEOUT_SEC),
                )
            logging.warning(
                "TLS tunnel pid %d is not listening on port %s after %s sec, continuing with the mount",
                tunnel_proc.pid,
                tls_port,
                TUNNEL_LISTEN_TIMEOUT_SEC,
            )
            return

        time.sleep(DEFAULT_TIMEOUT)


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
        rc = subprocess.call(
            ["launchctl", "list", WATCHDOG_SERVICE],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
        if rc == 0:
            logging.debug("%s is already running", WATCHDOG_SERVICE)
        else:
            if not os.path.exists(WATCHDOG_SERVICE_PLIST_PATH):
                fatal_error(
                    "Watchdog plist file missing. Copy the watchdog plist file to /Library/LaunchDaemons/"
                )
                return

            logging.debug("Loading watchdog from %s", WATCHDOG_SERVICE_PLIST_PATH)
            rc = subprocess.call(
                ["launchctl", "load", WATCHDOG_SERVICE_PLIST_PATH],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
            )
            if rc != 0:
                fatal_error(
                    "Failed to load watchdog plist %s (exit code %d)"
                    % (WATCHDOG_SERVICE_PLIST_PATH, rc)
                )
                return
            logging.debug("Loaded watchdog from %s", WATCHDOG_SERVICE_PLIST_PATH)

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


def get_efs_proxy_worker_threads(config):
    """Return the configured efs-proxy worker-thread count, or None when unset.

    Checks only what the config file can settle: that the value is an integer,
    and that it is at least 1. A bad value is fatal rather than defaulted,
    because a caller who set the item to bound thread usage must not silently get
    the unbounded default. The upper bound -- not exceeding the parallelism the
    proxy actually has -- is efs-proxy's, in `validate_worker_threads`.

    An empty value is treated as unset, so a half-uncommented line does not fail
    a mount.
    """
    try:
        raw_value = config.get(CONFIG_SECTION, EFS_PROXY_WORKER_THREADS_ITEM)
    except (NoOptionError, NoSectionError):
        return None

    raw_value = raw_value.strip()
    if not raw_value:
        return None

    range_help = (
        "Expected a positive integer no greater than the number of CPUs "
        "available to this host, or remove the item to use one worker thread per "
        "available CPU."
    )

    try:
        worker_threads = int(raw_value)
    except ValueError:
        fatal_error(
            'Invalid value "%s" for %s in section %s of %s. %s'
            % (
                raw_value,
                EFS_PROXY_WORKER_THREADS_ITEM,
                CONFIG_SECTION,
                get_config_file_path(),
                range_help,
            )
        )

    if worker_threads < 1:
        fatal_error(
            "Invalid value %d for %s in section %s of %s. %s"
            % (
                worker_threads,
                EFS_PROXY_WORKER_THREADS_ITEM,
                CONFIG_SECTION,
                get_config_file_path(),
                range_help,
            )
        )

    return worker_threads


def start_tunnel_process(tunnel_args, efs_proxy_enabled, listen_sock=None):
    """
    Start efs-proxy or stunnel with `tunnel_args`.

    With `listen_sock`, a socket bound to the proxy's listen port, the socket is passed to
    efs-proxy as an inherited file descriptor named by --listen-fd, and this process's copy is
    closed once efs-proxy has started. The flag is added here only: `tunnel_args` is also the
    command saved in the state file, which the watchdog runs to restart a dead proxy, and a
    restarted proxy has no socket to inherit, so it binds the port itself.
    """
    popen_args = list(tunnel_args)
    pass_fds = ()
    if listen_sock is not None:
        listen_fd = listen_sock.fileno()
        popen_args += [EFS_PROXY_LISTEN_FD_OPTION, str(listen_fd)]
        pass_fds = (listen_fd,)

    # launch the tunnel in a process group so if it has any child processes, they can be killed easily by the mount watchdog
    logging.info(
        'Starting %s: "%s"',
        "efs-proxy" if efs_proxy_enabled else "stunnel",
        " ".join(popen_args),
    )
    try:
        return subprocess.Popen(
            popen_args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid,
            close_fds=True,
            pass_fds=pass_fds,
        )
    finally:
        if listen_sock is not None:
            # efs-proxy holds its own reference to the socket now, or failed to start.
            listen_sock.close()


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

    # Read this before anything is created. It is the only fatal_error between
    # choosing the port and writing the state file, and the watchdog's cleanup
    # (cleanup_mount_state_if_stunnel_not_running) is keyed off state files -- so
    # failing later would orphan the certificate directory and the proxy config
    # in /var/run/efs on every attempt, which accumulates under a CSI retry loop.
    # A config lookup is cheap, so failing fast here costs nothing.
    efs_proxy_worker_threads = get_efs_proxy_worker_threads(config)

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
                    # Recorded so the watchdog refreshes through this mount's STS
                    # endpoint: it does not inherit this process's AWS_USE_FIPS_ENDPOINT.
                    cert_details[USE_FIPS_ENDPOINT_STATE_KEY] = get_fips_config(config)
                    logging.debug(
                        "AWS credentials source used for IAM authentication: %s",
                        credentials_source,
                    )

                # Persist the credential expiration so the watchdog can schedule refresh
                # ahead of it.
                expiration = (
                    security_credentials.get("Expiration")
                    if security_credentials
                    else None
                )
                if not expiration:
                    logging.debug(
                        "No credential expiration available; the certificate will refresh on the "
                        "fixed tls_cert_renewal_interval_min interval"
                    )
                elif is_valid_credentials_expiration(expiration):
                    cert_details["certificateExpirationTime"] = expiration
                else:
                    logging.warning(
                        'Credential expiration "%s" is not valid ISO-8601; the watchdog will '
                        "fall back to the tls_cert_renewal_interval_min fixed interval",
                        expiration,
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
            if efs_proxy_worker_threads is not None:
                tunnel_args.extend(
                    [EFS_PROXY_WORKER_THREADS_OPTION, str(efs_proxy_worker_threads)]
                )
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
    except BaseException:
        proxy_listen_sock.close()
        raise

    if efs_proxy_enabled:
        # Hand the bound socket to efs-proxy, so the port stays bound from the moment it was
        # chosen until efs-proxy exits and no other process can take it in between.
        tunnel_proc = start_tunnel_process(
            tunnel_args, efs_proxy_enabled, listen_sock=proxy_listen_sock
        )
    else:
        # stunnel cannot take over a bound socket, so free the port for it to bind. This is done
        # only after the temporary state file, which acts as a lock on the port, is written, so a
        # concurrent mount that checks the state files skips this port.
        logging.debug(
            "Closing socket used to choose proxy listen port %s.", proxy_listen_port
        )
        proxy_listen_sock.close()
        tunnel_proc = start_tunnel_process(tunnel_args, efs_proxy_enabled)
    try:
        logging.info(
            "Started %s, pid: %d",
            "efs-proxy" if efs_proxy_enabled else "stunnel",
            tunnel_proc.pid,
        )

        update_tunnel_temp_state_file_with_tunnel_pid(
            temp_tls_state_file, state_file_dir, tunnel_proc.pid
        )

        wait_for_tunnel_to_listen(tunnel_proc, fs_id, options)
        yield tunnel_proc
    finally:
        # The caller of this function should use this function in the context of a `with` statement
        # so that the state file is correctly renamed.
        temp_path = os.path.join(state_file_dir, temp_tls_state_file)
        final_path = os.path.join(state_file_dir, temp_tls_state_file[1:])
        try:
            os.rename(temp_path, final_path)
        except FileNotFoundError:
            # The watchdog may have finalized it first.
            if not os.path.exists(final_path):
                raise
            logging.info(
                "State file %s was already finalized by the watchdog",
                temp_tls_state_file[1:],
            )
