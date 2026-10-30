#!/usr/bin/env python3
#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.


import errno
import logging
import os
import socket
import struct
import subprocess
import time

from efs_utils_common.constants import DEFAULT_TIMEOUT
from efs_utils_common.error_reporting import fatal_error
from efs_utils_common.exceptions import FallbackException
from efs_utils_common.process_utils import NetNS


def check_network_target(fs_id):
    with open(os.devnull, "w") as devnull:
        rc = subprocess.call(
            ["systemctl", "is-active", "network.target"],
            stdout=devnull,
            stderr=devnull,
            close_fds=True,
        )

    if rc != 0:
        # For fstab mount, the exit code 0 below is to avoid non-zero exit status causing instance to fail the
        # local-fs.target boot up and then fail the network setup failure can result in the instance being unresponsive.
        # https://docs.amazonaws.cn/en_us/efs/latest/ug/troubleshooting-efs-mounting.html#automount-fails
        #
        fatal_error(
            'Failed to mount %s because the network was not yet available, add "_netdev" to your mount options'
            % fs_id,
            exit_code=0,
        )


# This network status check is necessary for the fstab automount use case and should not be removed.
# efs-utils relies on the network to retrieve the instance metadata and get information e.g. region, to further parse
# the DNS name of file system to mount target IP address, we need a way to inform users to add `_netdev` option to fstab
# entry if they haven't do so.
#
# However, network.target status itself cannot accurately reflect the status of network reachability.
# We will replace this check with other accurate way such that even network.target is turned off while network is
# reachable, the mount can still proceed.
#
def check_network_status(fs_id, init_system):
    if init_system != "systemd":
        logging.debug("Not testing network on non-systemd init systems")
        return

    check_network_target(fs_id)


def test_tlsport(tlsport):
    retry_times = 5
    while not verify_tlsport_can_be_connected(tlsport) and retry_times > 0:
        logging.debug(
            "The tlsport %s cannot be connected yet, sleep %s(s), %s retry time(s) left",
            tlsport,
            DEFAULT_TIMEOUT,
            retry_times,
        )
        time.sleep(DEFAULT_TIMEOUT)
        retry_times -= 1


TCP_LISTEN_STATE = "0A"
SOCKET_LINK_PREFIX = "socket:["
# The tunnel (efs-proxy or stunnel) listens on, and mount.nfs4 connects to, this address only.
TUNNEL_LISTEN_ADDRESS = "127.0.0.1"


def _proc_net_tcp_address(ip_address, port):
    """
    Format an IPv4 address and port as /proc/net/tcp shows them: the address as
    the hex of its 32-bit value in host byte order, then the port in hex, e.g.
    127.0.0.1:20049 is "0100007F:4E51" on a little-endian host.
    """
    packed = socket.inet_aton(ip_address)
    return "%08X:%04X" % (struct.unpack("=I", packed)[0], port)


def get_listening_socket_inodes(
    pid, port, ip_address=TUNNEL_LISTEN_ADDRESS, proc_root="/proc"
):
    """
    Return the inodes of the TCP sockets listening on ip_address:port in the
    network namespace of process `pid`. Raises OSError if that namespace's socket
    table cannot be read.
    """
    local_address = _proc_net_tcp_address(ip_address, port)
    with open(os.path.join(proc_root, str(pid), "net", "tcp")) as f:
        lines = f.read().splitlines()[1:]

    inodes = set()
    for line in lines:
        # sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode
        fields = line.split()
        if (
            len(fields) >= 10
            and fields[1] == local_address
            and fields[3] == TCP_LISTEN_STATE
        ):
            inodes.add(fields[9])
    return inodes


# The process is gone, or going: its procfs entries no longer exist.
PROCESS_GONE_ERRNOS = (errno.ENOENT, errno.ESRCH)


def procfs_available(proc_root="/proc"):
    """True if this host has a procfs that shows per-process socket tables."""
    return os.path.isdir(os.path.join(proc_root, "self", "net"))


def process_listens_on_port(
    pid, port, ip_address=TUNNEL_LISTEN_ADDRESS, proc_root="/proc"
):
    """
    Return True if process `pid` holds a TCP socket listening on ip_address:port,
    False if it does not, and None if that cannot be determined on this host.

    Unlike a connect to the port, this tells the process's own listener apart from
    one that belongs to any other process.

    A process whose procfs entries no longer exist is reported as not listening.
    None is returned when the host has no procfs, or when reading the entries is
    refused. A refusal is ambiguous: it comes from a security policy or hidepid, and
    for a non-root reader also from a process that is exiting, whose /proc/<pid>/fd
    (mode 0500) moves to root. Callers must not treat None from a host with procfs
    as proof that the process is alive.
    """
    if not procfs_available(proc_root):
        return None

    try:
        listening_inodes = get_listening_socket_inodes(pid, port, ip_address, proc_root)
        if not listening_inodes:
            return False

        fd_dir = os.path.join(proc_root, str(pid), "fd")
        fds = os.listdir(fd_dir)
    except OSError as e:
        return False if e.errno in PROCESS_GONE_ERRNOS else None

    refused = False
    for fd in fds:
        try:
            target = os.readlink(os.path.join(fd_dir, fd))
        except OSError as e:
            # An fd closed since the listing is gone; anything else is a refusal.
            if e.errno not in PROCESS_GONE_ERRNOS:
                refused = True
            continue
        # A socket fd links to "socket:[<inode>]".
        if target.startswith(SOCKET_LINK_PREFIX) and target.endswith("]"):
            if target[len(SOCKET_LINK_PREFIX) : -1] in listening_inodes:
                return True
    return None if refused else False


def get_ipv6_addresses(hostname):
    try:
        addrinfo = socket.getaddrinfo(hostname, None, socket.AF_INET6)
        return [addr[4][0] for addr in addrinfo]
    except socket.gaierror:
        return []


def dns_name_can_be_resolved(dns_name):
    try:
        # Try resolution as-is first
        addr_info = socket.getaddrinfo(dns_name, None, socket.AF_UNSPEC)
        return len(addr_info) > 0
    except socket.gaierror:
        # If resolution fails and hostname is not already FQDN, retry with trailing
        # dot to force absolute resolution and bypass VPC search domain suffixing
        # (e.g. .compute.internal) which can cause transient NXDOMAIN failures.
        if not dns_name.endswith("."):
            try:
                fqdn = dns_name + "."
                addr_info = socket.getaddrinfo(fqdn, None, socket.AF_UNSPEC)
                return len(addr_info) > 0
            except socket.gaierror:
                return False
        return False


def mount_target_ip_address_can_be_resolved(
    mount_target_ip_address, passed_via_options=False, network_namespace=None
):
    tries = 3
    for attempt in range(tries):
        try:
            # Open a socket connection to mount target nfs port to verify that the mount target can be connected
            if not network_namespace:
                s = socket.create_connection((mount_target_ip_address, 2049), timeout=2)
            else:
                with NetNS(nspath=network_namespace):
                    s = socket.create_connection(
                        (mount_target_ip_address, 2049), timeout=2
                    )
            s.close()
            return True
        except socket.timeout:
            if attempt < tries - 1:
                message = (
                    "The ip address %s cannot be connected yet, sleep 0.5s, %s retry time(s) left"
                    % (mount_target_ip_address, tries - attempt - 1)
                )
                logging.warning(message)
                time.sleep(0.5)
                continue
            else:
                raise FallbackException(
                    "Connection to the mount target IP address %s timeout. Please retry in 5 minutes if the "
                    "mount target is newly created. Otherwise check your VPC and security group "
                    "configuration to ensure your file system is reachable via TCP port 2049 from your "
                    "instance." % mount_target_ip_address
                )
        except Exception as e:
            hint_message = (
                " Please check if the mount target ip address passed via mount option is correct."
                if passed_via_options
                else ""
            )
            raise FallbackException(
                "Unknown error when connecting to mount target IP address %s, %s.%s"
                % (mount_target_ip_address, e, hint_message)
            )


def verify_tlsport_can_be_connected(tlsport):
    try:
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    except Exception as e:
        logging.warning("Error opening a socket, %s", e)
        return False
    try:
        logging.debug("Trying to connect to 127.0.0.1: %s", tlsport)
        test_socket.connect(("127.0.0.1", tlsport))
        return True
    except Exception as e:
        logging.warning("Error connecting to 127.0.0.1:%s, %s", tlsport, e)
        return False
    finally:
        test_socket.close()
