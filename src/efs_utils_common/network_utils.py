#!/usr/bin/env python3
#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.


import logging
import os
import socket
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


def get_ipv6_addresses(hostname):
    try:
        addrinfo = socket.getaddrinfo(hostname, None, socket.AF_INET6)
        return [addr[4][0] for addr in addrinfo]
    except socket.gaierror:
        return []


def dns_name_can_be_resolved(dns_name):
    try:
        addr_info = socket.getaddrinfo(dns_name, None, socket.AF_UNSPEC)
        return len(addr_info) > 0
    except socket.gaierror:
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
