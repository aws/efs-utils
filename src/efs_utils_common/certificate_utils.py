#!/usr/bin/env python3
#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.


import base64
import errno
import hashlib
import hmac
import logging
import os
import time
from contextlib import contextmanager
from datetime import timedelta

try:
    from urllib.parse import quote_plus
except ImportError:
    from urllib import quote_plus

from efs_utils_common.constants import (
    ALGORITHM,
    AWS4_REQUEST,
    CANONICAL_HEADERS,
    CANONICAL_URI,
    CERT_DATETIME_FORMAT,
    DATE_ONLY_FORMAT,
    DEFAULT_TIMEOUT,
    HTTP_REQUEST_METHOD,
    NOT_AFTER_HOURS,
    NOT_BEFORE_MINS,
    PRIVATE_KEY_FILE,
    REQUEST_PAYLOAD,
    SIGNED_HEADERS,
    SIGV4_DATETIME_FORMAT,
    STATE_FILE_DIR,
)
from efs_utils_common.context import MountContext
from efs_utils_common.error_reporting import fatal_error
from efs_utils_common.file_utils import (
    check_and_remove_lock_file,
    create_required_directory,
    get_utc_now,
)
from efs_utils_common.metadata import CA_CONFIG_BODY
from efs_utils_common.process_utils import subprocess_call


def create_certificate(
    config,
    mount_name,
    common_name,
    region,
    fs_id,
    security_credentials,
    ap_id,
    client_info,
    base_path=STATE_FILE_DIR,
):
    current_time = get_utc_now()
    tls_paths = tls_paths_dictionary(mount_name, base_path)

    certificate_config = os.path.join(tls_paths["mount_dir"], "config.conf")
    certificate_signing_request = os.path.join(tls_paths["mount_dir"], "request.csr")
    certificate = os.path.join(tls_paths["mount_dir"], "certificate.pem")

    ca_dirs_check(config, tls_paths["database_dir"], tls_paths["certs_dir"])
    ca_supporting_files_check(
        tls_paths["index"],
        tls_paths["index_attr"],
        tls_paths["serial"],
        tls_paths["rand"],
    )

    private_key = check_and_create_private_key(base_path)

    if security_credentials:
        public_key = os.path.join(tls_paths["mount_dir"], "publicKey.pem")
        create_public_key(private_key, public_key)

    create_ca_conf(
        certificate_config,
        common_name,
        tls_paths["mount_dir"],
        private_key,
        current_time,
        region,
        fs_id,
        security_credentials,
        ap_id,
        client_info,
    )
    create_certificate_signing_request(
        certificate_config, private_key, certificate_signing_request
    )

    not_before = get_certificate_timestamp(current_time, minutes=-NOT_BEFORE_MINS)
    not_after = get_certificate_timestamp(current_time, hours=NOT_AFTER_HOURS)

    cmd = (
        "openssl ca -startdate %s -enddate %s -selfsign -batch -notext -config %s -in %s -out %s"
        % (
            not_before,
            not_after,
            certificate_config,
            certificate_signing_request,
            certificate,
        )
    )
    subprocess_call(cmd, "Failed to create self-signed client-side certificate")
    return current_time.strftime(CERT_DATETIME_FORMAT)


def get_private_key_path():
    """Wrapped for mocking purposes in unit tests"""
    return PRIVATE_KEY_FILE


def check_and_create_private_key(base_path=STATE_FILE_DIR):
    # Creating RSA private keys is slow, so we will create one private key and allow mounts to share it.
    # This means, however, that we have to include a locking mechanism to ensure that the private key is
    # atomically created, as mounts occurring in parallel may try to create the key simultaneously.
    key = get_private_key_path()

    @contextmanager
    def open_lock_file():
        lock_file = os.path.join(base_path, "efs-utils-lock")
        f = os.open(lock_file, os.O_CREAT | os.O_DSYNC | os.O_EXCL | os.O_RDWR)
        try:
            lock_file_contents = "PID: %s" % os.getpid()
            os.write(f, lock_file_contents.encode("utf-8"))
            yield f
        finally:
            check_and_remove_lock_file(lock_file, f)

    def do_with_lock(function):
        while True:
            try:
                with open_lock_file():
                    return function()
            except OSError as e:
                if e.errno == errno.EEXIST:
                    logging.info(
                        "Failed to take out private key creation lock, sleeping %s (s)",
                        DEFAULT_TIMEOUT,
                    )
                    time.sleep(DEFAULT_TIMEOUT)
                else:
                    # errno.ENOENT: No such file or directory, errno.EBADF: Bad file descriptor
                    if e.errno == errno.ENOENT or e.errno == errno.EBADF:
                        logging.debug(
                            "lock file does not exist or Bad file descriptor, The file is already removed nothing to do."
                        )
                    else:
                        raise Exception(
                            "Could not remove lock file unexpected exception: %s", e
                        )

    def generate_key():
        if os.path.isfile(key):
            # If the openssl genpkey command is interrupted or isn't successful,
            # it will leave behind an empty file.
            if os.path.getsize(key) == 0:
                logging.warning("Purging empty private key file")
                os.remove(key)
            else:
                return

        cmd = (
            "openssl genpkey -algorithm RSA -out %s -pkeyopt rsa_keygen_bits:3072" % key
        )
        subprocess_call(cmd, "Failed to create private key")
        read_only_mode = 0o400
        os.chmod(key, read_only_mode)

    do_with_lock(generate_key)
    return key


def create_certificate_signing_request(config_path, private_key, csr_path):
    cmd = "openssl req -new -config %s -key %s -out %s" % (
        config_path,
        private_key,
        csr_path,
    )
    subprocess_call(cmd, "Failed to create certificate signing request (csr)")


def create_ca_conf(
    config_path,
    common_name,
    directory,
    private_key,
    date,
    region,
    fs_id,
    security_credentials,
    ap_id,
    client_info,
):
    """Populate ca/req configuration file with fresh configurations at every mount since SigV4 signature can change"""
    public_key_path = os.path.join(directory, "publicKey.pem")
    ca_extension_body = ca_extension_builder(
        ap_id, security_credentials, fs_id, client_info
    )
    efs_client_auth_body = (
        efs_client_auth_builder(
            public_key_path,
            security_credentials["AccessKeyId"],
            security_credentials["SecretAccessKey"],
            date,
            region,
            fs_id,
            security_credentials["Token"],
        )
        if security_credentials
        else ""
    )
    efs_client_info_body = efs_client_info_builder(client_info) if client_info else ""
    full_config_body = CA_CONFIG_BODY % (
        directory,
        private_key,
        common_name,
        ca_extension_body,
        efs_client_auth_body,
        efs_client_info_body,
    )

    with open(config_path, "w") as f:
        f.write(full_config_body)

    return full_config_body


def ca_extension_builder(ap_id, security_credentials, fs_id, client_info):
    ca_extension_str = "[ v3_ca ]\nsubjectKeyIdentifier = hash"
    if ap_id:
        ca_extension_str += "\n1.3.6.1.4.1.4843.7.1 = ASN1:UTF8String:" + ap_id
    if security_credentials:
        ca_extension_str += "\n1.3.6.1.4.1.4843.7.2 = ASN1:SEQUENCE:efs_client_auth"

    ca_extension_str += "\n1.3.6.1.4.1.4843.7.3 = ASN1:UTF8String:" + fs_id

    if client_info:
        ca_extension_str += "\n1.3.6.1.4.1.4843.7.4 = ASN1:SEQUENCE:efs_client_info"

    return ca_extension_str


def efs_client_auth_builder(
    public_key_path,
    access_key_id,
    secret_access_key,
    date,
    region,
    fs_id,
    session_token=None,
):
    public_key_hash = get_public_key_sha1(public_key_path)
    canonical_request = create_canonical_request(
        public_key_hash, date, access_key_id, region, fs_id, session_token
    )
    string_to_sign = create_string_to_sign(canonical_request, date, region)
    signature = calculate_signature(string_to_sign, date, secret_access_key, region)
    efs_client_auth_str = "[ efs_client_auth ]"
    efs_client_auth_str += "\naccessKeyId = UTF8String:" + access_key_id
    efs_client_auth_str += "\nsignature = OCTETSTRING:" + signature
    efs_client_auth_str += "\nsigv4DateTime = UTCTIME:" + date.strftime(
        CERT_DATETIME_FORMAT
    )

    if session_token:
        efs_client_auth_str += "\nsessionToken = EXPLICIT:0,UTF8String:" + session_token

    return efs_client_auth_str


def efs_client_info_builder(client_info):
    efs_client_info_str = "[ efs_client_info ]"
    for key, value in client_info.items():
        efs_client_info_str += "\n%s = UTF8String:%s" % (key, value)
    return efs_client_info_str


def create_public_key(private_key, public_key):
    cmd = "openssl rsa -in %s -outform PEM -pubout -out %s" % (private_key, public_key)
    subprocess_call(cmd, "Failed to create public key")


def ca_dirs_check(config, database_dir, certs_dir):
    """Check if mount's database and certs directories exist and if not, create directories (also create all intermediate
    directories if they don't exist)."""
    if not os.path.exists(database_dir):
        create_required_directory(config, database_dir)
    if not os.path.exists(certs_dir):
        create_required_directory(config, certs_dir)


def ca_supporting_files_check(index_path, index_attr_path, serial_path, rand_path):
    """Recreate all supporting openssl ca and req files if they're not present in their respective directories"""
    if not os.path.isfile(index_path):
        open(index_path, "w").close()
    if not os.path.isfile(index_attr_path):
        with open(index_attr_path, "w+") as f:
            f.write("unique_subject = no")
    if not os.path.isfile(serial_path):
        with open(serial_path, "w+") as f:
            f.write("00")
    if not os.path.isfile(rand_path):
        open(rand_path, "w").close()


def get_certificate_timestamp(current_time, **kwargs):
    updated_time = current_time + timedelta(**kwargs)
    return updated_time.strftime(CERT_DATETIME_FORMAT)


def tls_paths_dictionary(mount_name, base_path=STATE_FILE_DIR):
    tls_dict = {
        "mount_dir": os.path.join(base_path, mount_name),
        # every mount will have its own ca mode assets due to lack of multi-threading support in openssl
        "database_dir": os.path.join(base_path, mount_name, "database"),
        "certs_dir": os.path.join(base_path, mount_name, "certs"),
        "index": os.path.join(base_path, mount_name, "database/index.txt"),
        "index_attr": os.path.join(base_path, mount_name, "database/index.txt.attr"),
        "serial": os.path.join(base_path, mount_name, "database/serial"),
        "rand": os.path.join(base_path, mount_name, "database/.rand"),
    }

    return tls_dict


def get_public_key_sha1(public_key):
    # truncating public key to remove the header and footer '-----(BEGIN|END) PUBLIC KEY-----'
    with open(public_key, "r") as f:
        lines = f.readlines()
        lines = lines[1:-1]

    key = "".join(lines)
    key = bytearray(base64.b64decode(key))

    # Parse the public key to pull out the actual key material by looking for the key BIT STRING
    # Example:
    #     0:d=0  hl=4 l= 418 cons: SEQUENCE
    #     4:d=1  hl=2 l=  13 cons: SEQUENCE
    #     6:d=2  hl=2 l=   9 prim: OBJECT            :rsaEncryption
    #    17:d=2  hl=2 l=   0 prim: NULL
    #    19:d=1  hl=4 l= 399 prim: BIT STRING
    cmd = "openssl asn1parse -inform PEM -in %s" % public_key
    output, err = subprocess_call(
        cmd, "Unable to ASN1 parse public key file, %s, correctly" % public_key
    )

    key_line = ""
    for line in output.splitlines():
        if "BIT STRING" in line.decode("utf-8"):
            key_line = line.decode("utf-8")

    if not key_line:
        err_msg = "Public key file, %s, is incorrectly formatted" % public_key
        fatal_error(err_msg, err_msg)

    key_line = key_line.replace(" ", "")

    # DER encoding TLV (Tag, Length, Value)
    # - the first octet (byte) is the tag (type)
    # - the next octets are the length - "definite form"
    #   - the first octet always has the high order bit (8) set to 1
    #   - the remaining 127 bits are used to encode the number of octets that follow
    #   - the following octets encode, as big-endian, the length (which may be 0) as a number of octets
    # - the remaining octets are the "value" aka content
    #
    # For a BIT STRING, the first octet of the value is used to signify the number of unused bits that exist in the last
    # content byte. Note that this is explicitly excluded from the SubjectKeyIdentifier hash, per
    # https://tools.ietf.org/html/rfc5280#section-4.2.1.2
    #
    # Example:
    #   0382018f00...<subjectPublicKey>
    #   - 03 - BIT STRING tag
    #   - 82 - 2 length octets to follow (ignore high order bit)
    #   - 018f - length of 399
    #   - 00 - no unused bits in the last content byte
    offset = int(key_line.split(":")[0])
    key = key[offset:]

    num_length_octets = key[1] & 0b01111111

    # Exclude the tag (1), length (1 + num_length_octets), and number of unused bits (1)
    offset = 1 + 1 + num_length_octets + 1
    key = key[offset:]

    sha1 = hashlib.sha1()
    sha1.update(key)

    return sha1.hexdigest()


def create_canonical_request(
    public_key_hash, date, access_key, region, fs_id, session_token=None
):
    """
    Create a Canonical Request - https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
    """
    formatted_datetime = date.strftime(SIGV4_DATETIME_FORMAT)
    credential = quote_plus(access_key + "/" + get_credential_scope(date, region))

    request = HTTP_REQUEST_METHOD + "\n"
    request += CANONICAL_URI + "\n"
    request += (
        create_canonical_query_string(
            public_key_hash, credential, formatted_datetime, session_token
        )
        + "\n"
    )
    request += CANONICAL_HEADERS % fs_id + "\n"
    request += SIGNED_HEADERS + "\n"

    sha256 = hashlib.sha256()
    sha256.update(REQUEST_PAYLOAD.encode())
    request += sha256.hexdigest()

    return request


def create_canonical_query_string(
    public_key_hash, credential, formatted_datetime, session_token=None
):
    canonical_query_params = {
        "Action": "Connect",
        # Public key hash is included in canonical request to tie the signature to a specific key pair to avoid replay attacks
        "PublicKeyHash": quote_plus(public_key_hash),
        "X-Amz-Algorithm": ALGORITHM,
        "X-Amz-Credential": credential,
        "X-Amz-Date": quote_plus(formatted_datetime),
        "X-Amz-Expires": 86400,
        "X-Amz-SignedHeaders": SIGNED_HEADERS,
    }

    if session_token:
        canonical_query_params["X-Amz-Security-Token"] = quote_plus(session_token)

    # Cannot use urllib.urlencode because it replaces the %s's
    return "&".join(
        ["%s=%s" % (k, v) for k, v in sorted(canonical_query_params.items())]
    )


def create_string_to_sign(canonical_request, date, region):
    """
    Create a String to Sign - https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
    """
    string_to_sign = ALGORITHM + "\n"
    string_to_sign += date.strftime(SIGV4_DATETIME_FORMAT) + "\n"
    string_to_sign += get_credential_scope(date, region) + "\n"

    sha256 = hashlib.sha256()
    sha256.update(canonical_request.encode())
    string_to_sign += sha256.hexdigest()

    return string_to_sign


def calculate_signature(string_to_sign, date, secret_access_key, region):
    """
    Calculate the Signature - https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
    """

    def _sign(key, msg):
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256)

    context = MountContext()
    logging.debug("Calculating signature for service: %s", context.service)

    key_date = _sign(
        ("AWS4" + secret_access_key).encode("utf-8"), date.strftime(DATE_ONLY_FORMAT)
    ).digest()
    add_region = _sign(key_date, region).digest()
    add_service = _sign(add_region, context.service).digest()
    signing_key = _sign(add_service, "aws4_request").digest()

    signature = _sign(signing_key, string_to_sign).hexdigest()
    logging.debug("Generated signature: %s", signature)
    return signature


def get_credential_scope(date, region):
    context = MountContext()
    credential_scope = "/".join(
        [date.strftime(DATE_ONLY_FORMAT), region, context.service, AWS4_REQUEST]
    )
    logging.debug(
        "Certificate credential scope: %s (service: %s)",
        credential_scope,
        context.service,
    )
    return credential_scope
