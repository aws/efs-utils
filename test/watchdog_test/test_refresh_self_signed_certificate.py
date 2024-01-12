# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.

import json
import logging
import os
from datetime import datetime, timedelta

import pytest

import mount_efs
import watchdog

try:
    import ConfigParser
except ImportError:
    from configparser import ConfigParser

DT_PATTERN = watchdog.CERT_DATETIME_FORMAT
FS_ID = "fs-deadbeef"
COMMON_NAME = "fs-deadbeef.efs.us-east-1.amazonaws.com"
PID = 1234
STATE_FILE = "stunnel-config.fs-deadbeef.mount.dir.12345"
MOUNT_NAME = "fs-deadbeef.mount.dir.12345"
REGION = "us-east-1"
AP_ID = "fsap-0123456789abcdef0"
BAD_AP_ID_INCORRECT_START = "bad-fsap-0123456789abc"
BAD_AP_ID_TOO_SHORT = "fsap-0123456789abcdef"
BAD_AP_ID_BAD_CHAR = "fsap-0123456789abcdefg"
CREDENTIALS_SOURCE = "credentials:default"
ACCESS_KEY_ID_VAL = "FAKE_AWS_ACCESS_KEY_ID"
SECRET_ACCESS_KEY_VAL = "FAKE_AWS_SECRET_ACCESS_KEY"
SESSION_TOKEN_VAL = "FAKE_SESSION_TOKEN"
FIXED_DT = datetime(2000, 1, 1, 12, 0, 0)
CLIENT_INFO = {"source": "test", "efs_utils_version": watchdog.VERSION}
CREDENTIALS = {
    "AccessKeyId": ACCESS_KEY_ID_VAL,
    "SecretAccessKey": SECRET_ACCESS_KEY_VAL,
    "Token": SESSION_TOKEN_VAL,
}
PUBLIC_KEY_BODY = (
    "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEArGJgJTTwefL+jHV8A9EM\npX56n3Z"
    "JczM+4iPPSnledJzBcUO1VF+j6TOzy39BWBtvRjSs0nqd5wqw+1xHawhh\ndJF5KsqMNGcP/y9fLi9Bm1vInHfQVan4NhXWh8S"
    "NbRZM1tNZV5/k+VnFur6ACHwq\neWppGXkGBASL0zG0MiCbOVMkwfv/E69APVC6ljnPXBWaDuggAClYheTv5RIU4wD1\nc1nohR"
    "b0ZHyfZjELjnqLfY0eOqY+msQXzP0eUmZXCMvUkGxi5DJnNVKhw5y96QbB\nRFO5ImQXpNsQmp8F9Ih1RIxNsl4csaEuK+/Zo"
    "J68vR47oQNtPp1PjdIwcnQ3cOvO\nHMxulMX21Fd/e9TsnqISOTOyebmYFgaHczg4JVu5lV699+7QWJm1a7M4ab0WgVVR\nz27J0"
    "Lx/691MZB4TbGoEIFza30/sk6uTPxAzebzCaroXzT7uA6TIRtRpxt4X9a+4\n6GhfgR5RJfFMb8rPGmaKWqA2YkTsZzRGHhbAzs"
    "J/nEstAgMBAAE=\n-----END PUBLIC KEY-----"
)


@pytest.fixture(autouse=True)
def setup(mocker):
    mocker.patch("socket.gethostbyname")
    mocker.patch("mount_efs.get_region_from_instance_metadata", return_value=REGION)
    mocker.patch("mount_efs.get_target_region", return_value=REGION)
    mocker.patch("mount_efs.get_aws_security_credentials", return_value=CREDENTIALS)
    mocker.patch("watchdog.get_aws_security_credentials", return_value=CREDENTIALS)


def _get_config(certificate_renewal_interval=60, client_info=None):
    try:
        config = ConfigParser.SafeConfigParser()
    except AttributeError:
        config = ConfigParser()
    config.add_section(mount_efs.CONFIG_SECTION)
    config.set(mount_efs.CONFIG_SECTION, "state_file_dir_mode", "0755")
    config.set(
        mount_efs.CONFIG_SECTION,
        "dns_name_format",
        "{fs_id}.efs.{region}.amazonaws.com",
    )
    config.add_section(watchdog.CONFIG_SECTION)
    config.set(
        watchdog.CONFIG_SECTION,
        "tls_cert_renewal_interval_min",
        str(certificate_renewal_interval),
    )
    if client_info:
        config.add_section(watchdog.CLIENT_INFO_SECTION)
        for key, value in client_info.items():
            config.set(watchdog.CLIENT_INFO_SECTION, key, value)
    return config


def _get_mock_private_key_path(mocker, tmpdir):
    pk_path = os.path.join(str(tmpdir), "privateKey.pem")
    mocker.patch("mount_efs.get_private_key_path", return_value=pk_path)
    mocker.patch("watchdog.get_private_key_path", return_value=pk_path)
    return pk_path


def _create_certificate_and_state(
    tls_dict,
    temp_dir,
    pk_path,
    timestamp,
    security_credentials=None,
    credentials_source=None,
    ap_id=None,
    remove_cert=False,
    client_info=None,
):
    config = _get_config()
    good_ap_id = AP_ID if ap_id else None
    mount_efs.create_certificate(
        config,
        MOUNT_NAME,
        COMMON_NAME,
        REGION,
        FS_ID,
        security_credentials,
        good_ap_id,
        client_info,
        base_path=str(temp_dir),
    )

    assert os.path.exists(pk_path)
    assert os.path.exists(os.path.join(tls_dict["mount_dir"], "request.csr"))
    assert os.path.exists(os.path.join(tls_dict["mount_dir"], "certificate.pem"))

    public_key_present = (
        os.path.exists(os.path.join(tls_dict["mount_dir"], "publicKey.pem"))
        if security_credentials
        else not os.path.exists(os.path.join(tls_dict["mount_dir"], "publicKey.pem"))
    )
    assert public_key_present

    state = {
        "pid": PID,
        "commonName": COMMON_NAME,
        "certificate": os.path.join(tls_dict["mount_dir"], "certificate.pem"),
        "certificateCreationTime": timestamp,
        "mountStateDir": MOUNT_NAME,
        "region": REGION,
        "fsId": FS_ID,
        "privateKey": pk_path,
    }

    if credentials_source:
        state["awsCredentialsMethod"] = credentials_source

    if ap_id:
        state["accessPoint"] = ap_id

    with open(os.path.join(temp_dir, STATE_FILE), "w+") as f:
        f.write(json.dumps(state))

    if remove_cert:
        os.remove(os.path.join(tls_dict["mount_dir"], "certificate.pem"))
        assert not os.path.exists(
            os.path.join(tls_dict["mount_dir"], "certificate.pem")
        )

    return state


def _create_ca_conf_helper(
    mocker, tmpdir, current_time, iam=True, ap=True, client_info=True
):
    config = _get_config()
    tls_dict = mount_efs.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    mount_efs.create_required_directory({}, tls_dict["mount_dir"])
    tls_dict["certificate_path"] = os.path.join(tls_dict["mount_dir"], "config.conf")
    tls_dict["private_key"] = os.path.join(tls_dict["mount_dir"], "privateKey.pem")
    tls_dict["public_key"] = os.path.join(tls_dict["mount_dir"], "publicKey.pem")

    if iam:
        with open(tls_dict["public_key"], "w") as f:
            f.write(PUBLIC_KEY_BODY)

    mocker.patch("watchdog.get_aws_security_credentials", return_value=CREDENTIALS)
    credentials = "dummy:lookup" if iam else None
    ap_id = AP_ID if ap else None
    client_info = CLIENT_INFO if client_info else None
    full_config_body = watchdog.create_ca_conf(
        config,
        tls_dict["certificate_path"],
        COMMON_NAME,
        tls_dict["mount_dir"],
        tls_dict["private_key"],
        current_time,
        REGION,
        FS_ID,
        credentials,
        ap_id,
        client_info,
    )
    assert os.path.exists(tls_dict["certificate_path"])

    return tls_dict, full_config_body


def _test_refresh_certificate_helper(
    mocker,
    tmpdir,
    caplog,
    minutes_back,
    renewal_interval=60,
    with_iam=True,
    with_ap=True,
):
    mocker.patch("watchdog.get_utc_now", return_value=FIXED_DT)
    config = _get_config(certificate_renewal_interval=renewal_interval)
    pk_path = _get_mock_private_key_path(mocker, tmpdir)
    minutes_back = (FIXED_DT - timedelta(minutes=minutes_back)).strftime(DT_PATTERN)
    tls_dict = watchdog.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))

    if not with_iam and with_ap:
        state = _create_certificate_and_state(
            tls_dict, str(tmpdir), pk_path, minutes_back, ap_id=AP_ID
        )
    elif with_iam and not with_ap:
        state = _create_certificate_and_state(
            tls_dict,
            str(tmpdir),
            pk_path,
            minutes_back,
            security_credentials=CREDENTIALS,
            credentials_source=CREDENTIALS_SOURCE,
        )
    else:
        state = _create_certificate_and_state(
            tls_dict,
            str(tmpdir),
            pk_path,
            minutes_back,
            security_credentials=CREDENTIALS,
            credentials_source=CREDENTIALS_SOURCE,
            ap_id=AP_ID,
        )

    watchdog.check_certificate(
        config, state, str(tmpdir), STATE_FILE, base_path=str(tmpdir)
    )

    with open(os.path.join(str(tmpdir), STATE_FILE), "r") as state_json:
        state = json.load(state_json)

    if not with_iam and with_ap:
        assert state["accessPoint"] == AP_ID
        assert not state.get("awsCredentialsMethod")
        assert not os.path.exists(os.path.join(tls_dict["mount_dir"], "publicKey.pem"))
    elif with_iam and not with_ap:
        assert "accessPoint" not in state
        assert state["awsCredentialsMethod"] == CREDENTIALS_SOURCE
        assert os.path.exists(os.path.join(tls_dict["mount_dir"], "publicKey.pem"))
    else:
        assert state["accessPoint"] == AP_ID
        assert state["awsCredentialsMethod"] == CREDENTIALS_SOURCE
        assert os.path.exists(os.path.join(tls_dict["mount_dir"], "publicKey.pem"))

    assert datetime.strptime(
        state["certificateCreationTime"], DT_PATTERN
    ) > datetime.strptime(minutes_back, DT_PATTERN)
    assert os.path.exists(pk_path)
    assert os.path.exists(os.path.join(tls_dict["mount_dir"], "request.csr"))
    assert os.path.exists(os.path.join(tls_dict["mount_dir"], "certificate.pem"))

    return caplog


def test_do_not_refresh_self_signed_certificate(mocker, tmpdir):
    mocker.patch("watchdog.get_utc_now", return_value=FIXED_DT)
    config = _get_config()
    pk_path = _get_mock_private_key_path(mocker, tmpdir)
    current_time_formatted = FIXED_DT.strftime(DT_PATTERN)
    tls_dict = watchdog.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    state = _create_certificate_and_state(
        tls_dict, str(tmpdir), pk_path, current_time_formatted, ap_id=AP_ID
    )

    watchdog.check_certificate(
        config, state, str(tmpdir), STATE_FILE, base_path=str(tmpdir)
    )

    with open(os.path.join(str(tmpdir), STATE_FILE), "r") as state_json:
        state = json.load(state_json)

    assert datetime.strptime(
        state["certificateCreationTime"], DT_PATTERN
    ) == datetime.strptime(current_time_formatted, DT_PATTERN)
    assert state["accessPoint"] == AP_ID
    assert not state.get("awsCredentialsMethod")
    assert os.path.exists(pk_path)
    assert not os.path.exists(os.path.join(tls_dict["mount_dir"], "publicKey.pem"))
    assert os.path.exists(os.path.join(tls_dict["mount_dir"], "request.csr"))
    assert os.path.exists(os.path.join(tls_dict["mount_dir"], "certificate.pem"))


def test_do_not_refresh_self_signed_certificate_bad_ap_id_incorrect_start(
    mocker, tmpdir, caplog
):
    caplog.set_level(logging.ERROR)
    mocker.patch("watchdog.get_utc_now", return_value=FIXED_DT)
    config = _get_config()
    pk_path = _get_mock_private_key_path(mocker, tmpdir)
    four_hours_back = (FIXED_DT - timedelta(hours=4)).strftime(DT_PATTERN)
    tls_dict = watchdog.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    state = _create_certificate_and_state(
        tls_dict,
        str(tmpdir),
        pk_path,
        four_hours_back,
        ap_id=BAD_AP_ID_INCORRECT_START,
        remove_cert=True,
    )

    watchdog.check_certificate(
        config, state, str(tmpdir), STATE_FILE, base_path=str(tmpdir)
    )

    assert datetime.strptime(
        state["certificateCreationTime"], DT_PATTERN
    ) == datetime.strptime(four_hours_back, DT_PATTERN)
    assert not state["accessPoint"] == AP_ID
    assert (
        'Access Point ID "%s" has been changed in the state file to a malformed format'
        % BAD_AP_ID_INCORRECT_START
        in caplog.text
    )


def test_do_not_refresh_self_signed_certificate_bad_ap_id_too_short(
    mocker, tmpdir, caplog
):
    caplog.set_level(logging.ERROR)
    mocker.patch("watchdog.get_utc_now", return_value=FIXED_DT)
    config = _get_config()
    pk_path = _get_mock_private_key_path(mocker, tmpdir)
    four_hours_back = (FIXED_DT - timedelta(hours=4)).strftime(DT_PATTERN)
    tls_dict = watchdog.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    state = _create_certificate_and_state(
        tls_dict,
        str(tmpdir),
        pk_path,
        four_hours_back,
        ap_id=BAD_AP_ID_TOO_SHORT,
        remove_cert=True,
    )

    watchdog.check_certificate(
        config, state, str(tmpdir), STATE_FILE, base_path=str(tmpdir)
    )

    assert datetime.strptime(
        state["certificateCreationTime"], DT_PATTERN
    ) == datetime.strptime(four_hours_back, DT_PATTERN)
    assert not state["accessPoint"] == AP_ID
    assert (
        'Access Point ID "%s" has been changed in the state file to a malformed format'
        % BAD_AP_ID_TOO_SHORT
        in caplog.text
    )


def test_do_not_refresh_self_signed_certificate_bad_ap_id_bad_char(
    mocker, tmpdir, caplog
):
    caplog.set_level(logging.ERROR)
    mocker.patch("watchdog.get_utc_now", return_value=FIXED_DT)
    config = _get_config()
    pk_path = _get_mock_private_key_path(mocker, tmpdir)
    four_hours_back = (FIXED_DT - timedelta(hours=4)).strftime(DT_PATTERN)
    tls_dict = watchdog.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    state = _create_certificate_and_state(
        tls_dict,
        str(tmpdir),
        pk_path,
        four_hours_back,
        ap_id=BAD_AP_ID_BAD_CHAR,
        remove_cert=True,
    )

    watchdog.check_certificate(
        config, state, str(tmpdir), STATE_FILE, base_path=str(tmpdir)
    )

    assert datetime.strptime(
        state["certificateCreationTime"], DT_PATTERN
    ) == datetime.strptime(four_hours_back, DT_PATTERN)
    assert not state["accessPoint"] == AP_ID
    assert (
        'Access Point ID "%s" has been changed in the state file to a malformed format'
        % BAD_AP_ID_BAD_CHAR
        in caplog.text
    )


def test_recreate_missing_self_signed_certificate(mocker, tmpdir):
    mocker.patch("watchdog.get_utc_now", return_value=FIXED_DT)
    config = _get_config()
    pk_path = _get_mock_private_key_path(mocker, tmpdir)
    four_hours_back = (FIXED_DT - timedelta(hours=4)).strftime(DT_PATTERN)
    tls_dict = watchdog.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    state = _create_certificate_and_state(
        tls_dict, str(tmpdir), pk_path, four_hours_back, ap_id=AP_ID, remove_cert=True
    )

    watchdog.check_certificate(
        config, state, str(tmpdir), STATE_FILE, base_path=str(tmpdir)
    )

    assert datetime.strptime(
        state["certificateCreationTime"], DT_PATTERN
    ) > datetime.strptime(four_hours_back, DT_PATTERN)

    assert state["accessPoint"] == AP_ID
    assert not state.get("awsCredentialsMethod")
    assert os.path.exists(pk_path)
    assert not os.path.exists(os.path.join(tls_dict["mount_dir"], "publicKey.pem"))
    assert os.path.exists(os.path.join(tls_dict["mount_dir"], "request.csr"))
    assert os.path.exists(os.path.join(tls_dict["mount_dir"], "certificate.pem"))


def test_refresh_self_signed_certificate_without_iam_with_ap_id(mocker, caplog, tmpdir):
    _test_refresh_certificate_helper(mocker, tmpdir, caplog, 240, with_iam=False)


def test_refresh_self_signed_certificate_with_iam_without_ap_id(mocker, caplog, tmpdir):
    _test_refresh_certificate_helper(mocker, tmpdir, caplog, 240, with_ap=False)


def test_refresh_self_signed_certificate_with_iam_with_ap_id(mocker, caplog, tmpdir):
    _test_refresh_certificate_helper(mocker, tmpdir, caplog, 240)


def test_refresh_self_signed_certificate_custom_renewal_interval(
    mocker, caplog, tmpdir
):
    _test_refresh_certificate_helper(mocker, tmpdir, caplog, 45, renewal_interval=30)


def test_refresh_self_signed_certificate_invalid_refresh_interval(
    mocker, caplog, tmpdir
):
    caplog.set_level(logging.WARNING)
    caplog = _test_refresh_certificate_helper(
        mocker, tmpdir, caplog, 240, renewal_interval="not_an_int"
    )

    assert (
        'Bad tls_cert_renewal_interval_min value, "not_an_int", in config file "/etc/amazon/efs/efs-utils.conf". Defaulting'
        " to 60 minutes." in caplog.text
    )


def test_refresh_self_signed_certificate_too_low_refresh_interval(
    mocker, caplog, tmpdir
):
    caplog.set_level(logging.WARNING)
    caplog = _test_refresh_certificate_helper(
        mocker, tmpdir, caplog, 240, renewal_interval=0
    )

    assert (
        'tls_cert_renewal_interval_min value in config file "/etc/amazon/efs/efs-utils.conf" is lower than 1 minute. '
        "Defaulting to 60 minutes." in caplog.text
    )


def test_refresh_self_signed_certificate_send_sighup(mocker, tmpdir, caplog):
    caplog.set_level(logging.INFO)
    process_group = "fake_pg"

    mocker.patch("watchdog.is_mount_stunnel_proc_running", return_value=True)
    mocker.patch("os.getpgid", return_value=process_group)
    mocker.patch("os.killpg")

    config = _get_config()
    pk_path = _get_mock_private_key_path(mocker, tmpdir)
    four_hours_back = (datetime.utcnow() - timedelta(hours=4)).strftime(DT_PATTERN)
    tls_dict = watchdog.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    state = _create_certificate_and_state(
        tls_dict, str(tmpdir), pk_path, four_hours_back, ap_id=AP_ID
    )

    watchdog.check_certificate(
        config, state, str(tmpdir), STATE_FILE, base_path=str(tmpdir)
    )

    # SIGHUP signal is 1
    assert "1" in caplog.text
    assert "PID: %d, group ID: %s" % (PID, process_group) in caplog.text


def test_refresh_self_signed_certificate_pid_not_running(mocker, tmpdir, caplog):
    caplog.set_level(logging.WARN)

    mocker.patch("watchdog.is_mount_stunnel_proc_running", return_value=False)

    config = _get_config()
    pk_path = _get_mock_private_key_path(mocker, tmpdir)
    four_hours_back = (datetime.utcnow() - timedelta(hours=4)).strftime(DT_PATTERN)
    tls_dict = watchdog.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    state = _create_certificate_and_state(
        tls_dict, str(tmpdir), pk_path, four_hours_back, False, ap_id=AP_ID
    )

    watchdog.check_certificate(
        config, state, str(tmpdir), STATE_FILE, base_path=str(tmpdir)
    )

    assert "TLS tunnel is not running for" in caplog.text


def test_create_canonical_request_without_token(mocker):
    mocker.patch("watchdog.get_utc_now", return_value=FIXED_DT)
    public_key_hash = "fake_public_key_hash"
    canonical_request_out = watchdog.create_canonical_request(
        public_key_hash, FIXED_DT, ACCESS_KEY_ID_VAL, REGION, FS_ID
    )

    assert (
        "GET\n/\nAction=Connect&PublicKeyHash=fake_public_key_hash&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential="
        "FAKE_AWS_ACCESS_KEY_ID%2F20000101%2Fus-east-1%2Felasticfilesystem%2Faws4_request&X-Amz-Date=20000101T120000Z&"
        "X-Amz-Expires=86400&X-Amz-SignedHeaders=host\nhost:fs-deadbeef\nhost\n"
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        == canonical_request_out
    )


def test_create_canonical_request_with_token(mocker):
    mocker.patch("watchdog.get_utc_now", return_value=FIXED_DT)
    public_key_hash = "fake_public_key_hash"
    canonical_request_out = watchdog.create_canonical_request(
        public_key_hash, FIXED_DT, ACCESS_KEY_ID_VAL, REGION, FS_ID, SESSION_TOKEN_VAL
    )

    assert (
        "GET\n/\nAction=Connect&PublicKeyHash=fake_public_key_hash&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential="
        "FAKE_AWS_ACCESS_KEY_ID%2F20000101%2Fus-east-1%2Felasticfilesystem%2Faws4_request&X-Amz-Date=20000101T120000Z&"
        "X-Amz-Expires=86400&X-Amz-Security-Token=FAKE_SESSION_TOKEN&X-Amz-SignedHeaders=host\nhost:fs-deadbeef\nhost"
        "\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        == canonical_request_out
    )


def test_get_public_key_sha1(tmpdir):
    fake_public_key_filename = "fake_public_key.pem"
    fake_public_key_path = os.path.join(str(tmpdir), fake_public_key_filename)
    tmpdir.join(fake_public_key_filename).write(PUBLIC_KEY_BODY)

    sha1_result = watchdog.get_public_key_sha1(fake_public_key_path)

    assert sha1_result == "d9c2a68f2c4de49982e310d95e539a89abd6bc13"


def test_create_string_to_sign(mocker):
    mocker.patch("watchdog.get_utc_now", return_value=FIXED_DT)
    canonical_request = "canonical_request"

    string_to_sign_output = watchdog.create_string_to_sign(
        canonical_request, FIXED_DT, REGION
    )

    assert (
        "AWS4-HMAC-SHA256\n20000101T120000Z\n20000101/us-east-1/elasticfilesystem/aws4_request\n"
        "572b1e335109068b81e4def81524c5fe5d0e385143b5656cbf2f7c88e5c1a51e"
        == string_to_sign_output
    )


def test_calculate_signature(mocker):
    mocker.patch("watchdog.get_utc_now", return_value=FIXED_DT)
    string_to_sign = "string_to_sign"

    signature_output = watchdog.calculate_signature(
        string_to_sign, FIXED_DT, SECRET_ACCESS_KEY_VAL, REGION
    )

    assert (
        "6aa643803d4a1b07c5ac87bff96347ef28dab1cb5a5c5d63969c90ca11454c4a"
        == signature_output
    )


def test_recreate_certificate_primary_assets_created(mocker, tmpdir):
    config = _get_config()
    pk_path = _get_mock_private_key_path(mocker, tmpdir)
    tls_dict = watchdog.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    watchdog.recreate_certificate(
        config,
        MOUNT_NAME,
        COMMON_NAME,
        FS_ID,
        None,
        AP_ID,
        REGION,
        base_path=str(tmpdir),
    )
    assert os.path.exists(pk_path)
    assert not os.path.exists(os.path.join(tls_dict["mount_dir"], "publicKey.pem"))
    assert os.path.exists(os.path.join(tls_dict["mount_dir"], "request.csr"))
    assert os.path.exists(os.path.join(tls_dict["mount_dir"], "certificate.pem"))


def _test_recreate_certificate_with_valid_client_source_config(
    mocker, tmpdir, client_source
):
    config = _get_config(client_info={"source": client_source})
    pk_path = _get_mock_private_key_path(mocker, tmpdir)
    tls_dict = watchdog.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    tmp_config_path = os.path.join(str(tmpdir), MOUNT_NAME, "tmpConfig")
    current_time = mount_efs.get_utc_now()
    watchdog.recreate_certificate(
        config,
        MOUNT_NAME,
        COMMON_NAME,
        FS_ID,
        CREDENTIALS,
        AP_ID,
        REGION,
        base_path=str(tmpdir),
    )

    expected_client_info = {
        "source": client_source,
        "efs_utils_version": watchdog.VERSION,
    }

    with open(os.path.join(tls_dict["mount_dir"], "config.conf")) as f:
        conf_body = f.read()
        assert conf_body == watchdog.create_ca_conf(
            config,
            tmp_config_path,
            COMMON_NAME,
            tls_dict["mount_dir"],
            pk_path,
            current_time,
            REGION,
            FS_ID,
            CREDENTIALS,
            AP_ID,
            expected_client_info,
        )
    assert os.path.exists(pk_path)
    assert os.path.exists(os.path.join(tls_dict["mount_dir"], "publicKey.pem"))
    assert os.path.exists(os.path.join(tls_dict["mount_dir"], "request.csr"))
    assert os.path.exists(os.path.join(tls_dict["mount_dir"], "certificate.pem"))


def test_recreate_certificate_with_valid_client_source(mocker, tmpdir):
    _test_recreate_certificate_with_valid_client_source_config(mocker, tmpdir, "TEST")


def _test_recreate_certificate_with_invalid_client_source_config(
    mocker, tmpdir, client_source
):
    mocker.patch("watchdog.check_if_running_on_macos", return_value=False)
    config = (
        _get_config(client_info={"source": client_source})
        if client_source
        else _get_config()
    )
    pk_path = _get_mock_private_key_path(mocker, tmpdir)
    tls_dict = watchdog.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    tmp_config_path = os.path.join(str(tmpdir), MOUNT_NAME, "tmpConfig")
    current_time = mount_efs.get_utc_now()
    watchdog.recreate_certificate(
        config,
        MOUNT_NAME,
        COMMON_NAME,
        FS_ID,
        CREDENTIALS,
        AP_ID,
        REGION,
        base_path=str(tmpdir),
    )

    # Any invalid or not given client source should be marked as unknown
    expected_client_info = {"source": "unknown", "efs_utils_version": watchdog.VERSION}

    with open(os.path.join(tls_dict["mount_dir"], "config.conf")) as f:
        conf_body = f.read()
        assert conf_body == watchdog.create_ca_conf(
            config,
            tmp_config_path,
            COMMON_NAME,
            tls_dict["mount_dir"],
            pk_path,
            current_time,
            REGION,
            FS_ID,
            CREDENTIALS,
            AP_ID,
            expected_client_info,
        )
    assert os.path.exists(pk_path)
    assert os.path.exists(os.path.join(tls_dict["mount_dir"], "publicKey.pem"))
    assert os.path.exists(os.path.join(tls_dict["mount_dir"], "request.csr"))
    assert os.path.exists(os.path.join(tls_dict["mount_dir"], "certificate.pem"))


def test_certificate_with_iam_with_ap_with_none_client_source_config(mocker, tmpdir):
    _test_recreate_certificate_with_invalid_client_source_config(mocker, tmpdir, None)


def test_certificate_with_iam_with_ap_with_empty_client_source_config(mocker, tmpdir):
    _test_recreate_certificate_with_invalid_client_source_config(mocker, tmpdir, "")


def test_certificate_with_iam_with_ap_with_long_client_source_config(mocker, tmpdir):
    _test_recreate_certificate_with_invalid_client_source_config(
        mocker, tmpdir, "a" * 101
    )


def test_create_ca_supporting_dirs(tmpdir):
    config = _get_config()
    tls_dict = watchdog.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    watchdog.ca_dirs_check(config, tls_dict["database_dir"], tls_dict["certs_dir"])
    assert os.path.exists(tls_dict["database_dir"])
    assert os.path.exists(tls_dict["certs_dir"])


def test_create_ca_supporting_files(tmpdir):
    config = _get_config()
    tls_dict = watchdog.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    index = tls_dict["index"]
    index_attr = tls_dict["index_attr"]
    serial = tls_dict["serial"]
    rand = tls_dict["rand"]

    watchdog.ca_dirs_check(config, tls_dict["database_dir"], tls_dict["certs_dir"])
    watchdog.ca_supporting_files_check(index, index_attr, serial, rand)
    with open(index_attr, "r") as index_attr_file:
        index_attr_content = index_attr_file.read()
    with open(serial, "r") as serial_file:
        serial_content = serial_file.read()

    assert os.path.exists(index)
    assert os.path.exists(index_attr)
    assert os.path.exists(serial)
    assert os.path.exists(rand)

    assert "unique_subject = no" == index_attr_content
    assert "00" == serial_content


def test_create_ca_conf_with_awsprofile_no_credentials_found(mocker, caplog, tmpdir):
    config = _get_config()
    mocker.patch("watchdog.get_aws_security_credentials", return_value=None)
    watchdog.create_ca_conf(
        config,
        None,
        None,
        str(tmpdir),
        None,
        None,
        None,
        None,
        CREDENTIALS_SOURCE,
        None,
    )
    assert (
        "Failed to retrieve AWS security credentials using lookup method: %s"
        % CREDENTIALS_SOURCE
        in [rec.message for rec in caplog.records][0]
    )


def test_create_ca_conf_without_client_info(mocker, tmpdir):
    current_time = mount_efs.get_utc_now()
    tls_dict, full_config_body = _create_ca_conf_helper(
        mocker, tmpdir, current_time, iam=True, ap=True, client_info=False
    )

    ca_extension_body = (
        "[ v3_ca ]\n"
        "subjectKeyIdentifier = hash\n"
        "1.3.6.1.4.1.4843.7.1 = ASN1:UTF8String:%s\n"
        "1.3.6.1.4.1.4843.7.2 = ASN1:SEQUENCE:efs_client_auth\n"
        "1.3.6.1.4.1.4843.7.3 = ASN1:UTF8String:%s"
    ) % (AP_ID, FS_ID)
    efs_client_auth_body = watchdog.efs_client_auth_builder(
        tls_dict["public_key"],
        CREDENTIALS["AccessKeyId"],
        CREDENTIALS["SecretAccessKey"],
        current_time,
        REGION,
        FS_ID,
        CREDENTIALS["Token"],
    )
    efs_client_info_body = ""
    matching_config_body = watchdog.CA_CONFIG_BODY % (
        tls_dict["mount_dir"],
        tls_dict["private_key"],
        COMMON_NAME,
        ca_extension_body,
        efs_client_auth_body,
        efs_client_info_body,
    )

    assert full_config_body == matching_config_body


def test_create_ca_conf_with_all(mocker, tmpdir):
    current_time = mount_efs.get_utc_now()
    tls_dict, full_config_body = _create_ca_conf_helper(
        mocker, tmpdir, current_time, iam=True, ap=True, client_info=True
    )

    ca_extension_body = (
        "[ v3_ca ]\n"
        "subjectKeyIdentifier = hash\n"
        "1.3.6.1.4.1.4843.7.1 = ASN1:UTF8String:%s\n"
        "1.3.6.1.4.1.4843.7.2 = ASN1:SEQUENCE:efs_client_auth\n"
        "1.3.6.1.4.1.4843.7.3 = ASN1:UTF8String:%s\n"
        "1.3.6.1.4.1.4843.7.4 = ASN1:SEQUENCE:efs_client_info"
    ) % (AP_ID, FS_ID)
    efs_client_auth_body = watchdog.efs_client_auth_builder(
        tls_dict["public_key"],
        CREDENTIALS["AccessKeyId"],
        CREDENTIALS["SecretAccessKey"],
        current_time,
        REGION,
        FS_ID,
        CREDENTIALS["Token"],
    )
    efs_client_info_body = watchdog.efs_client_info_builder(CLIENT_INFO)
    matching_config_body = watchdog.CA_CONFIG_BODY % (
        tls_dict["mount_dir"],
        tls_dict["private_key"],
        COMMON_NAME,
        ca_extension_body,
        efs_client_auth_body,
        efs_client_info_body,
    )

    assert full_config_body == matching_config_body


def test_create_ca_conf_with_iam_no_accesspoint(mocker, tmpdir):
    current_time = mount_efs.get_utc_now()
    tls_dict, full_config_body = _create_ca_conf_helper(
        mocker, tmpdir, current_time, iam=True, ap=False, client_info=True
    )

    ca_extension_body = (
        "[ v3_ca ]\n"
        "subjectKeyIdentifier = hash\n"
        "1.3.6.1.4.1.4843.7.2 = ASN1:SEQUENCE:efs_client_auth\n"
        "1.3.6.1.4.1.4843.7.3 = ASN1:UTF8String:%s\n"
        "1.3.6.1.4.1.4843.7.4 = ASN1:SEQUENCE:efs_client_info"
    ) % (FS_ID)
    efs_client_auth_body = watchdog.efs_client_auth_builder(
        tls_dict["public_key"],
        CREDENTIALS["AccessKeyId"],
        CREDENTIALS["SecretAccessKey"],
        current_time,
        REGION,
        FS_ID,
        CREDENTIALS["Token"],
    )
    efs_client_info_body = watchdog.efs_client_info_builder(CLIENT_INFO)
    matching_config_body = watchdog.CA_CONFIG_BODY % (
        tls_dict["mount_dir"],
        tls_dict["private_key"],
        COMMON_NAME,
        ca_extension_body,
        efs_client_auth_body,
        efs_client_info_body,
    )

    assert full_config_body == matching_config_body


def test_create_ca_conf_with_accesspoint_no_iam(mocker, tmpdir):
    current_time = mount_efs.get_utc_now()
    tls_dict, full_config_body = _create_ca_conf_helper(
        mocker, tmpdir, current_time, iam=False, ap=True, client_info=True
    )

    ca_extension_body = (
        "[ v3_ca ]\n"
        "subjectKeyIdentifier = hash\n"
        "1.3.6.1.4.1.4843.7.1 = ASN1:UTF8String:%s\n"
        "1.3.6.1.4.1.4843.7.3 = ASN1:UTF8String:%s\n"
        "1.3.6.1.4.1.4843.7.4 = ASN1:SEQUENCE:efs_client_info"
    ) % (AP_ID, FS_ID)
    efs_client_auth_body = ""
    efs_client_info_body = watchdog.efs_client_info_builder(CLIENT_INFO)
    matching_config_body = watchdog.CA_CONFIG_BODY % (
        tls_dict["mount_dir"],
        tls_dict["private_key"],
        COMMON_NAME,
        ca_extension_body,
        efs_client_auth_body,
        efs_client_info_body,
    )

    assert full_config_body == matching_config_body


def test_check_and_create_private_key_key_was_empty(mocker, tmpdir):
    pk_path = _get_mock_private_key_path(mocker, tmpdir)
    with open(pk_path, "w") as pk_file:
        pass

    state_file_dir = str(tmpdir)
    watchdog.check_and_create_private_key(state_file_dir)
    assert os.path.getsize(pk_path) > 0


def test_check_and_create_private_key_key_already_exists(mocker, tmpdir):
    pk_path = _get_mock_private_key_path(mocker, tmpdir)
    with open(pk_path, "w") as pk_file:
        pk_file.write("private key file contents")

    call_mock = mocker.patch("watchdog.subprocess_call")

    state_file_dir = str(tmpdir)
    watchdog.check_and_create_private_key(state_file_dir)
    assert call_mock.call_count == 0
