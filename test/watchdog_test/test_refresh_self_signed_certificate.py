#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import mount_efs
import watchdog

import logging
import json
import os

import pytest

from mock import MagicMock

from datetime import datetime, timedelta

DT_PATTERN = watchdog.CERT_DATETIME_FORMAT
FS_ID = 'fs-deadbeef'
COMMON_NAME = 'fs-deadbeef.efs.us-east-1.amazonaws.com'
PID = 1234
STATE_FILE = 'stunnel-config.fs-deadbeef.mount.dir.12345'
MOUNT_NAME = 'fs-deadbeef.mount.dir.12345'
REGION = 'us-east-1'
AP_ID = 'fsap-0123456789abcdef0'
BAD_AP_ID_INCORRECT_START = 'bad-fsap-0123456789abc'
BAD_AP_ID_TOO_SHORT = 'fsap-0123456789abcdef'
BAD_AP_ID_BAD_CHAR = 'fsap-0123456789abcdefg'
ACCESS_KEY_ID_VAL = 'FAKE_AWS_ACCESS_KEY_ID'
SECRET_ACCESS_KEY_VAL = 'FAKE_AWS_SECRET_ACCESS_KEY'
SESSION_TOKEN_VAL = 'FAKE_SESSION_TOKEN'
FIXED_DT = datetime(2000, 1, 1, 12, 0, 0)
CREDENTIALS = {
    'AccessKeyId': ACCESS_KEY_ID_VAL,
    'SecretAccessKey': SECRET_ACCESS_KEY_VAL,
    'Token': SESSION_TOKEN_VAL
}


@pytest.fixture(autouse=True)
def setup(mocker):
    mocker.patch('socket.gethostbyname')
    mocker.patch('mount_efs.get_region', return_value=REGION)
    mocker.patch('mount_efs.get_region_helper', return_value=REGION)
    mocker.patch('mount_efs.get_aws_security_credentials', return_value=CREDENTIALS)
    mocker.patch('watchdog.get_aws_security_credentials', return_value=CREDENTIALS)


def _get_config(dns_name_format='{fs_id}.efs.{region}.amazonaws.com'):
    def config_get_side_effect(section, field):
        if field == 'state_file_dir_mode':
            return '0755'
        elif field == 'dns_name_format':
            return dns_name_format
        else:
            raise ValueError('Unexpected arguments')

    mock_config = MagicMock()
    mock_config.get.side_effect = config_get_side_effect
    return mock_config


def _get_mock_private_key_path(mocker, tmpdir):
    pk_path = os.path.join(str(tmpdir), 'privateKey.pem')
    mocker.patch('mount_efs.get_private_key_path', return_value=pk_path)
    mocker.patch('watchdog.get_private_key_path', return_value=pk_path)
    return pk_path


def _create_certificate_and_state(tls_dict, temp_dir, pk_path, timestamp, iam, ap_id=None, remove_cert=False):
    config = _get_config()
    good_ap_id = AP_ID if ap_id else None
    mount_efs.create_certificate(config, MOUNT_NAME, COMMON_NAME, REGION, FS_ID, iam, good_ap_id, base_path=str(temp_dir))

    assert os.path.exists(pk_path)
    assert os.path.exists(os.path.join(tls_dict['mount_dir'], 'request.csr'))
    assert os.path.exists(os.path.join(tls_dict['mount_dir'], 'certificate.pem'))

    public_key_present = os.path.exists(os.path.join(tls_dict['mount_dir'], 'publicKey.pem')) if iam \
        else not os.path.exists(os.path.join(tls_dict['mount_dir'], 'publicKey.pem'))
    assert public_key_present

    state = {
        'pid': PID,
        'commonName': COMMON_NAME,
        'certificate': os.path.join(tls_dict['mount_dir'], 'certificate.pem'),
        'certificateCreationTime': timestamp,
        'mountStateDir': MOUNT_NAME,
        'region': REGION,
        'fsId': FS_ID,
        'useIam': iam,
        'privateKey': pk_path,
    }

    if ap_id:
        state['accessPoint'] = ap_id

    with open(os.path.join(temp_dir, STATE_FILE), 'w+') as f:
        f.write(json.dumps(state))

    if remove_cert:
        os.remove(os.path.join(tls_dict['mount_dir'], 'certificate.pem'))
        assert not os.path.exists(os.path.join(tls_dict['mount_dir'], 'certificate.pem'))

    return state


def test_do_not_refresh_self_signed_certificate(mocker, tmpdir):
    mocker.patch('watchdog.get_utc_now', return_value=FIXED_DT)
    config = _get_config()
    pk_path = _get_mock_private_key_path(mocker, tmpdir)
    current_time_formatted = FIXED_DT.strftime(DT_PATTERN)
    tls_dict = watchdog.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    state = _create_certificate_and_state(tls_dict, str(tmpdir), pk_path, current_time_formatted, False, ap_id=AP_ID)

    watchdog.check_certificate(config, state, str(tmpdir), STATE_FILE, base_path=str(tmpdir))

    with open(os.path.join(str(tmpdir), STATE_FILE), 'r') as state_json:
        state = json.load(state_json)

    assert datetime.strptime(state['certificateCreationTime'], DT_PATTERN) == datetime.strptime(current_time_formatted,
                                                                                                DT_PATTERN)
    assert state['accessPoint'] == AP_ID
    assert state['useIam'] is False
    assert os.path.exists(pk_path)
    assert not os.path.exists(os.path.join(tls_dict['mount_dir'], 'publicKey.pem'))
    assert os.path.exists(os.path.join(tls_dict['mount_dir'], 'request.csr'))
    assert os.path.exists(os.path.join(tls_dict['mount_dir'], 'certificate.pem'))


def test_do_not_refresh_self_signed_certificate_bad_ap_id_incorrect_start(mocker, tmpdir, caplog):
    caplog.set_level(logging.ERROR)
    mocker.patch('watchdog.get_utc_now', return_value=FIXED_DT)
    config = _get_config()
    pk_path = _get_mock_private_key_path(mocker, tmpdir)
    four_hours_back = (FIXED_DT - timedelta(hours=4)).strftime(DT_PATTERN)
    tls_dict = watchdog.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    state = _create_certificate_and_state(tls_dict, str(tmpdir), pk_path, four_hours_back, False, ap_id=BAD_AP_ID_INCORRECT_START,
                                          remove_cert=True)

    watchdog.check_certificate(config, state, str(tmpdir), STATE_FILE, base_path=str(tmpdir))

    assert datetime.strptime(state['certificateCreationTime'], DT_PATTERN) == datetime.strptime(four_hours_back, DT_PATTERN)
    assert not state['accessPoint'] == AP_ID
    assert 'Access Point ID "%s" has been changed in the state file to a malformed format' \
           % BAD_AP_ID_INCORRECT_START in caplog.text


def test_do_not_refresh_self_signed_certificate_bad_ap_id_too_short(mocker, tmpdir, caplog):
    caplog.set_level(logging.ERROR)
    mocker.patch('watchdog.get_utc_now', return_value=FIXED_DT)
    config = _get_config()
    pk_path = _get_mock_private_key_path(mocker, tmpdir)
    four_hours_back = (FIXED_DT - timedelta(hours=4)).strftime(DT_PATTERN)
    tls_dict = watchdog.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    state = _create_certificate_and_state(tls_dict, str(tmpdir), pk_path, four_hours_back, False, ap_id=BAD_AP_ID_TOO_SHORT,
                                          remove_cert=True)

    watchdog.check_certificate(config, state, str(tmpdir), STATE_FILE, base_path=str(tmpdir))

    assert datetime.strptime(state['certificateCreationTime'], DT_PATTERN) == datetime.strptime(four_hours_back, DT_PATTERN)
    assert not state['accessPoint'] == AP_ID
    assert 'Access Point ID "%s" has been changed in the state file to a malformed format' % BAD_AP_ID_TOO_SHORT in caplog.text


def test_do_not_refresh_self_signed_certificate_bad_ap_id_bad_char(mocker, tmpdir, caplog):
    caplog.set_level(logging.ERROR)
    mocker.patch('watchdog.get_utc_now', return_value=FIXED_DT)
    config = _get_config()
    pk_path = _get_mock_private_key_path(mocker, tmpdir)
    four_hours_back = (FIXED_DT - timedelta(hours=4)).strftime(DT_PATTERN)
    tls_dict = watchdog.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    state = _create_certificate_and_state(tls_dict, str(tmpdir), pk_path, four_hours_back, False, ap_id=BAD_AP_ID_BAD_CHAR,
                                          remove_cert=True)

    watchdog.check_certificate(config, state, str(tmpdir), STATE_FILE, base_path=str(tmpdir))

    assert datetime.strptime(state['certificateCreationTime'], DT_PATTERN) == datetime.strptime(four_hours_back, DT_PATTERN)
    assert not state['accessPoint'] == AP_ID
    assert 'Access Point ID "%s" has been changed in the state file to a malformed format' % BAD_AP_ID_BAD_CHAR in caplog.text


def test_recreate_missing_self_signed_certificate(mocker, tmpdir):
    mocker.patch('watchdog.get_utc_now', return_value=FIXED_DT)
    config = _get_config()
    pk_path = _get_mock_private_key_path(mocker, tmpdir)
    four_hours_back = (FIXED_DT - timedelta(hours=4)).strftime(DT_PATTERN)
    tls_dict = watchdog.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    state = _create_certificate_and_state(tls_dict, str(tmpdir), pk_path, four_hours_back, False, ap_id=AP_ID, remove_cert=True)

    watchdog.check_certificate(config, state, str(tmpdir), STATE_FILE, base_path=str(tmpdir))

    assert datetime.strptime(state['certificateCreationTime'], DT_PATTERN) > datetime.strptime(four_hours_back, DT_PATTERN)

    assert state['accessPoint'] == AP_ID
    assert state['useIam'] is False
    assert os.path.exists(pk_path)
    assert not os.path.exists(os.path.join(tls_dict['mount_dir'], 'publicKey.pem'))
    assert os.path.exists(os.path.join(tls_dict['mount_dir'], 'request.csr'))
    assert os.path.exists(os.path.join(tls_dict['mount_dir'], 'certificate.pem'))


def test_refresh_self_signed_certificate_without_iam_with_ap_id(mocker, tmpdir):
    mocker.patch('watchdog.get_utc_now', return_value=FIXED_DT)
    config = _get_config()
    pk_path = _get_mock_private_key_path(mocker, tmpdir)
    four_hours_back = (FIXED_DT - timedelta(hours=4)).strftime(DT_PATTERN)
    tls_dict = watchdog.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    state = _create_certificate_and_state(tls_dict, str(tmpdir), pk_path, four_hours_back, False, ap_id=AP_ID)

    watchdog.check_certificate(config, state, str(tmpdir), STATE_FILE, base_path=str(tmpdir))

    with open(os.path.join(str(tmpdir), STATE_FILE), 'r') as state_json:
        state = json.load(state_json)

    assert datetime.strptime(state['certificateCreationTime'], DT_PATTERN) > datetime.strptime(four_hours_back, DT_PATTERN)
    assert state['accessPoint'] == AP_ID
    assert state['useIam'] is False
    assert os.path.exists(pk_path)
    assert not os.path.exists(os.path.join(tls_dict['mount_dir'], 'publicKey.pem'))
    assert os.path.exists(os.path.join(tls_dict['mount_dir'], 'request.csr'))
    assert os.path.exists(os.path.join(tls_dict['mount_dir'], 'certificate.pem'))


def test_refresh_self_signed_certificate_with_iam_without_ap_id(mocker, tmpdir):
    mocker.patch('watchdog.get_utc_now', return_value=FIXED_DT)
    config = _get_config()
    pk_path = _get_mock_private_key_path(mocker, tmpdir)
    four_hours_back = (FIXED_DT - timedelta(hours=4)).strftime(DT_PATTERN)
    tls_dict = watchdog.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    state = _create_certificate_and_state(tls_dict, str(tmpdir), pk_path, four_hours_back, True)

    watchdog.check_certificate(config, state, str(tmpdir), STATE_FILE, base_path=str(tmpdir))

    with open(os.path.join(str(tmpdir), STATE_FILE), 'r') as state_json:
        state = json.load(state_json)

    assert datetime.strptime(state['certificateCreationTime'], DT_PATTERN) > datetime.strptime(four_hours_back, DT_PATTERN)
    assert 'accessPoint' not in state
    assert state['useIam'] is True
    assert os.path.exists(pk_path)
    assert os.path.exists(os.path.join(tls_dict['mount_dir'], 'publicKey.pem'))
    assert os.path.exists(os.path.join(tls_dict['mount_dir'], 'request.csr'))
    assert os.path.exists(os.path.join(tls_dict['mount_dir'], 'certificate.pem'))


def test_refresh_self_signed_certificate_with_iam_with_ap_id(mocker, tmpdir):
    mocker.patch('watchdog.get_utc_now', return_value=FIXED_DT)
    config = _get_config()
    pk_path = _get_mock_private_key_path(mocker, tmpdir)
    four_hours_back = (FIXED_DT - timedelta(hours=4)).strftime(DT_PATTERN)
    tls_dict = watchdog.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    state = _create_certificate_and_state(tls_dict, str(tmpdir), pk_path, four_hours_back, True, ap_id=AP_ID)

    watchdog.check_certificate(config, state, str(tmpdir), STATE_FILE, base_path=str(tmpdir))

    with open(os.path.join(str(tmpdir), STATE_FILE), 'r') as state_json:
        state = json.load(state_json)

    assert datetime.strptime(state['certificateCreationTime'], DT_PATTERN) > datetime.strptime(four_hours_back, DT_PATTERN)
    assert state['accessPoint'] == AP_ID
    assert state['useIam'] is True
    assert os.path.exists(pk_path)
    assert os.path.exists(os.path.join(tls_dict['mount_dir'], 'publicKey.pem'))
    assert os.path.exists(os.path.join(tls_dict['mount_dir'], 'request.csr'))
    assert os.path.exists(os.path.join(tls_dict['mount_dir'], 'certificate.pem'))


def test_refresh_self_signed_certificate_send_sighup(mocker, tmpdir, caplog):
    caplog.set_level(logging.INFO)
    process_group = 'fake_pg'

    mocker.patch('watchdog.is_pid_running', return_value=True)
    mocker.patch('os.getpgid', return_value=process_group)
    mocker.patch('os.killpg')

    config = _get_config()
    pk_path = _get_mock_private_key_path(mocker, tmpdir)
    four_hours_back = (datetime.utcnow() - timedelta(hours=4)).strftime(DT_PATTERN)
    tls_dict = watchdog.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    state = _create_certificate_and_state(tls_dict, str(tmpdir), pk_path, four_hours_back, False, ap_id=AP_ID)

    watchdog.check_certificate(config, state, str(tmpdir), STATE_FILE, base_path=str(tmpdir))

    assert 'SIGHUP signal to stunnel. PID: %d, group ID: %s' % (PID, process_group) in caplog.text


def test_refresh_self_signed_certificate_pid_not_running(mocker, tmpdir, caplog):
    caplog.set_level(logging.WARN)

    mocker.patch('watchdog.is_pid_running', return_value=False)

    config = _get_config()
    pk_path = _get_mock_private_key_path(mocker, tmpdir)
    four_hours_back = (datetime.utcnow() - timedelta(hours=4)).strftime(DT_PATTERN)
    tls_dict = watchdog.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    state = _create_certificate_and_state(tls_dict, str(tmpdir), pk_path, four_hours_back, False, ap_id=AP_ID)

    watchdog.check_certificate(config, state, str(tmpdir), STATE_FILE, base_path=str(tmpdir))

    assert 'TLS tunnel is not running for' in caplog.text


def test_create_canonical_request_without_token(mocker):
    mocker.patch('watchdog.get_utc_now', return_value=FIXED_DT)
    public_key_hash = 'fake_public_key_hash'
    canonical_request_out = watchdog.create_canonical_request(public_key_hash, FIXED_DT, ACCESS_KEY_ID_VAL, REGION, FS_ID)

    assert 'GET\n/\nAction=Connect&PublicKeyHash=fake_public_key_hash&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=' \
           'FAKE_AWS_ACCESS_KEY_ID%2F20000101%2Fus-east-1%2Felasticfilesystem%2Faws4_request&X-Amz-Date=20000101T120000Z&' \
           'X-Amz-Expires=86400&X-Amz-SignedHeaders=host\nhost:fs-deadbeef\nhost\n' \
           'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' == canonical_request_out


def test_create_canonical_request_with_token(mocker):
    mocker.patch('watchdog.get_utc_now', return_value=FIXED_DT)
    public_key_hash = 'fake_public_key_hash'
    canonical_request_out = watchdog.create_canonical_request(public_key_hash, FIXED_DT, ACCESS_KEY_ID_VAL, REGION, FS_ID,
                                                              SESSION_TOKEN_VAL)

    assert 'GET\n/\nAction=Connect&PublicKeyHash=fake_public_key_hash&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=' \
           'FAKE_AWS_ACCESS_KEY_ID%2F20000101%2Fus-east-1%2Felasticfilesystem%2Faws4_request&X-Amz-Date=20000101T120000Z&' \
           'X-Amz-Expires=86400&X-Amz-Security-Token=FAKE_SESSION_TOKEN&X-Amz-SignedHeaders=host\nhost:fs-deadbeef\nhost' \
           '\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' == canonical_request_out


def test_get_public_key_sha1(tmpdir):
    fake_public_key_filename = 'fake_public_key.pem'
    fake_public_key_path = os.path.join(str(tmpdir), fake_public_key_filename)
    public_key_body = '-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEArGJgJTTwefL+jHV8A9EM\npX56n3Z' \
                      'JczM+4iPPSnledJzBcUO1VF+j6TOzy39BWBtvRjSs0nqd5wqw+1xHawhh\ndJF5KsqMNGcP/y9fLi9Bm1vInHfQVan4NhXWh8S' \
                      'NbRZM1tNZV5/k+VnFur6ACHwq\neWppGXkGBASL0zG0MiCbOVMkwfv/E69APVC6ljnPXBWaDuggAClYheTv5RIU4wD1\nc1nohR' \
                      'b0ZHyfZjELjnqLfY0eOqY+msQXzP0eUmZXCMvUkGxi5DJnNVKhw5y96QbB\nRFO5ImQXpNsQmp8F9Ih1RIxNsl4csaEuK+/Zo' \
                      'J68vR47oQNtPp1PjdIwcnQ3cOvO\nHMxulMX21Fd/e9TsnqISOTOyebmYFgaHczg4JVu5lV699+7QWJm1a7M4ab0WgVVR\nz27J0' \
                      'Lx/691MZB4TbGoEIFza30/sk6uTPxAzebzCaroXzT7uA6TIRtRpxt4X9a+4\n6GhfgR5RJfFMb8rPGmaKWqA2YkTsZzRGHhbAzs' \
                      'J/nEstAgMBAAE=\n-----END PUBLIC KEY-----'
    tmpdir.join(fake_public_key_filename).write(public_key_body)

    sha1_result = watchdog.get_public_key_sha1(fake_public_key_path)

    assert sha1_result == 'd9c2a68f2c4de49982e310d95e539a89abd6bc13'


def test_create_string_to_sign(mocker):
    mocker.patch('watchdog.get_utc_now', return_value=FIXED_DT)
    canonical_request = 'canonical_request'

    string_to_sign_output = watchdog.create_string_to_sign(canonical_request, FIXED_DT, REGION)

    assert 'AWS4-HMAC-SHA256\n20000101T120000Z\n20000101/us-east-1/elasticfilesystem/aws4_request\n' \
           '572b1e335109068b81e4def81524c5fe5d0e385143b5656cbf2f7c88e5c1a51e' == string_to_sign_output


def test_calculate_signature(mocker):
    mocker.patch('watchdog.get_utc_now', return_value=FIXED_DT)
    string_to_sign = 'string_to_sign'

    signature_output = watchdog.calculate_signature(string_to_sign, FIXED_DT, SECRET_ACCESS_KEY_VAL, REGION)

    assert '6aa643803d4a1b07c5ac87bff96347ef28dab1cb5a5c5d63969c90ca11454c4a' == signature_output


def test_recreate_certificate_primary_assets_created(mocker, tmpdir):
    config = _get_config()
    pk_path = _get_mock_private_key_path(mocker, tmpdir)
    tls_dict = watchdog.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    watchdog.recreate_certificate(config, MOUNT_NAME, COMMON_NAME, FS_ID, False, AP_ID, None, REGION, base_path=str(tmpdir))
    assert os.path.exists(pk_path)
    assert not os.path.exists(os.path.join(tls_dict['mount_dir'], 'publicKey.pem'))
    assert os.path.exists(os.path.join(tls_dict['mount_dir'], 'request.csr'))
    assert os.path.exists(os.path.join(tls_dict['mount_dir'], 'certificate.pem'))


def test_create_ca_supporting_dirs(tmpdir):
    config = _get_config()
    tls_dict = watchdog.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    watchdog.ca_dirs_check(config, tls_dict['database_dir'], tls_dict['certs_dir'])
    assert os.path.exists(tls_dict['database_dir'])
    assert os.path.exists(tls_dict['certs_dir'])


def test_create_ca_supporting_files(tmpdir):
    config = _get_config()
    tls_dict = watchdog.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    index = tls_dict['index']
    index_attr = tls_dict['index_attr']
    serial = tls_dict['serial']
    rand = tls_dict['rand']

    watchdog.ca_dirs_check(config, tls_dict['database_dir'], tls_dict['certs_dir'])
    watchdog.ca_supporting_files_check(index, index_attr, serial, rand)
    with open(index_attr, 'r') as index_attr_file:
        index_attr_content = index_attr_file.read()
    with open(serial, 'r') as serial_file:
        serial_content = serial_file.read()

    assert os.path.exists(index)
    assert os.path.exists(index_attr)
    assert os.path.exists(serial)
    assert os.path.exists(rand)

    assert 'unique_subject = no' == index_attr_content
    assert '00' == serial_content


def test_create_ca_conf_with_awsprofile_no_credentials_found(mocker, caplog, tmpdir):
    mocker.patch('watchdog.get_aws_security_credentials', return_value=None)
    watchdog.create_ca_conf(None, None, str(tmpdir), None, None, None, None, True, awsprofile='test_profile')
    assert 'Failed to retrieve AWS security credentials from named profile "%s"' % 'test_profile' in \
           [rec.message for rec in caplog.records][0]
