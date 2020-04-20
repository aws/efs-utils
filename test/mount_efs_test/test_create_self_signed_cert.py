#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import mount_efs
import os

import pytest

from datetime import datetime
from mock import MagicMock

try:
    import ConfigParser
except ImportError:
    from configparser import ConfigParser

FS_ID = 'fs-deadbeef'
AP_ID = 'fsap-fedcba9876543210'
CLIENT_INFO = {'source': 'test'}
REGION = 'us-east-1'
COMMON_NAME = 'fs-deadbeef.efs.us-east-1.amazonaws.com'
MOUNT_NAME = 'fs-deadbeef.mount.dir.12345'
ACCESS_KEY_ID_VAL = 'FAKE_AWS_ACCESS_KEY_ID'
SECRET_ACCESS_KEY_VAL = 'FAKE_AWS_SECRET_ACCESS_KEY'
SESSION_TOKEN_VAL = 'FAKE_SESSION_TOKEN'
CREDENTIALS = {
    'AccessKeyId': ACCESS_KEY_ID_VAL,
    'SecretAccessKey': SECRET_ACCESS_KEY_VAL,
    'Token': SESSION_TOKEN_VAL
}
FIXED_DT = datetime(2000, 1, 1, 12, 0, 0)
PUBLIC_KEY_BODY = '-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEArGJgJTTwefL+jHV8A9EM\npX56n3Z' \
                  'JczM+4iPPSnledJzBcUO1VF+j6TOzy39BWBtvRjSs0nqd5wqw+1xHawhh\ndJF5KsqMNGcP/y9fLi9Bm1vInHfQVan4NhXWh8S' \
                  'NbRZM1tNZV5/k+VnFur6ACHwq\neWppGXkGBASL0zG0MiCbOVMkwfv/E69APVC6ljnPXBWaDuggAClYheTv5RIU4wD1\nc1nohR' \
                  'b0ZHyfZjELjnqLfY0eOqY+msQXzP0eUmZXCMvUkGxi5DJnNVKhw5y96QbB\nRFO5ImQXpNsQmp8F9Ih1RIxNsl4csaEuK+/Zo' \
                  'J68vR47oQNtPp1PjdIwcnQ3cOvO\nHMxulMX21Fd/e9TsnqISOTOyebmYFgaHczg4JVu5lV699+7QWJm1a7M4ab0WgVVR\nz27J0' \
                  'Lx/691MZB4TbGoEIFza30/sk6uTPxAzebzCaroXzT7uA6TIRtRpxt4X9a+4\n6GhfgR5RJfFMb8rPGmaKWqA2YkTsZzRGHhbAzs' \
                  'J/nEstAgMBAAE=\n-----END PUBLIC KEY-----'


@pytest.fixture(autouse=True)
def setup_method(mocker):
    mocker.patch('mount_efs.get_region_from_instance_metadata', return_value=REGION)
    mocker.patch('mount_efs.get_target_region', return_value=REGION)
    mocker.patch('mount_efs.get_aws_security_credentials', return_value=CREDENTIALS)
    mocker.patch('mount_efs.get_utc_now', return_value=FIXED_DT)
    mocker.patch('socket.gethostbyname')


def _get_config():
    try:
        config = ConfigParser.SafeConfigParser()
    except AttributeError:
        config = ConfigParser()
    config.add_section(mount_efs.CONFIG_SECTION)
    config.set(mount_efs.CONFIG_SECTION, 'state_file_dir_mode', '750')
    config.set(mount_efs.CONFIG_SECTION, 'dns_name_format', '{fs_id}.efs.{region}.amazonaws.com')
    return config


def _create_ca_conf_helper(tmpdir, current_time, iam=True, ap=True, client_info=True):
    tls_dict = mount_efs.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    mount_efs.create_required_directory({}, tls_dict['mount_dir'])
    tls_dict['certificate_path'] = os.path.join(tls_dict['mount_dir'], 'config.conf')
    tls_dict['private_key'] = os.path.join(tls_dict['mount_dir'], 'privateKey.pem')
    tls_dict['public_key'] = os.path.join(tls_dict['mount_dir'], 'publicKey.pem')

    if iam:
        with open(tls_dict['public_key'], 'w') as f:
            f.write(PUBLIC_KEY_BODY)

    credentials = CREDENTIALS if iam else None
    ap_id = AP_ID if ap else None
    client_info = CLIENT_INFO if client_info else None
    full_config_body = mount_efs.create_ca_conf(tls_dict['certificate_path'], COMMON_NAME, tls_dict['mount_dir'],
                                                tls_dict['private_key'], current_time, REGION, FS_ID, credentials,
                                                ap_id, client_info)
    assert os.path.exists(tls_dict['certificate_path'])

    return tls_dict, full_config_body


def _get_mock_config(dns_name_format='{fs_id}.efs.{region}.amazonaws.com', client_info=CLIENT_INFO):
    def config_get_side_effect(section, field):
        if section == mount_efs.CONFIG_SECTION and field == 'state_file_dir_mode':
            return '0755'
        elif section == mount_efs.CONFIG_SECTION and field == 'dns_name_format':
            return dns_name_format
        elif section == mount_efs.CLIENT_INFO_SECTION and field == 'source':
            return client_info['source']
        else:
            raise ValueError('Unexpected arguments')

    mock_config = MagicMock()
    mock_config.get.side_effect = config_get_side_effect
    return mock_config


def _get_mock_private_key_path(mocker, tmpdir):
    pk_path = os.path.join(str(tmpdir), 'privateKey.pem')
    mocker.patch('mount_efs.get_private_key_path', return_value=pk_path)
    return pk_path  


def test_certificate_without_iam_with_ap_id(mocker, tmpdir):
    config = _get_mock_config()
    pk_path = _get_mock_private_key_path(mocker, tmpdir)
    tls_dict = mount_efs.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    tmp_config_path = os.path.join(str(tmpdir), MOUNT_NAME, 'tmpConfig')
    mount_efs.create_certificate(config, MOUNT_NAME, COMMON_NAME, REGION, FS_ID, None, AP_ID, CLIENT_INFO, base_path=str(tmpdir))
    with open(os.path.join(tls_dict['mount_dir'], 'config.conf')) as f:
        conf_body = f.read()
        assert conf_body == mount_efs.create_ca_conf(tmp_config_path, COMMON_NAME, tls_dict['mount_dir'], pk_path, FIXED_DT, REGION,
                                                     FS_ID, None, AP_ID, CLIENT_INFO)
    assert os.path.exists(pk_path)
    assert not os.path.exists(os.path.join(tls_dict['mount_dir'], 'publicKey.pem'))
    assert os.path.exists(os.path.join(tls_dict['mount_dir'], 'request.csr'))
    assert os.path.exists(os.path.join(tls_dict['mount_dir'], 'certificate.pem'))


def test_certificate_with_iam_with_ap_id(mocker, tmpdir):
    config = _get_mock_config()
    pk_path = _get_mock_private_key_path(mocker, tmpdir)
    tls_dict = mount_efs.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    tmp_config_path = os.path.join(str(tmpdir), MOUNT_NAME, 'tmpConfig')
    mount_efs.create_certificate(config, MOUNT_NAME, COMMON_NAME, REGION, FS_ID, CREDENTIALS, AP_ID, CLIENT_INFO, base_path=str(tmpdir))
    with open(os.path.join(tls_dict['mount_dir'], 'config.conf')) as f:
        conf_body = f.read()
        assert conf_body == mount_efs.create_ca_conf(tmp_config_path, COMMON_NAME, tls_dict['mount_dir'], pk_path, FIXED_DT, REGION,
                                                     FS_ID, CREDENTIALS, AP_ID, CLIENT_INFO)
    assert os.path.exists(pk_path)
    assert os.path.exists(os.path.join(tls_dict['mount_dir'], 'publicKey.pem'))
    assert os.path.exists(os.path.join(tls_dict['mount_dir'], 'request.csr'))
    assert os.path.exists(os.path.join(tls_dict['mount_dir'], 'certificate.pem'))


def _test_certificate_with_iam_with_ap_with_invalid_client_source_config(mocker, tmpdir, client_source):
    config = _get_mock_config(client_info={'source': client_source}) if client_source else _get_config()
    pk_path = _get_mock_private_key_path(mocker, tmpdir)
    tls_dict = mount_efs.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    tmp_config_path = os.path.join(str(tmpdir), MOUNT_NAME, 'tmpConfig')
    mount_efs.create_certificate(config, MOUNT_NAME, COMMON_NAME, REGION, FS_ID, CREDENTIALS, AP_ID, None,
                                 base_path=str(tmpdir))
    with open(os.path.join(tls_dict['mount_dir'], 'config.conf')) as f:
        conf_body = f.read()
        assert conf_body == mount_efs.create_ca_conf(tmp_config_path, COMMON_NAME, tls_dict['mount_dir'], pk_path,
                                                     FIXED_DT, REGION, FS_ID, CREDENTIALS, AP_ID, None)
    assert os.path.exists(pk_path)
    assert os.path.exists(os.path.join(tls_dict['mount_dir'], 'publicKey.pem'))
    assert os.path.exists(os.path.join(tls_dict['mount_dir'], 'request.csr'))
    assert os.path.exists(os.path.join(tls_dict['mount_dir'], 'certificate.pem'))


def test_certificate_with_iam_with_ap_with_empty_client_source_config(mocker, tmpdir):
    _test_certificate_with_iam_with_ap_with_invalid_client_source_config(mocker, tmpdir, None)


def test_certificate_with_iam_with_ap_with_empty_client_source_config(mocker, tmpdir):
    _test_certificate_with_iam_with_ap_with_invalid_client_source_config(mocker, tmpdir, '')


def test_certificate_with_iam_with_ap_with_long_client_source_config(mocker, tmpdir):
    _test_certificate_with_iam_with_ap_with_invalid_client_source_config(mocker, tmpdir, 'a' * 101)


def test_certificate_with_iam_without_ap_id(mocker, tmpdir):
    config = _get_mock_config()
    pk_path = _get_mock_private_key_path(mocker, tmpdir)
    tls_dict = mount_efs.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    tmp_config_path = os.path.join(str(tmpdir), MOUNT_NAME, 'tmpConfig')
    mount_efs.create_certificate(config, MOUNT_NAME, COMMON_NAME, REGION, FS_ID, CREDENTIALS, None, CLIENT_INFO, base_path=str(tmpdir))
    with open(os.path.join(tls_dict['mount_dir'], 'config.conf')) as f:
        conf_body = f.read()
        assert conf_body == mount_efs.create_ca_conf(tmp_config_path, COMMON_NAME, tls_dict['mount_dir'], pk_path, FIXED_DT, REGION,
                                                     FS_ID, CREDENTIALS, None, CLIENT_INFO)
    assert os.path.exists(pk_path)
    assert os.path.exists(os.path.join(tls_dict['mount_dir'], 'publicKey.pem'))
    assert os.path.exists(os.path.join(tls_dict['mount_dir'], 'request.csr'))
    assert os.path.exists(os.path.join(tls_dict['mount_dir'], 'certificate.pem'))


def test_certificate_without_iam_without_ap_id_without_client_source(mocker, tmpdir):
    config = _get_config()
    pk_path = _get_mock_private_key_path(mocker, tmpdir)
    tls_dict = mount_efs.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    tmp_config_path = os.path.join(str(tmpdir), MOUNT_NAME, 'tmpConfig')
    mount_efs.create_certificate(config, MOUNT_NAME, COMMON_NAME, REGION, FS_ID, None, None, None, base_path=str(tmpdir))
    with open(os.path.join(tls_dict['mount_dir'], 'config.conf')) as f:
        conf_body = f.read()
        assert conf_body == mount_efs.create_ca_conf(tmp_config_path, COMMON_NAME, tls_dict['mount_dir'], pk_path, FIXED_DT,
                                                     REGION, FS_ID, None, None, None)
    assert os.path.exists(pk_path)
    assert not os.path.exists(os.path.join(tls_dict['mount_dir'], 'publicKey.pem'))
    assert os.path.exists(os.path.join(tls_dict['mount_dir'], 'request.csr'))
    assert os.path.exists(os.path.join(tls_dict['mount_dir'], 'certificate.pem'))


def test_certificate_without_iam_without_ap_id_with_client_source(mocker, tmpdir):
    config = _get_mock_config()
    pk_path = _get_mock_private_key_path(mocker, tmpdir)
    tls_dict = mount_efs.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    tmp_config_path = os.path.join(str(tmpdir), MOUNT_NAME, 'tmpConfig')
    mount_efs.create_certificate(config, MOUNT_NAME, COMMON_NAME, REGION, FS_ID, None, None, CLIENT_INFO, base_path=str(tmpdir))
    with open(os.path.join(tls_dict['mount_dir'], 'config.conf')) as f:
        conf_body = f.read()
        assert conf_body == mount_efs.create_ca_conf(tmp_config_path, COMMON_NAME, tls_dict['mount_dir'], pk_path, FIXED_DT,
                                                     REGION, FS_ID, None, None, CLIENT_INFO)
    assert os.path.exists(pk_path)
    assert not os.path.exists(os.path.join(tls_dict['mount_dir'], 'publicKey.pem'))
    assert os.path.exists(os.path.join(tls_dict['mount_dir'], 'request.csr'))
    assert os.path.exists(os.path.join(tls_dict['mount_dir'], 'certificate.pem'))


def test_create_ca_supporting_dirs(tmpdir):
    config = _get_config()
    tls_dict = mount_efs.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    mount_efs.ca_dirs_check(config, tls_dict['database_dir'], tls_dict['certs_dir'])
    assert os.path.exists(tls_dict['database_dir'])
    assert os.path.exists(tls_dict['certs_dir'])


def test_create_ca_supporting_files(tmpdir):
    config = _get_config()
    tls_dict = mount_efs.tls_paths_dictionary(MOUNT_NAME, str(tmpdir))
    index = tls_dict['index']
    index_attr = tls_dict['index_attr']
    serial = tls_dict['serial']
    rand = tls_dict['rand']

    mount_efs.ca_dirs_check(config, tls_dict['database_dir'], tls_dict['certs_dir'])
    mount_efs.ca_supporting_files_check(index, index_attr, serial, rand)
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


def test_create_canonical_request_without_token():
    public_key_hash = 'fake_public_key_hash'
    canonical_request_out = mount_efs.create_canonical_request(public_key_hash, FIXED_DT, ACCESS_KEY_ID_VAL, REGION, FS_ID)

    assert 'GET\n/\nAction=Connect&PublicKeyHash=fake_public_key_hash&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=' \
           'FAKE_AWS_ACCESS_KEY_ID%2F20000101%2Fus-east-1%2Felasticfilesystem%2Faws4_request&X-Amz-Date=20000101T120000Z&' \
           'X-Amz-Expires=86400&X-Amz-SignedHeaders=host\nhost:fs-deadbeef\nhost\n' \
           'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' == canonical_request_out


def test_create_canonical_request_with_token(mocker):
    mocker.patch('mount_efs.get_utc_now', return_value=FIXED_DT)
    public_key_hash = 'fake_public_key_hash'
    canonical_request_out = mount_efs.create_canonical_request(public_key_hash, FIXED_DT, ACCESS_KEY_ID_VAL, REGION, FS_ID,
                                                               SESSION_TOKEN_VAL)

    assert 'GET\n/\nAction=Connect&PublicKeyHash=fake_public_key_hash&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=' \
           'FAKE_AWS_ACCESS_KEY_ID%2F20000101%2Fus-east-1%2Felasticfilesystem%2Faws4_request&X-Amz-Date=20000101T120000Z&' \
           'X-Amz-Expires=86400&X-Amz-Security-Token=FAKE_SESSION_TOKEN&X-Amz-SignedHeaders=host\nhost:fs-deadbeef\nhost' \
           '\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' == canonical_request_out


def test_get_public_key_sha1(tmpdir):
    fake_public_key_filename = 'fake_public_key.pem'
    fake_public_key_path = os.path.join(str(tmpdir), fake_public_key_filename)
    tmpdir.join(fake_public_key_filename).write(PUBLIC_KEY_BODY)

    sha1_result = mount_efs.get_public_key_sha1(fake_public_key_path)

    assert sha1_result == 'd9c2a68f2c4de49982e310d95e539a89abd6bc13'


def test_create_string_to_sign():
    canonical_request = 'canonical_request'

    string_to_sign_output = mount_efs.create_string_to_sign(canonical_request, FIXED_DT, REGION)

    assert 'AWS4-HMAC-SHA256\n20000101T120000Z\n20000101/us-east-1/elasticfilesystem/aws4_request\n' \
           '572b1e335109068b81e4def81524c5fe5d0e385143b5656cbf2f7c88e5c1a51e' == string_to_sign_output


def test_calculate_signature():
    string_to_sign = 'string_to_sign'

    signature_output = mount_efs.calculate_signature(string_to_sign, FIXED_DT, SECRET_ACCESS_KEY_VAL, REGION)

    assert '6aa643803d4a1b07c5ac87bff96347ef28dab1cb5a5c5d63969c90ca11454c4a' == signature_output


def test_create_ca_conf_without_client_info(tmpdir):
    current_time = mount_efs.get_utc_now()
    tls_dict, full_config_body = _create_ca_conf_helper(tmpdir, current_time, iam=True, ap=True, client_info=False)

    ca_extension_body = ('[ v3_ca ]\n'
                         'subjectKeyIdentifier = hash\n' 
                        '1.3.6.1.4.1.4843.7.1 = ASN1:UTF8String:%s\n' 
                        '1.3.6.1.4.1.4843.7.2 = ASN1:SEQUENCE:efs_client_auth\n' 
                        '1.3.6.1.4.1.4843.7.3 = ASN1:UTF8String:%s'
                         ) % (AP_ID, FS_ID)
    efs_client_auth_body = mount_efs.efs_client_auth_builder(tls_dict['public_key'], CREDENTIALS['AccessKeyId'],
                                                             CREDENTIALS['SecretAccessKey'], current_time, REGION,
                                                             FS_ID, CREDENTIALS['Token'])
    efs_client_info_body = ''
    matching_config_body = mount_efs.CA_CONFIG_BODY % (tls_dict['mount_dir'], tls_dict['private_key'], COMMON_NAME,
                                                       ca_extension_body, efs_client_auth_body, efs_client_info_body)

    assert full_config_body == matching_config_body


def test_create_ca_conf_with_all(tmpdir):
    current_time = mount_efs.get_utc_now()
    tls_dict, full_config_body = _create_ca_conf_helper(tmpdir, current_time, iam=True, ap=True)

    ca_extension_body = ('[ v3_ca ]\n'
                        'subjectKeyIdentifier = hash\n'
                        '1.3.6.1.4.1.4843.7.1 = ASN1:UTF8String:%s\n'
                        '1.3.6.1.4.1.4843.7.2 = ASN1:SEQUENCE:efs_client_auth\n'
                        '1.3.6.1.4.1.4843.7.3 = ASN1:UTF8String:%s\n'
                        '1.3.6.1.4.1.4843.7.4 = ASN1:SEQUENCE:efs_client_info'
                         ) % (AP_ID, FS_ID)
    efs_client_auth_body = mount_efs.efs_client_auth_builder(tls_dict['public_key'], CREDENTIALS['AccessKeyId'],
                                                             CREDENTIALS['SecretAccessKey'], current_time, REGION, FS_ID,
                                                             CREDENTIALS['Token'])
    efs_client_info_body = mount_efs.efs_client_info_builder(CLIENT_INFO)
    matching_config_body = mount_efs.CA_CONFIG_BODY % (tls_dict['mount_dir'], tls_dict['private_key'], COMMON_NAME,
                                                       ca_extension_body, efs_client_auth_body, efs_client_info_body)

    assert full_config_body == matching_config_body


def test_create_ca_conf_with_iam_no_accesspoint(tmpdir):
    current_time = mount_efs.get_utc_now()
    tls_dict, full_config_body = _create_ca_conf_helper(tmpdir, current_time, iam=True, ap=False, client_info=True)

    ca_extension_body = ('[ v3_ca ]\n' 
                        'subjectKeyIdentifier = hash\n' 
                        '1.3.6.1.4.1.4843.7.2 = ASN1:SEQUENCE:efs_client_auth\n' 
                        '1.3.6.1.4.1.4843.7.3 = ASN1:UTF8String:%s\n' 
                        '1.3.6.1.4.1.4843.7.4 = ASN1:SEQUENCE:efs_client_info'
                         ) % (FS_ID)
    efs_client_auth_body = mount_efs.efs_client_auth_builder(tls_dict['public_key'], CREDENTIALS['AccessKeyId'],
                                                             CREDENTIALS['SecretAccessKey'], current_time, REGION, FS_ID,
                                                             CREDENTIALS['Token'])
    efs_client_info_body = mount_efs.efs_client_info_builder(CLIENT_INFO)
    matching_config_body = mount_efs.CA_CONFIG_BODY % (tls_dict['mount_dir'], tls_dict['private_key'], COMMON_NAME,
                                                       ca_extension_body, efs_client_auth_body, efs_client_info_body)

    assert full_config_body == matching_config_body


def test_create_ca_conf_with_accesspoint_no_iam(tmpdir):
    current_time = mount_efs.get_utc_now()
    tls_dict, full_config_body = _create_ca_conf_helper(tmpdir, current_time, iam=False, ap=True, client_info=True)

    ca_extension_body = ('[ v3_ca ]\n' 
                        'subjectKeyIdentifier = hash\n' 
                        '1.3.6.1.4.1.4843.7.1 = ASN1:UTF8String:%s\n' 
                        '1.3.6.1.4.1.4843.7.3 = ASN1:UTF8String:%s\n' 
                        '1.3.6.1.4.1.4843.7.4 = ASN1:SEQUENCE:efs_client_info'
                         ) % (AP_ID, FS_ID)
    efs_client_auth_body = ''
    efs_client_info_body = mount_efs.efs_client_info_builder(CLIENT_INFO)
    matching_config_body = mount_efs.CA_CONFIG_BODY % (tls_dict['mount_dir'], tls_dict['private_key'], COMMON_NAME,
                                                       ca_extension_body, efs_client_auth_body, efs_client_info_body)

    assert full_config_body == matching_config_body


def test_create_ca_conf_no_ap_no_iam_no_client_source(tmpdir):
    current_time = mount_efs.get_utc_now()
    tls_dict, full_config_body = _create_ca_conf_helper(tmpdir, current_time, iam=False, ap=False, client_info=False)

    ca_extension_body = ('[ v3_ca ]\n'
                         'subjectKeyIdentifier = hash\n'
                         '1.3.6.1.4.1.4843.7.3 = ASN1:UTF8String:%s'
                         ) % (FS_ID)
    efs_client_auth_body = ''
    efs_client_info_body = ''
    matching_config_body = mount_efs.CA_CONFIG_BODY % (tls_dict['mount_dir'], tls_dict['private_key'], COMMON_NAME,
                                                       ca_extension_body, efs_client_auth_body, efs_client_info_body)

    assert full_config_body == matching_config_body


def test_create_ca_conf_no_ap_no_iam_with_client_source(tmpdir):
    current_time = mount_efs.get_utc_now()
    tls_dict, full_config_body = _create_ca_conf_helper(tmpdir, current_time, iam=False, ap=False, client_info=True)

    ca_extension_body = ('[ v3_ca ]\n'
                         'subjectKeyIdentifier = hash\n'
                         '1.3.6.1.4.1.4843.7.3 = ASN1:UTF8String:%s\n' 
                        '1.3.6.1.4.1.4843.7.4 = ASN1:SEQUENCE:efs_client_info'
                         ) % (FS_ID)
    efs_client_auth_body = ''
    efs_client_info_body = mount_efs.efs_client_info_builder(CLIENT_INFO)
    matching_config_body = mount_efs.CA_CONFIG_BODY % (tls_dict['mount_dir'], tls_dict['private_key'], COMMON_NAME,
                                                       ca_extension_body, efs_client_auth_body, efs_client_info_body)

    assert full_config_body == matching_config_body