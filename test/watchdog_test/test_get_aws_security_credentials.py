#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import watchdog

import json
import os
import logging
import pytest

try:
    import ConfigParser
except ImportError:
    from configparser import ConfigParser

try:
    from urllib2 import HTTPError
except ImportError:
    from urllib.error import HTTPError

ACCESS_KEY_ID_KEY = 'aws_access_key_id'
SECRET_ACCESS_KEY_KEY = 'aws_secret_access_key'
SESSION_TOKEN_KEY = 'aws_session_token'
ACCESS_KEY_ID_VAL = 'FAKE_AWS_ACCESS_KEY_ID'
SECRET_ACCESS_KEY_VAL = 'FAKE_AWS_SECRET_ACCESS_KEY'
SESSION_TOKEN_VAL = 'FAKE_SESSION_TOKEN'
WRONG_ACCESS_KEY_ID_VAL = 'WRONG_AWS_ACCESS_KEY_ID'
WRONG_SECRET_ACCESS_KEY_VAL = 'WRONG_AWS_SECRET_ACCESS_KEY'
WRONG_SESSION_TOKEN_VAL = 'WRONG_SESSION_TOKEN'

AWS_CONFIG_FILE = 'fake_aws_config'
DEFAULT_PROFILE = 'DEFAULT'
AWSPROFILE = 'test_profile'


class MockHeaders(object):
    def __init__(self, content_charset=None):
        self.content_charset = content_charset

    def get_content_charset(self):
        return self.content_charset


class MockUrlLibResponse(object):
    def __init__(self, code=200, data={}, headers=MockHeaders()):
        self.code = code
        self.data = data
        self.headers = headers

    def getcode(self):
        return self.code

    def read(self):
        return self.data


@pytest.fixture(autouse=True)
def setup(mocker):
    mocker.patch('os.path.expanduser')


def _config_helper(tmpdir, add_test_profile=False):
    fake_file = os.path.join(str(tmpdir), AWS_CONFIG_FILE)

    try:
        config = ConfigParser.SafeConfigParser()
    except AttributeError:
        config = ConfigParser()

    if add_test_profile:
        config.add_section(AWSPROFILE)

    return fake_file, config


def test_get_aws_security_credentials_credentials_file_found_credentials_found_without_token(mocker):
    file_helper_resp = {
        'AccessKeyId': ACCESS_KEY_ID_VAL,
        'SecretAccessKey': SECRET_ACCESS_KEY_VAL,
        'Token': None
    }

    mocker.patch.dict(os.environ, {})
    mocker.patch('os.path.exists', return_value=True)
    mocker.patch('watchdog.credentials_file_helper', return_value=file_helper_resp)

    credentials = watchdog.get_aws_security_credentials('credentials:default', 'us-east-1')

    assert credentials['AccessKeyId'] == ACCESS_KEY_ID_VAL
    assert credentials['SecretAccessKey'] == SECRET_ACCESS_KEY_VAL
    assert credentials['Token'] is None


def test_get_aws_security_credentials_config_file_found_credentials_found_without_token(mocker):
    file_helper_resp = {
        'AccessKeyId': ACCESS_KEY_ID_VAL,
        'SecretAccessKey': SECRET_ACCESS_KEY_VAL,
        'Token': None
    }

    mocker.patch.dict(os.environ, {})
    mocker.patch('os.path.exists', return_value=True)
    mocker.patch('watchdog.credentials_file_helper', return_value=file_helper_resp)

    credentials = watchdog.get_aws_security_credentials('config:default', 'us-east-1')

    assert credentials['AccessKeyId'] == ACCESS_KEY_ID_VAL
    assert credentials['SecretAccessKey'] == SECRET_ACCESS_KEY_VAL
    assert credentials['Token'] is None


def test_get_aws_security_credentials_credentials_file_found_credentials_found(mocker):
    file_helper_resp = {
        'AccessKeyId': ACCESS_KEY_ID_VAL,
        'SecretAccessKey': SECRET_ACCESS_KEY_VAL,
        'Token': SESSION_TOKEN_VAL
    }

    mocker.patch.dict(os.environ, {})
    mocker.patch('os.path.exists', return_value=True)
    mocker.patch('watchdog.credentials_file_helper', return_value=file_helper_resp)

    credentials = watchdog.get_aws_security_credentials('credentials:default', 'us-east-1')

    assert credentials['AccessKeyId'] == ACCESS_KEY_ID_VAL
    assert credentials['SecretAccessKey'] == SECRET_ACCESS_KEY_VAL
    assert credentials['Token'] is SESSION_TOKEN_VAL


def test_get_aws_security_credentials_config_file_found_credentials_found(mocker):
    file_helper_resp = {
        'AccessKeyId': ACCESS_KEY_ID_VAL,
        'SecretAccessKey': SECRET_ACCESS_KEY_VAL,
        'Token': SESSION_TOKEN_VAL
    }

    mocker.patch.dict(os.environ, {})
    mocker.patch('os.path.exists', return_value=True)
    mocker.patch('watchdog.credentials_file_helper', return_value=file_helper_resp)

    credentials = watchdog.get_aws_security_credentials('config:default', 'us-east-1')

    assert credentials['AccessKeyId'] == ACCESS_KEY_ID_VAL
    assert credentials['SecretAccessKey'] == SECRET_ACCESS_KEY_VAL
    assert credentials['Token'] is SESSION_TOKEN_VAL


def test_get_aws_security_credentials_ecs(mocker):
    mocker.patch.dict(os.environ, {})
    mocker.patch('os.path.exists', return_value=False)
    response = json.dumps({
        'AccessKeyId': ACCESS_KEY_ID_VAL,
        'Expiration': 'EXPIRATION_DATE',
        'RoleArn': 'TASK_ROLE_ARN',
        'SecretAccessKey': SECRET_ACCESS_KEY_VAL,
        'Token': SESSION_TOKEN_VAL
    })
    mocker.patch.dict(os.environ, {'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI': 'fake_uri'})
    mocker.patch('watchdog.urlopen', return_value=MockUrlLibResponse(data=response))

    credentials = watchdog.get_aws_security_credentials('ecs:fake_uri', 'us-east-1')

    assert credentials['AccessKeyId'] == ACCESS_KEY_ID_VAL
    assert credentials['SecretAccessKey'] == SECRET_ACCESS_KEY_VAL
    assert credentials['Token'] == SESSION_TOKEN_VAL


def test_get_aws_security_credentials_instance_metadata_role_name_str(mocker):
    _test_get_aws_security_credentials_instance_metadata_role_name(mocker, is_name_str=True, is_imds_v2=False)


def test_get_aws_security_credentials_instance_metadata_role_name_str_imds_v2(mocker):
    _test_get_aws_security_credentials_instance_metadata_role_name(mocker, is_name_str=True, is_imds_v2=True)


def test_get_aws_security_credentials_instance_metadata_role_name_bytes(mocker):
    _test_get_aws_security_credentials_instance_metadata_role_name(mocker, is_name_str=False, is_imds_v2=False)


def test_get_aws_security_credentials_instance_metadata_role_name_bytes_imds_v2(mocker):
    _test_get_aws_security_credentials_instance_metadata_role_name(mocker, is_name_str=False, is_imds_v2=True)


def _test_get_aws_security_credentials_instance_metadata_role_name(mocker, is_name_str=True, is_imds_v2=False):
    mocker.patch.dict(os.environ, {})
    mocker.patch('os.path.exists', return_value=False)
    response = json.dumps({
        'Code': 'Success',
        'LastUpdated': '2019-10-25T14:41:42Z',
        'Type': 'AWS-HMAC',
        'AccessKeyId': ACCESS_KEY_ID_VAL,
        'SecretAccessKey': SECRET_ACCESS_KEY_VAL,
        'Token': SESSION_TOKEN_VAL,
        'Expiration': '2019-10-25T21:17:24Z'
    })

    if is_name_str:
        role_name_data = b'FAKE_IAM_ROLE_NAME'
    else:
        role_name_data = 'FAKE_IAM_ROLE_NAME'
    if is_imds_v2:
        side_effects = [HTTPError('url', 401, 'Unauthorized', None, None)]
        mocker.patch('watchdog.get_aws_ec2_metadata_token', return_value='ABCDEFG==')
    else:
        side_effects = []
    side_effects = side_effects + [MockUrlLibResponse(data=role_name_data), MockUrlLibResponse(data=response)]
    mocker.patch('watchdog.urlopen', side_effect=side_effects)

    credentials = watchdog.get_aws_security_credentials('metadata:', 'us-east-1')

    assert credentials['AccessKeyId'] == ACCESS_KEY_ID_VAL
    assert credentials['SecretAccessKey'] == SECRET_ACCESS_KEY_VAL
    assert credentials['Token'] == SESSION_TOKEN_VAL


def test_get_aws_security_credentials_not_found_bad_credentials_source():
    credentials = watchdog.get_aws_security_credentials('dummy:source', 'us-east-1')
    assert not credentials


def test_get_aws_security_credentials_not_found_file_not_found(mocker):
    mocker.patch('os.path.exists', return_value=False)
    credentials = watchdog.get_aws_security_credentials('credentials:default', 'us-east-1')
    assert not credentials


def test_get_aws_security_credentials_not_found_file_found_no_creds(mocker):
    file_helper_resp = {'AccessKeyId': None, 'SecretAccessKey': None, 'Token': None}
    mocker.patch('os.path.exists', return_value=True)
    mocker.patch('watchdog.credentials_file_helper', return_value=file_helper_resp)
    credentials = watchdog.get_aws_security_credentials('credentials:default', 'us-east-1')
    assert not credentials


def test_get_aws_security_credentials_ecs_no_response(mocker):
    mocker.patch('watchdog.url_request_helper', return_value=None)
    credentials = watchdog.get_aws_security_credentials('ecs:fake_uri', 'us-east-1')
    assert not credentials


def test_get_aws_security_credentials_instance_metadata_no_response(mocker):
    mocker.patch('watchdog.url_request_helper', return_value=None)
    credentials = watchdog.get_aws_security_credentials('metadata:', 'us-east-1')
    assert not credentials


def test_credentials_file_helper_found_with_token(tmpdir):
    fake_file, config = _config_helper(tmpdir, add_test_profile=True)

    config.set(DEFAULT_PROFILE, ACCESS_KEY_ID_KEY, WRONG_ACCESS_KEY_ID_VAL)
    config.set(DEFAULT_PROFILE, SECRET_ACCESS_KEY_KEY, WRONG_SECRET_ACCESS_KEY_VAL)
    config.set(DEFAULT_PROFILE, SESSION_TOKEN_KEY, WRONG_SESSION_TOKEN_VAL)
    config.set(AWSPROFILE, ACCESS_KEY_ID_KEY, ACCESS_KEY_ID_VAL)
    config.set(AWSPROFILE, SECRET_ACCESS_KEY_KEY, SECRET_ACCESS_KEY_VAL)
    config.set(AWSPROFILE, SESSION_TOKEN_KEY, SESSION_TOKEN_VAL)
    with open(fake_file, 'w') as f:
        config.write(f)

    credentials = watchdog.credentials_file_helper(fake_file, AWSPROFILE)

    assert credentials['AccessKeyId'] == ACCESS_KEY_ID_VAL
    assert credentials['SecretAccessKey'] == SECRET_ACCESS_KEY_VAL
    assert credentials['Token'] == SESSION_TOKEN_VAL


def test_credentials_file_helper_found_without_token(caplog, tmpdir):
    caplog.set_level(logging.DEBUG)
    fake_file, config = _config_helper(tmpdir, add_test_profile=True)

    config.set(DEFAULT_PROFILE, ACCESS_KEY_ID_KEY, WRONG_ACCESS_KEY_ID_VAL)
    config.set(DEFAULT_PROFILE, SECRET_ACCESS_KEY_KEY, WRONG_SECRET_ACCESS_KEY_VAL)
    config.set(AWSPROFILE, ACCESS_KEY_ID_KEY, ACCESS_KEY_ID_VAL)
    config.set(AWSPROFILE, SECRET_ACCESS_KEY_KEY, SECRET_ACCESS_KEY_VAL)
    with open(fake_file, 'w') as f:
        config.write(f)

    credentials = watchdog.credentials_file_helper(fake_file, AWSPROFILE)

    assert credentials['AccessKeyId'] == ACCESS_KEY_ID_VAL
    assert credentials['SecretAccessKey'] == SECRET_ACCESS_KEY_VAL
    assert credentials['Token'] is None
    assert 'aws_session_token' in [rec.message for rec in caplog.records][0]


def test_credentials_file_helper_not_found(caplog, tmpdir):
    caplog.set_level(logging.DEBUG)
    fake_file = os.path.join(str(tmpdir), 'fake_aws_config')
    tmpdir.join('fake_aws_config').write('')

    credentials = watchdog.credentials_file_helper(fake_file, AWSPROFILE)

    assert credentials['AccessKeyId'] is None
    assert credentials['SecretAccessKey'] is None
    assert credentials['Token'] is None
    assert 'No [%s] section found in config file' % AWSPROFILE in [rec.message for rec in caplog.records][0]


def test_credentials_file_helper_not_found_with_awsprofile(caplog, tmpdir):
    caplog.set_level(logging.DEBUG)
    fake_file, config = _config_helper(tmpdir, add_test_profile=True)

    config.set(DEFAULT_PROFILE, SECRET_ACCESS_KEY_KEY, WRONG_SECRET_ACCESS_KEY_VAL)
    config.set(AWSPROFILE, SECRET_ACCESS_KEY_KEY, SECRET_ACCESS_KEY_VAL)
    with open(fake_file, 'w') as f:
        config.write(f)

    credentials = watchdog.credentials_file_helper(fake_file, awsprofile=AWSPROFILE)

    assert credentials['AccessKeyId'] is None
    assert credentials['SecretAccessKey'] is None
    assert credentials['Token'] is None
    assert 'aws_access_key_id or aws_secret_access_key not found' in [rec.message for rec in caplog.records][0]
