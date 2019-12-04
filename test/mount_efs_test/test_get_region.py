#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import mount_efs
import json

import pytest

try:
    from urllib2 import URLError
except ImportError:
    from urllib.error import URLError

INSTANCE_DATA = {
  'devpayProductCodes': None,
  'privateIp': '192.168.1.1',
  'availabilityZone': 'us-east-1a',
  'version': '2010-08-31',
  'instanceId': 'i-deadbeefdeadbeef0',
  'billingProducts': None,
  'pendingTime': '2017-06-20T18:32:00Z',
  'instanceType': 'm3.xlarge',
  'accountId': '123412341234',
  'architecture': 'x86_64',
  'kernelId': None,
  'ramdiskId': None,
  'imageId': 'ami-deadbeef',
  'region': 'us-east-1'
}

INSTANCE_DOCUMENT = json.dumps(INSTANCE_DATA)


class MockHeaders(object):
    def __init__(self, content_charset=None):
        self.content_charset = content_charset

    def get_content_charset(self):
        return self.content_charset


class MockUrlLibResponse(object):
    def __init__(self, code=200, data=INSTANCE_DOCUMENT, headers=MockHeaders()):
        self.code = code
        self.data = data
        self.headers = headers

    def getcode(self):
        return self.code

    def read(self):
        return self.data


def test_get_region(mocker):
    mocker.patch('mount_efs.urlopen', return_value=MockUrlLibResponse())

    assert 'us-east-1' == mount_efs.get_region()


def test_get_region_py3_no_charset(mocker):
    mocker.patch('mount_efs.urlopen', return_value=MockUrlLibResponse(data=bytearray(INSTANCE_DOCUMENT, 'us-ascii')))

    assert 'us-east-1' == mount_efs.get_region()


def test_get_region_py3_utf8_charset(mocker):
    charset = 'utf-8'
    mocker.patch('mount_efs.urlopen', return_value=MockUrlLibResponse(data=bytearray(INSTANCE_DOCUMENT, charset)),
                 headers=MockHeaders(content_charset=charset))

    assert 'us-east-1' == mount_efs.get_region()


def _test_get_region_error(mocker, capsys, response=None, error=None):
    if (response and error) or (not response and not error):
        raise ValueError('Invalid arguments')
    elif response:
        mocker.patch('mount_efs.urlopen', return_value=response)
    elif error:
        mocker.patch('mount_efs.urlopen', side_effect=error)

    with pytest.raises(SystemExit) as ex:
        mount_efs.get_region()

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert 'Error retrieving region' in err


def test_get_region_bad_response(mocker, capsys):
    _test_get_region_error(mocker, capsys, response=MockUrlLibResponse(code=400))


def test_get_region_error_response(mocker, capsys):
    _test_get_region_error(mocker, capsys, error=URLError('test error'))


def test_get_region_bad_json(mocker, capsys):
    _test_get_region_error(mocker, capsys, response=MockUrlLibResponse(data='not json'))


def test_get_region_missing_region(mocker, capsys):
    _test_get_region_error(mocker, capsys, response=MockUrlLibResponse(data=json.dumps({})))
