#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import mount_efs

import pytest

from contextlib import contextmanager


@contextmanager
def dummy_contextmanager(*args, **kwargs):
    yield


def _test_main(mocker, tls=False, root=True):
    if tls:
        options = {'tls': None}
    else:
        options = {}

    if root:
        mocker.patch('getpass.getuser', return_value='root')
    else:
        mocker.patch('getpass.getuser', return_value='user')

    bootstrap_logging_mock = mocker.patch('mount_efs.bootstrap_logging')
    get_dns_mock = mocker.patch('mount_efs.get_dns_name')
    parse_arguments_mock = mocker.patch('mount_efs.parse_arguments', return_value=('fs-deadbeef', '/', '/mnt', options))
    bootstrap_tls_mock = mocker.patch('mount_efs.bootstrap_tls', side_effect=dummy_contextmanager)
    mount_mock = mocker.patch('mount_efs.mount_nfs')

    mount_efs.main()

    bootstrap_logging_mock.assert_called_once()
    get_dns_mock.assert_called_once()
    parse_arguments_mock.assert_called_once()
    mount_mock.assert_called_once()

    if tls:
        bootstrap_tls_mock.assert_called_once()
    else:
        bootstrap_tls_mock.assert_not_called()


def test_main_tls(mocker):
    _test_main(mocker, tls=True)


def test_main_no_tls(mocker):
    _test_main(mocker, tls=False)


def test_main_non_root(mocker, capsys):
    with pytest.raises(SystemExit) as ex:
        _test_main(mocker, root=False)

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert 'only root' in err
