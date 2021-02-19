#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import mount_efs

import pytest

from mock import MagicMock, patch


def _mock_popen(mocker, returncode=0, stdout='stdout', stderr='stderr'):
    popen_mock = MagicMock()
    popen_mock.communicate.return_value = (stdout, stderr, )
    popen_mock.returncode = returncode

    return mocker.patch('subprocess.Popen', return_value=popen_mock)


def test_get_default_nfs_mount_options():
    nfs_opts = mount_efs.get_nfs_mount_options({})

    assert 'nfsvers=4.1' in nfs_opts
    assert 'rsize=1048576' in nfs_opts
    assert 'wsize=1048576' in nfs_opts
    assert 'hard' in nfs_opts
    assert 'timeo=600' in nfs_opts
    assert 'retrans=2' in nfs_opts


def test_override_nfs_version():
    nfs_opts = mount_efs.get_nfs_mount_options({'nfsvers': 4.0})

    assert 'nfsvers=4.0' in nfs_opts
    assert 'nfsvers=4.1' not in nfs_opts


def test_override_nfs_version_alternate_option():
    nfs_opts = mount_efs.get_nfs_mount_options({'vers': 4.0})

    assert 'vers=4.0' in nfs_opts
    assert 'nfsvers=4.0' not in nfs_opts
    assert 'nfsvers=4.1' not in nfs_opts


def test_override_rsize():
    nfs_opts = mount_efs.get_nfs_mount_options({'rsize': 1})

    assert 'rsize=1' in nfs_opts
    assert 'rsize=1048576' not in nfs_opts


def test_override_wsize():
    nfs_opts = mount_efs.get_nfs_mount_options({'wsize': 1})

    assert 'wsize=1' in nfs_opts
    assert 'wsize=1048576' not in nfs_opts


def test_override_recovery_soft():
    nfs_opts = mount_efs.get_nfs_mount_options({'soft': None})

    assert 'soft' in nfs_opts
    assert 'soft=' not in nfs_opts
    assert 'hard' not in nfs_opts


def test_override_timeo():
    nfs_opts = mount_efs.get_nfs_mount_options({'timeo': 1})

    assert 'timeo=1' in nfs_opts
    assert 'timeo=600' not in nfs_opts


def test_override_retrans():
    nfs_opts = mount_efs.get_nfs_mount_options({'retrans': 1})

    assert 'retrans=1' in nfs_opts
    assert 'retrans=2' not in nfs_opts


def test_tlsport():
    nfs_opts = mount_efs.get_nfs_mount_options({'tls': None, 'tlsport': 3030})

    assert 'port=3030' in nfs_opts
    assert 'tls' not in nfs_opts


def test_get_default_nfs_mount_options_macos(mocker):
    mocker.patch('mount_efs.check_if_platform_is_mac', return_value=True)
    nfs_opts = mount_efs.get_nfs_mount_options({})

    assert 'nfsvers=4.0' in nfs_opts
    assert 'rsize=1048576' in nfs_opts
    assert 'wsize=1048576' in nfs_opts
    assert 'hard' in nfs_opts
    assert 'timeo=600' in nfs_opts
    assert 'retrans=2' in nfs_opts
    assert 'mountport=2049' in nfs_opts


def _test_unsupported_mount_options_macos(mocker, capsys, options={}):
    mocker.patch('mount_efs.check_if_platform_is_mac', return_value=True)
    _mock_popen(mocker, stdout='nfs')
    with pytest.raises(SystemExit) as ex:
        mount_efs.get_nfs_mount_options(options)

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert 'NFSv4.1 is not supported on MacOS' in err


def test_unsupported_nfsvers_mount_options_macos(mocker, capsys):
    _test_unsupported_mount_options_macos(mocker, capsys, {'nfsvers': '4.1'})

def test_unsupported_vers_mount_options_macos(mocker, capsys):
    _test_unsupported_mount_options_macos(mocker, capsys, {'vers': '4.1'})

def test_unsupported_minorversion_mount_options_macos(mocker, capsys):
    _test_unsupported_mount_options_macos(mocker, capsys, {'minorversion': 1})
