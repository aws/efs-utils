#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import mount_efs

import pytest


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


def test_tls_with_port(capsys):
    with pytest.raises(SystemExit) as ex:
        mount_efs.get_nfs_mount_options({'tls': None, 'port': 3030})

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert 'mutually exclusive' in err
