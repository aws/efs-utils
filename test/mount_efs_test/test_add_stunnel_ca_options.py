#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import mount_efs
import tempfile

import pytest

CAPATH = '/capath'
CAFILE = '/cafile.crt'


def create_temp_file(tmpdir, content=''):
    temp_file = tmpdir.join(tempfile.mktemp())
    temp_file.write(content, ensure=True)
    return temp_file


def test_use_capath():
    efs_config = {}
    options = {
        'capath': CAPATH
    }

    mount_efs.add_stunnel_ca_options(efs_config, options)

    assert CAPATH == efs_config.get('CApath')
    assert 'CAfile' not in efs_config


def test_use_cafile():
    efs_config = {}
    options = {
        'cafile': CAFILE
    }

    mount_efs.add_stunnel_ca_options(efs_config, options)

    assert CAFILE == efs_config.get('CAfile')
    assert 'CApath' not in efs_config


def test_use_default_cafile_exists(tmpdir):
    efs_config = {}
    ca_file = str(create_temp_file(tmpdir))
    default_stunnel_cafile_paths = [
        '/missing1',
        ca_file,
        '/missing2',
    ]

    mount_efs.add_stunnel_ca_options(efs_config, {}, default_stunnel_cafile_paths)

    assert ca_file == efs_config.get('CAfile')
    assert 'CApath' not in efs_config


def test_use_default_cafile_multiple_exists(tmpdir):
    efs_config = {}
    ca_file_1 = str(create_temp_file(tmpdir))
    ca_file_2 = str(create_temp_file(tmpdir))
    default_stunnel_cafile_paths = [
        ca_file_1,
        ca_file_2,
        '/missing',
    ]

    mount_efs.add_stunnel_ca_options(efs_config, {}, default_stunnel_cafile_paths)

    assert ca_file_1 == efs_config.get('CAfile')
    assert 'CApath' not in efs_config


def test_use_default_cafile_missing(capsys):
    efs_config = {}
    default_stunnel_cafile_paths = [
        '/missing1',
        '/missing2',
    ]

    with pytest.raises(SystemExit) as ex:
        mount_efs.add_stunnel_ca_options(efs_config, {}, default_stunnel_cafile_paths)

    assert 0 != ex.value.code

    out, err = capsys.readouterr()
    assert 'Failed to find a certificate authority file for verification' in err
