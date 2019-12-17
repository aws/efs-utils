#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import errno
import mount_efs
import os
import tempfile

import pytest

try:
    import ConfigParser
except ImportError:
    from configparser import ConfigParser


def _get_config(mode=None):
    try:
        config = ConfigParser.SafeConfigParser()
    except AttributeError:
        config = ConfigParser()
    config.add_section(mount_efs.CONFIG_SECTION)

    if mode is not None:
        config.set(mount_efs.CONFIG_SECTION, 'state_file_dir_mode', mode)

    return config


def test_create_state_file_dir(tmpdir):
    state_file_dir = str(tmpdir.join('efs'))

    mount_efs.create_state_file_dir(_get_config(), state_file_dir)

    assert os.path.isdir(state_file_dir)
    assert '0750' == oct(os.stat(state_file_dir).st_mode)[-4:]


def test_create_state_file_dir_exists(tmpdir):
    state_file_dir = str(tmpdir.join('efs'))
    os.makedirs(state_file_dir)

    mount_efs.create_state_file_dir(_get_config(), state_file_dir)

    assert os.path.isdir(state_file_dir)


def test_create_state_file_dir_exists_as_file(tmpdir):
    state_file = tmpdir.join('efs')
    state_file.write('', ensure=True)

    with pytest.raises(OSError) as ex:
        mount_efs.create_state_file_dir(_get_config(), str(state_file))

    assert errno.EEXIST == ex.value.errno


def test_create_state_file_dir_overridden_mode(tmpdir):
    state_file_dir = str(tmpdir.join('efs'))

    mount_efs.create_state_file_dir(_get_config(mode=str(755)), state_file_dir)

    assert os.path.isdir(state_file_dir)
    assert '0755' == oct(os.stat(state_file_dir).st_mode)[-4:]


def test_create_state_file_dir_overridden_bad_mode(tmpdir):
    state_file_dir = str(tmpdir.join('efs'))

    mount_efs.create_state_file_dir(_get_config(mode='invalid-mode'), state_file_dir)

    assert os.path.isdir(state_file_dir)
    assert '0750' == oct(os.stat(state_file_dir).st_mode)[-4:]
