#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import os

try:
    import ConfigParser
except ImportError:
    from configparser import ConfigParser

FILE_LIST = ['src/watchdog/__init__.py', 'src/mount_efs/__init__.py', 'dist/amazon-efs-utils.spec',
             'dist/amazon-efs-utils.control', 'build-deb.sh']
RPM_FILE = 'dist/amazon-efs-utils.spec'

GLOBAL_CONFIG = 'config.ini'


def test_global_version_match():
    global_version = get_global_value('version')

    for f in FILE_LIST:
        version_in_file = get_version_for_file(f)
        assert version_in_file == global_version, \
            'version in {} is {}, does not match global version {}'.format(f, version_in_file, global_version)


def test_changelog_version_match():
    global_version = get_global_value('version')
    global_release = get_global_value('release')
    expected_version_release = global_version + '-' + global_release

    version_release_in_changelog = get_version_for_changelog(RPM_FILE)
    assert version_release_in_changelog is not None and version_release_in_changelog == expected_version_release, \
        'version in {} is {}, does not match expected_version_release {}, you need to add changelog in the spec file'\
            .format(RPM_FILE, version_release_in_changelog, expected_version_release)


def get_version_for_changelog(file_path):
    mount_helper_root_folder = uppath(os.path.abspath(__file__), 3)
    file_to_check = os.path.join(mount_helper_root_folder, file_path)
    has_changelog = False
    with open(file_to_check) as fp:
        lines = fp.readlines()
    for line in lines:
        if line.startswith('%changelog'):
            has_changelog = True
        if has_changelog and line.startswith('*'):
            return line.split(' ')[-1].strip()
    return None


def get_version_for_file(file_path):
    mount_helper_root_folder = uppath(os.path.abspath(__file__), 3)
    file_to_check = os.path.join(mount_helper_root_folder, file_path)
    with open(file_to_check) as fp:
        lines = fp.readlines()
    for line in lines:
        if line.startswith('VERSION'):
            return line.split('=')[1].strip().replace("'", '')
        if line.startswith('Version'):
            return line.split(':')[1].strip()
    return None


def get_global_value(key):
    mount_helper_root_folder = uppath(os.path.abspath(__file__), 3)
    config_file = os.path.join(mount_helper_root_folder, GLOBAL_CONFIG)
    cp = read_config(config_file)
    value = str(cp.get('global', key))
    return value


# Given:    path  :   file path
#            n    :   the number of parent level we want to reach
# Returns: parent path of certain level n
# Example: uppath('/usr/lib/java', 1) -> '/usr/lib'
#          uppath('/usr/lib/java', 2) -> '/usr'
def uppath(path, n):
    return os.sep.join(path.split(os.sep)[:-n])


def read_config(config_file):
    try:
        p = ConfigParser.SafeConfigParser()
    except AttributeError:
        p = ConfigParser()
    p.read(config_file)
    return p
