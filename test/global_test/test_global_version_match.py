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


SPEC_FILE = "amazon-efs-utils.spec"
DEB_FILE = "build-deb.sh"
FILE_LIST = [
    "build-deb.sh",
    "src/watchdog/__init__.py",
    "src/mount_efs/__init__.py",
    "dist/amazon-efs-utils.control",
    "build-deb.sh",
    "amazon-efs-utils.spec",
]

GLOBAL_CONFIG = "config.ini"


def test_file_version_match():
    global_version = get_global_version()
    for f in FILE_LIST:
        version_in_file = get_version_for_file(f)
        assert (
            version_in_file == global_version
        ), "version in {} is {}, does not match global version {}".format(
            f, version_in_file, global_version
        )


def test_file_release_match():
    global_release = get_global_release()
    for f in [DEB_FILE, SPEC_FILE]:
        release_in_file = get_release_for_file(f)
        assert (
            release_in_file == global_release
        ), "release in {} is {}, does not match global release {}".format(
            f, release_in_file, global_release
        )


def test_changelog_version_match():
    global_version = get_global_version()

    version_in_changelog = get_version_for_changelog(SPEC_FILE)
    assert (
        version_in_changelog is not None and version_in_changelog == global_version
    ), "version in {} is {}, does not match expected_version_release {}, you need to add changelog in the spec file".format(
        SPEC_FILE, version_in_changelog, global_version
    )


def get_global_version():
    return get_global_value("version")


def get_global_release():
    return get_global_value("release")


def get_version_for_changelog(file_path):
    mount_helper_root_folder = uppath(os.path.abspath(__file__), 3)
    file_to_check = os.path.join(mount_helper_root_folder, file_path)
    has_changelog = False
    with open(file_to_check) as fp:
        lines = fp.readlines()
    for line in lines:
        if line.startswith("%changelog"):
            has_changelog = True
        if has_changelog and line.startswith("*"):
            return line.split(" ")[-1].strip()
    return None


def get_version_for_file(file_path):
    mount_helper_root_folder = uppath(os.path.abspath(__file__), 3)
    file_to_check = os.path.join(mount_helper_root_folder, file_path)
    with open(file_to_check) as fp:
        lines = fp.readlines()
    for line in lines:
        if line.startswith("VERSION"):
            return (
                line.split("=")[1].strip().replace('"', "")
            )  # Replacing the double quotes instead of single quotes as
            # "black" reformates every single quotes to double quotes.
        if line.startswith("Version"):
            return line.split(":")[1].strip()
    return None


def get_release_for_file(file_path):
    mount_helper_root_folder = uppath(os.path.abspath(__file__), 3)
    file_to_check = os.path.join(mount_helper_root_folder, file_path)
    with open(file_to_check) as fp:
        lines = fp.readlines()
    for line in lines:
        if line.startswith("RELEASE"):
            return line.split("=")[1].strip()
        if line.startswith("Release"):
            return line.split(":")[1].strip().split("%")[0]
    return None


def get_global_value(key):
    mount_helper_root_folder = uppath(os.path.abspath(__file__), 3)
    config_file = os.path.join(mount_helper_root_folder, GLOBAL_CONFIG)
    cp = read_config(config_file)
    value = str(cp.get("global", key))
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
