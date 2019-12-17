#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#

import mount_efs

def test_no_unsupported_options(capsys):
    options = {}

    mount_efs.check_unsupported_options(options)

    out, err = capsys.readouterr()
    assert not out


def test_cafile_unsupported(capsys):
    options = {'capath': '/capath'}

    mount_efs.check_unsupported_options(options)

    out, err = capsys.readouterr()
    assert 'not supported' in err
    assert 'capath' in err
    assert 'capath' not in options


def test_capath_unsupported(capsys):
    options = {'cafile': '/cafile'}

    mount_efs.check_unsupported_options(options)

    out, err = capsys.readouterr()
    assert 'not supported' in err
    assert 'cafile' in err
    assert 'cafile' not in options
