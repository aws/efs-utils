# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
import pytest

import efs_utils_common.proxy as proxy
from efs_utils_common import constants, context
from efs_utils_common.constants import CONFIG_SECTION, EFS_PROXY_WORKER_THREADS_ITEM

try:
    import ConfigParser
except ImportError:
    from configparser import ConfigParser


@pytest.fixture(autouse=True)
def setup_test():
    # The rejection paths report the config file they read, which the mount
    # context resolves.
    mount_context = context.MountContext()
    mount_context.reset()
    mount_context.mount_type = constants.MOUNT_TYPE_EFS
    mount_context.config_file_path = constants.CONFIG_FILE
    yield mount_context
    mount_context.reset()


def _get_config(value=None, add_section=True):
    try:
        config = ConfigParser.SafeConfigParser()
    except AttributeError:
        config = ConfigParser()
    if add_section:
        config.add_section(CONFIG_SECTION)
        if value is not None:
            config.set(CONFIG_SECTION, EFS_PROXY_WORKER_THREADS_ITEM, str(value))
    return config


def test_worker_threads_not_configured():
    """Omitting the item means efs-proxy keeps its own per-CPU default."""
    assert proxy.get_efs_proxy_worker_threads(_get_config()) is None


def test_worker_threads_missing_section():
    """A config file without a [mount] section must not fail the mount."""
    assert proxy.get_efs_proxy_worker_threads(_get_config(add_section=False)) is None


@pytest.mark.parametrize("raw_value", ["", "   "])
def test_worker_threads_empty_value_treated_as_unset(raw_value):
    """`efs_proxy_worker_threads =` with no value is not a configuration error."""
    assert proxy.get_efs_proxy_worker_threads(_get_config(raw_value)) is None


@pytest.mark.parametrize("configured", [1, 2, 4, 8, 16, 96, 100000])
def test_worker_threads_valid_values(configured):
    """Any positive integer passes here.

    The upper bound is efs-proxy's job (`validate_worker_threads`), because only
    that process can read its own available parallelism exactly. `100000` is
    included deliberately: this reader must not be the thing that rejects it.
    """
    assert proxy.get_efs_proxy_worker_threads(_get_config(configured)) == configured


def test_worker_threads_surrounding_whitespace_is_tolerated():
    assert proxy.get_efs_proxy_worker_threads(_get_config(" 8 ")) == 8


@pytest.mark.parametrize("configured", [0, -1, -8])
def test_worker_threads_rejects_non_positive(configured, capsys):
    with pytest.raises(SystemExit) as ex:
        proxy.get_efs_proxy_worker_threads(_get_config(configured))

    assert 0 != ex.value.code
    _, err = capsys.readouterr()
    assert EFS_PROXY_WORKER_THREADS_ITEM in err
    assert "positive integer" in err


@pytest.mark.parametrize("configured", ["eight", "8.5", "8 threads", "0x8"])
def test_worker_threads_rejects_malformed(configured, capsys):
    with pytest.raises(SystemExit) as ex:
        proxy.get_efs_proxy_worker_threads(_get_config(configured))

    assert 0 != ex.value.code
    _, err = capsys.readouterr()
    assert configured in err
