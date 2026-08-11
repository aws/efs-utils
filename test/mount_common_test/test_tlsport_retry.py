# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
import efs_utils_common.network_utils as network_utils
from efs_utils_common.constants import DEFAULT_TIMEOUT

from .. import utils

TLS_PORT = 20049


def test_tlsport_connectable_first_try_no_retry_no_sleep(mocker):
    verify_mock = mocker.patch(
        "efs_utils_common.network_utils.verify_tlsport_can_be_connected",
        return_value=True,
    )
    sleep_mock = mocker.patch("efs_utils_common.network_utils.time.sleep")

    network_utils.test_tlsport(TLS_PORT)

    # Connectable on the first check: exactly one verify, no sleep, no retries.
    utils.assert_called_once(verify_mock)
    utils.assert_not_called(sleep_mock)


def test_tlsport_not_connectable_then_connectable_retries_then_succeeds(mocker):
    # Fails the first check, succeeds on the second — one retry with one sleep.
    verify_mock = mocker.patch(
        "efs_utils_common.network_utils.verify_tlsport_can_be_connected",
        side_effect=[False, True],
    )
    sleep_mock = mocker.patch("efs_utils_common.network_utils.time.sleep")

    network_utils.test_tlsport(TLS_PORT)

    utils.assert_called_n_times(verify_mock, 2)
    utils.assert_called_once(sleep_mock)
    sleep_mock.assert_called_with(DEFAULT_TIMEOUT)


def test_tlsport_never_connectable_exhausts_five_retries(mocker):
    # Never connectable: initial check + 5 retries = 6 verify calls, 5 sleeps.
    verify_mock = mocker.patch(
        "efs_utils_common.network_utils.verify_tlsport_can_be_connected",
        return_value=False,
    )
    sleep_mock = mocker.patch("efs_utils_common.network_utils.time.sleep")

    network_utils.test_tlsport(TLS_PORT)

    utils.assert_called_n_times(verify_mock, 6)
    utils.assert_called_n_times(sleep_mock, 5)
    # Every sleep uses the configured retry interval, not a real wall-clock delay.
    for call in sleep_mock.call_args_list:
        assert call[0][0] == DEFAULT_TIMEOUT
