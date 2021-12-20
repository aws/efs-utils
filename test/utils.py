#
# Copyright 2017-2018 Amazon.com, Inc. and its affiliates. All Rights Reserved.
#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
#


def assert_called_once(mock):
    assert (
        mock.call_count == 1
    ), "Expected mock to have been called once. Called {} times.".format(
        mock.call_count
    )


def assert_called_n_times(mock, n):
    assert (
        mock.call_count == n
    ), "Expected mock to have been called {} times. Called {} times.".format(
        n, mock.call_count
    )


def assert_not_called(mock):
    assert (
        mock.call_count == 0
    ), "Expected mock to have been not called. Called {} times.".format(mock.call_count)


def assert_called(mock):
    assert (
        mock.call_count != 0
    ), "Expected mock to have been called. While the mock is not called."
