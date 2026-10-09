#
# Licensed under the MIT License. See the LICENSE accompanying this file
# for the specific language governing permissions and limitations under
# the License.
"""The watchdog launches the proxy with stderr=DEVNULL, so when a restarted
efs-proxy refuses a pinned worker count there is otherwise no trace of why.
These cover the hint that makes that diagnosable in mount-watchdog.log."""

import logging

import watchdog

PROXY = "/sbin/efs-proxy"
CONFIG = "/var/run/efs/stunnel-config.fs-123.mnt.a.20000"


def test_hint_names_the_option_and_the_configured_count(caplog):
    command = [PROXY, CONFIG, "--tls", "--worker-threads", "6"]

    with caplog.at_level(logging.WARNING):
        watchdog.log_worker_threads_restart_hint(command)

    assert 1 == len(caplog.records)
    message = caplog.records[0].getMessage()
    assert "--worker-threads 6" in message
    # Must name the item a customer can actually change, not just the CLI option.
    assert "efs_proxy_worker_threads" in message
    assert "cgroup" in message


def test_hint_is_silent_when_no_worker_count_is_pinned(caplog):
    """The overwhelmingly common case: nothing to explain, so say nothing."""
    command = [PROXY, CONFIG, "--tls", "--no-direct-s3-read"]

    with caplog.at_level(logging.WARNING):
        watchdog.log_worker_threads_restart_hint(command)

    assert [] == caplog.records


def test_hint_does_not_raise_on_a_trailing_option_with_no_value(caplog):
    """A malformed persisted command must not turn a proxy failure into a
    traceback inside the watchdog's restart loop."""
    command = [PROXY, CONFIG, "--worker-threads"]

    with caplog.at_level(logging.WARNING):
        watchdog.log_worker_threads_restart_hint(command)

    assert [] == caplog.records


def test_hint_reports_no_parallelism_number(caplog):
    """Computing available parallelism here would read only the affinity mask and
    ignore any cgroup CPU quota, so it could contradict the number efs-proxy
    used. The message must stay qualitative."""
    command = [PROXY, CONFIG, "--worker-threads", "6"]

    with caplog.at_level(logging.WARNING):
        watchdog.log_worker_threads_restart_hint(command)

    message = caplog.records[0].getMessage()
    assert "available to its own process" in message
    assert "exceeds the" not in message
