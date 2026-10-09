use tikv_jemallocator::Jemalloc;

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

use clap::Parser;
use efs_proxy::aws::cw_publisher::{CloudWatchClient, CloudWatchPublisher, CW_NAMESPACE_EFS};
use efs_proxy::aws::s3_client::S3ClientStandardBuilder;
use efs_proxy::awsfile_rpc::AwsFileRpcClient;
use efs_proxy::config_parser::ProxyConfig;
use efs_proxy::connections::{PlainTextPartitionFinder, TlsPartitionFinder};
use efs_proxy::controller::Controller;
use efs_proxy::logger;
use efs_proxy::status_reporter;
use efs_proxy::tls::get_tls_config;
use efs_proxy::tls::TlsConfig;
use efs_proxy::utils::is_running_on_lambda;
use log::{debug, error, info};
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::runtime;
use tokio::signal;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

// The AWS-file XDR protocol is generated in and exported by the efs-proxy lib
// crate (which re-exports it from amzn-efs-client-core). Re-use it here instead
// of regenerating from OUT_DIR.
#[allow(unused_imports)]
use efs_proxy::awsfile_prot;

/// Reject a worker count the process does not have the parallelism to use.
///
/// This bound lives here rather than in the mount helper because this is the
/// only place the number is exact. `available` comes from
/// `std::thread::available_parallelism()`, which is the same call Tokio's
/// default sizing goes through (`Builder::worker_threads` unset ->
/// `loom::sys::num_cpus` -> `available_parallelism`), so the ceiling *is* the
/// count this runtime would have chosen on its own. On Linux that is
/// `min(sched_getaffinity mask, cgroup CPU quota)` -- and the quota half is why
/// the mount helper cannot compute it: reproducing it in Python means
/// hand-copying ~200 lines of cgroup v1/v2 `/proc` parsing out of Rust std,
/// which would drift the moment std changes. The helper therefore validates
/// only what a config file can settle on its own (integer syntax, and >= 1).
///
/// Above the available parallelism the extra workers each cost a thread stack
/// and scheduling overhead while adding none, since the proxy's work is async
/// I/O plus TLS crypto and genuinely blocking work goes to Tokio's separate
/// `spawn_blocking` pool.
///
/// `available` is a parameter rather than read inside so the bound is testable
/// without the test host's own CPU count deciding the outcome. `None` for
/// either argument means there is no bound to apply: nothing was configured, or
/// the platform could not report its parallelism, and refusing to start on an
/// unknown count would be worse than honoring the operator's number.
fn validate_worker_threads(
    requested: Option<NonZeroUsize>,
    available: Option<NonZeroUsize>,
) -> Result<(), String> {
    let (Some(requested), Some(available)) = (requested, available) else {
        return Ok(());
    };

    if requested <= available {
        return Ok(());
    }

    Err(format!(
        "--worker-threads {requested} exceeds the {available} CPUs available to this process. \
         Set [mount] efs_proxy_worker_threads in efs-utils.conf to a value between 1 and \
         {available}, or remove it to use one worker thread per available CPU. A worker count \
         above the available CPUs adds a thread stack and scheduling overhead per worker \
         without adding parallelism."
    ))
}

/// Build the Tokio runtime the proxy runs on.
///
/// Split out of `main` so the worker-count wiring is reachable from a test:
/// `main` is the process entry point and is never executed by the unit test
/// binary, so anything inlined there can only be tested by restating it.
fn build_runtime(worker_threads: Option<NonZeroUsize>) -> runtime::Runtime {
    let mut builder = runtime::Builder::new_multi_thread();
    builder.enable_all();
    if let Some(worker_threads) = worker_threads {
        // An explicit value also takes precedence over TOKIO_WORKER_THREADS:
        // Tokio only consults that variable when the builder leaves the worker
        // count unset.
        builder.worker_threads(worker_threads.get());
    }

    builder
        .build()
        .expect("Failed to build efs-proxy Tokio runtime")
}

/// Build the Tokio runtime, then run the proxy on it.
///
/// The runtime is built here rather than by `#[tokio::main]` because its worker
/// count is an argument: `#[tokio::main]` expands to a runtime constructed
/// before the function body runs, so `Args::parse()` would not have happened
/// yet and `--worker-threads` could not reach the builder.
///
/// Excluded from coverage: this is the process entry point, so the unit-test
/// binary never executes it. Every statement delegates to code that IS covered
/// -- `validate_worker_threads` and `build_runtime` by their own tests, `run` by
/// the integration tests -- so the only way to score these lines would be to
/// restate them in a test, which is what the exclusion exists to avoid. The
/// marker names are the ones this package's grcov invocation passes as
/// `--excl-start` / `--excl-stop`.
// GRCOV_STOP_COVERAGE
fn main() {
    let args = Args::parse();

    // Written to stderr, which the mount helper captures and embeds in the
    // mount.log entry for a failed proxy start, so the message above reaches
    // whoever set the config item.
    if let Err(message) = validate_worker_threads(
        args.worker_threads,
        std::thread::available_parallelism().ok(),
    ) {
        eprintln!("{message}");
        std::process::exit(1);
    }

    build_runtime(args.worker_threads).block_on(run(args));
}
// GRCOV_BEGIN_COVERAGE

/// Log the worker count the runtime actually built.
///
/// The count is read back off the live runtime rather than echoed from the
/// argument, so the log reports what Tokio really built -- including the
/// per-available-CPU count it chose when no override was given. Split out of
/// `run` so it is reachable from a test without standing up a whole proxy.
///
/// Both values are bound before the `info!` call rather than passed as macro
/// arguments: `info!` expands to a level check around its argument list, so
/// with no logger installed -- which is every unit test -- the arguments are
/// never evaluated, and a test calling this function would exercise nothing.
fn log_worker_threads(worker_threads: Option<NonZeroUsize>) {
    let num_workers = runtime::Handle::current().metrics().num_workers();
    let source = match worker_threads {
        Some(_) => "--worker-threads",
        None => "Tokio default",
    };

    info!("Tokio runtime using {num_workers} worker threads ({source})");
}

async fn run(args: Args) {
    let proxy_config = match ProxyConfig::from_path(Path::new(&args.proxy_config_path)) {
        Ok(mut config) => {
            // no_direct_s3_read argument takes precedence over read_bypass_requested value from config file
            if args.no_direct_s3_read {
                config.nested_config.read_bypass_config.requested = false;
                config.nested_config.read_bypass_config.enabled = false;
            }
            config
        }
        Err(e) => panic!("Failed to read configuration. {}", e),
    };

    logger::init(&proxy_config);

    log_worker_threads(args.worker_threads);

    info!("Running with configuration: {:?}", proxy_config);

    let pid_file_path = Path::new(&proxy_config.pid_file_path);
    let _ = write_pid_file(pid_file_path).await;

    // This "status reporter" is currently only used in tests
    let (_status_requester, status_reporter) = status_reporter::create_status_channel();

    let sigterm_cancellation_token = CancellationToken::new();
    let mut sigterm_listener = match signal::unix::signal(signal::unix::SignalKind::terminate()) {
        Ok(listener) => listener,
        Err(e) => panic!("Failed to create SIGTERM listener. {}", e),
    };

    // Build a shared CloudWatch metric publisher for NFS reachability metrics.
    // Only needed when read bypass is requested — the publisher at this level is only used for
    // NFSConnectionAccessible metric in Controller::emit_nfs_reachability, which is a read-bypass feature.
    // Skipping it when RBP is off avoids ~9 MiB of memory from AWS SDK/credentials/HTTP pool init.
    let telemetry = &proxy_config.nested_config.telemetry_config;
    let cw_publisher: Option<Arc<dyn CloudWatchClient>> = if is_running_on_lambda() {
        info!("Running on Lambda, skipping CloudWatch publisher initialization");
        None
    } else if !proxy_config.nested_config.read_bypass_config.requested {
        info!("Read bypass not requested, skipping CloudWatch publisher initialization");
        None
    } else if !telemetry.cloud_watch_metrics_enabled && !telemetry.cloud_watch_logs_enabled {
        info!("CloudWatch metrics and logs both disabled, skipping CloudWatch publisher initialization");
        None
    } else {
        Some(Arc::new(
            CloudWatchPublisher::new_from_config(&proxy_config, None, CW_NAMESPACE_EFS).await,
        ))
    };

    let controller_handle = if args.tls {
        let tls_config = match get_tls_config(&proxy_config).await {
            Ok(config) => Arc::new(Mutex::new(config)),
            Err(e) => panic!("Failed to obtain TLS config:{}", e),
        };

        run_sighup_handler(proxy_config.clone(), tls_config.clone());

        let controller = Controller::new(
            &proxy_config.nested_config.listen_addr,
            proxy_config.clone(),
            Arc::new(TlsPartitionFinder::new(tls_config)),
            status_reporter,
            cw_publisher.clone(),
        )
        .await;
        tokio::spawn(controller.run(
            sigterm_cancellation_token.clone(),
            AwsFileRpcClient,
            S3ClientStandardBuilder,
        ))
    } else {
        let controller = Controller::new(
            &proxy_config.nested_config.listen_addr,
            proxy_config.clone(),
            Arc::new(PlainTextPartitionFinder {
                mount_target_addr: proxy_config.nested_config.mount_target_addr.clone(),
            }),
            status_reporter,
            cw_publisher.clone(),
        )
        .await;
        tokio::spawn(controller.run(
            sigterm_cancellation_token.clone(),
            AwsFileRpcClient,
            S3ClientStandardBuilder,
        ))
    };

    tokio::select! {
        shutdown_reason = controller_handle => error!("Shutting down. {:?}", shutdown_reason),
        _ = sigterm_listener.recv() => {
            info!("Received SIGTERM");
            sigterm_cancellation_token.cancel();
        },
    }
    if pid_file_path.exists() {
        match tokio::fs::remove_file(&pid_file_path).await {
            Ok(()) => info!("Removed pid file"),
            Err(e) => error!("Unable to remove pid_file: {e}"),
        }
    }
}

async fn write_pid_file(pid_file_path: &Path) -> Result<(), anyhow::Error> {
    let mut pid_file = tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .open(pid_file_path)
        .await?;
    pid_file
        .write_all(std::process::id().to_string().as_bytes())
        .await?;
    pid_file.write_u8(b'\x0A').await?;
    pid_file.flush().await?;
    Ok(())
}

fn run_sighup_handler(proxy_config: ProxyConfig, tls_config: Arc<Mutex<TlsConfig>>) {
    tokio::spawn(async move {
        let mut sighup_listener = match signal::unix::signal(signal::unix::SignalKind::hangup()) {
            Ok(listener) => listener,
            Err(e) => panic!("Failed to create SIGHUP listener. {}", e),
        };

        loop {
            sighup_listener
                .recv()
                .await
                .expect("SIGHUP listener stream is closed");

            debug!("Received SIGHUP");
            let mut locked_config = tls_config.lock().await;
            match get_tls_config(&proxy_config).await {
                Ok(config) => *locked_config = config,
                Err(e) => panic!("Failed to acquire TLS config. {}", e),
            }
        }
    });
}

#[derive(Parser, Debug, Clone)]
pub struct Args {
    pub proxy_config_path: String,

    #[arg(long, default_value_t = false)]
    pub tls: bool,

    #[arg(long, default_value_t = false)]
    pub no_direct_s3_read: bool,

    /// Number of Tokio worker threads to run. Unset keeps Tokio's own default of
    /// one worker per available CPU.
    ///
    /// `NonZeroUsize` makes clap reject 0 -- and every negative or malformed
    /// value -- during parsing, so an unusable worker count fails the mount with
    /// a message naming the option instead of starting a proxy that cannot make
    /// progress. The mount helper rejects those same values earlier, from the
    /// config file, where it can name the item and file; this is the guard for
    /// anyone invoking efs-proxy directly.
    ///
    /// The upper bound is checked here rather than by the mount helper, because
    /// this process is the only one that can ask for the exact number: see
    /// `validate_worker_threads`. Values above the available parallelism are
    /// refused before the runtime is built.
    #[arg(long, value_name = "N")]
    pub worker_threads: Option<NonZeroUsize>,
}

#[cfg(test)]
pub mod tests {

    use super::*;

    /// Build the runtime through the same function `main` uses, and report the
    /// worker count the runtime actually ended up with. Calling `build_runtime`
    /// rather than restating its body is what makes these assertions a test of
    /// the production wiring instead of a restatement of the parsed value.
    fn built_worker_count(argv: &[&str]) -> usize {
        let args = Args::parse_from(argv);
        build_runtime(args.worker_threads).metrics().num_workers()
    }

    #[test]
    fn test_worker_threads_absent_by_default() {
        let args = Args::parse_from(["efs-proxy", "proxy-config"]);
        assert_eq!(None, args.worker_threads);
    }

    #[test]
    fn test_worker_threads_parsed() {
        let args = Args::parse_from(["efs-proxy", "proxy-config", "--worker-threads", "4"]);
        assert_eq!(Some(NonZeroUsize::new(4).unwrap()), args.worker_threads);
    }

    #[test]
    fn test_worker_threads_coexists_with_other_options() {
        let args = Args::parse_from([
            "efs-proxy",
            "proxy-config",
            "--tls",
            "--no-direct-s3-read",
            "--worker-threads",
            "2",
        ]);
        assert_eq!("proxy-config", args.proxy_config_path);
        assert!(args.tls);
        assert!(args.no_direct_s3_read);
        assert_eq!(Some(NonZeroUsize::new(2).unwrap()), args.worker_threads);
    }

    #[test]
    fn test_worker_threads_rejects_unusable_values() {
        // Zero, negative and malformed values must fail parsing rather than
        // silently degrade to a default: a caller who asked for a specific
        // worker count would otherwise run with the unbounded per-CPU one.
        for unusable in ["0", "-1", "eight", "4.5", ""] {
            assert!(
                Args::try_parse_from(["efs-proxy", "proxy-config", "--worker-threads", unusable])
                    .is_err(),
                "--worker-threads {unusable} should be rejected"
            );
        }
    }

    fn nz(n: usize) -> Option<NonZeroUsize> {
        NonZeroUsize::new(n)
    }

    #[test]
    fn test_validate_worker_threads_accepts_at_or_below_available() {
        // The boundary is inclusive: asking for exactly the available
        // parallelism is what Tokio would have chosen unprompted.
        for (requested, available) in [(1, 1), (1, 16), (8, 16), (15, 16), (16, 16)] {
            assert_eq!(
                Ok(()),
                validate_worker_threads(nz(requested), nz(available)),
                "--worker-threads {requested} should be accepted on {available} CPUs"
            );
        }
    }

    #[test]
    fn test_validate_worker_threads_rejects_above_available() {
        for (requested, available) in [(2, 1), (17, 16), (1000, 16), (usize::MAX, 96)] {
            assert!(
                validate_worker_threads(nz(requested), nz(available)).is_err(),
                "--worker-threads {requested} should be rejected on {available} CPUs"
            );
        }
    }

    #[test]
    fn test_validate_worker_threads_error_is_actionable() {
        // The text reaches the operator through mount.log, so it has to name the
        // config item and both ends of the accepted range -- not just "invalid".
        let message = validate_worker_threads(nz(64), nz(8)).expect_err("64 > 8 must be rejected");

        assert!(
            message.contains("64"),
            "names the requested count: {message}"
        );
        assert!(
            message.contains('8'),
            "names the available count: {message}"
        );
        assert!(
            message.contains("efs_proxy_worker_threads"),
            "names the config item so mount.log is actionable: {message}"
        );
        assert!(
            message.contains("between 1 and 8"),
            "names the accepted range: {message}"
        );
    }

    #[test]
    fn test_validate_worker_threads_unset_is_always_ok() {
        // Nothing configured means Tokio picks the count itself, so there is
        // nothing to bound -- including when parallelism is unknown.
        assert_eq!(Ok(()), validate_worker_threads(None, nz(16)));
        assert_eq!(Ok(()), validate_worker_threads(None, None));
    }

    #[test]
    fn test_validate_worker_threads_skips_the_bound_when_parallelism_is_unknown() {
        // `available_parallelism()` can fail (sandboxed /proc, exotic platform).
        // Honor the operator's count rather than refusing to start, and rather
        // than falling back to 1, which would reject every value above 1.
        for requested in [1, 8, 4096] {
            assert_eq!(
                Ok(()),
                validate_worker_threads(nz(requested), None),
                "--worker-threads {requested} should be allowed when parallelism is unknown"
            );
        }
    }

    #[test]
    fn test_validate_worker_threads_agrees_with_the_runtime_default() {
        // The claim the bound rests on: the ceiling equals the worker count
        // Tokio builds when nothing is configured. Asserting it against the
        // live runtime means a future change to either side breaks this test
        // rather than silently letting the two drift apart.
        // The ceiling is `available_parallelism()`, which is what Tokio defaults
        // to only when TOKIO_WORKER_THREADS is absent. Skip when a developer's
        // own shell has that variable set, since the invariant genuinely does not
        // hold under an override. Nothing in this suite sets it, so there is no
        // in-process writer to race.
        if std::env::var_os("TOKIO_WORKER_THREADS").is_some() {
            return;
        }

        let available = std::thread::available_parallelism()
            .expect("this test host must be able to report its parallelism");
        let default_workers = built_worker_count(&["efs-proxy", "proxy-config"]);

        assert_eq!(available.get(), default_workers);
        assert_eq!(
            Ok(()),
            validate_worker_threads(Some(available), Some(available))
        );
        assert!(validate_worker_threads(nz(available.get() + 1), Some(available)).is_err());
    }

    #[test]
    fn test_unset_is_indistinguishable_from_a_vanilla_tokio_runtime() {
        // The compatibility guarantee, and the precedence rule, asserted without
        // touching any environment variable.
        //
        // Precedence over TOKIO_WORKER_THREADS is a consequence of two facts.
        // First, `test_runtime_uses_configured_worker_count` shows an explicit
        // count yields exactly that many workers -- so nothing else, the
        // environment included, can influence the count on that path. Second,
        // this test shows the unset path is byte-for-byte the builder state bare
        // `#[tokio::main]` produced, so whatever Tokio resolves from the
        // environment it resolves identically before and after this change.
        //
        // Comparing against a locally built vanilla runtime rather than against
        // `available_parallelism()` is what makes this hermetic: both runtimes
        // read the same ambient environment, so they agree whatever it says, and
        // the test neither mutates a process-global nor skips.
        let vanilla = runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("vanilla multi-thread runtime must build")
            .metrics()
            .num_workers();

        assert_eq!(
            vanilla,
            built_worker_count(&["efs-proxy", "proxy-config"]),
            "omitting --worker-threads must leave exactly the builder state \
             #[tokio::main] used"
        );
    }

    #[test]
    fn test_runtime_uses_configured_worker_count() {
        for requested in [1, 2, 4, 8, 16] {
            let count = built_worker_count(&[
                "efs-proxy",
                "proxy-config",
                "--worker-threads",
                &requested.to_string(),
            ]);
            assert_eq!(requested, count);
        }
    }

    #[test]
    fn test_runtime_defaults_to_available_parallelism() {
        // With the option unset the runtime keeps Tokio's own default. That
        // default is `TOKIO_WORKER_THREADS` when set and `available_parallelism`
        // otherwise -- the rule in `loom::sys::num_cpus` -- so deriving the
        // expectation the same way keeps this test correct in any environment
        // instead of failing, or silently skipping, when the variable is set.
        let expected = std::env::var("TOKIO_WORKER_THREADS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or_else(|| {
                std::thread::available_parallelism()
                    .map(NonZeroUsize::get)
                    .unwrap_or(1)
            });

        assert_eq!(expected, built_worker_count(&["efs-proxy", "proxy-config"]));
    }

    #[test]
    fn test_log_worker_threads_reads_the_live_runtime() {
        // `log_worker_threads` reads `Handle::current()`, so it has to run on a
        // runtime. Driving it through `build_runtime` covers both the override
        // and the default arm of the message it formats.
        for worker_threads in [NonZeroUsize::new(2), None] {
            build_runtime(worker_threads).block_on(async move {
                log_worker_threads(worker_threads);
            });
        }
    }

    #[tokio::test]
    async fn test_write_pid_file() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let pid_file = tempfile::NamedTempFile::new()?;
        let pid_file_path = pid_file.path();

        write_pid_file(pid_file_path).await?;

        let expected_pid = std::process::id().to_string();
        let read_pid = tokio::fs::read_to_string(pid_file_path).await?;
        assert_eq!(expected_pid + "\n", read_pid);
        Ok(())
    }
}
