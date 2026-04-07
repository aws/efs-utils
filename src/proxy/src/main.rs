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
use std::path::Path;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::signal;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

#[allow(clippy::all)]
#[allow(deprecated)]
#[allow(invalid_value)]
#[allow(non_camel_case_types)]
#[allow(unused_assignments)]
mod awsfile_prot {
    include!(concat!(env!("OUT_DIR"), "/awsfile_prot_xdr.rs"));
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

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
}

#[cfg(test)]
pub mod tests {

    use super::*;

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
