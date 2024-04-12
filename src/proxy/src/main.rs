use crate::config_parser::ProxyConfig;
use crate::connections::{PlainTextPartitionFinder, TlsPartitionFinder};
use crate::tls::TlsConfig;
use clap::Parser;
use controller::Controller;
use log::{debug, error, info};
use std::path::Path;
use std::sync::Arc;
use tokio::signal;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

mod config_parser;
mod connections;
mod controller;
mod efs_rpc;
mod error;
mod logger;
mod proxy;
mod proxy_identifier;
mod rpc;
mod shutdown;
mod status_reporter;
mod tls;

#[allow(clippy::all)]
#[allow(deprecated)]
#[allow(invalid_value)]
#[allow(non_camel_case_types)]
#[allow(unused_assignments)]
mod efs_prot {
    include!(concat!(env!("OUT_DIR"), "/efs_prot_xdr.rs"));
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let proxy_config = match ProxyConfig::from_path(Path::new(&args.proxy_config_path)) {
        Ok(config) => config,
        Err(e) => panic!("Failed to read configuration. {}", e),
    };

    if let Some(_log_file_path) = &proxy_config.output {
        logger::init(&proxy_config)
    }

    info!("Running with configuration: {:?}", proxy_config);

    // This "status reporter" is currently only used in tests
    let (_status_requester, status_reporter) = status_reporter::create_status_channel();

    let sigterm_cancellation_token = CancellationToken::new();
    let mut sigterm_listener = match signal::unix::signal(signal::unix::SignalKind::terminate()) {
        Ok(listener) => listener,
        Err(e) => panic!("Failed to create SIGTERM listener. {}", e),
    };

    let controller_handle = if args.tls {
        let tls_config = match get_tls_config(&proxy_config).await {
            Ok(config) => Arc::new(Mutex::new(config)),
            Err(e) => panic!("Failed to obtain TLS config:{}", e),
        };

        run_sighup_handler(proxy_config.clone(), tls_config.clone());

        let controller = Controller::new(
            &proxy_config.nested_config.listen_addr,
            Arc::new(TlsPartitionFinder::new(tls_config)),
            status_reporter,
        )
        .await;
        tokio::spawn(controller.run(sigterm_cancellation_token.clone()))
    } else {
        let controller = Controller::new(
            &proxy_config.nested_config.listen_addr,
            Arc::new(PlainTextPartitionFinder {
                mount_target_addr: proxy_config.nested_config.mount_target_addr.clone(),
            }),
            status_reporter,
        )
        .await;
        tokio::spawn(controller.run(sigterm_cancellation_token.clone()))
    };

    tokio::select! {
        shutdown_reason = controller_handle => error!("Shutting down. {:?}", shutdown_reason),
        _ = sigterm_listener.recv() => {
            info!("Received SIGTERM");
            sigterm_cancellation_token.cancel();
        },
    }
}

async fn get_tls_config(proxy_config: &ProxyConfig) -> Result<TlsConfig, anyhow::Error> {
    let tls_config = TlsConfig::new(
        proxy_config.fips,
        Path::new(&proxy_config.nested_config.ca_file),
        Path::new(&proxy_config.nested_config.client_cert_pem_file),
        Path::new(&proxy_config.nested_config.client_private_key_pem_file),
        &proxy_config.nested_config.mount_target_addr,
        &proxy_config.nested_config.expected_server_hostname_tls,
    )
    .await;
    let tls_config = tls_config?;
    Ok(tls_config)
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
}
