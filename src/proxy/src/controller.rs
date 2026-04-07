use crate::{
    aws::{
        cw_publisher::{CloudWatchClient, LogLevel},
        s3_client::S3ClientBuilder,
    },
    awsfile_prot::{
        AwsFileChannelInitArgs, AwsFileReadBypassConfigArgs, ChannelConfigArgs, ScaleUpConfig,
    },
    awsfile_rpc::{PartitionId, RpcClient},
    config::channel_init_config::ChannelInitConfig,
    config_parser::ProxyConfig,
    connections::{configure_stream, PartitionFinder, ProxyStream},
    proxy::Proxy,
    proxy_builder::ProxyBuilder,
    proxy_identifier::ProxyIdentifier,
    proxy_task::PerformanceStats,
    shutdown::{ShutdownHandle, ShutdownReason},
    status_reporter::{self, StatusReporter},
    utils::create_deadline,
};
use log::{debug, error, info, warn};
use std::{sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::mpsc, time::Instant};
use tokio_util::sync::CancellationToken;

pub const DEFAULT_SCALE_UP_BACKOFF: Duration = Duration::from_secs(300);

pub const DEFAULT_SCALE_UP_CONFIG: ScaleUpConfig = ScaleUpConfig {
    max_multiplexed_connections: 5,
    scale_up_bytes_per_ms_threshold: 300 * 1024 * 1024 / 1000,
    scale_up_threshold_breached_duration_ms: 1000,
    scale_up_lookback_window_size_ms: 1000,
};

#[derive(Debug)]
pub enum Event<S> {
    ProxyUpdate(PerformanceStats),
    ConnectionSuccess(Option<PartitionId>, Vec<S>, ScaleUpConfig),
    ConnectionFail(Option<ScaleUpConfig>),
}

enum EventResult<S> {
    Restart((Option<PartitionId>, Vec<S>, Option<ScaleUpConfig>)),
    Ok,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ConnectionSearchState {
    SearchingAdditional(Option<PartitionId>),
    Stop(Instant),
    Idle,
}

struct IncarnationState<S: ProxyStream> {
    pub proxy_id: ProxyIdentifier,
    pub last_proxy_update: Option<(Instant, PerformanceStats)>,
    pub partition_id: Option<PartitionId>,
    connection_state: ConnectionSearchState,
    pub num_connections: u16,
    events_tx: mpsc::Sender<Event<S>>,
}

impl<S: ProxyStream> IncarnationState<S> {
    fn new(
        proxy_id: ProxyIdentifier,
        partition_id: Option<PartitionId>,
        events_tx: mpsc::Sender<Event<S>>,
        num_connections: u16,
    ) -> Self {
        Self {
            proxy_id,
            last_proxy_update: None,
            partition_id,
            connection_state: ConnectionSearchState::Idle,
            num_connections,
            events_tx,
        }
    }
}

pub struct Controller<S: ProxyStream> {
    pub listener: TcpListener,
    pub partition_finder: Arc<dyn PartitionFinder<S> + Sync + Send>,
    pub proxy_id: ProxyIdentifier,
    pub scale_up_attempt_count: u64,
    pub restart_count: u64,
    pub scale_up_config: ScaleUpConfig,
    pub status_reporter: StatusReporter,
    pub proxy_config: ProxyConfig,
    pub cw_publisher: Option<Arc<dyn CloudWatchClient>>,
}

impl<S: ProxyStream> Controller<S> {
    pub async fn new(
        listen_addr: &str,
        proxy_config: ProxyConfig,
        partition_finder: Arc<impl PartitionFinder<S> + Sync + Send + 'static>,
        status_reporter: StatusReporter,
        cw_publisher: Option<Arc<dyn CloudWatchClient>>,
    ) -> Self {
        let Ok(listener) = TcpListener::bind(listen_addr).await else {
            panic!("Failed to bind {}", listen_addr);
        };

        Self {
            listener,
            partition_finder,
            proxy_id: ProxyIdentifier::new(),
            scale_up_attempt_count: 0,
            restart_count: 0,
            scale_up_config: DEFAULT_SCALE_UP_CONFIG,
            status_reporter,
            proxy_config,
            cw_publisher,
        }
    }

    pub async fn run<T: RpcClient, V: S3ClientBuilder>(
        mut self,
        token: CancellationToken,
        rpc_client: T,
        s3_client_builder: V,
    ) -> Option<ShutdownReason> {
        let mut ready_connections = None;
        // Main Proxy incarnation management loop
        loop {
            // Set init_deadline to be 1 second less than the `proxy_init_timeout_sec`, as we
            // expect this proxy to be killed if the initial NFS mount did not succeed when the full
            // `proxy_init_timeout_sec` has elapsed.
            let init_deadline = create_deadline(Duration::from_secs(
                self.proxy_config
                    .nested_config
                    .proxy_init_timeout_sec
                    .saturating_sub(1),
            ));

            info!("Starting new incarnation of proxy");
            let nfs_client = match self.listener.accept().await {
                Ok((client, socket_addr)) => {
                    self.proxy_id.increment();
                    info!(
                        "Accepted new connection {:?}, {:?} ",
                        socket_addr, self.proxy_id
                    );
                    configure_stream(client)
                }
                Err(e) => {
                    error!("Failed to establish connection to NFS client. {e}");
                    continue;
                }
            };

            let peek_result = nfs_client.peek(&mut [0; 1]).await;
            if let Ok(0) = peek_result {
                // efs-utils performs a test in which it checks if a connection to the proxy port
                // can be established. This connection is never used and is immediately closed.
                // When this behavior is detected, this loops should be restarted so that another
                // connection to the port can be established
                debug!("Connection to nfs client was closed before any data was sent to the proxy. This is expected. Restarting controller");
                continue;
            } else if let Err(e) = peek_result {
                error!("Failed to check if data was sent by the NFS client. {}", e);
                return Some(ShutdownReason::UnexpectedError);
            }

            // Create Status Notifications channel, to be used by Proxy's status_reporter for notifying controller about Proxy status
            let (status_events_tx, mut status_events_rx) = mpsc::channel(1024);
            let (shutdown, mut waiter) = ShutdownHandle::new(token.child_token());

            let (partition_id, mut partition_servers, scale_up_config) = match ready_connections {
                Some(connections) => {
                    ready_connections = None;
                    connections
                }
                None => {
                    let result = self
                        .partition_finder
                        .establish_connection(init_deadline, self.proxy_id)
                        .await;

                    self.emit_nfs_reachability(
                        result.is_ok(),
                        self.proxy_config.nested_config.fs_id.as_str(),
                    )
                    .await;

                    match result {
                        Ok((s, partition_id, scale_up_config)) => {
                            (partition_id, vec![s], scale_up_config)
                        }
                        Err(e) => {
                            warn!("Failed to establish an initial connection to EFS. Error: {e}");
                            continue;
                        }
                    }
                }
            };

            match partition_id {
                Some(id) => debug!("Established initial connection with PartitionId: {id:?}"),
                None => debug!("Established initial connection without a PartitionId"),
            }

            let mut configs = Vec::new();

            // Add read bypass config if requested
            if self.proxy_config.nested_config.read_bypass_config.requested {
                configs.push(ChannelConfigArgs::AWSFILE_READ_BYPASS(
                    AwsFileReadBypassConfigArgs {
                        enabled: self.proxy_config.nested_config.read_bypass_config.enabled,
                    },
                ));
            }

            let channel_init_args = AwsFileChannelInitArgs {
                minor_version: 1,
                configs,
            };

            let channel_init_config = match rpc_client
                .channel_init(
                    init_deadline,
                    &channel_init_args,
                    partition_servers
                        .get_mut(0)
                        .expect("No awsfile server connections exist"),
                )
                .await
            {
                Ok(config) => {
                    debug!("ChannelInitConfig: {:#?}", config);
                    config
                }
                Err(e) => {
                    warn!("{e}");
                    ChannelInitConfig::default()
                }
            };

            self.scale_up_config = scale_up_config.unwrap_or(self.scale_up_config);
            debug!("ScaleUpConfig: {:#?}", self.scale_up_config);

            let s3_client = match channel_init_config.read_bypass_config.enabled
                && self.proxy_config.nested_config.read_bypass_config.enabled
            {
                true => {
                    let s3_bucket = channel_init_config.read_bypass_config.bucket_name.clone();
                    let s3_prefix = channel_init_config.read_bypass_config.prefix.clone();
                    s3_client_builder
                        .build(&s3_bucket, &s3_prefix, &self.proxy_config)
                        .await
                }
                false => None,
            };

            let mut state = IncarnationState::new(
                self.proxy_id,
                partition_id,
                status_events_tx.clone(),
                partition_servers.len() as u16,
            );

            let mut proxy = ProxyBuilder::build_proxy(
                nfs_client,
                partition_servers,
                status_events_tx,
                shutdown.clone(),
                self.proxy_config.clone(),
                channel_init_config,
                s3_client,
            )
            .await;

            // Proxy status loop
            let mut metrics_interval = tokio::time::interval_at(
                tokio::time::Instant::now() + Duration::from_secs(60),
                Duration::from_secs(60),
            );
            loop {
                let mut err = Ok(());
                tokio::select! {
                    _ = metrics_interval.tick() => {
                        let fs_id = self.proxy_config.nested_config.fs_id.as_str();
                        self.emit_nfs_reachability(true, fs_id).await;
                    }
                    _ = self.status_reporter.await_report_request() => {
                        let report = status_reporter::Report {
                            proxy_id: state.proxy_id,
                            partition_id: state.partition_id,
                            connection_state: state.connection_state.clone(),
                            num_connections: state.num_connections as usize,
                            last_proxy_update: state.last_proxy_update,
                            scale_up_attempt_count: self.scale_up_attempt_count,
                            restart_count: self.restart_count
                        };
                        self.status_reporter.publish_status(report).await;
                    }
                    event = status_events_rx.recv() => {
                        if let Some(next_event) = event {
                            match self.handle_event(next_event, &mut proxy, &mut state, shutdown.clone()).await {
                                Ok(EventResult::Restart(connections)) => {
                                    debug!("Restarting proxy to use multiple connections");
                                    ready_connections = Some(connections);
                                    shutdown.exit(Some(ShutdownReason::NeedsRestart)).await;
                                    break;
                                },
                                Ok(EventResult::Ok) => continue,
                                Err(e) => err = Err(e),
                            };

                        } else {
                            err = Err("All senders have closed");
                        }
                    }
                    _ = shutdown.cancellation_token.cancelled() => {
                        debug!("Controller exiting due to child exit");
                        break;
                    }
                    _ = self.listener.accept() => {
                        warn!("Unexpected connection, ignoring")
                    }
                }
                if err.is_err() {
                    info!("Starting proxy restart due to {}", err.unwrap_err());
                    break;
                }
            }

            if let Some(count) = self.restart_count.checked_add(1) {
                self.restart_count = count;
            }

            // Ensure that connection(s) to EFS is closed. If we can't successfully stop the proxy,
            // then exit from this process and allow the watchdog to restart the efs-proxy program.
            //
            if let Err(e) = proxy.shutdown().await {
                error!("Proxy shutdown failed. {}", e);
                return Some(ShutdownReason::UnexpectedError);
            };

            let shutdown_reason = waiter.recv().await;
            match shutdown_reason {
                Some(ShutdownReason::NeedsRestart) => {
                    debug!("Proxy restarting with ShutdownReason::NeedsRestart")
                }
                Some(ShutdownReason::Unmount) => {
                    debug!("Proxy restarting with ShutdownReason::Unmount")
                }
                reason => return reason,
            }
        }
    }

    fn should_scale_up(&self, state: &mut IncarnationState<S>, stats: PerformanceStats) -> bool {
        if let ConnectionSearchState::Stop(last_failure) = state.connection_state {
            if Instant::now().duration_since(last_failure) > DEFAULT_SCALE_UP_BACKOFF {
                state.connection_state = ConnectionSearchState::Idle;
            }
        }

        state.num_connections == 1
            && state.connection_state == ConnectionSearchState::Idle
            && stats.get_total_throughput_per_second()
                >= self.scale_up_config.scale_up_bytes_per_ms_threshold as u64 / 1000
    }

    async fn handle_event(
        &mut self,
        event: Event<S>,
        proxy: &mut Proxy<S>,
        state: &mut IncarnationState<S>,
        shutdown_handle: ShutdownHandle,
    ) -> Result<EventResult<S>, &str> {
        match event {
            Event::ProxyUpdate(stats) => {
                info!("Proxy performance: {:?}", stats);

                if self.should_scale_up(state, stats) {
                    info!("Searching for a new connection");
                    if let Some(count) = self.scale_up_attempt_count.checked_add(1) {
                        self.scale_up_attempt_count = count;
                    }

                    state.connection_state =
                        ConnectionSearchState::SearchingAdditional(state.partition_id);
                    self.partition_finder
                        .scale_up_connection(
                            state.proxy_id,
                            state.partition_id,
                            state.events_tx.clone(),
                            shutdown_handle,
                        )
                        .await;
                }
            }
            Event::ConnectionSuccess(id, streams, scale_up_config) => {
                info!("Established new TCP connection to {:?}", id);
                if state.partition_id == id {
                    assert_eq!(
                        (self.scale_up_config.max_multiplexed_connections - 1) as usize,
                        streams.len()
                    );
                    for stream in streams {
                        ProxyBuilder::add_connection(proxy, stream).await;
                    }
                } else {
                    assert_eq!(
                        self.scale_up_config.max_multiplexed_connections as usize,
                        streams.len()
                    );
                    assert!(id.is_some());
                    assert_ne!(state.partition_id, id);

                    return Ok(EventResult::Restart((id, streams, Some(scale_up_config))));
                }
                state.num_connections = self.scale_up_config.max_multiplexed_connections as u16;
                state.connection_state = ConnectionSearchState::Idle;
                self.scale_up_config = scale_up_config;
            }
            Event::ConnectionFail(scale_up_config) => {
                state.connection_state = ConnectionSearchState::Stop(Instant::now());
                self.scale_up_config = scale_up_config.unwrap_or(self.scale_up_config);
                info!("Connection failed");
            }
        }
        debug!("ScaleUpConfig: {:#?}", self.scale_up_config);
        Ok(EventResult::Ok)
    }

    async fn emit_nfs_reachability(&self, is_reachable: bool, fs_id: &str) {
        if let Some(publisher) = &self.cw_publisher {
            let (level, message) = if is_reachable {
                (
                    LogLevel::Info,
                    format!("NFS connection to EFS is established: fs_id='{}'", fs_id),
                )
            } else {
                (
                    // We use Warn level since these logs might be emitted during reconnections
                    // (scale up / scale down, EFS-side load balancing etc), which is not a real reachibility error
                    LogLevel::Warn,
                    format!(
                        "Failed to establish NFS connection to EFS: fs_id='{}'",
                        fs_id
                    ),
                )
            };
            publisher.emit_log(level, &message);
            publisher.publish_nfs_reachability(is_reachable, fs_id);
        }
    }
}
