use crate::{
    aws::{
        cw_publisher::{CloudWatchClient, LogLevel},
        s3_client::S3ClientBuilder,
    },
    awsfile_prot::{
        AwsFileChannelInitArgs, AwsFileReadBypassConfigArgsV2, ChannelConfigArgs, ScaleUpConfig,
    },
    awsfile_rpc::{PartitionId, RpcClient},
    config::channel_init_config::ChannelInitConfig,
    config_parser::ProxyConfig,
    connections::{configure_stream, PartitionFinder, ProxyStream},
    error::RpcError,
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

pub const METRICS_EMISSION_PERIOD: Duration = Duration::from_secs(60);

pub const AWSFILE_CHANNEL_INIT_MINOR_VERSION: u32 = 2;

pub const DEFAULT_SCALE_UP_BACKOFF: Duration = Duration::from_secs(300);

pub const DEFAULT_SCALE_UP_CONFIG: ScaleUpConfig = ScaleUpConfig {
    max_multiplexed_connections: 5,
    scale_up_bytes_per_sec_threshold: 300 * 1024 * 1024,
    scale_up_threshold_breached_duration_sec: 1,
    scale_up_lookback_window_size_sec: 1,
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

/// Result of the proxy status loop, used to communicate back to the outer incarnation loop.
pub(crate) enum StatusLoopResult<S> {
    /// The proxy should restart with pre-established connections.
    RestartWithConnections((Option<PartitionId>, Vec<S>, Option<ScaleUpConfig>)),
    /// The proxy status loop exited normally (shutdown or error).
    Break,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ConnectionSearchState {
    SearchingAdditional(Option<PartitionId>),
    Stop(Instant),
    Idle,
}

pub(crate) struct IncarnationState<S: ProxyStream> {
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
    ) -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind(listen_addr).await.map_err(|e| {
            error!(
                "Failed to bind to {}: {}. \
                Ensure the address is reachable and the port is not already in use.",
                listen_addr, e
            );
            e
        })?;

        Ok(Self {
            listener,
            partition_finder,
            proxy_id: ProxyIdentifier::new(),
            scale_up_attempt_count: 0,
            restart_count: 0,
            scale_up_config: DEFAULT_SCALE_UP_CONFIG,
            status_reporter,
            proxy_config,
            cw_publisher,
        })
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

            // Set init_deadline to be 1 second less than the `proxy_init_timeout_sec`, as we
            // expect this proxy to be killed if the initial NFS mount did not succeed when the full
            // `proxy_init_timeout_sec` has elapsed.
            // Set after accept so the timeout budget is not consumed by time spent waiting for
            // the NFS client to reconnect.
            let init_deadline = create_deadline(Duration::from_secs(
                self.proxy_config
                    .nested_config
                    .proxy_init_timeout_sec
                    .saturating_sub(1),
            ));

            // Create Status Notifications channel, to be used by Proxy's status_reporter for notifying controller about Proxy status
            let (status_events_tx, mut status_events_rx) = mpsc::channel(1024);
            let (shutdown, mut waiter) = ShutdownHandle::new(token.child_token());

            let used_reused_connections = ready_connections.is_some();
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

            // Skip channel init if read bypass is not requested
            let channel_init_config = if !self
                .proxy_config
                .nested_config
                .read_bypass_config
                .requested
            {
                ChannelInitConfig::default()
            } else {
                let configs = vec![ChannelConfigArgs::AWSFILE_READ_BYPASS_V2(
                    AwsFileReadBypassConfigArgsV2 {
                        enabled: self.proxy_config.nested_config.read_bypass_config.enabled,
                        efs_utils_version: self
                            .proxy_config
                            .nested_config
                            .efs_utils_version
                            .as_bytes()
                            .to_vec(),
                    },
                )];

                let channel_init_args = AwsFileChannelInitArgs {
                    minor_version: AWSFILE_CHANNEL_INIT_MINOR_VERSION,
                    configs,
                };

                match rpc_client
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
                        if used_reused_connections && matches!(&e, RpcError::ChannelInitTimeout) {
                            warn!("channel_init timed out on reused connections, restarting with fresh connections");
                            ready_connections = None;
                            continue;
                        }
                        ChannelInitConfig::default()
                    }
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

            let status_loop_result = self
                .run_proxy_status_loop(
                    &mut proxy,
                    &mut state,
                    &mut status_events_rx,
                    shutdown.clone(),
                    METRICS_EMISSION_PERIOD,
                )
                .await;

            if let StatusLoopResult::RestartWithConnections(connections) = status_loop_result {
                ready_connections = Some(connections);
                shutdown.exit(Some(ShutdownReason::NeedsRestart)).await;
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

    pub(crate) async fn run_proxy_status_loop(
        &mut self,
        proxy: &mut Proxy<S>,
        state: &mut IncarnationState<S>,
        status_events_rx: &mut mpsc::Receiver<Event<S>>,
        shutdown: ShutdownHandle,
        metrics_emission_period: Duration,
    ) -> StatusLoopResult<S> {
        let mut metrics_interval = tokio::time::interval_at(
            tokio::time::Instant::now() + metrics_emission_period,
            metrics_emission_period,
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
                        match self.handle_event(next_event, proxy, state, shutdown.clone()).await {
                            Ok(EventResult::Restart(connections)) => {
                                debug!("Restarting proxy to use multiple connections");
                                return StatusLoopResult::RestartWithConnections(connections);
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
        StatusLoopResult::Break
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
                >= self.scale_up_config.scale_up_bytes_per_sec_threshold as u64
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        aws::cw_publisher::LogLevel, config::channel_init_config::ChannelInitConfig,
        proxy_builder::ProxyBuilder, status_reporter::create_status_channel,
    };
    use std::sync::atomic::AtomicU64;
    use tokio::net::TcpStream;
    use tokio_util::sync::CancellationToken;

    struct MockCloudWatchClient {
        nfs_reachability_calls: AtomicU64,
    }

    impl MockCloudWatchClient {
        fn new() -> Self {
            Self {
                nfs_reachability_calls: AtomicU64::new(0),
            }
        }

        fn nfs_reachability_call_count(&self) -> u64 {
            self.nfs_reachability_calls
                .load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl CloudWatchClient for MockCloudWatchClient {
        fn emit_log(&self, _level: LogLevel, _message: &str) {}
        fn publish_s3_reachable(&self, _bucket: &str, _is_reachable: bool) {}
        fn publish_s3_permitted(&self, _bucket: &str, _is_permitted: bool) {}
        fn publish_nfs_reachability(&self, _is_reachable: bool, _fs_id: &str) {
            self.nfs_reachability_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    struct MockPartitionFinder;

    #[async_trait::async_trait]
    impl PartitionFinder<TcpStream> for MockPartitionFinder {
        async fn create_connect_future(
            &self,
        ) -> futures::future::BoxFuture<'static, Result<TcpStream, crate::error::ConnectError>>
        {
            unimplemented!()
        }
    }

    async fn create_tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    #[tokio::test]
    async fn test_status_loop_emits_nfs_reachability_every_minute() {
        let mock_publisher = Arc::new(MockCloudWatchClient::new());
        let (_status_requester, status_reporter) = create_status_channel();

        let controller_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();

        let mut proxy_config = ProxyConfig::default();
        proxy_config.nested_config.fs_id = "fs-test123".to_string();

        let mut controller = Controller::<TcpStream> {
            listener: controller_listener,
            partition_finder: Arc::new(MockPartitionFinder),
            proxy_id: ProxyIdentifier::new(),
            scale_up_attempt_count: 0,
            restart_count: 0,
            scale_up_config: DEFAULT_SCALE_UP_CONFIG,
            status_reporter,
            proxy_config: proxy_config.clone(),
            cw_publisher: Some(mock_publisher.clone()),
        };

        // Build a minimal proxy
        let (nfs_client, _nfs_server) = create_tcp_pair().await;
        let (_efs_client, efs_server) = create_tcp_pair().await;
        let (events_tx, mut events_rx) = mpsc::channel(1024);
        let token = CancellationToken::new();
        let (shutdown, _waiter) = ShutdownHandle::new(token.clone());

        let mut proxy = ProxyBuilder::<TcpStream>::build_proxy(
            nfs_client,
            vec![efs_server],
            events_tx.clone(),
            shutdown.clone(),
            proxy_config,
            ChannelInitConfig::default(),
            None,
        )
        .await;

        let mut state = IncarnationState::new(ProxyIdentifier::new(), None, events_tx, 1);

        let period_secs = 10;
        let publisher_clone = mock_publisher.clone();
        let cancel_token = token.clone();

        tokio::time::pause();

        let handle = tokio::spawn(async move {
            controller
                .run_proxy_status_loop(
                    &mut proxy,
                    &mut state,
                    &mut events_rx,
                    shutdown,
                    Duration::from_secs(period_secs),
                )
                .await;
            proxy
        });

        // Let the spawned task start polling
        tokio::task::yield_now().await;

        // First tick
        tokio::time::advance(Duration::from_secs(period_secs)).await;
        for _ in 0..10 {
            tokio::time::advance(Duration::from_millis(10)).await;
            tokio::task::yield_now().await;
        }
        assert_eq!(publisher_clone.nfs_reachability_call_count(), 1);

        // Second tick
        tokio::time::advance(Duration::from_secs(period_secs)).await;
        for _ in 0..10 {
            tokio::time::advance(Duration::from_millis(10)).await;
            tokio::task::yield_now().await;
        }
        assert_eq!(publisher_clone.nfs_reachability_call_count(), 2);

        // Third tick
        tokio::time::advance(Duration::from_secs(period_secs)).await;
        for _ in 0..10 {
            tokio::time::advance(Duration::from_millis(10)).await;
            tokio::task::yield_now().await;
        }
        assert_eq!(publisher_clone.nfs_reachability_call_count(), 3);

        cancel_token.cancel();
        tokio::time::resume();

        let proxy = handle.await.unwrap();
        let _ = proxy.shutdown().await;
    }

    #[tokio::test]
    async fn test_controller_new_bind_failure_returns_err() {
        // Occupy a port so the second bind attempt fails.
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = occupied.local_addr().unwrap();

        let (_status_requester, status_reporter) = create_status_channel();
        let result = Controller::new(
            &addr.to_string(),
            ProxyConfig::default(),
            Arc::new(MockPartitionFinder),
            status_reporter,
            None,
        )
        .await;

        assert!(result.is_err(), "expected Err when port is already bound");
    }
}
