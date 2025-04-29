use crate::connections::configure_stream;
use crate::efs_prot::ScaleUpConfig;
use crate::efs_rpc::PartitionId;
use crate::shutdown::ShutdownReason;
use crate::status_reporter::{self, StatusReporter};
use crate::{
    connections::{PartitionFinder, ProxyStream},
    proxy::Proxy,
    proxy_identifier::ProxyIdentifier,
    proxy_task::PerformanceStats,
    shutdown::ShutdownHandle,
};
use log::{debug, error, info, warn};
use std::{sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::mpsc, time::Instant};
use tokio_util::sync::CancellationToken;

pub const DEFAULT_SCALE_UP_BACKOFF: Duration = Duration::from_secs(300);

pub const DEFAULT_SCALE_UP_CONFIG: ScaleUpConfig = ScaleUpConfig {
    max_multiplexed_connections: 5,
    scale_up_bytes_per_sec_threshold: 300 * 1024 * 1024,
    scale_up_threshold_breached_duration_sec: 1,
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
}

impl<S: ProxyStream> Controller<S> {
    pub async fn new(
        listen_addr: &str,
        partition_finder: Arc<impl PartitionFinder<S> + Sync + Send + 'static>,
        status_reporter: StatusReporter,
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
        }
    }

    pub async fn run(mut self, token: CancellationToken) -> Option<ShutdownReason> {
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

            // Create Status Notifications channel, to be used by Proxy's status_reporter for notifying controller about Proxy status
            let (status_events_tx, mut status_events_rx) = mpsc::channel(1024);
            let (shutdown, mut waiter) = ShutdownHandle::new(token.child_token());

            let (partition_id, partition_servers, scale_up_config) = match ready_connections {
                Some(connections) => {
                    ready_connections = None;
                    connections
                }
                None => {
                    match self
                        .partition_finder
                        .establish_connection(self.proxy_id)
                        .await
                    {
                        Ok((s, partition_id, scale_up_config)) => {
                            (partition_id, vec![s], scale_up_config)
                        }
                        Err(e) => {
                            warn!("Failed to establish an initial connection to EFS. Error: {e}",);
                            continue;
                        }
                    }
                }
            };

            match partition_id {
                Some(id) => debug!("Established initial connection with PartitionId: {id:?}"),
                None => debug!("Established initial connection without a PartitionId"),
            }

            self.scale_up_config = scale_up_config.unwrap_or(self.scale_up_config);
            debug!("ScaleUpConfig: {:#?}", self.scale_up_config);

            let mut state = IncarnationState::new(
                self.proxy_id,
                partition_id,
                status_events_tx.clone(),
                partition_servers.len() as u16,
            );

            let mut proxy = Proxy::new(
                nfs_client,
                partition_servers,
                status_events_tx,
                shutdown.clone(),
            );

            // Proxy status loop
            loop {
                let mut err = Ok(());
                tokio::select! {
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
            && stats.get_total_throughput()
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
                        proxy.add_connection(stream).await;
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
}
