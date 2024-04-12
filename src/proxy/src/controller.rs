use crate::connections::configure_stream;
use crate::efs_prot::ScaleUpConfig;
use crate::efs_rpc::PartitionId;
use crate::shutdown::ShutdownReason;
use crate::status_reporter::{self, StatusReporter};
use crate::{
    connections::{PartitionFinder, ProxyStream},
    proxy::{PerformanceStats, Proxy},
    proxy_identifier::ProxyIdentifier,
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
    listener: TcpListener,
    partition_finder: Arc<dyn PartitionFinder<S> + Sync + Send>,
    proxy_id: ProxyIdentifier,
    scale_up_attempt_count: u64,
    restart_count: u64,
    scale_up_config: ScaleUpConfig,
    status_reporter: StatusReporter,
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

            let (events_tx, mut events_rx) = mpsc::channel(1024);
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
                events_tx.clone(),
                partition_servers.len() as u16,
            );

            let mut proxy = Proxy::new(nfs_client, partition_servers, events_tx, shutdown.clone());

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
                    event = events_rx.recv() => {
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

#[cfg(test)]
pub mod tests {
    use crate::config_parser::tests::get_test_config;
    use crate::connections::PlainTextPartitionFinder;
    use crate::connections::ProxyStream;
    use crate::connections::MULTIPLEX_CONNECTION_TIMEOUT_SEC;
    use crate::controller::ConnectionSearchState;
    use crate::controller::DEFAULT_SCALE_UP_BACKOFF;
    use crate::efs_prot;
    use crate::efs_prot::BindResponse;
    use crate::efs_prot::ScaleUpConfig;
    use crate::efs_rpc;
    use crate::efs_rpc::PartitionId;
    use crate::proxy;
    use crate::proxy_identifier::ProxyIdentifier;
    use crate::proxy_identifier::INITIAL_INCARNATION;
    use crate::rpc;
    use crate::rpc::RPC_HEADER_SIZE;
    use crate::shutdown::ShutdownReason;
    use crate::status_reporter;
    use crate::status_reporter::Report;
    use crate::status_reporter::StatusRequester;
    use crate::tls::tests::get_server_config;
    use crate::tls::TlsConfig;
    use crate::{connections::TlsPartitionFinder, controller::Controller};

    use bytes::BytesMut;
    use log::debug;
    use onc_rpc::RpcMessage;
    use rand::Rng;
    use std::collections::HashMap;
    use std::collections::HashSet;
    use std::io::ErrorKind;
    use std::sync::atomic::AtomicU32;
    use std::time::Duration;
    use std::{self, io::Error, sync::Arc};
    use test_case::test_case;
    use tokio::time::error::Elapsed;
    use tokio::time::timeout;
    use tokio::{
        io::AsyncWriteExt,
        net::{TcpListener, TcpStream},
        sync::oneshot,
        sync::Mutex,
        task::JoinHandle,
    };
    use tokio_util::sync::CancellationToken;

    use super::DEFAULT_SCALE_UP_CONFIG;

    #[derive(Copy, Clone, Debug, PartialEq)]
    pub enum ServiceAction {
        // Server will reject the next incoming TCP connection. Further attempts will succeed.
        //
        RejectNextNewConnectionRequest,

        // The server will close the next connection that receives a request from the proxy.
        //
        CloseOnNextRequest,

        // The server will close a random connection without waiting for any incoming request.
        //
        CloseRandomConnection,

        // This service will restart accepting connections to the given PartitionId
        //
        _RestartPartitionAcceptor(PartitionId),

        // This service will not accept connections to the given PartitionId
        //
        StopPartitionAcceptor(PartitionId),

        // This service will close the connection if a bind_client_to_partition request is received
        //
        CloseOnNextBindClientToPartitionRequest,

        // The service will send BindResponse::RETRY_LATER on subsequent bind_client_to_partition requests
        //
        DisableScaleUp,

        // The service will allow re-enabling scale up after the DisableScaleUp action is posted.
        //
        EnableScaleUp,

        // The service will respond with BindResponse::RETRY on the next n bind_client_to_partition requests
        SendRetries(u32),
    }

    const PARTITION_COUNT: usize = 3;

    pub struct TestService {
        pub listen_port: u16,
        posted_action: Arc<Mutex<Option<ServiceAction>>>,
        shutdown_tx: oneshot::Sender<()>,
        join_handle: JoinHandle<()>,
        pub partition_ids: Vec<PartitionId>,
        pub stopped_partitions: Arc<Mutex<HashSet<PartitionId>>>,
        pub request_counter: Arc<Mutex<HashMap<PartitionId, Vec<Arc<AtomicU32>>>>>,
    }

    impl TestService {
        const ALWAYS_SCALE_UP_THRESHOLD_BYTES_PER_SEC: i32 = 0;
        const NEVER_SCALE_UP_THRESHOLD_BYTES_PER_SEC: i32 = i32::MAX;

        pub async fn new(tls: bool) -> Self {
            TestService::new_with_partition_count(PARTITION_COUNT, tls).await
        }

        pub async fn new_with_partition_count(count: usize, tls: bool) -> Self {
            TestService::new_with_partition_count_and_scale_up_config(
                count,
                super::DEFAULT_SCALE_UP_CONFIG,
                tls,
            )
            .await
        }

        pub async fn new_with_throughput_scale_up_threshold(threshold: i32, tls: bool) -> Self {
            let mut config = super::DEFAULT_SCALE_UP_CONFIG.clone();
            config.scale_up_bytes_per_sec_threshold = threshold;
            TestService::new_with_partition_count_and_scale_up_config(PARTITION_COUNT, config, tls)
                .await
        }

        pub async fn new_with_partition_count_and_scale_up_threshold(
            count: usize,
            threshold: i32,
            tls: bool,
        ) -> Self {
            let mut config = super::DEFAULT_SCALE_UP_CONFIG.clone();
            config.scale_up_bytes_per_sec_threshold = threshold;
            TestService::new_with_partition_count_and_scale_up_config(count, config, tls).await
        }

        pub async fn new_with_partition_count_and_scale_up_config(
            count: usize,
            scale_up_config: ScaleUpConfig,
            tls: bool,
        ) -> Self {
            let (tcp_listener, listen_port) = find_available_port().await;

            let partition_ids = (0..count)
                .map(|_| PartitionId {
                    id: efs_rpc::tests::generate_partition_id().0,
                })
                .collect::<Vec<PartitionId>>();

            let stopped_partitions = Arc::new(Mutex::new(HashSet::new()));

            let mut counter = HashMap::new();
            for id in partition_ids.iter() {
                counter.insert(id.clone(), Vec::new());
            }
            let request_counter = Arc::new(Mutex::new(counter));

            let posted_action = Arc::new(Mutex::new(Option::None));
            let (shutdown_tx, shutdown_rx) = oneshot::channel();

            let service_handle = TestService::run(
                tcp_listener,
                scale_up_config,
                partition_ids.clone(),
                stopped_partitions.clone(),
                request_counter.clone(),
                posted_action.clone(),
                tls,
                shutdown_rx,
            );

            TestService {
                listen_port,
                posted_action,
                shutdown_tx,
                join_handle: service_handle,
                partition_ids,
                stopped_partitions,
                request_counter,
            }
        }

        pub async fn post_action(&self, new_action: ServiceAction) {
            match new_action {
                ServiceAction::_RestartPartitionAcceptor(id) => {
                    let mut stopped = self.stopped_partitions.lock().await;
                    assert!(stopped.remove(&id), "Partition is not stopped");
                    return;
                }
                ServiceAction::StopPartitionAcceptor(id) => {
                    let mut stopped = self.stopped_partitions.lock().await;
                    stopped.insert(id);
                    return;
                }
                ServiceAction::EnableScaleUp => {
                    TestService::check_and_consume_action(
                        &self.posted_action,
                        ServiceAction::DisableScaleUp,
                    )
                    .await;
                    return;
                }
                _ => (),
            };

            let mut consumable_action = self.posted_action.lock().await;
            if consumable_action.is_some() {
                panic!("Previous action was not consumed");
            }
            *consumable_action = Some(new_action);
        }

        fn run(
            listener: TcpListener,
            scale_up_config: ScaleUpConfig,
            partition_ids: Vec<PartitionId>,
            stopped_partitions: Arc<Mutex<HashSet<PartitionId>>>,
            request_counter: Arc<Mutex<HashMap<PartitionId, Vec<Arc<AtomicU32>>>>>,
            posted_action: Arc<Mutex<Option<ServiceAction>>>,
            tls: bool,
            mut shutdown_rx: oneshot::Receiver<()>,
        ) -> JoinHandle<()> {
            tokio::spawn(async move {
                let mut partition_idx = 0;
                loop {
                    tokio::select! {
                        socket = listener.accept() => {
                            let Ok((tcp_stream, _socket_addr)) = socket else {
                                panic!("Failed to establish connection to client");
                            };

                            if tls {
                                let tls_acceptor = s2n_tls_tokio::TlsAcceptor::new(get_server_config().await.expect("Could not get config"));
                                let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                                    Ok(conn) => conn,
                                    Err(e) => {
                                        panic!("Failed to establish TLS connection: {}", e);
                                    }
                                };
                                Self::inner_run(tls_stream, scale_up_config, &mut partition_idx, &partition_ids, stopped_partitions.clone(), request_counter.clone(), posted_action.clone()).await;
                            } else {
                                Self::inner_run(tcp_stream, scale_up_config, &mut partition_idx, &partition_ids, stopped_partitions.clone(), request_counter.clone(), posted_action.clone()).await;
                            }
                        },
                        _ = &mut shutdown_rx => {
                            break;
                        }
                    };
                }
            })
        }

        async fn inner_run<S: ProxyStream>(
            stream: S,
            scale_up_config: ScaleUpConfig,
            partition_idx: &mut usize,
            partition_ids: &Vec<PartitionId>,
            stopped_partitions: Arc<Mutex<HashSet<PartitionId>>>,
            request_counter: Arc<Mutex<HashMap<PartitionId, Vec<Arc<AtomicU32>>>>>,
            posted_action: Arc<Mutex<Option<ServiceAction>>>,
        ) {
            if TestService::check_and_consume_action(
                &posted_action,
                ServiceAction::RejectNextNewConnectionRequest,
            )
            .await
                || TestService::check_and_consume_action(
                    &posted_action,
                    ServiceAction::CloseRandomConnection,
                )
                .await
            {
                debug!("RejectNextNewConnectionRequest processed");
                drop(stream);
            } else {
                let stopped = stopped_partitions.lock().await;
                let mut next_id = None;
                for i in 0..partition_ids.len() {
                    *partition_idx = (*partition_idx + i + 1) % partition_ids.len();
                    if !stopped.contains(&partition_ids[*partition_idx]) {
                        next_id = Some(partition_ids[*partition_idx].clone());
                        break;
                    }
                }
                let Some(id) = next_id else {
                    panic!("No available PartitionIds")
                };

                let request_count = Arc::new(AtomicU32::new(0));
                request_counter
                    .lock()
                    .await
                    .get_mut(&id)
                    .expect("Counter for partition not found")
                    .push(request_count.clone());

                tokio::spawn(TestService::new_connection(
                    stream,
                    scale_up_config,
                    posted_action.clone(),
                    id,
                    request_count.clone(),
                ));
            }
        }

        async fn check_and_consume_action(
            posted_action: &Arc<Mutex<Option<ServiceAction>>>,
            to_check: ServiceAction,
        ) -> bool {
            let mut action = posted_action.lock().await;
            if *action == Some(to_check) {
                *action = Option::None;
                true
            } else {
                false
            }
        }

        async fn check_action(
            posted_action: &Arc<Mutex<Option<ServiceAction>>>,
            to_check: ServiceAction,
        ) -> bool {
            let action = posted_action.lock().await;
            *action == Some(to_check)
        }

        async fn new_connection<S: ProxyStream>(
            mut stream: S,
            scale_up_config: ScaleUpConfig,
            posted_action: Arc<Mutex<Option<ServiceAction>>>,
            partition_id: PartitionId,
            request_count: Arc<AtomicU32>,
        ) {
            loop {
                let Ok(message) = rpc::read_rpc_bytes(&mut stream).await else {
                    break;
                };

                request_count.fetch_add(1, std::sync::atomic::Ordering::AcqRel);

                if TestService::check_and_consume_action(
                    &posted_action,
                    ServiceAction::CloseOnNextRequest,
                )
                .await
                {
                    debug!("CloseOnNextRequest processed");
                    break;
                }

                let response = match TestService::parse_bind_client_to_partition_request(&message) {
                    Ok(rpc_message) => {
                        if TestService::check_and_consume_action(
                            &posted_action,
                            ServiceAction::CloseOnNextBindClientToPartitionRequest,
                        )
                        .await
                        {
                            debug!("CloseOnNextBindClientToPartitionRequest processed");
                            break;
                        }

                        let mut bind_response =
                            BindResponse::READY(efs_prot::PartitionId(partition_id.id));

                        if TestService::check_action(&posted_action, ServiceAction::DisableScaleUp)
                            .await
                        {
                            bind_response = BindResponse::RETRY_LATER(
                                "Returning BindResponse::RETRY_LATER".into(),
                            );
                        }

                        let mut action = posted_action.lock().await;
                        if let Some(ServiceAction::SendRetries(count)) = *action {
                            bind_response =
                                BindResponse::RETRY("Returning BindResponse::RETRY".into());
                            if count > 1 {
                                *action = Some(ServiceAction::SendRetries(count - 1));
                            } else {
                                *action = None;
                            }
                        }

                        efs_rpc::tests::create_bind_client_to_partition_response(
                            rpc_message.xid(),
                            bind_response,
                            scale_up_config,
                        )
                        .expect("Could not create response")
                    }
                    Err(_) => {
                        // If the test server doesn't parse a `bind_client_to_partition` request,
                        // then echo request back to the client
                        message
                    }
                };

                stream
                    .write_all(&response)
                    .await
                    .expect("Could not write to stream");
            }
        }

        fn parse_bind_client_to_partition_request(
            request: &Vec<u8>,
        ) -> Result<RpcMessage<&[u8], &[u8]>, Box<dyn std::error::Error + Send + Sync>> {
            let rpc_message = onc_rpc::RpcMessage::try_from(request.as_slice())?;
            efs_rpc::tests::parse_bind_client_to_partition_request(&rpc_message)?;
            Ok(rpc_message)
        }

        pub async fn shutdown(self) {
            drop(self.shutdown_tx);
            self.join_handle.await.unwrap();
        }
    }

    struct TestClient {
        stream: TcpStream,
        next_xid: u32,
    }

    impl TestClient {
        async fn new(proxy_port: u16) -> Self {
            let stream = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
            Self {
                stream,
                next_xid: 0,
            }
        }

        async fn send_message_with_size(&mut self, size: usize) -> Result<(), Error> {
            self.next_xid += 1;
            let (request, expected_data) = rpc::test::generate_msg_fragments(size, 1);
            self.stream.write_all(&request).await?;

            let response = rpc::read_rpc_bytes(&mut self.stream).await?;

            let payload_result =
                rpc::RpcBatch::parse_batch(&mut BytesMut::from(response.as_slice()))
                    .expect("No message found")
                    .expect("failed to parse");

            let rpc = payload_result.rpcs.get(0).expect("No RPCs found");
            assert_eq!(expected_data, rpc.to_vec()[RPC_HEADER_SIZE..]);
            Ok(())
        }

        async fn send_partial_message_with_size(&mut self, size: usize) -> Result<(), Error> {
            self.next_xid += 1;
            let (_, m1) = rpc::test::generate_msg_fragments(size, 1);
            let mut rng = rand::thread_rng();
            self.stream
                .write_all(&m1[0..rng.gen_range(1..size - 1)])
                .await?;
            Ok(())
        }
    }

    pub struct ProxyUnderTest {
        listen_port: u16,
        handle: JoinHandle<Option<ShutdownReason>>,
        status_requester: StatusRequester,
        scale_up_config: ScaleUpConfig,
    }

    impl ProxyUnderTest {
        pub async fn new(tls: bool, server_port: u16) -> Self {
            let scale_up_config = DEFAULT_SCALE_UP_CONFIG;
            let (tcp_listener, listen_port) = find_available_port().await;

            let (status_requester, status_reporter) = status_reporter::create_status_channel();

            let handle = if tls {
                let mut tls_config = TlsConfig::new_from_config(&get_test_config())
                    .await
                    .expect("Failed to acquire TlsConfig.");
                tls_config.remote_addr = format!("127.0.0.1:{}", server_port);

                let partition_finder =
                    Arc::new(TlsPartitionFinder::new(Arc::new(Mutex::new(tls_config))));

                let controller = Controller {
                    listener: tcp_listener,
                    partition_finder,
                    proxy_id: ProxyIdentifier::new(),
                    scale_up_attempt_count: 0,
                    restart_count: 0,
                    scale_up_config: scale_up_config,
                    status_reporter,
                };

                let token = CancellationToken::new();
                tokio::spawn(controller.run(token))
            } else {
                let partition_finder = Arc::new(PlainTextPartitionFinder {
                    mount_target_addr: format!("127.0.0.1:{}", server_port),
                });

                let controller = Controller {
                    listener: tcp_listener,
                    partition_finder,
                    proxy_id: ProxyIdentifier::new(),
                    scale_up_attempt_count: 0,
                    restart_count: 0,
                    scale_up_config: scale_up_config,
                    status_reporter,
                };

                let token = CancellationToken::new();
                tokio::spawn(controller.run(token))
            };

            Self {
                listen_port,
                handle,
                status_requester,
                scale_up_config,
            }
        }

        pub async fn poll_scale_up(&mut self) -> Result<(), Elapsed> {
            timeout(Duration::from_secs(5), async {
                loop {
                    let num_connections = self.get_num_connections().await;
                    if num_connections == self.scale_up_config.max_multiplexed_connections as usize
                    {
                        break;
                    } else {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                }
            })
            .await
        }

        pub async fn get_report(&mut self) -> Report {
            self.status_requester
                ._request_status()
                .await
                .expect("Could not get report")
        }

        pub async fn get_proxy_id(&mut self) -> ProxyIdentifier {
            let report = self.get_report().await;
            report.proxy_id
        }

        async fn get_num_connections(&mut self) -> usize {
            let report = self.get_report().await;
            report.num_connections
        }
    }

    pub async fn find_available_port() -> (TcpListener, u16) {
        for port in 10000..15000 {
            match TcpListener::bind(("127.0.0.1", port)).await {
                Ok(v) => {
                    return (v, port);
                }
                Err(_) => continue,
            }
        }
        panic!("Failed to find port");
    }

    #[test_case(true; "tls enabled")]
    #[test_case(false; "tls disabled")]
    #[tokio::test]
    async fn test_basic(tls_enabled: bool) {
        let service = TestService::new(tls_enabled).await;
        let mut proxy = ProxyUnderTest::new(tls_enabled, service.listen_port).await;
        let mut client = TestClient::new(proxy.listen_port).await;
        client.send_message_with_size(10).await.unwrap();
        client.send_message_with_size(1024).await.unwrap();

        let report = proxy.get_report().await;
        assert!(report.partition_id.is_some());

        service.shutdown().await;
    }

    #[test_case(true; "tls enabled")]
    #[test_case(false; "tls disabled")]
    #[tokio::test]
    async fn test_success_after_connection_closed_on_bind_client_to_partition_request(
        tls_enabled: bool,
    ) {
        let service = TestService::new(tls_enabled).await;
        let mut proxy = ProxyUnderTest::new(tls_enabled, service.listen_port).await;
        let mut client = TestClient::new(proxy.listen_port).await;

        service
            .post_action(ServiceAction::CloseOnNextBindClientToPartitionRequest)
            .await;

        client.send_message_with_size(10).await.unwrap();
        client.send_message_with_size(1024).await.unwrap();

        let report = proxy.get_report().await;
        assert!(report.partition_id.is_none());

        service.shutdown().await;
    }

    #[test_case(true; "tls enabled")]
    #[test_case(false; "tls disabled")]
    #[tokio::test]
    async fn test_success_after_bind_client_to_partition_stop_response_on_initial_connection(
        tls_enabled: bool,
    ) {
        let service = TestService::new(tls_enabled).await;
        let mut proxy = ProxyUnderTest::new(tls_enabled, service.listen_port).await;
        let mut client = TestClient::new(proxy.listen_port).await;

        service.post_action(ServiceAction::DisableScaleUp).await;

        client.send_message_with_size(10).await.unwrap();
        client.send_message_with_size(1024).await.unwrap();

        let report = proxy.get_report().await;
        assert!(report.partition_id.is_none());

        service.shutdown().await;
    }

    #[test_case(true; "tls enabled")]
    #[test_case(false; "tls disabled")]
    #[tokio::test]
    async fn test_closed_connection(tls_enabled: bool) {
        let service = TestService::new(tls_enabled).await;
        let proxy = ProxyUnderTest::new(tls_enabled, service.listen_port).await;
        let mut client = TestClient::new(proxy.listen_port).await;
        client.send_message_with_size(10).await.unwrap();
        service.post_action(ServiceAction::CloseOnNextRequest).await;
        let result = client.send_message_with_size(10).await;
        assert!(result.is_err());
    }

    #[test_case(true; "tls enabled")]
    #[test_case(false; "tls disabled")]
    #[tokio::test]
    async fn test_closed_connection_after_scale_up(tls_enabled: bool) {
        // Use a single partition so that the same PartitionId is return on each
        // bind_client_to_partition request. This prevents a controller "reset", which simplifies
        // testing that the proxy will retry scale up after the backoff time as elapsed.
        //
        let scale_up_threshold = 10;
        let service = TestService::new_with_partition_count_and_scale_up_threshold(
            1,
            scale_up_threshold,
            tls_enabled,
        )
        .await;

        let mut proxy = ProxyUnderTest::new(tls_enabled, service.listen_port).await;

        let mut client = TestClient::new(proxy.listen_port).await;
        client.send_message_with_size(100).await.unwrap();

        // Expect that scale up does not occur
        proxy.poll_scale_up().await.expect("Scale up did not occur");

        // Close one proxy connection. The subsequent requests should fail.
        service.post_action(ServiceAction::CloseOnNextRequest).await;
        client.send_message_with_size(100).await.unwrap_err();

        // Wait some time for proxy to reset
        tokio::time::sleep(Duration::from_secs(5)).await;

        for _ in 0..5 {
            client.send_message_with_size(100).await.unwrap_err();
        }

        // Reconnecting with the client should result in successful requests
        let mut new_client = TestClient::new(proxy.listen_port).await;
        new_client.send_message_with_size(5).await.unwrap();

        let num_connections = proxy.get_report().await.num_connections;
        assert_eq!(1, num_connections);

        service.shutdown().await;
    }

    #[test_case(true; "tls enabled")]
    #[test_case(false; "tls disabled")]
    #[tokio::test]
    async fn test_closed_connection_when_big_frame_sent(tls_enabled: bool) {
        let service = TestService::new(tls_enabled).await;
        let proxy = ProxyUnderTest::new(tls_enabled, service.listen_port).await;
        let mut client = TestClient::new(proxy.listen_port).await;
        let result = client.send_message_with_size(22222220).await;
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(
            error.kind() == ErrorKind::BrokenPipe || error.kind() == ErrorKind::ConnectionReset
        );
        let reason_opt = proxy.handle.await.unwrap();
        assert_eq!(reason_opt, Some(ShutdownReason::FrameSizeExceeded));
    }

    #[test_case(true; "tls enabled")]
    #[test_case(false; "tls disabled")]
    #[tokio::test]
    async fn test_message_too_small(tls_enabled: bool) {
        let service = TestService::new(tls_enabled).await;
        let proxy = ProxyUnderTest::new(tls_enabled, service.listen_port).await;
        let mut client = TestClient::new(proxy.listen_port).await;
        let _ = client.send_message_with_size(1).await;
        let reason_opt = proxy.handle.await.unwrap();
        assert_eq!(reason_opt, Some(ShutdownReason::FrameSizeTooSmall));
    }

    #[test_case(true; "tls enabled")]
    #[test_case(false; "tls disabled")]
    #[tokio::test]
    async fn test_client_disconnects(tls_enabled: bool) {
        let service = TestService::new(tls_enabled).await;
        let proxy = ProxyUnderTest::new(tls_enabled, service.listen_port).await;
        let mut initial_client = TestClient::new(proxy.listen_port).await;
        let _ = initial_client.send_partial_message_with_size(1000).await;
        // Drop has been implemented to simulate client disconnection
        drop(initial_client);

        // After initial_client is disconnects, the proxy should still accept new connection
        let mut client = TestClient::new(proxy.listen_port).await;
        assert!(matches!(
            client.send_partial_message_with_size(1000).await,
            Ok(())
        ));
    }

    #[test_case(true; "tls enabled")]
    #[test_case(false; "tls disabled")]
    #[tokio::test]
    async fn test_client_disconnects_without_send(tls_enabled: bool) {
        let service = TestService::new(tls_enabled).await;
        let proxy = ProxyUnderTest::new(tls_enabled, service.listen_port).await;

        // Drop this client to simulate a connection to the proxy port that immediately closes
        let disconnecting_client = TestClient::new(proxy.listen_port).await;
        drop(disconnecting_client);

        // After the connection to the disconnecting_client is dropped, the proxy should still accept new connection
        let mut client = TestClient::new(proxy.listen_port).await;
        assert!(matches!(
            client.send_partial_message_with_size(1000).await,
            Ok(())
        ));
    }

    #[test_case(true; "tls enabled")]
    #[test_case(false; "tls disabled")]
    #[tokio::test]
    async fn test_handle_server_disconnect(tls_enabled: bool) {
        let service = TestService::new(tls_enabled).await;
        let mut proxy = ProxyUnderTest::new(tls_enabled, service.listen_port).await;

        let mut client = TestClient::new(proxy.listen_port).await;
        assert!(client.send_message_with_size(10).await.is_ok());

        // Incarnation is incremented when connection with NFS client is established
        assert_eq!(
            INITIAL_INCARNATION + 1,
            proxy.get_proxy_id().await.incarnation
        );

        service.post_action(ServiceAction::CloseOnNextRequest).await;

        assert!(client.send_message_with_size(10).await.is_err());

        // Reconnect
        client = TestClient::new(proxy.listen_port).await;
        assert!(client.send_message_with_size(10).await.is_ok());

        // Incarnation is incremented when connection with NFS client is reestablished
        assert_eq!(
            INITIAL_INCARNATION + 2,
            proxy.get_proxy_id().await.incarnation
        );

        proxy.handle.abort();
        service.shutdown().await;
    }

    #[test_case(true; "tls enabled")]
    #[test_case(false; "tls disabled")]
    #[tokio::test]
    async fn test_scale_up_same_partition(tls_enabled: bool) {
        let service = TestService::new_with_partition_count_and_scale_up_threshold(
            1,
            TestService::ALWAYS_SCALE_UP_THRESHOLD_BYTES_PER_SEC,
            tls_enabled,
        )
        .await;
        let mut proxy = ProxyUnderTest::new(tls_enabled, service.listen_port).await;

        // A request from the client will cause the proxy to establish an addition connection to the NFS server
        let mut client = TestClient::new(proxy.listen_port).await;
        client.send_message_with_size(10).await.unwrap();

        proxy
            .poll_scale_up()
            .await
            .expect("Timeout exceeded while awaiting scale up");

        service.shutdown().await;
    }

    #[test_case(true; "tls enabled")]
    #[test_case(false; "tls disabled")]
    #[tokio::test]
    async fn test_scale_up_periodic_workload(tls_enabled: bool) {
        // Requests of 15 bytes every 100 milliseconds should result in 300 bytes of traffic (150
        // bytes sent, 150 bytes received) every second. This exceeds the scale_up_threshold of 299
        // bytes/s.
        let scale_up_threshold = 299;
        let num_requests = 60;
        let request_size = 30;
        let request_interval_millis = 100;

        let service = TestService::new_with_partition_count_and_scale_up_threshold(
            1,
            scale_up_threshold,
            tls_enabled,
        )
        .await;

        let mut proxy = ProxyUnderTest::new(tls_enabled, service.listen_port).await;

        let mut client = TestClient::new(proxy.listen_port).await;
        for _ in 0..num_requests {
            client.send_message_with_size(request_size).await.unwrap();
            tokio::time::sleep(Duration::from_millis(request_interval_millis)).await;
        }

        proxy
            .poll_scale_up()
            .await
            .expect("Timeout exceeded while awaiting scale up");

        service.shutdown().await;
    }

    #[test_case(true; "tls enabled")]
    #[test_case(false; "tls disabled")]
    #[tokio::test]
    async fn test_no_scale_up_periodic_workload(tls_enabled: bool) {
        // Requests of 10 bytes every 100 milliseconds should result in 200 bytes of traffic (100
        // bytes sent, 100 bytes received) every seconds. This does not exceeds the
        // scale_up_threshold of 300 bytes/s.
        //
        let scale_up_threshold = 300;
        let num_requests = 60;
        let request_size = 10;
        let request_interval_millis = 100;

        let service = TestService::new_with_partition_count_and_scale_up_threshold(
            1,
            scale_up_threshold,
            tls_enabled,
        )
        .await;
        let mut proxy = ProxyUnderTest::new(tls_enabled, service.listen_port).await;

        // Only requests proxied within the monitoring window will be considered when determining
        // when to scale up. The following requests should not result in a scale up attempt.
        //
        let mut client = TestClient::new(proxy.listen_port).await;
        for _ in 0..num_requests {
            client.send_message_with_size(request_size).await.unwrap();
            tokio::time::sleep(Duration::from_millis(request_interval_millis)).await;
        }

        proxy
            .poll_scale_up()
            .await
            .expect_err("Unexpected Scale Up");

        service.shutdown().await;
    }

    #[test_case(true; "tls enabled")]
    #[test_case(false; "tls disabled")]
    #[tokio::test]
    async fn test_scale_up_new_partition(tls_enabled: bool) {
        let service = TestService::new_with_throughput_scale_up_threshold(
            TestService::ALWAYS_SCALE_UP_THRESHOLD_BYTES_PER_SEC,
            tls_enabled,
        )
        .await;
        let mut proxy = ProxyUnderTest::new(tls_enabled, service.listen_port).await;

        // A request from the client will cause the proxy to establish an addition connection to
        // the NFS server
        //
        let mut client = TestClient::new(proxy.listen_port).await;
        client.send_message_with_size(10).await.unwrap();

        let report = proxy.get_report().await;
        let initial_partition_id = report.partition_id.expect("No PartitionId");

        service
            .post_action(ServiceAction::StopPartitionAcceptor(initial_partition_id))
            .await;

        // After scale up, we need to wait for the controller to reset and to listen to a new
        // connection from the client
        //
        tokio::time::sleep(Duration::from_secs(5)).await;

        let mut new_client = TestClient::new(proxy.listen_port).await;
        new_client.send_message_with_size(10).await.unwrap();

        proxy
            .poll_scale_up()
            .await
            .expect("Timeout exceeded while awaiting scale up");

        let connection_state = proxy.get_report().await.connection_state;
        assert_eq!(ConnectionSearchState::Idle, connection_state);

        service.shutdown().await;
    }

    #[test_case(true; "tls enabled")]
    #[test_case(false; "tls disabled")]
    #[tokio::test]
    async fn test_successful_scale_up_with_retries(tls_enabled: bool) {
        let scale_up_threshold = 10;
        let service = TestService::new_with_partition_count_and_scale_up_threshold(
            1,
            scale_up_threshold,
            tls_enabled,
        )
        .await;
        let mut proxy = ProxyUnderTest::new(tls_enabled, service.listen_port).await;

        // A request from the client will cause the proxy to establish an addition connection to the NFS server
        let mut client = TestClient::new(proxy.listen_port).await;
        client.send_message_with_size(5).await.unwrap();

        service
            .post_action(ServiceAction::SendRetries(std::cmp::min(
                5,
                crate::connections::MAX_ATTEMPT_COUNT - 5,
            )))
            .await;

        client.send_message_with_size(100).await.unwrap();

        proxy
            .poll_scale_up()
            .await
            .expect("Timeout exceeded while awaiting scale up");

        service.shutdown().await;
    }

    #[test_case(true; "tls enabled")]
    #[test_case(false; "tls disabled")]
    #[tokio::test]
    async fn test_no_scale_up_threshold_not_exceed(tls_enabled: bool) {
        let service = TestService::new_with_throughput_scale_up_threshold(
            TestService::NEVER_SCALE_UP_THRESHOLD_BYTES_PER_SEC,
            tls_enabled,
        )
        .await;
        let mut proxy = ProxyUnderTest::new(tls_enabled, service.listen_port).await;

        // Requests from the client below the throughput threshold should not cause new connections
        // to the NFS server to be established
        let mut client = TestClient::new(proxy.listen_port).await;
        client.send_message_with_size(10).await.unwrap();

        proxy
            .poll_scale_up()
            .await
            .expect_err("Unexpected scale up occured");

        let connection_state = proxy.get_report().await.connection_state;
        assert_eq!(ConnectionSearchState::Idle, connection_state);

        service.shutdown().await;
    }

    #[test_case(true; "tls enabled")]
    #[test_case(false; "tls disabled")]
    #[tokio::test]
    async fn test_no_scale_up_if_already_scaled_up(tls_enabled: bool) {
        let scale_up_threshold = 10;
        let service = TestService::new_with_partition_count_and_scale_up_threshold(
            5,
            scale_up_threshold,
            tls_enabled,
        )
        .await;

        let mut proxy = ProxyUnderTest::new(tls_enabled, service.listen_port).await;

        // Requests from the client below the throughput threshold should not cause scale up
        let mut client = TestClient::new(proxy.listen_port).await;
        client
            .send_message_with_size((scale_up_threshold - 1) as usize)
            .await
            .unwrap();

        // Stop initial partition so that the proxy resets after scale up
        let initial_report = proxy.get_report().await;
        let initial_partition_id = initial_report.partition_id.expect("No PartitionId");
        assert_eq!(0, initial_report.scale_up_attempt_count);
        assert_eq!(0, initial_report.restart_count);

        service
            .post_action(ServiceAction::StopPartitionAcceptor(initial_partition_id))
            .await;

        // This requests should cause scale up to be attempted
        client
            .send_message_with_size((scale_up_threshold + 10) as usize)
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_secs(5)).await;
        let mut client = TestClient::new(proxy.listen_port).await;
        client
            .send_message_with_size((scale_up_threshold - 1) as usize)
            .await
            .unwrap();

        proxy
            .poll_scale_up()
            .await
            .expect("Timeout exceeded while awaiting scale up");

        let second_report = proxy.get_report().await;
        assert_eq!(ConnectionSearchState::Idle, second_report.connection_state);
        assert_eq!(
            DEFAULT_SCALE_UP_CONFIG.max_multiplexed_connections as usize,
            second_report.num_connections
        );
        assert_eq!(1, second_report.scale_up_attempt_count);
        assert_eq!(1, second_report.restart_count);

        // Additional requests from the client should not cause additional scale up attempts
        for _ in 0..5 {
            client
                .send_message_with_size((scale_up_threshold + 10) as usize)
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        let third_report = proxy.get_report().await;
        assert_eq!(ConnectionSearchState::Idle, third_report.connection_state);
        assert_eq!(
            DEFAULT_SCALE_UP_CONFIG.max_multiplexed_connections as usize,
            third_report.num_connections
        );
        assert_eq!(1, third_report.scale_up_attempt_count);
        assert_eq!(1, third_report.restart_count);

        service.shutdown().await;
    }

    #[test_case(true; "tls enabled")]
    #[test_case(false; "tls disabled")]
    #[tokio::test]
    async fn test_scale_up_failed_too_many_retries(tls_enabled: bool) {
        // Use a single partition so that the same PartitionId is return on each
        // bind_client_to_partition request. This prevents a controller "reset", which simplifies
        // testing that the proxy will retry scale up after the backoff time as elapsed.
        //
        let scale_up_threshold = 10;
        let service = TestService::new_with_partition_count_and_scale_up_threshold(
            1,
            scale_up_threshold,
            tls_enabled,
        )
        .await;

        let mut proxy = ProxyUnderTest::new(tls_enabled, service.listen_port).await;

        let mut client = TestClient::new(proxy.listen_port).await;

        // Send an initial request in which the bind_client_to_partition request succeeds, and the
        // main controller loop starts, but scale up is not requested
        //
        client
            .send_message_with_size((scale_up_threshold - 1) as usize)
            .await
            .unwrap();

        // Update the server to return BindResponse::RETRY until scale up attempt fails
        service
            .post_action(ServiceAction::SendRetries(
                crate::connections::MAX_ATTEMPT_COUNT + 1,
            ))
            .await;

        // This request will cause the proxy to attempt scale up, in which bind_client_to_partition
        // requests will fail
        //
        client.send_message_with_size(100).await.unwrap();

        // Wait for scale up to fail
        tokio::time::sleep(Duration::from_secs(5)).await;

        // Expect that scale up does not occur
        proxy
            .poll_scale_up()
            .await
            .expect_err("Unexpected scale up occured");

        let report = proxy.get_report().await;
        assert!(matches!(
            report.connection_state,
            ConnectionSearchState::Stop(_)
        ));

        // Advance time and assert that scale up occurs after backoff duration elapsed
        tokio::time::pause();
        tokio::time::advance(
            DEFAULT_SCALE_UP_BACKOFF + Duration::from_secs(MULTIPLEX_CONNECTION_TIMEOUT_SEC),
        )
        .await;
        tokio::time::resume();

        service.post_action(ServiceAction::EnableScaleUp).await;
        client.send_message_with_size(100).await.unwrap();

        proxy.poll_scale_up().await.expect("Scale up failed");

        let connection_state = proxy.get_report().await.connection_state;
        assert_eq!(ConnectionSearchState::Idle, connection_state);

        service.shutdown().await;
    }

    #[test_case(true; "tls enabled")]
    #[test_case(false; "tls disabled")]
    #[tokio::test]
    async fn test_scale_up_failed_retry_later(tls_enabled: bool) {
        // Use a single partition so that the same PartitionId is return on each
        // bind_client_to_partition request. This prevents a controller "reset", which simplifies
        // testing that the proxy will retry scale up after the backoff time as elapsed.
        //
        let scale_up_threshold = 10;
        let service = TestService::new_with_partition_count_and_scale_up_threshold(
            1,
            scale_up_threshold,
            tls_enabled,
        )
        .await;

        let mut proxy = ProxyUnderTest::new(tls_enabled, service.listen_port).await;

        let mut client = TestClient::new(proxy.listen_port).await;

        // Send an initial request in which the bind_client_to_partition request succeeds, and the
        // main controller loop starts, but scale up is not requested
        //
        client
            .send_message_with_size((scale_up_threshold - 1) as usize)
            .await
            .unwrap();

        // Update the server to return BindResponse::RETRY_LATER on the next bind_client_to_partition rpc
        // request
        //
        service.post_action(ServiceAction::DisableScaleUp).await;

        // This request will cause the proxy to attempt scale up, in which bind_client_to_partition
        // requests will fail
        //
        client
            .send_message_with_size((scale_up_threshold) as usize)
            .await
            .unwrap();

        // Expect that scale up does not occur
        proxy
            .poll_scale_up()
            .await
            .expect_err("Unexpected scale up occured");

        let report = proxy.get_report().await;
        assert!(matches!(
            report.connection_state,
            ConnectionSearchState::Stop(_)
        ));

        // Advance time and assert that scale up occurs after backoff duration elapsed
        tokio::time::pause();
        tokio::time::advance(
            DEFAULT_SCALE_UP_BACKOFF + Duration::from_secs(MULTIPLEX_CONNECTION_TIMEOUT_SEC),
        )
        .await;
        tokio::time::resume();

        service.post_action(ServiceAction::EnableScaleUp).await;
        client
            .send_message_with_size(
                (scale_up_threshold * proxy::REPORT_INTERVAL_SECS as i32) as usize,
            )
            .await
            .unwrap();

        proxy.poll_scale_up().await.expect("Scale up failed");

        let connection_state = proxy.get_report().await.connection_state;
        assert_eq!(ConnectionSearchState::Idle, connection_state);

        service.shutdown().await;
    }

    #[test_case(true; "tls enabled")]
    #[test_case(false; "tls disabled")]
    #[tokio::test]
    async fn test_scale_up_connection_usage(tls_enabled: bool) {
        // Prevent controller reset after scale up by using existing partition
        let service = TestService::new_with_partition_count_and_scale_up_threshold(
            1,
            TestService::ALWAYS_SCALE_UP_THRESHOLD_BYTES_PER_SEC,
            tls_enabled,
        )
        .await;

        let mut proxy = ProxyUnderTest::new(tls_enabled, service.listen_port).await;

        let mut client = TestClient::new(proxy.listen_port).await;
        client.send_message_with_size(10).await.unwrap();

        proxy
            .poll_scale_up()
            .await
            .expect("Timeout exceeded while awaiting scale up");

        let request_to_send_per_connection = 10;
        for _ in
            0..(request_to_send_per_connection * proxy.scale_up_config.max_multiplexed_connections)
        {
            client.send_message_with_size(10).await.unwrap();
        }

        // Check that requests are routed over multiple connections
        let partition_id = proxy
            .get_report()
            .await
            .partition_id
            .expect("Missing PartitionId");

        let request_counter = service.request_counter.lock().await;
        let counts = request_counter
            .get(&partition_id)
            .expect("Missing request counts");

        assert!(counts.len() >= proxy.scale_up_config.max_multiplexed_connections as usize);
        for count in counts {
            let operation_count = count.load(std::sync::atomic::Ordering::Acquire);
            // Unused connections to a partition can be established during connection search. For
            // this connections, the operation count will be 1
            //
            assert!(
                operation_count >= request_to_send_per_connection as u32 || operation_count == 1
            );
        }

        drop(request_counter);
        service.shutdown().await;
    }

    #[test_case(true; "tls enabled")]
    #[tokio::test]
    async fn test_efs_utils_port_test(tls_enabled: bool) {
        let service = TestService::new(tls_enabled).await;
        let mut proxy = ProxyUnderTest::new(tls_enabled, service.listen_port).await;
        let mut port_health_check = TestClient::new(proxy.listen_port).await;
        // Mimic efs-utils's port test which checks whether efs-proxy is alive.
        let _ = port_health_check.stream.shutdown().await.unwrap();
        let mut client = TestClient::new(proxy.listen_port).await;
        client.send_message_with_size(10).await.unwrap();
        client.send_message_with_size(1024).await.unwrap();

        let report = proxy.get_report().await;
        assert!(report.partition_id.is_some());

        service.shutdown().await;
    }
}
