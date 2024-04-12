use crate::efs_prot::{BindClientResponse, BindResponse, ScaleUpConfig};
use crate::efs_rpc::{self, PartitionId};
use crate::error::{ConnectError, RpcError};
use crate::proxy_identifier::ProxyIdentifier;
use crate::{
    controller::Event, shutdown::ShutdownHandle, tls::establish_tls_stream, tls::TlsConfig,
};
use async_trait::async_trait;
use futures::future;
use log::{debug, info, warn};
use s2n_tls_tokio::TlsStream;
use std::sync::Arc;
use std::{collections::HashMap, time::Duration};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio::{
    io::AsyncWriteExt,
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::mpsc,
};

const CONCURRENT_ATTEMPT_COUNT: u32 = 3;

pub const MAX_ATTEMPT_COUNT: u32 = 120;
const SINGLE_CONNECTION_TIMEOUT_SEC: u64 = 15;
pub const MULTIPLEX_CONNECTION_TIMEOUT_SEC: u64 = 15;

pub trait ProxyStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> ProxyStream for T {}

#[async_trait]
pub trait PartitionFinder<S: ProxyStream> {
    async fn establish_connection(
        &self,
        proxy_id: ProxyIdentifier,
    ) -> Result<(S, Option<PartitionId>, Option<ScaleUpConfig>), ConnectError>;

    async fn spawn_establish_connection_task(
        &self,
        proxy_id: ProxyIdentifier,
    ) -> JoinHandle<Result<(S, Result<BindClientResponse, RpcError>), ConnectError>>;

    // Establish multiple connections to an EFS "Partition" to enable higher IO throughput. A
    // `target` partition should be provided if the proxy owns an existing connection to EFS. When
    // provided, the search will prefer to find a connection that maps to this `target` partition.
    // This `target` does not represent a hard requirement, as connections mapping to a different
    // partition can still be returned.
    //
    async fn inner_establish_multiplex_connection(
        &self,
        proxy_id: ProxyIdentifier,
        target: Option<PartitionId>,
        shutdown_handle: ShutdownHandle,
    ) -> Result<(PartitionId, Vec<S>, ScaleUpConfig), (ConnectError, Option<ScaleUpConfig>)> {
        let mut connect_futures = Vec::with_capacity(CONCURRENT_ATTEMPT_COUNT as usize);
        for _ in 0..CONCURRENT_ATTEMPT_COUNT {
            connect_futures.push(self.spawn_establish_connection_task(proxy_id).await);
        }

        let mut connected_partitions: HashMap<PartitionId, Vec<S>> = HashMap::new();

        let mut failure_count = 0;
        let mut attempt_count = CONCURRENT_ATTEMPT_COUNT;

        let overall_timeout =
            tokio::time::sleep(Duration::from_secs(MULTIPLEX_CONNECTION_TIMEOUT_SEC));
        tokio::pin!(overall_timeout);

        loop {
            tokio::select! {
                (join_result, index, _) = future::select_all(connect_futures.iter_mut()) => {
                    let Ok(connection_result) = join_result else {
                        warn!("JoinError encountered during connection search.");
                        tokio::spawn(shutdown_connections(connected_partitions));
                        return Err((ConnectError::MultiplexFailure, None));
                    };

                    let (stream, bind_result) = match connection_result {
                        Ok(r) => r,
                        Err(ConnectError::IoError(e)) => {
                            debug!("Retryable ConnectError encountered during connection search. Error: {:?}", e);
                            failure_count += 1;
                            self.retry_multiplex_connection_attempt(proxy_id, &mut attempt_count, index, &mut connect_futures).await?;
                            continue;
                        },
                        Err(e) => {
                            warn!("Non-retryable ConnectError encountered during connection search. Error: {}", e);
                            tokio::spawn(shutdown_connections(connected_partitions));
                            return Err((ConnectError::MultiplexFailure, None))
                        }
                    };

                    let response = match bind_result {
                        Ok(r) => r,
                        Err(RpcError::IoError(e)) => {
                            debug!("Retryable RpcError encountered during connection search. Error: {:?}", e);
                            failure_count += 1;
                            self.retry_multiplex_connection_attempt(proxy_id, &mut attempt_count, index, &mut connect_futures).await?;
                            continue;
                        },
                        Err(e) => {
                            warn!("Non-retryable RpcError encountered during connection search. Error: {}", e);
                            tokio::spawn(shutdown_connections(connected_partitions));
                            return Err((ConnectError::MultiplexFailure, None))
                        }
                    };

                    let bind_response = response.bind_response;
                    let new_scale_up_config = response.scale_up_config;
                    debug!("Received {}", get_bind_response_string(&bind_response));
                    match bind_response {
                        BindResponse::READY(id) => {
                            let partition_id = PartitionId { id: id.0 };

                            if Some(partition_id) == target {
                                debug!("Connection to target partition found. Attempt Count: {}, Failure Count: {}", attempt_count, failure_count);
                            } else {
                                debug!("Connection to non-target partition found. Attempt Count: {}, Failure Count: {}", attempt_count, failure_count);
                            }

                            if let Some(mut streams) = connected_partitions.remove(&partition_id) {
                                streams.push(stream);

                                let target_connection_count = if Some(partition_id) == target {
                                    (new_scale_up_config.max_multiplexed_connections - 1) as usize
                                } else {
                                    new_scale_up_config.max_multiplexed_connections as usize
                                };

                                if streams.len() >= target_connection_count {
                                    tokio::spawn(shutdown_connections(connected_partitions));
                                    return Ok((partition_id, streams, new_scale_up_config));
                                } else {
                                    connected_partitions.insert(partition_id, streams);
                                }
                            } else {
                                connected_partitions.insert(partition_id, vec!(stream));
                            }
                        },
                        BindResponse::RETRY(_) | BindResponse::PREFERRED(_) => (),
                        BindResponse::RETRY_LATER(_) | BindResponse::ERROR(_) | BindResponse::default => {
                            tokio::spawn(shutdown_connections(connected_partitions));
                            return Err((ConnectError::MultiplexFailure, Some(new_scale_up_config)))
                        },
                    };

                    debug!("Continuing partition search. Attempt Count: {}, Failure Count: {}, Partitions Found: {}", attempt_count, failure_count, connected_partitions.len());
                    self.retry_multiplex_connection_attempt(proxy_id, &mut attempt_count, index, &mut connect_futures).await?;
                },
                _ = &mut overall_timeout => {
                    tokio::spawn(shutdown_connections(connected_partitions));
                    return Err((ConnectError::Timeout, None));
                },
                _ = shutdown_handle.cancellation_token.cancelled() => {
                    tokio::spawn(shutdown_connections(connected_partitions));
                    return Err((ConnectError::Cancelled, None));
                }
            }
        }
    }

    async fn retry_multiplex_connection_attempt(
        &self,
        proxy_id: ProxyIdentifier,
        attempt_count: &mut u32,
        last_failed_index: usize,
        connect_futures: &mut Vec<
            JoinHandle<Result<(S, Result<BindClientResponse, RpcError>), ConnectError>>,
        >,
    ) -> Result<(), (ConnectError, Option<ScaleUpConfig>)> {
        if *attempt_count > MAX_ATTEMPT_COUNT {
            return Err((ConnectError::MaxAttemptsExceeded, None));
        } else {
            connect_futures.swap_remove(last_failed_index);
            connect_futures.push(self.spawn_establish_connection_task(proxy_id).await);
            *attempt_count += 1;
            Ok(())
        }
    }

    // Increase the number of connections to the EFS Service.
    async fn scale_up_connection(
        &self,
        proxy_id: ProxyIdentifier,
        partition_id: Option<PartitionId>,
        notification_queue: mpsc::Sender<Event<S>>,
        shutdown_handle: ShutdownHandle,
    ) {
        let result = match self
            .inner_establish_multiplex_connection(proxy_id, partition_id, shutdown_handle)
            .await
        {
            Ok((id, proxy_streams, scale_up_config)) => {
                notification_queue
                    .send(Event::ConnectionSuccess(
                        Some(id),
                        proxy_streams,
                        scale_up_config,
                    ))
                    .await
            }
            Err(e) => {
                info!("Attempt to scale up failed: {}", e.0);
                notification_queue.send(Event::ConnectionFail(e.1)).await
            }
        };
        result.unwrap_or_else(|_| warn!("Unable to notify event queue of established connections"));
    }
}

pub fn configure_stream(tcp_stream: TcpStream) -> TcpStream {
    match tcp_stream.set_nodelay(true) {
        Ok(_) => {}
        Err(e) => warn!("Error setting TCP_NODELAY: {}", e),
    }
    tcp_stream
}

// Allow for graceful closure of Tls connections
async fn shutdown_connections<S: ProxyStream>(connections: HashMap<PartitionId, Vec<S>>) {
    for streams in connections.into_values() {
        for mut stream in streams.into_iter() {
            tokio::spawn(async move {
                if let Err(e) = stream.shutdown().await {
                    debug!("Failed to gracefully shutdown connection: {}", e);
                }
            });
        }
    }
}

// BindResponse in generated by xdrgen and does not implement the Debug or Display traits
pub fn get_bind_response_string(bind_response: &BindResponse) -> String {
    match bind_response {
        BindResponse::PREFERRED(_partition_id) => String::from("BindResponse::PREFERRED"),
        BindResponse::READY(_partition_id) => String::from("BindResponse::READY"),
        BindResponse::RETRY(m) => {
            if m.is_empty() {
                String::from("BindResponse::RETRY")
            } else {
                format!("BindResponse::RETRY. message: {m}")
            }
        }
        BindResponse::RETRY_LATER(m) => {
            if m.is_empty() {
                String::from("BindResponse::RETRY_LATER")
            } else {
                format!("BindResponse::RETRY_LATER. message: {m}")
            }
        }
        BindResponse::ERROR(m) => {
            if m.is_empty() {
                String::from("BindResponse::ERROR")
            } else {
                format!("BindResponse::ERROR. message: {m}")
            }
        }
        BindResponse::default => String::from("BindResponse::default"),
    }
}

#[derive(Clone)]
pub struct PlainTextPartitionFinder {
    pub mount_target_addr: String,
}

impl PlainTextPartitionFinder {
    async fn establish_plain_text_connection(
        mount_target_addr: String,
        proxy_id: ProxyIdentifier,
    ) -> Result<(TcpStream, Result<BindClientResponse, RpcError>), ConnectError> {
        timeout(Duration::from_secs(SINGLE_CONNECTION_TIMEOUT_SEC), async {
            let mut tcp_stream = TcpStream::connect(mount_target_addr).await?;
            let response = efs_rpc::bind_client_to_partition(proxy_id, &mut tcp_stream).await;
            Ok((configure_stream(tcp_stream), response))
        })
        .await
        .map_err(|_| ConnectError::Timeout)?
    }
}

#[async_trait]
impl PartitionFinder<TcpStream> for PlainTextPartitionFinder {
    async fn establish_connection(
        &self,
        proxy_id: ProxyIdentifier,
    ) -> Result<(TcpStream, Option<PartitionId>, Option<ScaleUpConfig>), ConnectError> {
        let (s, bind_result) =
            Self::establish_plain_text_connection(self.mount_target_addr.clone(), proxy_id).await?;
        match bind_result {
            Ok(response) => {
                debug!(
                    "EFS RPC call succeeded while establishing initial connection. Response: {}",
                    get_bind_response_string(&response.bind_response)
                );
                let partition_id = match &response.bind_response {
                    BindResponse::READY(id) => Some(PartitionId { id: id.0 }),
                    _ => None,
                };
                Ok((s, partition_id, Some(response.scale_up_config)))
            }
            Err(e) => {
                warn!("EFS RPC call errored while establishing initial connection. Error {e}",);
                let tcp_stream = TcpStream::connect(self.mount_target_addr.clone()).await?;
                return Ok((configure_stream(tcp_stream), None, None));
            }
        }
    }

    async fn spawn_establish_connection_task(
        &self,
        proxy_id: ProxyIdentifier,
    ) -> JoinHandle<Result<(TcpStream, Result<BindClientResponse, RpcError>), ConnectError>> {
        let addr = self.mount_target_addr.clone();
        tokio::spawn(Self::establish_plain_text_connection(addr, proxy_id))
    }
}

pub struct TlsPartitionFinder {
    tls_config: Arc<tokio::sync::Mutex<TlsConfig>>,
}

impl TlsPartitionFinder {
    pub fn new(tls_config: Arc<tokio::sync::Mutex<TlsConfig>>) -> Self {
        TlsPartitionFinder { tls_config }
    }

    async fn establish_tls_connection(
        tls_config: TlsConfig,
        proxy_id: ProxyIdentifier,
    ) -> Result<(TlsStream<TcpStream>, Result<BindClientResponse, RpcError>), ConnectError> {
        timeout(Duration::from_secs(SINGLE_CONNECTION_TIMEOUT_SEC), async {
            let mut tls_stream = establish_tls_stream(tls_config).await?;
            let response = efs_rpc::bind_client_to_partition(proxy_id, &mut tls_stream).await;
            Ok((tls_stream, response))
        })
        .await
        .map_err(|_| ConnectError::Timeout)?
    }
}

#[async_trait]
impl PartitionFinder<TlsStream<TcpStream>> for TlsPartitionFinder {
    async fn establish_connection(
        &self,
        proxy_id: ProxyIdentifier,
    ) -> Result<
        (
            TlsStream<TcpStream>,
            Option<PartitionId>,
            Option<ScaleUpConfig>,
        ),
        ConnectError,
    > {
        let tls_config_copy = self.tls_config.lock().await.clone();
        let (s, bind_result) = Self::establish_tls_connection(tls_config_copy, proxy_id).await?;
        let (bind_response, scale_up_config) = match bind_result {
            Ok(response) => {
                warn!(
                    "EFS RPC call succeeded while establishing initial connection. Response: {}",
                    get_bind_response_string(&response.bind_response)
                );
                (response.bind_response, Some(response.scale_up_config))
            }
            Err(e) => {
                warn!("EFS RPC call errored while establishing initial connection. Error {e}",);
                let tls_stream = establish_tls_stream(self.tls_config.lock().await.clone()).await?;
                return Ok((tls_stream, None, None));
            }
        };

        match bind_response {
            BindResponse::READY(id) => Ok((s, Some(PartitionId { id: id.0 }), scale_up_config)),
            _ => Ok((s, None, scale_up_config)),
        }
    }

    async fn spawn_establish_connection_task(
        &self,
        proxy_id: ProxyIdentifier,
    ) -> JoinHandle<
        Result<(TlsStream<TcpStream>, Result<BindClientResponse, RpcError>), ConnectError>,
    > {
        let tls_config_copy = self.tls_config.lock().await.clone();
        tokio::spawn(Self::establish_tls_connection(tls_config_copy, proxy_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_parser::tests::get_test_config;
    use crate::connections::PartitionFinder;
    use crate::controller::tests::{find_available_port, ServiceAction, TestService};
    use crate::controller::DEFAULT_SCALE_UP_CONFIG;
    use crate::ProxyConfig;
    use nix::sys::signal::kill;
    use nix::sys::signal::Signal;
    use std::path::Path;
    use std::str::FromStr;
    use tokio::signal;
    use tokio::sync::Mutex;
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;

    const PROXY_ID: ProxyIdentifier = ProxyIdentifier {
        uuid: Uuid::from_u128(1 as u128),
        incarnation: 0,
    };

    struct MultiplexTest {
        service: TestService,
        partition_finder: TlsPartitionFinder,
        initial_partition_id: PartitionId,
    }

    impl MultiplexTest {
        async fn new() -> Self {
            let service = TestService::new(true).await;
            MultiplexTest::new_with_service(service).await
        }

        async fn new_with_service(service: TestService) -> Self {
            let mut tls_config = TlsConfig::new_from_config(&get_test_config())
                .await
                .expect("Failed to acquire TlsConfig.");
            tls_config.remote_addr = format!("127.0.0.1:{}", service.listen_port);

            let partition_finder = TlsPartitionFinder::new(Arc::new(Mutex::new(tls_config)));

            let (_s, id, _) = partition_finder
                .establish_connection(PROXY_ID.clone())
                .await
                .expect("Failed to connect to server");

            let Some(initial_partition_id) = id else {
                panic!("Partition Id not found for initial connection.")
            };

            MultiplexTest {
                service,
                partition_finder: partition_finder,
                initial_partition_id,
            }
        }
    }

    #[tokio::test]
    async fn test_establish_multiplex_same_partition_found() {
        let test = MultiplexTest::new().await;

        let (shutdown_handle, _waiter) = ShutdownHandle::new(CancellationToken::new());

        let (new_connnection_id, connections, _) = test
            .partition_finder
            .inner_establish_multiplex_connection(
                PROXY_ID.clone(),
                Some(test.initial_partition_id.clone()),
                shutdown_handle,
            )
            .await
            .expect("Could not establish a multiplex connection");

        assert_eq!(test.initial_partition_id, new_connnection_id);
        assert_eq!(
            DEFAULT_SCALE_UP_CONFIG.max_multiplexed_connections - 1,
            connections.len() as i32
        );

        test.service.shutdown().await;
    }

    #[tokio::test]
    async fn test_establish_multiplex_new_partition_found() {
        let test = MultiplexTest::new().await;

        let (shutdown_handle, _waiter) = ShutdownHandle::new(CancellationToken::new());

        test.service
            .post_action(ServiceAction::StopPartitionAcceptor(
                test.initial_partition_id.clone(),
            ))
            .await;

        let (new_connnection_id, connections, _) = test
            .partition_finder
            .inner_establish_multiplex_connection(
                PROXY_ID.clone(),
                Some(test.initial_partition_id.clone()),
                shutdown_handle,
            )
            .await
            .expect("Could not establish a multiplex connection");

        assert_eq!(
            DEFAULT_SCALE_UP_CONFIG.max_multiplexed_connections,
            connections.len() as i32
        );
        assert_ne!(test.initial_partition_id, new_connnection_id);

        test.service.shutdown().await;
    }

    #[tokio::test]
    async fn test_establish_multiplex_no_target() {
        let test = MultiplexTest::new().await;

        let (shutdown_handle, _waiter) = ShutdownHandle::new(CancellationToken::new());

        let (new_connnection_id, connections, _) = test
            .partition_finder
            .inner_establish_multiplex_connection(PROXY_ID.clone(), None, shutdown_handle)
            .await
            .expect("Could not establish a multiplex connection");

        assert_eq!(
            DEFAULT_SCALE_UP_CONFIG.max_multiplexed_connections,
            connections.len() as i32
        );
        assert_ne!(test.initial_partition_id, new_connnection_id);

        test.service.shutdown().await;
    }

    #[tokio::test]
    async fn test_establish_connection_timeout() {
        let (_listener, port) = find_available_port().await;

        let error = tokio::spawn(async move {
            let partition_finder = PlainTextPartitionFinder {
                mount_target_addr: format!("127.0.0.1:{}", port.clone()),
            };
            partition_finder
                .establish_connection(PROXY_ID.clone())
                .await
        })
        .await
        .expect("join err");

        assert!(matches!(error, Err(ConnectError::Timeout)));
    }

    #[tokio::test]
    async fn test_establish_multiplex_timeout() {
        let (_listener, port) = find_available_port().await;

        let error = tokio::spawn(async move {
            let (shutdown_handle, _waiter) = ShutdownHandle::new(CancellationToken::new());

            let partition_finder = PlainTextPartitionFinder {
                mount_target_addr: format!("127.0.0.1:{}", port.clone()),
            };
            partition_finder
                .inner_establish_multiplex_connection(PROXY_ID.clone(), None, shutdown_handle)
                .await
        })
        .await
        .expect("join err");

        assert!(matches!(error, Err((ConnectError::Timeout, None))));
    }

    #[tokio::test]
    async fn test_establish_multiplex_shutdown() {
        let (_listener, port) = find_available_port().await;

        let (shutdown_handle, _waiter) = ShutdownHandle::new(CancellationToken::new());

        let shutdown_handle_clone = shutdown_handle.clone();
        let task = tokio::spawn(async move {
            let partition_finder = PlainTextPartitionFinder {
                mount_target_addr: format!("127.0.0.1:{}", port.clone()),
            };
            partition_finder
                .inner_establish_multiplex_connection(PROXY_ID.clone(), None, shutdown_handle_clone)
                .await
        });

        shutdown_handle.exit(None).await;
        let error = task.await.expect("Unexpected join error");

        assert!(matches!(error, Err((ConnectError::Cancelled, None))));
    }

    #[tokio::test]
    async fn test_scale_up_max_attempts() {
        // Create a service in which the all calls of bind_client_to_partition will return a
        // different value. Our "TestService" returns these PartitionIds in a round robin fashion,
        // and this service will have more PartitionId than MAX_ATTEMPT_COUNT
        let service =
            TestService::new_with_partition_count((MAX_ATTEMPT_COUNT + 2) as usize, true).await;

        let test = MultiplexTest::new_with_service(service).await;

        let (shutdown_handle, _waiter) = ShutdownHandle::new(CancellationToken::new());

        let error = test
            .partition_finder
            .inner_establish_multiplex_connection(
                PROXY_ID.clone(),
                Some(test.initial_partition_id.clone()),
                shutdown_handle.clone(),
            )
            .await;

        assert!(matches!(
            error,
            Err((ConnectError::MaxAttemptsExceeded, None))
        ));
    }

    enum BrokenPartitionFinderType {
        _ConnectIoError,
        _RpcIoError,
        RpcNonIoError,
    }

    struct BrokenPartitionFinder {
        finder_type: BrokenPartitionFinderType,
    }

    impl BrokenPartitionFinder {
        fn new(finder_type: BrokenPartitionFinderType) -> Self {
            Self { finder_type }
        }
    }

    #[async_trait]
    impl PartitionFinder<TcpStream> for BrokenPartitionFinder {
        async fn establish_connection(
            &self,
            _proxy_id: ProxyIdentifier,
        ) -> Result<(TcpStream, Option<PartitionId>, Option<ScaleUpConfig>), ConnectError> {
            unimplemented!()
        }

        async fn spawn_establish_connection_task(
            &self,
            _proxy_id: ProxyIdentifier,
        ) -> JoinHandle<Result<(TcpStream, Result<BindClientResponse, RpcError>), ConnectError>>
        {
            let (_listener, port) = find_available_port().await;
            let tcp_stream = TcpStream::connect(("127.0.0.1", port))
                .await
                .expect("Could not establish TCP stream.");
            let error = match self.finder_type {
                BrokenPartitionFinderType::_ConnectIoError => Err(ConnectError::IoError(
                    tokio::io::ErrorKind::BrokenPipe.into(),
                )),
                BrokenPartitionFinderType::_RpcIoError => Ok((
                    tcp_stream,
                    Err(RpcError::IoError(tokio::io::ErrorKind::BrokenPipe.into())),
                )),
                BrokenPartitionFinderType::RpcNonIoError => {
                    Ok((tcp_stream, Err(RpcError::GarbageArgs)))
                }
            };
            tokio::spawn(async { error })
        }
    }

    #[tokio::test]
    async fn test_scale_up_rpc_error() {
        let partition_finder = BrokenPartitionFinder::new(BrokenPartitionFinderType::RpcNonIoError);

        let (shutdown_handle, _waiter) = ShutdownHandle::new(CancellationToken::new());
        let error = partition_finder
            .inner_establish_multiplex_connection(PROXY_ID.clone(), None, shutdown_handle.clone())
            .await;

        assert!(matches!(error, Err((ConnectError::MultiplexFailure, None))));
    }

    #[tokio::test]
    async fn test_reload_certificate() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let mut sigs_hangup_listener =
            signal::unix::signal(signal::unix::SignalKind::hangup()).unwrap();
        let config_file_path = Path::new("tests/certs/test_config.ini");
        let config_contents = std::fs::read_to_string(&config_file_path).unwrap();
        let proxy_config = ProxyConfig::from_str(&config_contents).unwrap();
        let mut tls_config = TlsConfig::new_from_config(&proxy_config).await.unwrap();
        tls_config.client_cert = vec![1, 2];
        let old_cert = tls_config.client_cert.clone();
        let tls_config_ptr = Arc::new(Mutex::new(tls_config));
        let cloned_tls_config_ptr = Arc::clone(&tls_config_ptr);
        tokio::spawn(async move {
            loop {
                // Check if the SIGHUP signal is received
                if (sigs_hangup_listener.recv().await).is_some() {
                    //Reloading the TLS configuration
                    let mut locked_config = cloned_tls_config_ptr.lock().await;
                    *locked_config = crate::get_tls_config(&proxy_config).await.unwrap();
                    tx.send(()).unwrap();
                    break;
                }
            }
        });
        let tls_partition_finder = TlsPartitionFinder {
            tls_config: tls_config_ptr.clone(),
        };
        let _ = kill(nix::unistd::Pid::this(), Signal::SIGHUP);
        rx.await.unwrap();
        assert_ne!(
            old_cert,
            tls_partition_finder.tls_config.lock().await.client_cert
        );
    }
}
