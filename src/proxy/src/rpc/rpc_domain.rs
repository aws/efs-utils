//! # Proxy data path Domain objects for RPC domain
//!
//! Note that EFS RPC is technically not on the data path for now.
//! If it is planned to be changed later, these RPC Domain primitives need to be extended.
//!

#![allow(unused)]

use std::{
    marker::PhantomData,
    sync::{atomic::AtomicU64, Arc},
};

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use log::{debug, error, info, trace};
use tokio::{
    io::AsyncReadExt,
    io::ReadHalf,
    net::tcp::OwnedReadHalf,
    sync::{
        mpsc::{self, error::SendError},
        Mutex,
    },
};

use crate::{
    connections::ProxyStream,
    domain::{ClientSocketReader, Dispatcher, DomainBuilder, ServerSocketReader},
    error::RpcError,
    proxy_task::ConnectionMessage,
    rpc::rpc::{BufferedRpcReader, RpcBatch, RpcBufferedReaderError},
    shutdown::{ShutdownHandle, ShutdownReason},
};

use super::{
    rpc_envelope::{RpcEnvelope, RpcEnvelopeBatch},
    rpc_error::{RpcFragmentParseError, RpcParseError},
};

#[cfg(test)]
pub const RPC_DOMAIN_NAME: &str = "RPC";

#[derive(Clone)]
pub struct RpcClientDispatcher {
    pub next_conn: usize,
    pub partition_senders: Arc<Mutex<Vec<mpsc::Sender<RpcBatch>>>>,
}

#[async_trait]
impl Dispatcher<RpcBatch, SendError<RpcBatch>> for RpcClientDispatcher {
    async fn dispatch(&mut self, message: RpcBatch) -> Result<(), SendError<RpcBatch>> {
        let f = self.partition_senders.lock().await;
        let r = f[self.next_conn].send(message).await;
        // select connection via round-robin
        self.next_conn = (self.next_conn + 1) % f.len();
        return r;
    }

    async fn handle_parse_error(
        &mut self,
        parse_error: RpcParseError,
    ) -> Result<(), SendError<RpcBatch>> {
        parse_error.log_parse_error("RpcClient");
        let rpc_batch = parse_error.into_rpc_batch();
        self.dispatch(rpc_batch).await
    }
}

impl RpcClientDispatcher {
    pub fn new(partition_senders: Arc<Mutex<Vec<mpsc::Sender<RpcBatch>>>>) -> Self {
        RpcClientDispatcher {
            next_conn: 0,
            partition_senders,
        }
    }
}

#[derive(Clone)]
pub struct RpcServerDispatcher {
    pub sender: mpsc::Sender<ConnectionMessage>,
}

#[async_trait]
impl Dispatcher<RpcBatch, SendError<ConnectionMessage>> for RpcServerDispatcher {
    async fn dispatch(&mut self, message: RpcBatch) -> Result<(), SendError<ConnectionMessage>> {
        return self.sender.send(ConnectionMessage::Response(message)).await;
    }

    async fn handle_parse_error(
        &mut self,
        parse_error: RpcParseError,
    ) -> Result<(), SendError<ConnectionMessage>> {
        parse_error.log_parse_error("RpcServer");
        let rpc_batch = parse_error.into_rpc_batch();
        self.dispatch(rpc_batch).await
    }
}

pub struct ClientReaderErrorHandler {}
impl ClientReaderErrorHandler {
    pub fn get_shutdown_reason(error: &RpcBufferedReaderError) -> ShutdownReason {
        match error {
            RpcBufferedReaderError::EndOfFile => ShutdownReason::Unmount,
            RpcBufferedReaderError::IoError(e) => {
                error!("Error reading from client: {:?}", e);
                ShutdownReason::UnexpectedError
            }
            RpcBufferedReaderError::InvalidSizeTooSmall => {
                error!("NFS Client Error: invalid RPC size - size too small");
                ShutdownReason::FrameSizeTooSmall
            }
            RpcBufferedReaderError::SizeLimitExceeded => {
                error!("NFS Client Error: invalid RPC size - size limit exceeded");
                ShutdownReason::FrameSizeExceeded
            }
        }
    }
}

pub struct RpcClientReader {
    pub dispatcher: RpcClientDispatcher,
}

impl RpcClientReader {
    fn get_shutdown_reason(error: &RpcBufferedReaderError) -> ShutdownReason {
        ClientReaderErrorHandler::get_shutdown_reason(error)
    }
}

#[async_trait]
impl ClientSocketReader for RpcClientReader {
    async fn run(
        &mut self,
        mut read_half: OwnedReadHalf,
        read_count: Arc<AtomicU64>,
        shutdown: ShutdownHandle,
    ) {
        let shutdown_reason: Option<ShutdownReason>;
        let mut reader = BufferedRpcReader::new(read_half, Some(read_count));
        loop {
            let rpc_batch = match reader.read().await {
                Ok(batch) => batch,
                Err(e) => {
                    drop(reader);
                    shutdown_reason = Some(Self::get_shutdown_reason(&e));
                    break;
                }
            };

            if let Err(e) = self.dispatcher.dispatch(rpc_batch).await {
                error!("Error sending message batch to dispatcher {:?}", e);
                shutdown_reason = Some(ShutdownReason::UnexpectedError);
                break;
            }
        }
        trace!("cli_to_server exiting!");
        shutdown.exit(shutdown_reason).await;
    }

    #[cfg(test)]
    fn get_domain(&self) -> &'static str {
        RPC_DOMAIN_NAME
    }
}

pub struct ServerReaderErrorHandler {}
impl ServerReaderErrorHandler {
    pub fn get_shutdown_reason(error: &RpcBufferedReaderError) -> ShutdownReason {
        match error {
            RpcBufferedReaderError::InvalidSizeTooSmall => {
                error!("NFS Server Error: invalid RPC size - size too small");
                ShutdownReason::UnexpectedError
            }
            RpcBufferedReaderError::IoError(e) => {
                error!("Error reading from server: {:?}", e);
                ShutdownReason::NeedsRestart
            }
            RpcBufferedReaderError::SizeLimitExceeded => {
                error!("NFS Server Error: invalid RPC size - size limit exceeded");
                ShutdownReason::UnexpectedError
            }
            RpcBufferedReaderError::EndOfFile => ShutdownReason::NeedsRestart,
        }
    }
}

#[derive(Clone)]
pub struct RpcServerReader {
    pub dispatcher: RpcServerDispatcher,
}

impl RpcServerReader {
    fn get_shutdown_reason(error: &RpcBufferedReaderError) -> ShutdownReason {
        ServerReaderErrorHandler::get_shutdown_reason(error)
    }
}

#[async_trait]
impl<S: ProxyStream> ServerSocketReader<S> for RpcServerReader {
    // EFS to Proxy
    async fn run(&mut self, mut read_half: ReadHalf<S>, shutdown: ShutdownHandle) {
        let shutdown_reason: Option<ShutdownReason>;
        let mut reader = BufferedRpcReader::new(read_half, /*read_count*/ None);
        loop {
            let rpc_batch = match reader.read().await {
                Ok(batch) => batch,
                Err(e) => {
                    drop(reader);
                    shutdown_reason = Some(Self::get_shutdown_reason(&e));
                    break;
                }
            };

            if let Err(e) = self.dispatcher.dispatch(rpc_batch).await {
                error!("Error sending message batch to dispatcher {:?}", e);
                shutdown_reason = Some(ShutdownReason::UnexpectedError);
                break;
            }
        }
        shutdown.exit(shutdown_reason).await;
    }

    #[cfg(test)]
    fn get_domain(&self) -> &'static str {
        RPC_DOMAIN_NAME
    }
}

pub struct RpcDomainBuilder<S> {
    phantom: PhantomData<S>,
}

impl<S: ProxyStream> DomainBuilder<S> for RpcDomainBuilder<S> {
    fn build_server_reader(
        &self,
        conn_sender: mpsc::Sender<ConnectionMessage>,
    ) -> Box<dyn ServerSocketReader<S>> {
        Box::new(RpcServerReader {
            dispatcher: RpcServerDispatcher {
                sender: conn_sender,
            },
        })
    }

    fn build_client_reader(
        &self,
        partition_senders: Arc<Mutex<Vec<mpsc::Sender<RpcBatch>>>>,
    ) -> Arc<Mutex<dyn ClientSocketReader>> {
        Arc::new(Mutex::new(RpcClientReader {
            dispatcher: RpcClientDispatcher {
                next_conn: 0,
                partition_senders,
            },
        }))
    }
}

impl<S: ProxyStream> RpcDomainBuilder<S> {
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::awsfile_rpc::AWSFILE_PROGRAM_NUMBER;
    use crate::rpc::rpc::RPC_MIN_SIZE;
    use crate::test_utils::generate_rpc_msg_fragments;

    use super::*;
    use bytes::BytesMut;
    use tokio::io::{split, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_util::sync::CancellationToken;

    #[tokio::test]
    async fn test_rpc_client_dispatcher() {
        let (tx1, mut rx1) = mpsc::channel(32);
        let senders = vec![tx1];
        let partition_senders = Arc::new(Mutex::new(senders));
        let mut dispatcher = RpcClientDispatcher::new(partition_senders.clone());

        // Verify round-robin behavior
        assert_eq!(dispatcher.next_conn, 0);
        let batch = RpcBatch { rpcs: Vec::new() };
        let res = dispatcher.dispatch(batch).await;
        assert!(res.is_ok(), "Dispatching error is: {:?}", res);
        assert!(res.is_ok());
        assert_eq!(dispatcher.next_conn, 0); // Should wrap around with single sender

        let (tx2, mut rx2) = mpsc::channel(32);
        let mut senders = partition_senders.lock().await;
        senders.push(tx2);
        drop(senders);
        let batch = RpcBatch { rpcs: Vec::new() };
        assert!(dispatcher.dispatch(batch).await.is_ok());
        assert_eq!(dispatcher.next_conn, 1);
        let batch = RpcBatch { rpcs: Vec::new() };
        assert!(dispatcher.dispatch(batch).await.is_ok());
        assert_eq!(dispatcher.next_conn, 0);

        // Verify messages received
        assert!((rx1.recv().await).is_some(), "Expected RpcBatch");
        assert!((rx2.recv().await).is_some(), "Expected RpcBatch");
    }

    #[tokio::test]
    async fn test_rpc_server_dispatcher() {
        let (tx, mut rx) = mpsc::channel(32);
        let mut dispatcher = RpcServerDispatcher { sender: tx };

        // Test dispatching a message
        let batch = RpcBatch { rpcs: Vec::new() };
        assert!(dispatcher.dispatch(batch).await.is_ok());

        // Verify message received
        assert!(
            matches!(rx.recv().await, Some(ConnectionMessage::Response(_))),
            "Expected ConnectionMessage::Response"
        );
    }

    /// Sanity test for ClientReader, full coverage is in the integration tests
    ///
    #[tokio::test]
    async fn test_rpc_client_reader() {
        let (tx, mut rx) = mpsc::channel(32);
        let senders = vec![tx.clone()];
        let partition_senders = Arc::new(Mutex::new(senders));
        let dispatcher = RpcClientDispatcher::new(partition_senders);

        let mut client_reader = RpcClientReader { dispatcher };

        // Create mock TCP connection between proxy and NFSClient
        // To work with OwnedReadHalf we need a real TcpStream
        // Use 0 as a port: :0 tells the OS to pick an open port.
        //
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut nfs_client = TcpStream::connect(addr).await.unwrap();
        let (proxy, _addr) = listener.accept().await.unwrap();

        // Create mock TCP connection between proxy and NFSClient
        let (read_half, _write_half) = proxy.into_split();
        let (shutdown, _waiter) = ShutdownHandle::new(CancellationToken::new());
        let shutdown_clone = shutdown.clone();
        let read_count = Arc::new(AtomicU64::new(0));

        // Run reader in separate task
        tokio::spawn(async move {
            tokio::select! {
                _ = shutdown.cancellation_token.cancelled() => trace!("Cancelled"),
                _ = client_reader.run(read_half, read_count, shutdown.clone()) => {},
            }
        });

        // write to a stream from the NFS client and make sure Reader's dispatcher sends that to the connection channel
        let (buffer, _) = generate_rpc_msg_fragments(RPC_MIN_SIZE, 1);
        assert!(nfs_client.write_all(&buffer).await.is_ok());
        assert!((rx.recv().await).is_some(), "Expected RpcBatch");

        // shutting down the reader
        shutdown_clone.cancellation_token.clone().cancel();
        drop(tx);
        assert!(
            (rx.recv().await).is_none(),
            "Expected None response since stream is empty"
        );
    }

    /// Sanity test for ServerReader, full coverage is in the integration tests
    ///
    #[tokio::test]
    async fn test_rpc_server_reader() {
        let (tx, mut rx) = mpsc::channel(32);

        let mut socket_reader = RpcServerReader {
            dispatcher: RpcServerDispatcher { sender: tx.clone() },
        };

        // Create mock connection between proxy (client) and NFS server
        let (client, mut server) = tokio::io::duplex(64);
        let (read_half, _write_half) = split(client);
        let (shutdown, _waiter) = ShutdownHandle::new(CancellationToken::new());
        let shutdown_clone = shutdown.clone();

        // Run reader in separate task
        tokio::spawn(async move {
            tokio::select! {
                _ = shutdown.cancellation_token.cancelled() => trace!("Cancelled"),
                _ = socket_reader.run(read_half, shutdown.clone()) => {},
            }
        });

        // write to a stream from the server and make sure dispatcher sends that to the channel
        let (buffer, _) = generate_rpc_msg_fragments(RPC_MIN_SIZE, 1);
        assert!(server.write_all(&buffer).await.is_ok());
        assert!(
            matches!(rx.recv().await, Some(ConnectionMessage::Response(_))),
            "Expected ConnectionMessage::Response"
        );

        // shutting down the reader
        shutdown_clone.cancellation_token.clone().cancel();
        drop(tx);
        assert!(
            (rx.recv().await).is_none(),
            "Expected None response since stream is empty"
        );
    }

    #[test]
    fn test_rpc_builder() {
        let builder = RpcDomainBuilder::<TcpStream>::new();
        let (tx, _rx) = mpsc::channel(10);

        let reader = builder.build_server_reader(tx);
        assert_eq!(reader.get_domain(), RPC_DOMAIN_NAME);

        let partition_senders = Arc::new(Mutex::new(Vec::<mpsc::Sender<RpcBatch>>::new()));
        let reader = builder.build_client_reader(partition_senders);

        let reader_guard = reader.try_lock();
        assert!(reader_guard.is_ok());
        assert_eq!(reader_guard.unwrap().get_domain(), RPC_DOMAIN_NAME);
    }
}
