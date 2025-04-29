use bytes::BytesMut;
use log::{debug, error, trace};
use tokio::{
    io::{split, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    sync::mpsc::{self},
};
use tokio_util::sync::CancellationToken;

use crate::{
    connections::ProxyStream,
    rpc::RpcBatch,
    shutdown::{ShutdownHandle, ShutdownReason},
};
use crate::{
    proxy_task::{ConnectionMessage, BUFFER_SIZE},
    rpc::RpcFragmentParseError,
};

pub struct ConnectionTask<S> {
    stream: S,
    proxy_receiver: mpsc::Receiver<RpcBatch>,
    proxy_sender: mpsc::Sender<ConnectionMessage>,
}

impl<S: ProxyStream> ConnectionTask<S> {
    pub fn new(
        stream: S,
        proxy_receiver: mpsc::Receiver<RpcBatch>,
        proxy_sender: mpsc::Sender<ConnectionMessage>,
    ) -> Self {
        Self {
            stream,
            proxy_receiver,
            proxy_sender,
        }
    }

    pub async fn run(self, shutdown_handle: ShutdownHandle) {
        let (r, w) = split(self.stream);

        let shutdown = shutdown_handle.clone();

        // This CancellationToken facilitates graceful TLS connection closures by ensuring that
        // that the ReadHalf is dropped only after the WriteHalf.shutdown() has returned
        let connection_cancellation_token = CancellationToken::new();

        // ConnectionTask Writer receives messages from NFSClient's Reader (ProxyTask reader) and writes them to connection socket
        let writer = Self::run_writer(
            w,
            self.proxy_receiver,
            shutdown_handle.clone(),
            connection_cancellation_token.clone(),
        );
        tokio::spawn(async move {
            tokio::select! {
                _ = shutdown.cancellation_token.cancelled() => trace!("Cancelled"),
                _ = writer => {},
            }
        });

        // ConnectionTask Reader reads messages from NFSServer's socket and sends to NFSClient Writer (ProxyTask writer)
        let reader = Self::run_reader(r, self.proxy_sender, shutdown_handle.clone());
        tokio::spawn(async move {
            tokio::select! {
                _ = connection_cancellation_token.cancelled() => trace!("Cancelled"),
                _ = reader => {},
            }
        });
    }

    // EFS to Proxy
    async fn run_reader(
        mut server_read_half: ReadHalf<S>,
        sender: mpsc::Sender<ConnectionMessage>,
        shutdown: ShutdownHandle,
    ) {
        let reason;
        let mut buffer = BytesMut::with_capacity(BUFFER_SIZE);
        loop {
            match server_read_half.read_buf(&mut buffer).await {
                Ok(n_read) => {
                    if n_read == 0 {
                        reason = Option::Some(ShutdownReason::NeedsRestart);
                        break;
                    }
                }
                Err(e) => {
                    debug!("Error reading from server: {:?}", e);
                    reason = Option::Some(ShutdownReason::NeedsRestart);
                    break;
                }
            };

            match RpcBatch::parse_batch(&mut buffer) {
                Ok(Some(batch)) => {
                    if let Err(e) = sender.send(ConnectionMessage::Response(batch)).await {
                        debug!("Error sending result back: {:?}", e);
                        reason = Some(ShutdownReason::UnexpectedError);
                        break;
                    }
                }
                Err(RpcFragmentParseError::InvalidSizeTooSmall) => {
                    drop(server_read_half);
                    error!("Server Error: invalid RPC size - size too small");
                    reason = Some(ShutdownReason::UnexpectedError);
                    break;
                }
                Err(RpcFragmentParseError::SizeLimitExceeded) => {
                    drop(server_read_half);
                    error!("Server Error: invalid RPC size - size limit exceeded");
                    reason = Some(ShutdownReason::UnexpectedError);
                    break;
                }
                Ok(None) | Err(RpcFragmentParseError::Incomplete) => (),
            }

            if buffer.capacity() == 0 {
                buffer.reserve(BUFFER_SIZE)
            }
        }
        shutdown.exit(reason).await;
    }

    // Proxy to EFS
    async fn run_writer(
        mut server_write_half: WriteHalf<S>,
        mut receiver: mpsc::Receiver<RpcBatch>,
        shutdown: ShutdownHandle,
        connection_cancellation_token: CancellationToken,
    ) {
        let mut reason = Option::None;
        loop {
            let Some(batch) = receiver.recv().await else {
                debug!("sender dropped");
                break;
            };

            for b in &batch.rpcs {
                match server_write_half.write_all(b).await {
                    Ok(_) => (),
                    Err(e) => {
                        debug!("Error writing to server: {:?}", e);
                        reason = Option::Some(ShutdownReason::NeedsRestart);
                        break;
                    }
                };
            }
        }

        tokio::spawn(async move {
            match server_write_half.shutdown().await {
                Ok(_) => (),
                Err(e) => debug!("Failed to gracefully shutdown connection: {}", e),
            };
            connection_cancellation_token.cancel();
        });
        shutdown.exit(reason).await;
    }
}
