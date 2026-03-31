use log::{debug, trace};
use tokio::{
    io::{split, AsyncWriteExt, ReadHalf, WriteHalf},
    sync::mpsc::{self},
};
use tokio_util::sync::CancellationToken;

use crate::{
    connections::ProxyStream,
    domain::ServerSocketReader,
    rpc::rpc::RpcBatch,
    shutdown::{ShutdownHandle, ShutdownReason},
};

pub struct ConnectionTask<S> {
    stream: S,
    proxy_receiver: mpsc::Receiver<RpcBatch>,
}

impl<S: ProxyStream> ConnectionTask<S> {
    pub fn new(stream: S, proxy_receiver: mpsc::Receiver<RpcBatch>) -> Self {
        Self {
            stream,
            proxy_receiver,
        }
    }

    pub async fn run(
        self,
        socket_reader: Box<dyn ServerSocketReader<S>>,
        shutdown_handle: ShutdownHandle,
    ) {
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
        let reader = Self::run_reader(r, socket_reader, shutdown_handle.clone());
        tokio::spawn(async move {
            tokio::select! {
                _ = connection_cancellation_token.cancelled() => trace!("Cancelled"),
                _ = reader => {},
            }
        });
    }

    // Reading and sending messages from EFS to Proxy
    //
    // Why do we use ReadHalf<S> but not OwnedReadHalf like in ProxyTask?
    // Because we can have connection with Tls and without it, so different types of TcpStream can be used.
    //
    async fn run_reader(
        server_read_half: ReadHalf<S>,
        mut socket_reader: Box<dyn ServerSocketReader<S>>,
        shutdown: ShutdownHandle,
    ) {
        trace!("Starting connection reader");
        socket_reader.run(server_read_half, shutdown).await;
    }

    // Getting messages from Proxy and sending to EFS
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
