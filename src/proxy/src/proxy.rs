use std::{
    error::Error,
    marker::PhantomData,
    sync::{atomic::AtomicU64, Arc},
    time::{Duration, Instant},
};

use bytes::BytesMut;
use log::{debug, error, info, trace};
use tokio::{
    io::{split, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
    sync::{
        mpsc::{self},
        Mutex,
    },
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use crate::rpc::{RpcFragmentParseError, RPC_MAX_SIZE};
use crate::{
    connections::ProxyStream,
    controller::Event,
    rpc::RpcBatch,
    shutdown::{ShutdownHandle, ShutdownReason},
};

pub const REPORT_INTERVAL_SECS: u64 = 3;

#[derive(Copy, Clone, Debug)]
pub struct PerformanceStats {
    _num_connections: usize,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub time_delta: Duration,
}

impl PerformanceStats {
    pub fn new(
        num_connections: usize,
        read_bytes: u64,
        write_bytes: u64,
        time_delta: Duration,
    ) -> Self {
        PerformanceStats {
            _num_connections: num_connections,
            read_bytes,
            write_bytes,
            time_delta,
        }
    }

    // Return total throughput in bytes per second
    pub fn get_total_throughput(&self) -> u64 {
        let time_delta_seconds = self.time_delta.as_secs();
        if time_delta_seconds == 0 {
            0
        } else {
            let total_bytes = self.read_bytes + self.write_bytes;
            total_bytes / time_delta_seconds
        }
    }
}
pub struct Proxy<S> {
    partition_to_nfs_cli_queue: mpsc::Sender<ConnectionMessage>,
    partition_senders: Arc<Mutex<Vec<mpsc::Sender<RpcBatch>>>>,
    shutdown: ShutdownHandle,
    proxy_task_handle: JoinHandle<()>,
    phantom: PhantomData<S>,
}

impl<S: ProxyStream> Proxy<S> {
    const SHUTDOWN_TIMEOUT: u64 = 15;

    pub fn new(
        nfs_client: TcpStream,
        partition_servers: Vec<S>,
        notification_queue: mpsc::Sender<Event<S>>,
        shutdown: ShutdownHandle,
    ) -> Self {
        let (tx, rx) = mpsc::channel(64);

        let senders = partition_servers
            .into_iter()
            .map(|stream| Proxy::create_connection(stream, tx.clone(), shutdown.clone()))
            .collect::<Vec<mpsc::Sender<RpcBatch>>>();

        let partition_senders = Arc::new(Mutex::new(senders));

        let proxy = ProxyTask::new(
            nfs_client,
            notification_queue,
            partition_senders.clone(),
            rx,
            shutdown.clone(),
        );
        let proxy_task_handle = tokio::spawn(proxy.run());
        Self {
            partition_to_nfs_cli_queue: tx,
            partition_senders,
            shutdown,
            proxy_task_handle,
            phantom: PhantomData,
        }
    }

    pub async fn add_connection(&self, stream: S) {
        let conn = Proxy::create_connection(
            stream,
            self.partition_to_nfs_cli_queue.clone(),
            self.shutdown.clone(),
        );
        let mut f = self.partition_senders.lock().await;
        f.push(conn);
    }

    fn create_connection(
        stream: S,
        proxy: mpsc::Sender<ConnectionMessage>,
        shutdown: ShutdownHandle,
    ) -> mpsc::Sender<RpcBatch> {
        let (tx, rx) = mpsc::channel(64);
        tokio::spawn(ConnectionTask::new(stream, rx, proxy).run(shutdown));
        tx
    }

    pub async fn shutdown(self) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.shutdown.cancellation_token.cancel();
        match tokio::time::timeout(
            Duration::from_secs(Self::SHUTDOWN_TIMEOUT),
            self.proxy_task_handle,
        )
        .await?
        {
            Ok(()) => Ok(()),
            Err(join_err) => Err(join_err.into()),
        }
    }
}

const BUFFER_SIZE: usize = RPC_MAX_SIZE;

struct ProxyTask<S> {
    nfs_client: TcpStream,
    notification_queue: mpsc::Sender<Event<S>>,
    partition_senders: Arc<Mutex<Vec<mpsc::Sender<RpcBatch>>>>,
    response_queue: mpsc::Receiver<ConnectionMessage>,
    shutdown: ShutdownHandle,
}

enum ConnectionMessage {
    Response(RpcBatch),
}

impl<S: ProxyStream> ProxyTask<S> {
    pub fn new(
        nfs_client: TcpStream,
        notification_queue: mpsc::Sender<Event<S>>,
        partition_senders: Arc<Mutex<Vec<mpsc::Sender<RpcBatch>>>>,
        response_queue: mpsc::Receiver<ConnectionMessage>,
        shutdown: ShutdownHandle,
    ) -> Self {
        Self {
            nfs_client,
            notification_queue,
            partition_senders,
            response_queue,
            shutdown,
        }
    }

    async fn run(self) {
        // Runs Proxy between NFS Client and the EFS Service.
        //
        // This function returns when it is cancelled by the `ShutdownHandle`, or if an error
        // causes the `ProxyTask`'s `reader`, `writer`, or `reporter` task to return. In any of
        // these cases, the `tokio::select!` block will cancel all of the tasks run by this object.
        //
        // An unused `mspc::Sender` is passed to each task spawned, so that we can await task
        // shutdown with `mspc::Receiver::recv`. See https://tokio.rs/tokio/topics/shutdown.

        trace!("Starting proxy task");

        let (shutdown_sender, mut shutdown_receiver) = mpsc::channel::<u8>(1);

        let write_byte_count = Arc::new(AtomicU64::new(0));
        let read_byte_count = Arc::new(AtomicU64::new(0));

        let (read_half, write_half) = self.nfs_client.into_split();

        let reader = Self::run_reader(
            read_half,
            read_byte_count.clone(),
            self.partition_senders.clone(),
            self.shutdown.clone(),
            shutdown_sender.clone(),
        );
        let shutdown = self.shutdown.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = reader => trace!("Proxy reader stopped"),
                _ = shutdown.cancellation_token.cancelled() => trace!("Proxy reader stopped by ShutdownHandle"),
            }
        });

        let writer = Self::run_writer(
            write_half,
            write_byte_count.clone(),
            self.response_queue,
            self.shutdown.clone(),
            shutdown_sender.clone(),
        );
        let shutdown = self.shutdown.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = writer => trace!("Proxy writer stopped"),
                _ = shutdown.cancellation_token.cancelled() => trace!("Proxy writer stopped by ShutdownHandle"),
            }
        });

        let reporter = Self::run_reporter(
            read_byte_count,
            write_byte_count,
            self.partition_senders.clone(),
            self.notification_queue.clone(),
            shutdown_sender.clone(),
        );
        let shutdown = self.shutdown.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = reporter => trace!("Proxy reporter stopped"),
                _ = shutdown.cancellation_token.cancelled() => trace!("Proxy reporter stopped by ShutdownHandle"),
            }
        });

        drop(shutdown_sender);
        shutdown_receiver.recv().await;
    }

    // NFS client to Proxy
    async fn run_reader(
        mut read_half: OwnedReadHalf,
        read_count: Arc<AtomicU64>,
        partition_senders: Arc<Mutex<Vec<mpsc::Sender<RpcBatch>>>>,
        shutdown: ShutdownHandle,
        _shutdown_sender: mpsc::Sender<u8>,
    ) {
        trace!("Starting proxy reader");
        let mut buffer = BytesMut::with_capacity(BUFFER_SIZE);
        let reason;
        let mut next_conn = 0;

        loop {
            match read_half.read_buf(&mut buffer).await {
                Ok(n_read) => {
                    if n_read == 0 {
                        reason = Some(ShutdownReason::Unmount);
                        break;
                    } else {
                        read_count.fetch_add(n_read as u64, std::sync::atomic::Ordering::AcqRel);
                    }
                }
                Err(e) => {
                    info!("Error reading from NFS client {:?}", e);
                    reason = Some(ShutdownReason::Unmount);
                    break;
                }
            }

            match RpcBatch::parse_batch(&mut buffer) {
                Ok(Some(batch)) => {
                    let f = partition_senders.lock().await;
                    let r = f[next_conn].send(batch).await;
                    next_conn = (next_conn + 1) % f.len();
                    if let Err(e) = r {
                        debug!("Error sending RPC batch to connection task {:?}", e);
                        reason = Some(ShutdownReason::UnexpectedError);
                        break;
                    };
                }
                Err(RpcFragmentParseError::InvalidSizeTooSmall) => {
                    drop(read_half);
                    error!("NFS Client Error: invalid RPC size - size too small");
                    reason = Some(ShutdownReason::FrameSizeTooSmall);
                    break;
                }
                Err(RpcFragmentParseError::SizeLimitExceeded) => {
                    drop(read_half);
                    error!("NFS Client Error: invalid RPC size - size limit exceeded");
                    reason = Some(ShutdownReason::FrameSizeExceeded);
                    break;
                }
                Ok(None) | Err(RpcFragmentParseError::Incomplete) => (),
            }

            if buffer.capacity() == 0 {
                buffer.reserve(BUFFER_SIZE)
            }
        }
        trace!("cli_to_server exiting!");
        shutdown.exit(reason).await;
    }

    // Proxy to NFS Client
    async fn run_writer(
        mut write_half: OwnedWriteHalf,
        write_count: Arc<AtomicU64>,
        mut response_queue: mpsc::Receiver<ConnectionMessage>,
        shutdown: ShutdownHandle,
        _shutdown_sender: mpsc::Sender<u8>,
    ) {
        trace!("Starting proxy writer");

        let mut reason = None;
        loop {
            match response_queue.recv().await {
                Some(ConnectionMessage::Response(batch)) => {
                    let mut total_written = 0;

                    for b in &batch.rpcs {
                        match write_half.write_all(b).await {
                            Ok(_) => total_written += b.len(),
                            Err(e) => {
                                debug!("Error writing to nfs_client. {:?}", e);
                                reason = Some(ShutdownReason::Unmount);
                                break;
                            }
                        };
                    }

                    write_count
                        .fetch_add(total_written as u64, std::sync::atomic::Ordering::AcqRel);
                }
                None => {
                    info!("Exiting server_to_cli");
                    break;
                }
            }
        }
        shutdown.exit(reason).await;
    }

    async fn run_reporter(
        read_count: Arc<AtomicU64>,
        write_count: Arc<AtomicU64>,
        partition_senders: Arc<Mutex<Vec<mpsc::Sender<RpcBatch>>>>,
        notification_queue: mpsc::Sender<Event<S>>,
        _shutdown_sender: mpsc::Sender<u8>,
    ) {
        trace!("Starting reporter task");

        let mut last = Instant::now();
        loop {
            tokio::time::sleep(Duration::from_secs(REPORT_INTERVAL_SECS)).await;

            let num_connections;
            {
                let t = partition_senders.lock().await;
                num_connections = t.len();
                drop(t);
            }

            let now = Instant::now();
            let delta = now - last;
            last = now;
            let read = read_count.swap(0, std::sync::atomic::Ordering::AcqRel);
            let write = write_count.swap(0, std::sync::atomic::Ordering::AcqRel);
            let result = notification_queue
                .send(Event::ProxyUpdate(PerformanceStats::new(
                    num_connections,
                    read,
                    write,
                    delta,
                )))
                .await;
            if result.is_err() {
                break;
            }
        }
    }
}

struct ConnectionTask<S> {
    stream: S,
    proxy_receiver: mpsc::Receiver<RpcBatch>,
    proxy_sender: mpsc::Sender<ConnectionMessage>,
}

impl<S: ProxyStream> ConnectionTask<S> {
    fn new(
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

    async fn run(self, shutdown_handle: ShutdownHandle) {
        let (r, w) = split(self.stream);

        let shutdown = shutdown_handle.clone();

        // This CancellationToken facilitates graceful TLS connection closures by ensuring that
        // that the ReadHalf is dropped only after the WriteHalf.shutdown() has returned
        let connection_cancellation_token = CancellationToken::new();

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
