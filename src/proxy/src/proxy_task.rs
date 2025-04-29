use std::{
    sync::{atomic::AtomicU64, Arc},
    time::{Duration, Instant},
};

use bytes::BytesMut;
use log::{debug, error, info, trace};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
    sync::{
        mpsc::{self},
        Mutex,
    },
};

use crate::rpc::{RpcFragmentParseError, RPC_MAX_SIZE};
use crate::{
    connections::ProxyStream,
    controller::Event,
    rpc::RpcBatch,
    shutdown::{ShutdownHandle, ShutdownReason},
};

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

pub const BUFFER_SIZE: usize = RPC_MAX_SIZE;
pub const REPORT_INTERVAL_SECS: u64 = 3;

pub struct ProxyTask<S> {
    nfs_client: TcpStream,
    notification_queue: mpsc::Sender<Event<S>>,
    partition_senders: Arc<Mutex<Vec<mpsc::Sender<RpcBatch>>>>,
    response_queue: mpsc::Receiver<ConnectionMessage>,
    shutdown: ShutdownHandle,
}

pub enum ConnectionMessage {
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

    pub async fn run(self) {
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

        // ProxyTask Reader reads NFS messages from NFSClient socket and sends it to ConnectionTask
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

        // ProxyTask Writer takes items from NFSClient channel and writes to the NFSClient socket
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
            // Read data from NFSClient socket
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

            // Parse message and send to particular connection's channel
            match RpcBatch::parse_batch(&mut buffer) {
                Ok(Some(batch)) => {
                    let f = partition_senders.lock().await;
                    let r = f[next_conn].send(batch).await;

                    // select connection via round-robin
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
