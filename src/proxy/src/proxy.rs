#![allow(unused)]

use std::{error::Error, marker::PhantomData, sync::Arc, time::Duration};

use tokio::{
    net::TcpStream,
    sync::{
        mpsc::{self},
        Mutex,
    },
    task::JoinHandle,
};

use crate::{
    config_parser::ProxyConfig,
    connection_task::ConnectionTask,
    connections::ProxyStream,
    controller::Event,
    domain::{ClientSocketReader, ServerSocketReader},
    proxy_task::{ConnectionMessage, ProxyTask},
    rpc::rpc::RpcBatch,
    shutdown::ShutdownHandle,
};

pub struct Proxy<S> {
    partition_senders: Arc<Mutex<Vec<mpsc::Sender<RpcBatch>>>>,
    shutdown: ShutdownHandle,
    proxy_task_handle: JoinHandle<()>,
    phantom: PhantomData<S>,
    pub proxy_config: ProxyConfig,
    // we want to keep a copy of NfsServerSocket reader
    // it will be cloned / reused during new connections creation
    pub server_socket_reader: Box<dyn ServerSocketReader<S>>,
}

#[allow(clippy::too_many_arguments)]
impl<S: ProxyStream> Proxy<S> {
    const SHUTDOWN_TIMEOUT: u64 = 15;

    pub fn new(
        nfs_client: TcpStream,
        client_reader: Arc<Mutex<dyn ClientSocketReader>>,
        partition_senders: Arc<Mutex<Vec<mpsc::Sender<RpcBatch>>>>,
        notification_queue: mpsc::Sender<Event<S>>,
        shutdown: ShutdownHandle,
        // receiver and sender for messages from server connections
        receiver: mpsc::Receiver<ConnectionMessage>,
        proxy_config: ProxyConfig,
        server_socket_reader: Box<dyn ServerSocketReader<S>>,
    ) -> Self {
        // rx is passed to ProxyTask, so it can receive NFS response messages from ConnectionTask
        // and write it to NFSClient socket
        let proxy_task = ProxyTask::new(
            nfs_client,
            notification_queue,
            partition_senders.clone(),
            receiver,
            shutdown.clone(),
        );

        let proxy_task_handle = tokio::spawn(proxy_task.run(client_reader));
        Self {
            partition_senders,
            shutdown,
            proxy_task_handle,
            phantom: PhantomData,
            proxy_config,
            server_socket_reader,
        }
    }

    pub async fn add_connection(&self, stream: S, conn_reader: Box<dyn ServerSocketReader<S>>) {
        let conn = Proxy::create_connection(stream, conn_reader, self.shutdown.clone());
        let mut f = self.partition_senders.lock().await;
        f.push(conn);
    }

    pub fn create_connection(
        stream: S,
        conn_reader: Box<dyn ServerSocketReader<S>>,
        shutdown: ShutdownHandle,
    ) -> mpsc::Sender<RpcBatch> {
        let (tx, rx) = mpsc::channel(64);
        tokio::spawn(ConnectionTask::new(stream, rx).run(conn_reader, shutdown));
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

    #[cfg(test)]
    pub async fn get_num_connections(&self) -> usize {
        self.partition_senders.lock().await.len()
    }
}
