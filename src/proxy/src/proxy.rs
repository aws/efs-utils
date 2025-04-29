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
    connection_task::ConnectionTask,
    connections::ProxyStream,
    controller::Event,
    proxy_task::{ConnectionMessage, ProxyTask},
    rpc::RpcBatch,
    shutdown::ShutdownHandle,
};

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
        // Channel for NFSServer -> NFSClient communication
        let (tx, rx) = mpsc::channel(64);

        // tx is passed to ConnectionTasks, so each ConnectionTask will be reading from NFS socket
        // and sending messages to NFSClient channel via tx
        let senders = partition_servers
            .into_iter()
            .map(|stream| Proxy::create_connection(stream, tx.clone(), shutdown.clone()))
            .collect::<Vec<mpsc::Sender<RpcBatch>>>();

        let partition_senders = Arc::new(Mutex::new(senders));

        // rx is passed to ProxyTask, so it can receive NFS response messages from ConnectionTask
        // and write it to NFSClient socket
        let proxy_task = ProxyTask::new(
            nfs_client,
            notification_queue,
            partition_senders.clone(),
            rx,
            shutdown.clone(),
        );
        let proxy_task_handle = tokio::spawn(proxy_task.run());
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
