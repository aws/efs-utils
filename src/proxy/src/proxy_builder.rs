//! # Builder for constructing proxy data path components based on selected domain and parameters
//! Essentially a Factory for creating a family of objects based on detected domain.
//!

use std::{marker::PhantomData, sync::Arc};

use tokio::sync::Mutex;
use tokio::{net::TcpStream, sync::mpsc};

use crate::{
    aws::s3_client::S3Client, config::channel_init_config::ChannelInitConfig,
    config_parser::ProxyConfig, connections::ProxyStream, controller::Event, domain::*,
    proxy::Proxy, read_bypass::read_bypass_domain_builder::ReadBypassDomainBuilder,
    rpc::rpc::RpcBatch, rpc::rpc_domain::*, shutdown::ShutdownHandle,
};

pub struct ProxyBuilder<S: ProxyStream> {
    // ProxyBuilder does not have explicit data members using type S, but it is used in its functions.
    // Shutting up compiler with PhantomData, as it recommends.
    _phantom: PhantomData<S>,
}

impl<S: ProxyStream> ProxyBuilder<S> {
    pub async fn add_connection(proxy: &mut Proxy<S>, stream: S) {
        let conn_reader = proxy.server_socket_reader.clone();
        proxy.add_connection(stream, conn_reader).await;
    }

    async fn create_builder(
        proxy_config: ProxyConfig,
        shutdown: ShutdownHandle,
        channel_init_config: ChannelInitConfig,
        s3client: Option<S3Client>,
    ) -> Box<dyn DomainBuilder<S>> {
        if proxy_config.nested_config.read_bypass_config.requested
            && proxy_config.nested_config.read_bypass_config.enabled
            && channel_init_config.read_bypass_config.enabled
            && s3client.is_some()
        {
            // If ReadBypass is requested by user (not opted-out) and we've got confirmation from server
            // that feature is enabled, we can construct the Proxy with ReadBypass support
            if let Some(client) = s3client {
                let read_bypass_builder = ReadBypassDomainBuilder::new(
                    proxy_config,
                    channel_init_config,
                    shutdown,
                    client,
                )
                .await;
                Box::new(read_bypass_builder)
            } else {
                unreachable!("s3client.is_some() was checked in the outer condition")
            }
        } else {
            Box::new(RpcDomainBuilder::<S>::new())
        }
    }

    pub async fn build_proxy(
        nfs_client_stream: TcpStream,
        partition_servers: Vec<S>,
        notification_queue: mpsc::Sender<Event<S>>,
        shutdown: ShutdownHandle,
        proxy_config: ProxyConfig,
        channel_init_config: ChannelInitConfig,
        s3_client: Option<S3Client>,
    ) -> Proxy<S> {
        // Channel for Server Connections -> Client communication
        let (tx, rx) = mpsc::channel(64);

        // tx is passed to ConnectionTask' readers, so each ConnectionTask will be reading from NFS socket
        // and sending messages to NFSClient channel via tx
        let builder = ProxyBuilder::<S>::create_builder(
            proxy_config.clone(),
            shutdown.clone(),
            channel_init_config,
            s3_client,
        )
        .await;
        let server_reader = builder.build_server_reader(tx.clone());

        let senders = partition_servers
            .into_iter()
            .map(|stream| {
                let conn_reader = server_reader.clone();
                Proxy::create_connection(stream, conn_reader, shutdown.clone())
            })
            .collect::<Vec<mpsc::Sender<RpcBatch>>>();

        let partition_senders = Arc::new(Mutex::new(senders));

        let client_socket_reader = builder.build_client_reader(partition_senders.clone());

        // rx is passed to ProxyTask, so it can receive NFS response messages from ConnectionTask
        // and write it to NFSClient socket
        Proxy::new(
            nfs_client_stream,
            client_socket_reader,
            partition_senders,
            notification_queue,
            shutdown.clone(),
            rx,
            proxy_config,
            server_reader,
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        rpc::rpc::{READER_BUFFER_SIZE, RPC_HEADER_SIZE, RPC_MIN_SIZE},
        test_utils::generate_rpc_msg_fragments,
    };

    use super::*;
    use bytes::BytesMut;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use tokio_util::sync::CancellationToken;

    async fn create_tcp_stream() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let writer_stream = TcpStream::connect(addr).await.unwrap();
        let (reader_stream, _addr) = listener.accept().await.unwrap();
        (reader_stream, writer_stream)
    }

    fn create_proxy_config(read_bypass_enabled: bool) -> ProxyConfig {
        let mut config = ProxyConfig::default();
        config.nested_config.read_bypass_config.requested = read_bypass_enabled;
        config.nested_config.read_bypass_config.enabled = read_bypass_enabled;
        config
    }

    #[tokio::test]
    async fn test_multi_connection_proxy() {
        let (nfs_client_reader_stream, mut nfs_client_writer_stream) = create_tcp_stream().await;
        let (mut server_reader_stream, server_writer_stream) = create_tcp_stream().await;

        let partition_servers = vec![server_writer_stream];
        let (notification_tx, _notification_rx) = mpsc::channel(10);

        let config = create_proxy_config(false);
        let (shutdown, _waiter) = ShutdownHandle::new(CancellationToken::new());

        let s3_client = None;

        // Build RPC proxy
        let mut proxy = ProxyBuilder::<TcpStream>::build_proxy(
            nfs_client_reader_stream,
            partition_servers,
            notification_tx,
            shutdown,
            config,
            ChannelInitConfig::default(),
            s3_client,
        )
        .await;

        // Creation of the Proxy always starts all the readers.
        // Let's write some messages to NFSClient stream and check whether they are routed to partition servers

        // Write to NFSClient stream
        let (buffer, _) = generate_rpc_msg_fragments(RPC_MIN_SIZE, 1);
        assert!(nfs_client_writer_stream.write_all(&buffer).await.is_ok());

        // Read and check from partition server stream
        let mut buffer = BytesMut::with_capacity(READER_BUFFER_SIZE);
        let res = server_reader_stream.read_buf(&mut buffer).await;
        assert!(res.is_ok(), "Unexpected error: {:?}", res);
        assert_eq!(
            res.unwrap(),
            RPC_MIN_SIZE + RPC_HEADER_SIZE,
            "Unexpected number of bytes read"
        );

        // Add another server connection
        let (mut _server_reader_stream2, server_writer_stream2) = create_tcp_stream().await;

        assert_eq!(
            proxy.get_num_connections().await,
            1,
            "Unexpected number of server connections"
        );
        ProxyBuilder::<TcpStream>::add_connection(&mut proxy, server_writer_stream2).await;
        assert_eq!(
            proxy.get_num_connections().await,
            2,
            "Unexpected number of server connections"
        );

        // Shutdown proxy
        assert!(proxy.shutdown().await.is_ok());
    }

    #[tokio::test]
    async fn test_read_bypass_proxy_building() {
        let (nfs_client_reader_stream, _nfs_client_writer_stream) = create_tcp_stream().await;
        let (_server_reader_stream, server_writer_stream) = create_tcp_stream().await;

        let partition_servers = vec![server_writer_stream];
        let (notification_tx, _notification_rx) = mpsc::channel(10);

        let config = create_proxy_config(true);
        let (shutdown, _waiter) = ShutdownHandle::new(CancellationToken::new());

        let s3_client = Some(S3Client::default().await);

        // Build RPC proxy
        let proxy = ProxyBuilder::<TcpStream>::build_proxy(
            nfs_client_reader_stream,
            partition_servers,
            notification_tx,
            shutdown,
            config,
            ChannelInitConfig::default(),
            s3_client,
        )
        .await;

        // Shutdown proxy
        assert!(proxy.shutdown().await.is_ok());
    }
}
