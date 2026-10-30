pub(crate) mod read_bypass_agent;
mod read_bypass_client_dispatcher;
pub mod read_bypass_domain_builder;
mod read_bypass_server_dispatcher;

use crate::{
    aws::s3_client::S3Client, config::channel_init_config::ChannelInitConfig,
    config_parser::ProxyConfig, connections::ProxyStream, domain::DomainBuilder,
    shutdown::ShutdownHandle,
};
use read_bypass_domain_builder::ReadBypassDomainBuilder;

pub const AVAILABLE: bool = true;

pub async fn domain_builder<S: ProxyStream>(
    proxy_config: ProxyConfig,
    channel_init_config: ChannelInitConfig,
    shutdown: ShutdownHandle,
    s3_client: S3Client,
) -> Box<dyn DomainBuilder<S>> {
    Box::new(
        ReadBypassDomainBuilder::new(proxy_config, channel_init_config, shutdown, s3_client).await,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy_builder::ProxyBuilder;
    use crate::test_utils::{create_proxy_config, create_tcp_stream};
    use tokio::{net::TcpStream, sync::mpsc};
    use tokio_util::sync::CancellationToken;

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
