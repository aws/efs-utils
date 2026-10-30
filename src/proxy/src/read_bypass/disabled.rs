//! Read bypass in a build without the `read-bypass` feature: never available, never built.

use crate::{
    aws::s3_client::S3Client, config::channel_init_config::ChannelInitConfig,
    config_parser::ProxyConfig, connections::ProxyStream, domain::DomainBuilder,
    shutdown::ShutdownHandle,
};

pub const AVAILABLE: bool = false;

pub async fn domain_builder<S: ProxyStream>(
    _proxy_config: ProxyConfig,
    _channel_init_config: ChannelInitConfig,
    _shutdown: ShutdownHandle,
    s3_client: S3Client,
) -> Box<dyn DomainBuilder<S>> {
    match s3_client {}
}
