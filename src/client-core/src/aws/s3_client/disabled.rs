use async_trait::async_trait;

use super::S3ClientBuilder;
use crate::config_parser::ProxyConfig;

pub enum S3Client {}

pub struct S3ClientStandardBuilder;

#[async_trait]
impl S3ClientBuilder for S3ClientStandardBuilder {
    async fn build(
        &self,
        _bucket: &str,
        _prefix: &str,
        _proxy_config: &ProxyConfig,
    ) -> Option<S3Client> {
        None
    }
}
