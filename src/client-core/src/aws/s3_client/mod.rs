//! S3 client for read bypass. Without the `read-bypass` feature there is no client:
//! [`S3Client`] has no values and [`S3ClientStandardBuilder`] never builds one.

use async_trait::async_trait;

use crate::config_parser::ProxyConfig;

#[cfg(feature = "read-bypass")]
mod client;
#[cfg(not(feature = "read-bypass"))]
#[path = "disabled.rs"]
mod client;

pub use client::*;

#[async_trait]
pub trait S3ClientBuilder {
    async fn build(
        &self,
        bucket: &str,
        prefix: &str,
        proxy_config: &ProxyConfig,
    ) -> Option<S3Client>;
}
