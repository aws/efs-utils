//! # ReadBypassContext
//! Data types and structures carrying ReadBypass context, to be shared between various ReadBypass domain component from different threads
//!

#![allow(unused)]

use std::time::Duration;

use crate::{
    aws::s3_client::S3Client,
    config_parser::{ProxyConfig, ReadBypassConfig},
    util::fh_denylist::FileHandleDenyList,
};

pub struct ReadBypassContext {
    pub fh_denylist: FileHandleDenyList,
    pub s3_bucket: String,
    pub s3_prefix: String,
    pub s3_client: S3Client,
    pub cache_enabled: bool,
    pub read_bypass_config: ReadBypassConfig,
}

impl ReadBypassContext {
    pub fn new(
        proxy_config: &ProxyConfig,
        s3_bucket: String,
        s3_prefix: String,
        s3_client: S3Client,
        cache_enabled: bool,
    ) -> Self {
        let read_bypass_config = proxy_config.nested_config.read_bypass_config.clone();
        let fh_denylist = FileHandleDenyList::new(
            read_bypass_config.denylist_size,
            Duration::from_secs(read_bypass_config.denylist_ttl_seconds),
        );
        ReadBypassContext {
            fh_denylist,
            s3_bucket,
            s3_prefix,
            s3_client,
            cache_enabled,
            read_bypass_config,
        }
    }

    pub fn is_read_bypass_enabled(&self) -> bool {
        self.s3_client.is_enabled()
    }

    #[cfg(any(test, feature = "test-util"))]
    pub async fn default() -> Self {
        Self {
            fh_denylist: FileHandleDenyList::default(),
            s3_bucket: String::new(),
            s3_prefix: String::new(),
            s3_client: S3Client::default().await,
            cache_enabled: false, // Default to disabled for tests
            read_bypass_config: ReadBypassConfig::default(),
        }
    }

    #[cfg(any(test, feature = "test-util"))]
    pub fn set_s3_client_enabled(&self, enabled: bool) {
        self.s3_client.set_enabled(enabled);
    }
}
