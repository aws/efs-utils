//! # ReadBypassContext
//! Data types and structures carrying ReadBypass context, to be shared between various ReadBypass domain component from different threads
//!

#![allow(unused)]

use std::time::Duration;
use tokio::sync::mpsc::error::SendError;

use crate::{
    aws::s3_client::S3Client,
    config_parser::{ProxyConfig, ReadBypassConfig},
    domain::Parser,
    nfs::nfs_rpc_envelope::{NfsRpcEnvelopeBatch, NfsRpcInfo},
    rpc::rpc::RpcBatch,
    util::fh_denylist::FileHandleDenyList,
};

// Message data structure for ReadBypass domain to work with
pub type NfsDispatcherError = SendError<RpcBatch>;

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

    #[cfg(test)]
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

    #[cfg(test)]
    pub fn set_s3_client_enabled(&self, enabled: bool) {
        self.s3_client.set_enabled(enabled);
    }
}

// Message to be sent from ReadBypassServerDispatcher to ReadBypassAgent
pub type ReadBypassMessage = NfsRpcInfo;
