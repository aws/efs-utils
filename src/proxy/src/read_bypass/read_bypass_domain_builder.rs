//! # ReadBypassDomainBuilder
//!
//! This module provides a builder for the Read Bypass domain, which uses the same reader structs
//! as NfsSnifferBuilder (NfsClientReader/NfsServerReader) but with dispatchers from the read bypass modules.

#![allow(unused)]

use std::{marker::PhantomData, sync::Arc};

use log::{debug, error, info, trace, warn};
use tokio::sync::{mpsc, Mutex};

use crate::{
    aws::s3_client::S3Client,
    config::channel_init_config::ChannelInitConfig,
    config_parser::ProxyConfig,
    connections::ProxyStream,
    domain::{ClientSocketReader, DomainBuilder, ServerSocketReader},
    nfs::nfs_reader::{NfsClientReader, NfsRpcParser, NfsServerReader},
    proxy_task::ConnectionMessage,
    read_ahead::readahead_cache::FileReadAheadCache,
    read_bypass::{
        read_bypass_agent::{CachedS3Reader, DirectS3Reader, ReadBypassAgent, S3Reader},
        read_bypass_client_dispatcher::ReadBypassClientDispatcher,
        read_bypass_server_dispatcher::ReadBypassServerDispatcher,
    },
    rpc::{rpc::RpcBatch, rpc_domain::RpcClientDispatcher},
    shutdown::ShutdownHandle,
    util::{
        read_bypass_context::{ReadBypassContext, ReadBypassMessage},
        s3_data_reader::S3ReadBypassReader,
    },
    utils::has_sufficient_memory_for_readahead_cache,
};

const READ_BYPASS_DOMAIN_NAME: &str = "ReadBypass";
const READ_BYPASS_AGENT_QUEUE_SIZE: usize = 128;

pub struct ReadBypassDomainBuilder<S> {
    read_bypass_context: Arc<ReadBypassContext>,
    shutdown: ShutdownHandle,
    phantom: PhantomData<S>,
}

impl<S: ProxyStream> DomainBuilder<S> for ReadBypassDomainBuilder<S> {
    fn build_server_reader(
        &self,
        from_conn_sender: mpsc::Sender<ConnectionMessage>,
    ) -> Box<dyn ServerSocketReader<S>> {
        // Create the message channel for ReadBypassAgent
        let (rba_message_sender, rba_message_receiver) =
            mpsc::channel::<ReadBypassMessage>(READ_BYPASS_AGENT_QUEUE_SIZE);

        // Create the ReadBypassServerDispatcher
        let server_dispatcher = ReadBypassServerDispatcher {
            nfs_client_sender: from_conn_sender.clone(),
            rba_sender: rba_message_sender.clone(),
            read_bypass_context: self.read_bypass_context.clone(),
        };

        // Now we have all the channels for ReadBypassAgent and can start it

        let read_bypass_config = &self.read_bypass_context.read_bypass_config;
        let s3_reader_impl =
            S3ReadBypassReader::new(read_bypass_config.read_bypass_max_in_flight_s3_bytes);

        let agent = if self.read_bypass_context.cache_enabled {
            info!("Read ahead caching is enabled");
            let readahead_cache_initial_window_size =
                read_bypass_config.readahead_init_window_size_bytes;
            let readahead_cache_max_window_size =
                read_bypass_config.readahead_max_window_size_bytes;
            let readahead_cache = Arc::new(FileReadAheadCache::new(
                readahead_cache_max_window_size as u64,
                readahead_cache_initial_window_size as u64,
                Arc::new(s3_reader_impl),
                read_bypass_config,
            ));
            readahead_cache.set_self_weak(Arc::downgrade(&readahead_cache));

            // Start background eviction task
            readahead_cache.clone().start_eviction_task(
                read_bypass_config.readahead_cache_eviction_interval_ms,
                self.shutdown.cancellation_token.clone(),
            );

            let s3_reader: Arc<dyn S3Reader> = Arc::new(CachedS3Reader { readahead_cache });
            ReadBypassAgent::new(self.read_bypass_context.clone(), s3_reader)
        } else {
            info!("Read ahead caching is disabled, will read through S3 directly");
            ReadBypassAgent::new(
                self.read_bypass_context.clone(),
                Arc::new(DirectS3Reader {
                    s3_data_reader: Box::new(s3_reader_impl),
                }),
            )
        };
        tokio::spawn(ReadBypassAgent::run(
            agent,
            rba_message_receiver,
            from_conn_sender,
            self.shutdown.clone(),
        ));

        // Create the NfsServerReader with the ReadBypassServerDispatcher
        Box::new(NfsServerReader {
            parser: NfsRpcParser,
            dispatcher: Box::new(server_dispatcher),
            domain_name: READ_BYPASS_DOMAIN_NAME,
        })
    }

    fn build_client_reader(
        &self,
        partition_senders: Arc<Mutex<Vec<mpsc::Sender<RpcBatch>>>>,
    ) -> Arc<Mutex<dyn ClientSocketReader>> {
        // Create the ReadBypassClientDispatcher
        let client_dispatcher = ReadBypassClientDispatcher::new(
            RpcClientDispatcher::new(partition_senders),
            self.read_bypass_context.clone(),
        );

        // Create the NfsClientReader with the ReadBypassClientDispatcher
        Arc::new(Mutex::new(NfsClientReader {
            parser: NfsRpcParser,
            dispatcher: Box::new(client_dispatcher),
            domain_name: READ_BYPASS_DOMAIN_NAME,
        }))
    }
}

impl<S: ProxyStream> ReadBypassDomainBuilder<S> {
    pub async fn new(
        proxy_config: ProxyConfig,
        channel_init_config: ChannelInitConfig,
        shutdown: ShutdownHandle,
        s3_client: S3Client,
    ) -> Self {
        let server_cache_enabled = channel_init_config
            .read_bypass_config
            .readahead_cache_enabled;
        let local_cache_enabled = proxy_config
            .nested_config
            .read_bypass_config
            .readahead_cache_enabled;
        let has_memory = has_sufficient_memory_for_readahead_cache();

        let cache_enabled = server_cache_enabled && local_cache_enabled && has_memory;

        if !has_memory && server_cache_enabled && local_cache_enabled {
            info!(
                "Readahead cache disabled due to insufficient system memory (requires >= {} GiB)",
                crate::utils::MIN_MEMORY_FOR_READAHEAD_GIB
            );
        }

        info!(
            "Readahead cache: server_cache_enabled={}, local_cache_enabled={}, has_memory={}, cache_enabled={}",
            server_cache_enabled, local_cache_enabled, has_memory, cache_enabled
        );

        let read_bypass_context = Arc::new(ReadBypassContext::new(
            &proxy_config,
            channel_init_config.read_bypass_config.bucket_name.clone(),
            channel_init_config.read_bypass_config.prefix.clone(),
            s3_client,
            cache_enabled,
        ));

        Self {
            read_bypass_context,
            shutdown,
            phantom: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpStream;
    use tokio_util::sync::CancellationToken;

    #[tokio::test]
    async fn test_read_bypass_builder() {
        let config = ProxyConfig::default();
        let (shutdown_handle, _waiter) = ShutdownHandle::new(CancellationToken::new());
        let channel_config = ChannelInitConfig::default();
        let s3_client = S3Client::default().await;

        // Capture the inputs to the cache_enabled formula before the configs are
        // moved into the builder.
        let server_cache_enabled = channel_config.read_bypass_config.readahead_cache_enabled;
        let local_cache_enabled = config
            .nested_config
            .read_bypass_config
            .readahead_cache_enabled;

        let builder = ReadBypassDomainBuilder::<TcpStream>::new(
            config,
            channel_config,
            shutdown_handle,
            s3_client,
        )
        .await;

        // cache_enabled requires the server config, the local config, AND enough
        // system memory (>= 30 GiB) to all be true. Mirror that here so the test
        // is correct regardless of the build host's RAM.
        let expected_cache_enabled = server_cache_enabled
            && local_cache_enabled
            && crate::utils::has_sufficient_memory_for_readahead_cache();
        assert_eq!(
            builder.read_bypass_context.cache_enabled,
            expected_cache_enabled
        );

        let (tx, _rx) = mpsc::channel(10);

        let reader = builder.build_server_reader(tx);
        assert_eq!(reader.get_domain(), READ_BYPASS_DOMAIN_NAME);

        let partition_senders = Arc::new(Mutex::new(Vec::<mpsc::Sender<RpcBatch>>::new()));
        let reader = builder.build_client_reader(partition_senders);

        let reader_guard = reader.try_lock();
        assert!(reader_guard.is_ok());
        assert_eq!(reader_guard.unwrap().get_domain(), READ_BYPASS_DOMAIN_NAME);
    }

    async fn build_with_cache_settings(
        server_enabled: bool,
        local_enabled: bool,
    ) -> ReadBypassDomainBuilder<TcpStream> {
        let mut config = ProxyConfig::default();
        config
            .nested_config
            .read_bypass_config
            .readahead_cache_enabled = local_enabled;

        let mut channel_config = ChannelInitConfig::default();
        channel_config.read_bypass_config.readahead_cache_enabled = server_enabled;

        let (shutdown_handle, _waiter) = ShutdownHandle::new(CancellationToken::new());
        let s3_client = S3Client::default().await;

        ReadBypassDomainBuilder::new(config, channel_config, shutdown_handle, s3_client).await
    }

    #[tokio::test]
    async fn test_readahead_cache_both_enabled() {
        let builder = build_with_cache_settings(true, true).await;
        let has_memory = crate::utils::has_sufficient_memory_for_readahead_cache();
        assert_eq!(builder.read_bypass_context.cache_enabled, has_memory);
    }

    #[tokio::test]
    async fn test_readahead_cache_server_disabled() {
        let builder = build_with_cache_settings(false, true).await;
        assert!(!builder.read_bypass_context.cache_enabled);
    }

    #[tokio::test]
    async fn test_readahead_cache_local_disabled() {
        let builder = build_with_cache_settings(true, false).await;
        assert!(!builder.read_bypass_context.cache_enabled);
    }

    #[tokio::test]
    async fn test_readahead_cache_both_disabled() {
        let builder = build_with_cache_settings(false, false).await;
        assert!(!builder.read_bypass_context.cache_enabled);
    }
}
