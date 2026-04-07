//! # NFS Reader
//!

#![allow(unused)]

use std::{
    error::Error,
    fmt::Debug,
    sync::{atomic::AtomicU64, Arc},
};

use async_trait::async_trait;
use log::{debug, error};
use tokio::{
    io::{AsyncRead, ReadHalf},
    net::tcp::OwnedReadHalf,
    sync::mpsc::error::SendError,
};

use crate::{
    connections::ProxyStream,
    domain::{ClientSocketReader, Dispatcher, Parser, ServerSocketReader},
    nfs::nfs_rpc_envelope::{NfsRpcEnvelope, NfsRpcEnvelopeBatch},
    proxy_task::ConnectionMessage,
    rpc::{
        rpc::{BufferedRpcReader, RpcBatch, RpcBufferedReaderError},
        rpc_domain::{ClientReaderErrorHandler, ServerReaderErrorHandler},
        rpc_envelope::EnvelopeBatch,
        rpc_error::RpcParseError,
    },
    shutdown::{ShutdownHandle, ShutdownReason},
};

#[derive(Clone)]
pub struct NfsRpcParser;

impl Parser<NfsRpcEnvelopeBatch, RpcParseError> for NfsRpcParser {
    fn parse(&self, rpc_batch: RpcBatch) -> Result<NfsRpcEnvelopeBatch, RpcParseError> {
        NfsRpcEnvelopeBatch::try_from(rpc_batch)
    }
}

#[async_trait]
pub trait NfsReader<DispatcherError: Debug> {
    fn get_parser(&self) -> &NfsRpcParser;
    fn get_dispatcher(
        &mut self,
    ) -> &mut Box<dyn Dispatcher<EnvelopeBatch<NfsRpcEnvelope>, DispatcherError> + Send + Sync>;
    fn get_shutdown_reason(e: &RpcBufferedReaderError) -> ShutdownReason;

    async fn run<R>(
        &mut self,
        read_half: R,
        read_count: Option<Arc<AtomicU64>>,
        shutdown: ShutdownHandle,
    ) where
        R: AsyncRead + Unpin + Send,
    {
        let shutdown_reason: Option<ShutdownReason>;
        let mut reader = BufferedRpcReader::<R>::new(read_half, read_count);
        loop {
            let rpc_batch = match reader.read().await {
                Ok(batch) => batch,
                Err(e) => {
                    drop(reader);
                    shutdown_reason = Some(Self::get_shutdown_reason(&e));
                    break;
                }
            };

            match self.get_parser().parse(rpc_batch) {
                Ok(batch) => {
                    if let Err(e) = self.get_dispatcher().dispatch(batch).await {
                        error!("Error sending message batch to dispatcher {:?}", e);
                        shutdown_reason = Some(ShutdownReason::UnexpectedError);
                        break;
                    }
                }
                Err(parse_error) => {
                    if let Err(e) = self.get_dispatcher().handle_parse_error(parse_error).await {
                        error!("Error sending message batch to dispatcher {:?}", e);
                        shutdown_reason = Some(ShutdownReason::UnexpectedError);
                        break;
                    }
                }
            };
        }
        shutdown.exit(shutdown_reason).await;
    }
}

pub struct NfsClientReader<E> {
    pub parser: NfsRpcParser,
    pub dispatcher: Box<dyn Dispatcher<EnvelopeBatch<NfsRpcEnvelope>, E> + Send + Sync>,

    // NFS readers can be used for different domains, so we want to preserve domain name inside
    pub domain_name: &'static str,
}

impl<E: Debug> NfsReader<E> for NfsClientReader<E> {
    fn get_parser(&self) -> &NfsRpcParser {
        &self.parser
    }

    fn get_dispatcher(
        &mut self,
    ) -> &mut Box<dyn Dispatcher<EnvelopeBatch<NfsRpcEnvelope>, E> + Send + Sync> {
        &mut self.dispatcher
    }

    fn get_shutdown_reason(e: &RpcBufferedReaderError) -> ShutdownReason {
        ClientReaderErrorHandler::get_shutdown_reason(e)
    }
}

#[async_trait]
impl ClientSocketReader for NfsClientReader<SendError<RpcBatch>> {
    async fn run(
        &mut self,
        read_half: OwnedReadHalf,
        read_count: Arc<AtomicU64>,
        shutdown: ShutdownHandle,
    ) {
        NfsReader::run(self, read_half, Some(read_count), shutdown).await
    }

    #[cfg(test)]
    fn get_domain(&self) -> &'static str {
        self.domain_name
    }
}

#[derive(Clone)]
pub struct NfsServerReader<E> {
    pub parser: NfsRpcParser,
    pub dispatcher: Box<dyn Dispatcher<EnvelopeBatch<NfsRpcEnvelope>, E> + Send + Sync>,

    // NFS readers can be used for different domains, so we want to preserve domain name inside
    pub domain_name: &'static str,
}

impl<E: Debug> NfsReader<E> for NfsServerReader<E> {
    fn get_parser(&self) -> &NfsRpcParser {
        &self.parser
    }

    fn get_dispatcher(
        &mut self,
    ) -> &mut Box<dyn Dispatcher<EnvelopeBatch<NfsRpcEnvelope>, E> + Send + Sync> {
        &mut self.dispatcher
    }

    fn get_shutdown_reason(e: &RpcBufferedReaderError) -> ShutdownReason {
        ServerReaderErrorHandler::get_shutdown_reason(e)
    }
}

#[async_trait]
impl<E: Debug + Clone, S: ProxyStream> ServerSocketReader<S> for NfsServerReader<E> {
    async fn run(&mut self, read_half: ReadHalf<S>, shutdown: ShutdownHandle) {
        NfsReader::run(self, read_half, None, shutdown).await
    }

    #[cfg(test)]
    fn get_domain(&self) -> &'static str {
        self.domain_name
    }
}
