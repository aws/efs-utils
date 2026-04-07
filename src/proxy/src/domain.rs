//! # Traits for Domain representation in Proxy data path
//!
//! EFS Proxy is structured such that its data path can be constructed for supporting specific set
//! of domains depending on mount parameters. For example, in default mode, when Proxy is used for
//! connection multiplexing only, it can be constructed with only RPC domain primitives. When Proxy
//! is used with enabled ReadBypass support, it is constructed with RPC and NFS and domain
//! primitives. In future there could be other modes of operations for proxy requiring additional
//! domains.
//!
//! Basic domain primitives are:
//!  - Parser: for parsing raw data received from the socket into domain representation (RPC batch,
//!    NFS compound structure etc)
//!  - Encoder: for serializing data from domain-specific representation into raw buffer
//!  - Dispatcher: entry point for domain-specific processing, pre-processing domain-specific data
//!    and dispatching for further processing if needed. For example, for RPC domain Dispatchers
//!    just send messages between Readers and Writers, and provide connection multiplexing
//!    functionality.
//!  - Reader: for continuous reading data from sockets, executing Parsers/Dispatchers and error
//!    handling
//!
//! For now the idea is that every domain should implement its own socket readers, and assemble
//! them during Proxy construction. There is too much specific in error handling and domain message
//! formats, so it is not worth prematurely investing into perfect generalization. We'll
//! refactor/generalize it later if required.
//!
#![allow(clippy::doc_lazy_continuation)]
use std::sync::{atomic::AtomicU64, Arc};

use async_trait::async_trait;
use dyn_clone::{clone_trait_object, DynClone};
use tokio::net::tcp::OwnedReadHalf;
use tokio::sync::Mutex;
use tokio::{io::ReadHalf, sync::mpsc};

use crate::{
    connections::ProxyStream, proxy_task::ConnectionMessage, rpc::rpc::RpcBatch,
    rpc::rpc_error::RpcParseError, shutdown::ShutdownHandle,
};

pub trait Parser<DomainType, ErrorType> {
    fn parse(&self, messages: RpcBatch) -> Result<DomainType, ErrorType>;
}

// Dispatcher has to be dyn-clonable, to be dyn compatible.
// We need to be able to clone dispatchers when new connection is created.
#[async_trait]
pub trait Dispatcher<DomainType, ErrorType>: DynClone {
    async fn dispatch(&mut self, message: DomainType) -> Result<(), ErrorType>;
    async fn handle_parse_error(&mut self, parse_error: RpcParseError) -> Result<(), ErrorType>;
}

clone_trait_object!(<DomainType, ErrorType> Dispatcher<DomainType, ErrorType>);

/// ClientSocketReader is used for reading and processing messages from NFS Client sockets.
///
#[async_trait]
pub trait ClientSocketReader: Send + Sync {
    async fn run(
        &mut self,
        read_half: OwnedReadHalf,
        read_count: Arc<AtomicU64>,
        shutdown: ShutdownHandle,
    );

    #[cfg(test)]
    fn get_domain(&self) -> &'static str;
}

/// ServerSocketReader is used for reading and processing messages from NFS Server Connection sockets.
///
#[async_trait]
pub trait ServerSocketReader<S: ProxyStream>: DynClone + Send + Sync {
    async fn run(&mut self, server_read_half: ReadHalf<S>, shutdown: ShutdownHandle);

    #[cfg(test)]
    fn get_domain(&self) -> &'static str;
}
clone_trait_object!(<S> ServerSocketReader<S> where S: ProxyStream + 'static);

// DomainBuilder is used for constructing and initializing all domain-specific entities.
// All the construction / initialization is supposed to happen during:
// 1/ Builder constructor (new)
// 2/ Building Readers (it is the only place where Proxy interacts with Domain-specific components)
//
// Interface between Domain Readers and Proxy Writers is fixed, so we use specific message types here for senders.
//

pub trait DomainBuilder<S: ProxyStream> {
    fn build_server_reader(
        &self,
        conn_sender: mpsc::Sender<ConnectionMessage>,
    ) -> Box<dyn ServerSocketReader<S>>;

    fn build_client_reader(
        &self,
        partition_senders: Arc<Mutex<Vec<mpsc::Sender<RpcBatch>>>>,
    ) -> Arc<Mutex<dyn ClientSocketReader>>;
}
