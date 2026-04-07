//! NFS Sniffer Builder constructs infrastructure for Proxy  to perform only NFS Sniffing functionality
//!

#![allow(unused)]

use crate::{
    connections::ProxyStream,
    domain::{ClientSocketReader, DomainBuilder, ServerSocketReader},
    nfs::{
        nfs_reader::{NfsClientReader, NfsRpcParser, NfsServerReader},
        nfs_sniffer_dispatchers::{NfsSnifferClientDispatcher, NfsSnifferServerDispatcher},
    },
    proxy_task::ConnectionMessage,
    rpc::{rpc::RpcBatch, rpc_domain::RpcClientDispatcher},
};
use std::{marker::PhantomData, sync::Arc};
use tokio::sync::{mpsc, Mutex};

const NFS_DOMAIN_NAME: &'static str = "NFS";

pub struct NfsSnifferBuilder<S> {
    phantom: PhantomData<S>,
}

impl<S: ProxyStream> DomainBuilder<S> for NfsSnifferBuilder<S> {
    fn build_server_reader(
        &self,
        conn_sender: mpsc::Sender<ConnectionMessage>,
    ) -> Box<dyn ServerSocketReader<S>> {
        Box::new(NfsServerReader {
            parser: NfsRpcParser,
            dispatcher: Box::new(NfsSnifferServerDispatcher::new(conn_sender)),
            domain_name: NFS_DOMAIN_NAME,
        })
    }

    fn build_client_reader(
        &self,
        partition_senders: Arc<Mutex<Vec<mpsc::Sender<RpcBatch>>>>,
    ) -> Arc<Mutex<dyn ClientSocketReader>> {
        Arc::new(Mutex::new(NfsClientReader {
            parser: NfsRpcParser,
            dispatcher: Box::new(NfsSnifferClientDispatcher::new(RpcClientDispatcher::new(
                partition_senders,
            ))),
            domain_name: NFS_DOMAIN_NAME,
        }))
    }
}

impl<S: ProxyStream> NfsSnifferBuilder<S> {
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpStream;

    #[test]
    fn test_nfs_builder() {
        let builder = NfsSnifferBuilder::<TcpStream>::new();
        let (tx, _rx) = mpsc::channel(10);

        let reader = builder.build_server_reader(tx);
        assert_eq!(reader.get_domain(), NFS_DOMAIN_NAME);

        let partition_senders = Arc::new(Mutex::new(Vec::<mpsc::Sender<RpcBatch>>::new()));
        let reader = builder.build_client_reader(partition_senders);

        let reader_guard = reader.try_lock();
        assert!(reader_guard.is_ok());
        assert_eq!(reader_guard.unwrap().get_domain(), NFS_DOMAIN_NAME);
    }
}
