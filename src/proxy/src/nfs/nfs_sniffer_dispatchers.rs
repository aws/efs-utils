//! # NFS Sniffer Dispatchers
//! Besides passing messages from client to server and vice versa, NFS Sniffer Dispatchers print message information to stdout
//!

use async_trait::async_trait;
use tokio::sync::mpsc::{self, error::SendError};

use crate::{
    domain::Dispatcher,
    nfs::nfs_rpc_envelope::NfsRpcInfo,
    proxy_task::ConnectionMessage,
    rpc::{rpc::RpcBatch, rpc_domain::RpcClientDispatcher, rpc_error::RpcParseError},
};

pub type NfsClientDispatcherError = SendError<RpcBatch>;
pub type NfsServerDispatcherError = SendError<ConnectionMessage>;

#[derive(Clone)]
pub struct NfsSnifferClientDispatcher {
    // Dispatcher for sending RpcBatch messages to Connection Writers
    pub rpc_conn_dispatcher: RpcClientDispatcher,
}

#[async_trait]
impl Dispatcher<NfsRpcInfo, NfsClientDispatcherError> for NfsSnifferClientDispatcher {
    async fn dispatch(&mut self, message: NfsRpcInfo) -> Result<(), NfsClientDispatcherError> {
        // we need to dispatch message to Connection Writers in a form of RpcBatch
        let rpc_batch: RpcBatch = message.into();
        self.rpc_conn_dispatcher.dispatch(rpc_batch).await
    }

    async fn handle_parse_error(
        &mut self,
        parse_error: RpcParseError,
    ) -> Result<(), NfsClientDispatcherError> {
        parse_error.log_parse_error("NfsSnifferClient");
        // Sniffer client dispatcher just sends the raw RpcBatch like normal dispatch
        // It is safe here to pass unparseable messages to the client or server as normal
        // as they will be handled by the client or server dispatcher. Passing through is
        // more preferred compare to crashing the proxy.
        let rpc_batch = parse_error.into_rpc_batch();
        self.rpc_conn_dispatcher.dispatch(rpc_batch).await
    }
}

impl NfsSnifferClientDispatcher {
    pub fn new(rpc_conn_dispatcher: RpcClientDispatcher) -> Self {
        NfsSnifferClientDispatcher {
            rpc_conn_dispatcher,
        }
    }
}

#[derive(Clone)]
pub struct NfsSnifferServerDispatcher {
    pub sender: mpsc::Sender<ConnectionMessage>,
}

#[async_trait]
impl Dispatcher<NfsRpcInfo, NfsServerDispatcherError> for NfsSnifferServerDispatcher {
    async fn dispatch(&mut self, message: NfsRpcInfo) -> Result<(), NfsServerDispatcherError> {

        let rpc_batch: RpcBatch = message.into();

        return self
            .sender
            .send(ConnectionMessage::Response(rpc_batch))
            .await;
    }

    async fn handle_parse_error(
        &mut self,
        parse_error: RpcParseError,
    ) -> Result<(), NfsServerDispatcherError> {
        parse_error.log_parse_error("NfsSnifferServer");
        // Sniffer server dispatcher just sends the raw RpcBatch like normal dispatch
        // It is safe here to pass unparseable messages to the client or server as normal
        // as they will be handled by the client or server dispatcher. Passing through is
        // more preferred compare to crashing the proxy.
        let rpc_batch = parse_error.into_rpc_batch();
        self.sender
            .send(ConnectionMessage::Response(rpc_batch))
            .await
    }
}

impl NfsSnifferServerDispatcher {
    pub fn new(sender: mpsc::Sender<ConnectionMessage>) -> Self {
        NfsSnifferServerDispatcher { sender }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nfs::nfs_rpc_envelope::NfsRpcEnvelopeBatch;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    #[tokio::test]
    async fn test_nfs_client_dispatcher() {
        let (tx1, mut rx1) = mpsc::channel(32);
        let senders = vec![tx1];
        let partition_senders = Arc::new(Mutex::new(senders));
        let mut dispatcher =
            NfsSnifferClientDispatcher::new(RpcClientDispatcher::new(partition_senders.clone()));

        // Verify round-robin behavior
        assert_eq!(dispatcher.rpc_conn_dispatcher.next_conn, 0);
        let batch = NfsRpcEnvelopeBatch {
            envelopes: Vec::new(),
        };
        let res = dispatcher.dispatch(batch).await;
        assert!(res.is_ok(), "Dispatching error is: {:?}", res);
        assert_eq!(dispatcher.rpc_conn_dispatcher.next_conn, 0); // Should wrap around with single sender

        let (tx2, mut rx2) = mpsc::channel(32);
        let mut senders = partition_senders.lock().await;
        senders.push(tx2);
        drop(senders);

        let batch = NfsRpcEnvelopeBatch {
            envelopes: Vec::new(),
        };
        assert!(dispatcher.dispatch(batch).await.is_ok());
        assert_eq!(dispatcher.rpc_conn_dispatcher.next_conn, 1);

        let batch = NfsRpcEnvelopeBatch {
            envelopes: Vec::new(),
        };
        assert!(dispatcher.dispatch(batch).await.is_ok());
        assert_eq!(dispatcher.rpc_conn_dispatcher.next_conn, 0);

        // Verify messages received
        assert!((rx1.recv().await).is_some(), "Expected RpcBatch");
        assert!((rx2.recv().await).is_some(), "Expected RpcBatch");
    }

    #[tokio::test]
    async fn test_nfs_server_dispatcher() {
        let (tx, mut rx) = mpsc::channel(32);
        let mut dispatcher = NfsSnifferServerDispatcher::new(tx);

        // Test dispatching a message
        let batch = NfsRpcEnvelopeBatch {
            envelopes: Vec::new(),
        };
        assert!(dispatcher.dispatch(batch).await.is_ok());

        // Verify message received
        assert!(
            matches!(rx.recv().await, Some(ConnectionMessage::Response(_))),
            "Expected ConnectionMessage::NfsResponse"
        );
    }
}
