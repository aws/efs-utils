//! ReadBypassServerDispatcher is a component responsible for dispatching messages received from  NFS Server
//! in a context of ReadBypass domain.
//!
//! Besides actual dispatching messages to NFS Client connection, it perform processing specific to ReadBypass domain, such that:
//!   - dispatching READBYPASS messages to ReadBypassAgent if they can be bypassed
//!   - converting non-bypassable READBYPASS operations to regulart READs
//!

#![allow(unused)]

use std::{error::Error, sync::Arc};

use async_trait::async_trait;
use log::{debug, trace, warn};
use tokio::sync::mpsc::{self, error::SendError};

use crate::{
    domain::Dispatcher,
    nfs::{
        nfs4_1_xdr::{
            nfs_opnum4, nfs_resop4, AWSFILE_READ_BYPASS4res, AWSFILE_READ_BYPASS4resok,
            COMPOUND4res, READ4res,
        },
        nfs_compound::{RefNfsCompound, RefNfsCompoundInfo},
        nfs_rpc_envelope::{NfsRpcEnvelope, NfsRpcInfo},
    },
    proxy_task::ConnectionMessage,
    rpc::rpc_envelope::{EnvelopeBatch, RpcMessageParams},
    rpc::{rpc::RpcBatch, rpc_error::RpcParseError},
    util::read_bypass_context::ReadBypassContext,
};

#[derive(Clone, Debug, thiserror::Error)]
pub enum ReadBypassServerDispatcherError {
    #[error("Dispatching to NFSClient failed")]
    DispatchingFailure,
    #[error("Unexpected READ_BYPASS response from server")]
    UnexpectedReadBypassResponse,
    #[error("Incorrect NFS compound")]
    IncorrectCompound,
    #[error("Dispatching to ReadBypassAgent failed")]
    ReadBypassAgentDispatchingFailure,
    #[error("Failure during converting READ_BYPASS operations into READ")]
    OperationConversionFailure,
}

#[derive(Clone)]
pub struct ReadBypassServerDispatcher {
    pub nfs_client_sender: mpsc::Sender<ConnectionMessage>,
    // Sender for sending messages to ReadBypass Agent
    pub rba_sender: mpsc::Sender<NfsRpcInfo>,
    pub read_bypass_context: Arc<ReadBypassContext>,
}

#[async_trait]
impl Dispatcher<NfsRpcInfo, ReadBypassServerDispatcherError> for ReadBypassServerDispatcher {
    async fn dispatch(
        &mut self,
        message: NfsRpcInfo,
    ) -> Result<(), ReadBypassServerDispatcherError> {
        // Note that at this level we should not check whether ReadBypass is enabled:
        // if we received READBYPASS from server - we have to process it.
        match self.preprocess_batch(message).await {
            Ok(batch) => {
                let rpc_batch: RpcBatch = batch.into();
                if rpc_batch.rpcs.is_empty() {
                    return Ok(());
                }
                // If there are any non-bypassable messages left in the batch - send them directly to the NfsClient
                let res = self
                    .nfs_client_sender
                    .send(ConnectionMessage::Response(rpc_batch))
                    .await;
                match res {
                    Ok(_) => Ok(()),
                    Err(e) => {
                        warn!("Error while sending message to NFS Client: {:?}", e);
                        Err(ReadBypassServerDispatcherError::DispatchingFailure)
                    }
                }
            }
            Err(e) => return Err(e),
        }
    }

    async fn handle_parse_error(
        &mut self,
        parse_error: RpcParseError,
    ) -> Result<(), ReadBypassServerDispatcherError> {
        parse_error.log_parse_error("ReadBypassServer");
        // ReadBypass server dispatcher just sends the raw RpcBatch like normal dispatch
        // This is simpler and more efficient than creating passthrough envelopes
        // only to convert back to RpcBatch in dispatch()
        let rpc_batch = parse_error.into_rpc_batch();
        let res = self
            .nfs_client_sender
            .send(ConnectionMessage::Response(rpc_batch))
            .await;
        match res {
            Ok(_) => Ok(()),
            Err(e) => {
                warn!("Error while sending message to NFS Client: {:?}", e);
                Err(ReadBypassServerDispatcherError::DispatchingFailure)
            }
        }
    }
}

enum CompoundResponsePreprocessStatus {
    BypassNotDetected,
    BypassAccepted(AWSFILE_READ_BYPASS4resok),
    BypassRejected,
}

impl ReadBypassServerDispatcher {
    pub fn new(
        nfs_client_sender: mpsc::Sender<ConnectionMessage>,
        rba_sender: mpsc::Sender<NfsRpcInfo>,
        read_bypass_context: Arc<ReadBypassContext>,
    ) -> Self {
        Self {
            nfs_client_sender,
            rba_sender,
            read_bypass_context,
        }
    }

    // Batch coming from the socket can contain multiple NFS compounds, each compound might need to be handled differently.
    // `preprocess_batch` performs proper in-place modification for READ_BYPASS operations
    // and sends compounds which contain bypassable reads to ReadBypassAgent.
    // It returns batch wih compounds which can be sent to NFSClient
    async fn preprocess_batch(
        &mut self,
        mut message: NfsRpcInfo,
    ) -> Result<NfsRpcInfo, ReadBypassServerDispatcherError> {
        // Batch coming from the socket can contain multiple NFS messages, we want to process them one-by-one separately,
        // since not all of them might need read-bypass-specific handling

        for i in (0..message.envelopes.len()).rev() {
            match self.preprocess_envelope(&mut message.envelopes[i]).await {
                Ok(res) => {
                    match res {
                        CompoundResponsePreprocessStatus::BypassAccepted(_) => {
                            // Compound was sent to ReadBypassAgent, we can remove it from the batch
                            message.envelopes.remove(i);
                        }
                        _ => {
                            // In all the other cases we need to keep compound in the batch and send it to NfsClient
                        }
                    }
                }
                Err(e) => {
                    warn!("Error while preprocessing compound: {:?}", e);
                    return Err(e);
                }
            }
        }
        Ok(message)
    }

    fn get_compound_read_bypass_status(
        nfs_res_compound: &mut RefNfsCompoundInfo<COMPOUND4res>,
    ) -> Result<CompoundResponsePreprocessStatus, ReadBypassServerDispatcherError> {
        let mut compound_has_readbypass = false;
        for i in 0..nfs_res_compound.op_vec.len() {
            if nfs_res_compound.op_vec[i] != nfs_opnum4::OP_AWSFILE_READ_BYPASS {
                continue;
            }
            compound_has_readbypass = true;
            let res = &nfs_res_compound.compound.resarray[i];
            if let nfs_resop4::OP_AWSFILE_READ_BYPASS(read_bypass_res) = res {
                match read_bypass_res {
                    // Read operation can be bypassed
                    AWSFILE_READ_BYPASS4res::NFS4ERR_AWSFILE_BYPASS(bypass_info) => {
                        return Ok(CompoundResponsePreprocessStatus::BypassAccepted(
                            bypass_info.clone(),
                        ));
                    }
                    // Payload is provided by EFS server, do nothing at this moment
                    AWSFILE_READ_BYPASS4res::NFS4_OK(_) => {}
                    AWSFILE_READ_BYPASS4res::default => {
                        warn!("Unexpected READ_BYPASS response: AWSFILE_READ_BYPASS4res::default");
                        return Err(ReadBypassServerDispatcherError::UnexpectedReadBypassResponse);
                    }
                }
            } else {
                warn!(
                    "Incorrectly parsed compound: Unexpected READ_BYPASS response: {:?}",
                    res
                );
                return Err(ReadBypassServerDispatcherError::IncorrectCompound);
            }
        }
        if (compound_has_readbypass) {
            // If compound has READ_BYPASS operations, but none of it was accepted,
            // it means all of the READ_BYPASS operations in compound were rejected
            return Ok(CompoundResponsePreprocessStatus::BypassRejected);
        }
        Ok(CompoundResponsePreprocessStatus::BypassNotDetected)
    }

    // Handle a single compound (wrapped into RPC Envelope).
    // Depending on what it contains, it is either dispatched to RBA, updated to have READs instead of
    // READ_BYPASS operations, or dispatched to NfsClient as is.
    async fn preprocess_envelope(
        &mut self,
        envelope: &mut NfsRpcEnvelope,
    ) -> Result<CompoundResponsePreprocessStatus, ReadBypassServerDispatcherError> {
        if let RefNfsCompound::Compound4res(nfs_res_compound) = &mut envelope.body {
            match Self::get_compound_read_bypass_status(nfs_res_compound) {
                Ok(value) => {
                    match value {
                        CompoundResponsePreprocessStatus::BypassAccepted(ref bypass_info) => {
                            let xid = match &envelope.header.params {
                                RpcMessageParams::ReplyParams(p) => p.xid,
                                RpcMessageParams::CallParams(p) => p.xid,
                                RpcMessageParams::RejectedReplyParams(p) => p.xid,
                            };
                            debug!(
                                "Detected bypassable READ xid={} s3_key={} offset={} count={}, dispatching to ReadBypassAgent",
                                xid,
                                String::from_utf8_lossy(&bypass_info.data_locator.s3_key),
                                bypass_info.data_locator.offset,
                                bypass_info.data_locator.count
                            );
                            // Here we want to clone the message, to avoid storing pointers to original BytesMut connection socket buffer,
                            // which can cause fragmentation. unwanted memory consumption growth etc
                            let batch_to_send = NfsRpcInfo {
                                envelopes: vec![envelope.clone()],
                            };
                            if let Err(e) = self.rba_sender.send(batch_to_send).await {
                                warn!("Error during dispatching message to ReadBypassAgent: {e}");
                                return Err(ReadBypassServerDispatcherError::ReadBypassAgentDispatchingFailure);
                            }
                        }
                        CompoundResponsePreprocessStatus::BypassRejected => {
                            debug!(
                                "Detected NFS response with rejected READBYPASS, converting response to READ..."
                            );
                            if let Err(e) = nfs_res_compound
                                .replace_all_target_ops_with_new_ops::<AWSFILE_READ_BYPASS4res, READ4res>()
                            {
                                warn!("Error during conversion of READ_BYPASS response to READ response: {e}");
                                return Err(ReadBypassServerDispatcherError::OperationConversionFailure);
                            }
                        }
                        CompoundResponsePreprocessStatus::BypassNotDetected => {
                            trace!("READ_BYPASS is not detected, keeping compound as is...");
                        }
                    }
                    return Ok(value);
                }
                Err(value) => return Err(value),
            }
        }
        Ok(CompoundResponsePreprocessStatus::BypassNotDetected)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::nfs::nfs4_1_xdr::*;
    use crate::nfs::nfs_test_utils::{
        create_nfs_rpc_envelope_batch_from_compound, create_nfs_rpc_envelope_from_compound,
        create_test_session_id, get_sample_op_getattr_res, get_sample_op_read_bypass_resok,
        get_sample_op_sequence_res,
    };
    use crate::rpc::rpc_envelope::{EnvelopeBatch, RpcMessageType};
    use bytes::Bytes;
    use tokio::sync::mpsc;
    use tokio::sync::mpsc::Receiver;

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Auxiliary test functions

    fn create_non_readbypass_test_envelope() -> NfsRpcEnvelope {
        let sequence_op_res = get_sample_op_sequence_res();
        let getattr_resok = GETATTR4resok {
            obj_attributes: fattr4 {
                attrmask: bitmap4(vec![4, 5, 6]),
                attr_vals: attrlist4(Vec::new()),
            },
        };
        let getattr_op_res = nfs_resop4::OP_GETATTR(GETATTR4res::NFS4_OK(getattr_resok));

        let compound_res = COMPOUND4res {
            status: nfsstat4::NFS4_OK,
            tag: utf8string(vec![]),
            resarray: vec![sequence_op_res, getattr_op_res],
        };

        return create_nfs_rpc_envelope_from_compound(RpcMessageType::Reply, compound_res);
    }

    fn create_readbypass_envelope(bypass_res: AWSFILE_READ_BYPASS4res) -> NfsRpcEnvelope {
        let sequence_op_res = get_sample_op_sequence_res();
        let bypass_op_res = nfs_resop4::OP_AWSFILE_READ_BYPASS(bypass_res);

        let compound_res = COMPOUND4res {
            status: nfsstat4::NFS4_OK,
            tag: utf8string(vec![]),
            resarray: vec![sequence_op_res, bypass_op_res],
        };

        create_nfs_rpc_envelope_from_compound(RpcMessageType::Reply, compound_res)
    }

    fn compound_contains_readbypass(compound: &RefNfsCompound) -> bool {
        if let RefNfsCompound::Compound4res(nfs_res_compound) = compound {
            for i in 0..nfs_res_compound.op_vec.len() {
                if nfs_res_compound.op_vec[i] == nfs_opnum4::OP_AWSFILE_READ_BYPASS {
                    if let Some(nfs_resop4::OP_AWSFILE_READ_BYPASS(_)) =
                        nfs_res_compound.compound.resarray.get(i)
                    {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    fn compound_contains_read(compound: &RefNfsCompound) -> bool {
        if let RefNfsCompound::Compound4res(nfs_res_compound) = compound {
            for i in 0..nfs_res_compound.op_vec.len() {
                if nfs_res_compound.op_vec[i] == nfs_opnum4::OP_READ {
                    if let Some(nfs_resop4::OP_READ(_)) = nfs_res_compound.compound.resarray.get(i)
                    {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    async fn create_dispatcher() -> (
        ReadBypassServerDispatcher,
        Receiver<ConnectionMessage>,
        Receiver<EnvelopeBatch<NfsRpcEnvelope>>,
    ) {
        let (client_tx, mut client_rx) = mpsc::channel::<ConnectionMessage>(10);
        let (rba_tx, mut rba_rx) = mpsc::channel::<NfsRpcInfo>(10);
        let context = Arc::new(ReadBypassContext::default().await);
        let dispatcher = ReadBypassServerDispatcher::new(client_tx, rba_tx, context);
        (dispatcher, client_rx, rba_rx)
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Test cases

    #[tokio::test]
    async fn test_dispatch_passes_through_message_from_server() {
        let (mut dispatcher, mut client_rx, mut rba_rx) = create_dispatcher().await;
        let message = create_non_readbypass_test_envelope();
        let message_batch = NfsRpcInfo {
            envelopes: vec![message.clone(), message],
        };

        let result = dispatcher.dispatch(message_batch).await;

        assert!(result.is_ok(), "Dispatch should succeed");
        let ConnectionMessage::Response(batch) = client_rx
            .try_recv()
            .expect("Expected ConnectionMessage::Response");
        assert_eq!(batch.rpcs.len(), 2, "Batch should have two messages");
        assert!(
            rba_rx.try_recv().is_err(),
            "No message should be sent to ReadBypassAgent"
        );
    }

    #[tokio::test]
    async fn test_clone() {
        let (mut dispatcher, _, _) = create_dispatcher().await;

        let cloned = dispatcher.clone();

        assert!(
            Arc::ptr_eq(&dispatcher.read_bypass_context, &cloned.read_bypass_context),
            "Cloned dispatcher should share the same context"
        );
    }

    #[tokio::test]
    async fn test_preprocess_envelope_bypass_not_detected() {
        let (mut dispatcher, _, _) = create_dispatcher().await;

        let envelope = &mut create_non_readbypass_test_envelope();
        let result = dispatcher.preprocess_envelope(envelope).await;

        assert!(result.is_ok());
        assert!(matches!(
            result.unwrap(),
            CompoundResponsePreprocessStatus::BypassNotDetected
        ));
    }

    #[tokio::test]
    async fn test_preprocess_envelope_bypass_rejected() {
        let (mut dispatcher, _, _) = create_dispatcher().await;

        let bypass_res = AWSFILE_READ_BYPASS4res::NFS4_OK(READ4resok {
            eof: false,
            data: DataPayload::Data(Bytes::from_static(b"test read data")),
        });
        let envelope = &mut create_readbypass_envelope(bypass_res);
        assert!(compound_contains_readbypass(&envelope.body));
        assert!(!compound_contains_read(&envelope.body));

        let result = dispatcher.preprocess_envelope(envelope).await;

        assert!(result.is_ok());
        assert!(matches!(
            result.unwrap(),
            CompoundResponsePreprocessStatus::BypassRejected
        ));
        // check that ReadBypass was converted to Read
        assert!(!compound_contains_readbypass(&envelope.body));
        assert!(compound_contains_read(&envelope.body));
    }

    #[tokio::test]
    async fn test_preprocess_envelope_bypass_accepted() {
        let (mut dispatcher, mut client_rx, mut rba_rx) = create_dispatcher().await;
        let bypass_res = get_sample_op_read_bypass_resok(0, 128, 256);
        let envelope = &mut create_readbypass_envelope(bypass_res);

        assert!(compound_contains_readbypass(&envelope.body));

        let result = dispatcher.preprocess_envelope(envelope).await;

        assert!(result.is_ok());
        assert!(
            compound_contains_readbypass(&envelope.body),
            "Compound should not be modified if ReadBypass is accepted"
        );
        assert!(matches!(
            result.unwrap(),
            CompoundResponsePreprocessStatus::BypassAccepted(_)
        ));
        // Check that ReadBypassAgent has received the message
        let res = rba_rx.try_recv();
        assert!(res.is_ok());
        let rba_message = res.unwrap();
        assert_eq!(rba_message.envelopes.len(), 1);
        let rba_envelope = &rba_message.envelopes[0];
        assert!(compound_contains_readbypass(&rba_envelope.body));
    }

    #[tokio::test]
    async fn test_single_nfs_rbp_data_response() {
        let (mut dispatcher, mut client_rx, mut rba_rx) = create_dispatcher().await;

        let bypass_res = AWSFILE_READ_BYPASS4res::NFS4_OK(READ4resok {
            eof: false,
            data: DataPayload::Data(Bytes::from_static(b"test read data")),
        });
        let mut envelope = create_readbypass_envelope(bypass_res);
        let message_batch = NfsRpcInfo {
            envelopes: vec![envelope],
        };

        let result = dispatcher.dispatch(message_batch).await;
        assert!(result.is_ok());

        let ConnectionMessage::Response(batch) = client_rx.try_recv().unwrap();
        assert_eq!(batch.rpcs.len(), 1, "NFSClient should receive one message");
        assert!(
            rba_rx.try_recv().is_err(),
            "No messages should be sent to ReadBypassAgent"
        );
    }

    #[tokio::test]
    async fn test_single_nfs_rbp_bypass_success() {
        let (mut dispatcher, mut client_rx, mut rba_rx) = create_dispatcher().await;

        let bypass_res = get_sample_op_read_bypass_resok(0, 128, 256);
        let envelope = create_readbypass_envelope(bypass_res);
        let message_batch = NfsRpcInfo {
            envelopes: vec![envelope],
        };

        let result = dispatcher.dispatch(message_batch).await;
        assert!(result.is_ok());

        // Should be empty because message was sent to RBA
        assert!(client_rx.try_recv().is_err());

        // Should receive message in RBA
        let rba_message = rba_rx.try_recv().unwrap();
        assert_eq!(rba_message.envelopes.len(), 1);
        let res_compound = &rba_message.envelopes[0].body;
        assert!(compound_contains_readbypass(res_compound));
        assert!(!compound_contains_read(res_compound));
    }

    #[tokio::test]
    async fn test_multiple_nfs_compounds_mixed() {
        let (mut dispatcher, mut client_rx, mut rba_rx) = create_dispatcher().await;

        let bypass_res = get_sample_op_read_bypass_resok(0, 128, 256);
        let envelope_bypass_accepted = create_readbypass_envelope(bypass_res);
        let bypass_res = AWSFILE_READ_BYPASS4res::NFS4_OK(READ4resok {
            eof: false,
            data: DataPayload::Data(Bytes::from_static(b"test read data")),
        });
        let envelope_bypass_rejected = create_readbypass_envelope(bypass_res);
        let envelope_no_bypass = create_non_readbypass_test_envelope();

        let message_batch = NfsRpcInfo {
            envelopes: vec![
                envelope_bypass_accepted,
                envelope_bypass_rejected,
                envelope_no_bypass,
            ],
        };

        let result = dispatcher.dispatch(message_batch).await;
        assert!(result.is_ok());

        // Should have 2 messages dispatched to client
        let ConnectionMessage::Response(batch) = client_rx.try_recv().unwrap();
        assert_eq!(batch.rpcs.len(), 2);

        // Should receive 1 message in RBA (bypass success)
        let rba_message = rba_rx.try_recv().unwrap();
        assert_eq!(rba_message.envelopes.len(), 1);
    }

    #[tokio::test]
    async fn test_mismatch_opvec_resarray() {
        let (mut dispatcher, _, _) = create_dispatcher().await;

        // Create compound with READBYPASS in op_vec but GETATTR in resarray
        let sequence_op_res = get_sample_op_sequence_res();
        let getattr_op_res = get_sample_op_getattr_res();
        let compound_res = COMPOUND4res {
            status: nfsstat4::NFS4_OK,
            tag: utf8string(vec![]),
            resarray: vec![sequence_op_res, getattr_op_res], // GETATTR instead of READBYPASS
        };
        let envelope = create_nfs_rpc_envelope_from_compound(RpcMessageType::Reply, compound_res);
        let message_batch = NfsRpcInfo {
            envelopes: vec![envelope],
        };

        let result = dispatcher.dispatch(message_batch).await;
        assert!(result.is_err()); // Should fail due to mismatch
    }
}
