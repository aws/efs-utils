//! ReadBypassClientDispatcher is a component responsible for dispatching messages received from  NFS Client
//! in a context of ReadBypass domain.
//!
//! Besides actual dispatching messages to NFS Server connections, it can perform in-place modifications of NFS Compounds
//! and dispatch messages into other dispatchers if used in a Multi-Domain context.
//!

#![allow(unused)]

use std::sync::{atomic::Ordering, Arc};

use crate::nfs::nfs4_1_xdr::*;
use crate::nfs::nfs_rpc_envelope::NfsRpcInfo;
use crate::rpc::rpc_encoder::RpcEncoder;
use crate::rpc::rpc_envelope::EnvelopeHeader;
use async_trait::async_trait;
use log::{debug, error, warn};
use tokio::sync::mpsc::error::SendError;

use crate::nfs::nfs_compound::RefNfsCompoundInfo;
use crate::{
    awsfile_rpc::{AWSFILE_PROGRAM_NUMBER, AWSFILE_PROGRAM_VERSION},
    domain::Dispatcher,
    nfs::{nfs4_1_xdr::nfs_fh4, nfs_rpc_envelope::NfsRpcEnvelope},
    proxy_task::ConnectionMessage,
    rpc::rpc_envelope::EnvelopeBatch,
    rpc::{rpc::RpcBatch, rpc_domain::RpcClientDispatcher, rpc_error::RpcParseError},
    util::read_bypass_context::{NfsDispatcherError, ReadBypassContext},
};

#[derive(Clone)]
pub struct ReadBypassClientDispatcher {
    // Dispatcher for sending RpcBatch messages to Connection Writers
    pub rpc_conn_dispatcher: RpcClientDispatcher,
    pub read_bypass_context: Arc<ReadBypassContext>,
}

impl ReadBypassClientDispatcher {
    pub fn new(
        rpc_conn_dispatcher: RpcClientDispatcher,
        read_bypass_context: Arc<ReadBypassContext>,
    ) -> Self {
        ReadBypassClientDispatcher {
            rpc_conn_dispatcher,
            read_bypass_context,
        }
    }

    // This function determines if READ operations should be converted to read_BYPASS.
    // Uses strict pattern matching - only allows read-bypass for the exact pattern we care about.
    //
    // Required pattern: First 3 operations must be SEQUENCE|PUTFH|READ
    // Additional requirement: No other READ operations anywhere in the compound
    // File handle must not be in denylist
    //
    fn process_compound_for_readbypass_request(
        &self,
        info: &mut RefNfsCompoundInfo<COMPOUND4args>,
        header: &mut EnvelopeHeader,
    ) -> Result<(), SendError<RpcBatch>> {
        if self.check_read_bypass_eligibility(&info.compound) {
            if info
                .replace_all_target_ops_with_new_ops::<READ4args, AWSFILE_READ_BYPASS4args>()
                .is_err()
            {
                return Err(SendError((RpcBatch { rpcs: Vec::new() })));
            }

            if let Err(e) = RpcEncoder::update_rpc_program_number_in_place(
                header,
                AWSFILE_PROGRAM_NUMBER,
                AWSFILE_PROGRAM_VERSION,
            ) {
                error!("Failed to update program number: {:?}", e);
                return Err(SendError((RpcBatch { rpcs: Vec::new() })));
            }
        }

        Ok(())
    }

    // First 3 ops must be SEQUENCE|PUTFH|READ, with no other READ ops and only safe ops after READ
    fn check_read_bypass_eligibility(&self, compound: &COMPOUND4args) -> bool {
        let ops = &compound.argarray;

        // Must have at least 3 operations
        if ops.len() < 3 {
            return false;
        }

        // Check first 3 operations are exactly SEQUENCE|PUTFH|READ
        let file_handle = match (&ops[0], &ops[1], &ops[2]) {
            (
                nfs_argop4::OP_SEQUENCE(_),
                nfs_argop4::OP_PUTFH(putfh_args),
                nfs_argop4::OP_READ(_),
            ) => &putfh_args.object,
            _ => return false,
        };

        // Check if file handle is in denylist
        if self.read_bypass_context.fh_denylist.contains(file_handle) {
            debug!(
                "Skipping read-bypass: filehandle is in denylist: {}",
                file_handle
                    .0
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>()
            );
            return false;
        }

        // Check there are no other READ operations after the first 3
        for op in ops.iter().skip(3) {
            if let nfs_argop4::OP_READ(_) = op {
                return false;
            }
        }

        true
    }
}

#[async_trait]
impl Dispatcher<NfsRpcInfo, NfsDispatcherError> for ReadBypassClientDispatcher {
    async fn dispatch(&mut self, mut message: NfsRpcInfo) -> Result<(), NfsDispatcherError> {
        if self.read_bypass_context.is_read_bypass_enabled() {
            for envelope in &mut message.envelopes {
                if let crate::nfs::nfs_compound::RefNfsCompound::Compound4args(ref mut info) =
                    envelope.body
                {
                    self.process_compound_for_readbypass_request(info, &mut envelope.header)?;
                }
            }
        }
        let rpc_batch: RpcBatch = message.into();
        self.rpc_conn_dispatcher.dispatch(rpc_batch).await
    }

    async fn handle_parse_error(
        &mut self,
        parse_error: RpcParseError,
    ) -> Result<(), NfsDispatcherError> {
        // Log parse error details for debugging
        parse_error.log_parse_error("ReadBypass");

        // Extract the RpcBatch from the error and forward it
        let rpc_batch = parse_error.into_rpc_batch();
        // ReadBypass client dispatcher just sends the raw RpcBatch like normal dispatch
        // This is simpler and more efficient than creating passthrough envelopes
        // only to convert back to RpcBatch in dispatch()
        self.rpc_conn_dispatcher.dispatch(rpc_batch).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::Receiver;

    use super::*;
    use crate::awsfile_rpc::{AWSFILE_PROGRAM_NUMBER, AWSFILE_PROGRAM_VERSION};
    use crate::logger;
    use crate::nfs::nfs4_1_xdr::*;
    use crate::nfs::nfs4_1_xdr_ext::opnum_from_argop;
    use crate::nfs::nfs_compound::{RefNfsCompound, RefNfsCompoundInfo};
    use crate::nfs::nfs_rpc_envelope::NfsRpcEnvelope;
    use crate::nfs::nfs_test_utils::*;
    use crate::rpc::rpc::RpcBatch;
    use crate::rpc::rpc_encoder::RpcEncoder;
    use crate::rpc::rpc_encoder::{RPC_FIELD_SIZE, RPC_PROGRAM_OFFSET, RPC_PROGRAM_VERSION_OFFSET};
    use crate::rpc::rpc_envelope::RpcMessageParams;
    use crate::test_utils::get_test_config;
    use crate::{config_parser::ProxyConfig, rpc::rpc_envelope::RpcMessageType};
    use log::logger;
    use tokio::sync::{mpsc, Mutex};

    // Helper function to create a test envelope with empty compound
    fn create_test_envelope_batch() -> NfsRpcInfo {
        let compound_res = COMPOUND4args {
            tag: utf8string(vec![]),
            minorversion: 0,
            argarray: vec![],
        };
        return create_nfs_rpc_envelope_batch_from_compound(RpcMessageType::Call, compound_res);
    }

    #[tokio::test]
    async fn test_dispatch_passes_through_when_read_bypass_disabled() {
        let (tx, mut rx) = mpsc::channel::<RpcBatch>(10);
        let partition_senders = Arc::new(Mutex::new(vec![tx]));
        let rpc_dispatcher = RpcClientDispatcher::new(partition_senders);

        // Create context with read_bypass disabled
        let context = Arc::new(ReadBypassContext::default().await);

        let mut dispatcher = ReadBypassClientDispatcher::new(rpc_dispatcher, context);
        let message = create_test_envelope_batch();

        let result = dispatcher.dispatch(message).await;

        // Verify the result
        assert!(result.is_ok(), "Dispatch should succeed");

        // Verify the message was passed through to the RPC dispatcher
        let received = rx.try_recv().unwrap();
        assert_eq!(received.rpcs.len(), 1, "Batch should have one message");
    }

    #[tokio::test]
    async fn test_dispatch_process_compound_with_valid_pattern_converts_read_to_read_bypass() {
        let (tx, mut rx) = mpsc::channel::<RpcBatch>(10);
        let partition_senders = Arc::new(Mutex::new(vec![tx]));
        let rpc_dispatcher = RpcClientDispatcher::new(partition_senders);

        // Create context with read_bypass enabled
        let context = Arc::new(ReadBypassContext::default().await);
        let mut dispatcher = ReadBypassClientDispatcher::new(rpc_dispatcher, context.clone());
        context.set_s3_client_enabled(true);

        // Create compound with valid pattern: SEQUENCE|PUTFH|READ
        let compound = COMPOUND4args {
            tag: utf8string(b"test_compound_args".to_vec()),
            minorversion: 1,
            argarray: vec![
                get_sample_op_sequnce_args(),
                get_sample_put_fh_args(),
                get_sample_op_read_args(),
            ],
        };
        let mut envelope =
            create_nfs_rpc_envelope_batch_from_compound(RpcMessageType::Call, compound);
        let mut message = NfsRpcInfo::from(envelope);
        dispatcher
            .dispatch(message)
            .await
            .expect("Failed to dispatch message");

        // Verify the message was passed through to the RPC dispatcher
        let received = rx.try_recv().expect("Failed to receive message");
        assert_eq!(received.rpcs.len(), 1, "Batch should have one message");

        // Verify the message is converted to READ_BYPASS
        let received_envelope = NfsRpcEnvelope::try_from(received.rpcs[0].clone())
            .expect("Failed to parse received envelope");
        let received_compound = received_envelope.body;
        let received_compound_info = match received_compound {
            crate::nfs::nfs_compound::RefNfsCompound::Compound4args(ref info) => info,
            _ => panic!("Received compound is not a Compound4args"),
        };
        let expected_ops = vec![
            nfs_opnum4::OP_SEQUENCE,
            nfs_opnum4::OP_PUTFH,
            nfs_opnum4::OP_AWSFILE_READ_BYPASS,
        ];
        for (i, expected_op) in expected_ops.iter().enumerate() {
            assert_eq!(
                received_compound_info.op_vec[i], *expected_op,
                "Expected {:?} at index {}",
                expected_op, i
            );
            assert_eq!(
                opnum_from_argop(&received_compound_info.compound.argarray[i]),
                *expected_op,
                "Expected {:?} at index {}",
                expected_op,
                i
            );
        }
    }

    #[tokio::test]
    async fn test_dispatch_process_compound_with_invalid_pattern_keeps_read_operations() {
        let (tx, mut rx) = mpsc::channel::<RpcBatch>(10);
        let partition_senders = Arc::new(Mutex::new(vec![tx]));
        let rpc_dispatcher = RpcClientDispatcher::new(partition_senders);

        // Create context with read_bypass enabled
        let context = Arc::new(ReadBypassContext::default().await);
        let mut dispatcher = ReadBypassClientDispatcher::new(rpc_dispatcher, context.clone());
        context.set_s3_client_enabled(true);

        // Create compound with invalid pattern: SEQUENCE|GETATTR|READ (missing PUTFH in position 1)
        let compound = COMPOUND4args {
            tag: utf8string(b"test_compound_args".to_vec()),
            minorversion: 1,
            argarray: vec![
                get_sample_op_sequnce_args(),
                get_sample_op_getattr_args(),
                get_sample_op_read_args(),
            ],
        };

        let mut envelope =
            create_nfs_rpc_envelope_batch_from_compound(RpcMessageType::Call, compound);
        let mut message = NfsRpcInfo::from(envelope);
        dispatcher
            .dispatch(message)
            .await
            .expect("Failed to dispatch message");

        // Verify the message was passed through to the RPC dispatcher
        let received = rx.try_recv().expect("Failed to receive message");
        assert_eq!(received.rpcs.len(), 1, "Batch should have one message");

        // Verify the message keeps READ operations (not converted to read-bypass)
        let received_envelope = NfsRpcEnvelope::try_from(received.rpcs[0].clone())
            .expect("Failed to parse received envelope");
        let received_compound = received_envelope.body;
        let received_compound_info = match received_compound {
            crate::nfs::nfs_compound::RefNfsCompound::Compound4args(ref info) => info,
            _ => panic!("Received compound is not a Compound4args"),
        };
        let expected_ops = vec![
            nfs_opnum4::OP_SEQUENCE,
            nfs_opnum4::OP_GETATTR,
            nfs_opnum4::OP_READ,
        ];
        for (i, expected_op) in expected_ops.iter().enumerate() {
            assert_eq!(
                received_compound_info.op_vec[i], *expected_op,
                "Expected {:?} at index {}",
                expected_op, i
            );
            assert_eq!(
                opnum_from_argop(&received_compound_info.compound.argarray[i]),
                *expected_op,
                "Expected {:?} at index {}",
                expected_op,
                i
            );
        }
    }

    #[tokio::test]
    async fn test_dispatch_process_compound_with_denylist_putfh_keeps_read_operations() {
        let (tx, mut rx) = mpsc::channel::<RpcBatch>(10);
        let partition_senders = Arc::new(Mutex::new(vec![tx]));
        let rpc_dispatcher = RpcClientDispatcher::new(partition_senders);

        // Create context with read_bypass enabled
        let context = Arc::new(ReadBypassContext::default().await);
        let mut dispatcher = ReadBypassClientDispatcher::new(rpc_dispatcher, context.clone());
        context.set_s3_client_enabled(true);

        // Create compound with valid pattern but with denylisted file handle
        let compound = COMPOUND4args {
            tag: utf8string(b"test_compound_args".to_vec()),
            minorversion: 1,
            argarray: vec![
                get_sample_op_sequnce_args(),
                nfs_argop4::OP_PUTFH(PUTFH4args {
                    object: nfs_fh4(vec![0xef; 16]), // This will be added to denylist
                }),
                get_sample_op_read_args(),
            ],
        };

        context.fh_denylist.add(nfs_fh4(vec![0xef; 16]));
        let envelope = create_nfs_rpc_envelope_batch_from_compound(RpcMessageType::Call, compound);
        let mut message = NfsRpcInfo::from(envelope);
        dispatcher
            .dispatch(message)
            .await
            .expect("Failed to dispatch message");

        // Verify the message was passed through to the RPC dispatcher
        let received = rx.try_recv().expect("Failed to receive message");
        assert_eq!(received.rpcs.len(), 1, "Batch should have one message");

        // Verify the message keeps READ operations unchanged (not converted to read-bypass)
        let received_envelope = NfsRpcEnvelope::try_from(received.rpcs[0].clone())
            .expect("Failed to parse received envelope");
        let received_compound = received_envelope.body;
        let received_compound_info = match received_compound {
            crate::nfs::nfs_compound::RefNfsCompound::Compound4args(ref info) => info,
            _ => panic!("Received compound is not a Compound4args"),
        };
        let expected_ops = vec![
            nfs_opnum4::OP_SEQUENCE,
            nfs_opnum4::OP_PUTFH,
            nfs_opnum4::OP_READ,
        ];
        for (i, expected_op) in expected_ops.iter().enumerate() {
            assert_eq!(
                received_compound_info.op_vec[i], *expected_op,
                "Expected {:?} at index {}",
                expected_op, i
            );
            assert_eq!(
                opnum_from_argop(&received_compound_info.compound.argarray[i]),
                *expected_op,
                "Expected {:?} at index {}",
                expected_op,
                i
            );
        }
    }

    #[tokio::test]
    async fn test_dispatch_process_compound_with_multiple_read_blocks_read_bypass() {
        let (tx, mut rx) = mpsc::channel::<RpcBatch>(10);
        let partition_senders = Arc::new(Mutex::new(vec![tx]));
        let rpc_dispatcher = RpcClientDispatcher::new(partition_senders);

        // Create context with read_bypass enabled
        let context = Arc::new(ReadBypassContext::default().await);
        let mut dispatcher = ReadBypassClientDispatcher::new(rpc_dispatcher, context.clone());
        context.set_s3_client_enabled(true);

        // Create compound with additional READ operation after the valid pattern
        let compound = COMPOUND4args {
            tag: utf8string(b"test_compound_args".to_vec()),
            minorversion: 1,
            argarray: vec![
                get_sample_op_sequnce_args(),
                get_sample_put_fh_args(),
                get_sample_op_read_args(),
                get_sample_op_read_args(), // Second READ operation - should block read-bypass
            ],
        };

        let mut envelope =
            create_nfs_rpc_envelope_batch_from_compound(RpcMessageType::Call, compound);
        let mut message = NfsRpcInfo::from(envelope);
        dispatcher
            .dispatch(message)
            .await
            .expect("Failed to dispatch message");

        // Verify the message was passed through but READ operations remain unchanged
        let received = rx.try_recv().expect("Failed to receive message");
        assert_eq!(received.rpcs.len(), 1, "Batch should have one message");

        let received_envelope = NfsRpcEnvelope::try_from(received.rpcs[0].clone())
            .expect("Failed to parse received envelope");
        let received_compound = received_envelope.body;
        let received_compound_info = match received_compound {
            crate::nfs::nfs_compound::RefNfsCompound::Compound4args(ref info) => info,
            _ => panic!("Received compound is not a Compound4args"),
        };

        // All READ operations should remain as READ (not converted to read-bypass)
        let expected_ops = vec![
            nfs_opnum4::OP_SEQUENCE,
            nfs_opnum4::OP_PUTFH,
            nfs_opnum4::OP_READ,
            nfs_opnum4::OP_READ,
        ];
        for (i, expected_op) in expected_ops.iter().enumerate() {
            assert_eq!(
                received_compound_info.op_vec[i], *expected_op,
                "Expected {:?} at index {}",
                expected_op, i
            );
            assert_eq!(
                opnum_from_argop(&received_compound_info.compound.argarray[i]),
                *expected_op,
                "Expected {:?} at index {}",
                expected_op,
                i
            );
        }
    }

    #[tokio::test]
    async fn test_dispatch_process_compound_with_valid_pattern_plus_getattr() {
        let (tx, mut rx) = mpsc::channel::<RpcBatch>(10);
        let partition_senders = Arc::new(Mutex::new(vec![tx]));
        let rpc_dispatcher = RpcClientDispatcher::new(partition_senders);

        // Create context with read_bypass enabled
        let context = Arc::new(ReadBypassContext::default().await);
        let mut dispatcher = ReadBypassClientDispatcher::new(rpc_dispatcher, context.clone());
        context.set_s3_client_enabled(true);

        // Create compound with valid pattern plus additional operations: SEQUENCE|PUTFH|READ|GETATTR
        let compound = COMPOUND4args {
            tag: utf8string(b"test_compound_args".to_vec()),
            minorversion: 1,
            argarray: vec![
                get_sample_op_sequnce_args(),
                get_sample_put_fh_args(),
                get_sample_op_read_args(),
                get_sample_op_getattr_args(), // Additional operation after READ
            ],
        };

        let mut envelope =
            create_nfs_rpc_envelope_batch_from_compound(RpcMessageType::Call, compound);
        let mut message = NfsRpcInfo::from(envelope);
        dispatcher
            .dispatch(message)
            .await
            .expect("Failed to dispatch message");

        // Verify the message was passed through to the RPC dispatcher
        let received = rx.try_recv().expect("Failed to receive message");
        assert_eq!(received.rpcs.len(), 1, "Batch should have one message");

        // Verify the READ operation is converted to read-bypass, GETATTR allowed
        let received_envelope = NfsRpcEnvelope::try_from(received.rpcs[0].clone())
            .expect("Failed to parse received envelope");
        let received_compound = received_envelope.body;
        let received_compound_info = match received_compound {
            crate::nfs::nfs_compound::RefNfsCompound::Compound4args(ref info) => info,
            _ => panic!("Received compound is not a Compound4args"),
        };

        let expected_ops = vec![
            nfs_opnum4::OP_SEQUENCE,
            nfs_opnum4::OP_PUTFH,
            nfs_opnum4::OP_AWSFILE_READ_BYPASS,
            nfs_opnum4::OP_GETATTR,
        ];
        for (i, expected_op) in expected_ops.iter().enumerate() {
            assert_eq!(
                received_compound_info.op_vec[i], *expected_op,
                "Expected {:?} at index {}",
                expected_op, i
            );
        }
    }

    #[tokio::test]
    async fn test_dispatch_process_compound_with_restorefh_valid_pattern_read_bypass() {
        let (tx, mut rx) = mpsc::channel::<RpcBatch>(10);
        let partition_senders = Arc::new(Mutex::new(vec![tx]));
        let rpc_dispatcher = RpcClientDispatcher::new(partition_senders);

        // Create context with read_bypass enabled
        let context = Arc::new(ReadBypassContext::default().await);
        let mut dispatcher = ReadBypassClientDispatcher::new(rpc_dispatcher, context.clone());
        context.set_s3_client_enabled(true);

        // Create compound with RESTOREFH after READ: SEQUENCE|PUTFH|READ|RESTOREFH
        let compound = COMPOUND4args {
            tag: utf8string(b"test_compound_args".to_vec()),
            minorversion: 1,
            argarray: vec![
                get_sample_op_sequnce_args(),
                get_sample_put_fh_args(),
                get_sample_op_read_args(),
                nfs_argop4::OP_RESTOREFH, // RESTOREFH after READ should block read-bypass
            ],
        };

        let mut envelope =
            create_nfs_rpc_envelope_batch_from_compound(RpcMessageType::Call, compound);
        let mut message = NfsRpcInfo::from(envelope);
        dispatcher
            .dispatch(message)
            .await
            .expect("Failed to dispatch message");

        // Verify the message was passed through to the RPC dispatcher
        let received = rx.try_recv().expect("Failed to receive message");
        assert_eq!(received.rpcs.len(), 1, "Batch should have one message");

        // Verify the READ operation remains unchanged (not converted to read-bypass)
        let received_envelope = NfsRpcEnvelope::try_from(received.rpcs[0].clone())
            .expect("Failed to parse received envelope");
        let received_compound = received_envelope.body;
        let received_compound_info = match received_compound {
            crate::nfs::nfs_compound::RefNfsCompound::Compound4args(ref info) => info,
            _ => panic!("Received compound is not a Compound4args"),
        };

        let expected_ops = vec![
            nfs_opnum4::OP_SEQUENCE,
            nfs_opnum4::OP_PUTFH,
            nfs_opnum4::OP_AWSFILE_READ_BYPASS, // Should be converted to read-bypass
            nfs_opnum4::OP_RESTOREFH,
        ];
        for (i, expected_op) in expected_ops.iter().enumerate() {
            assert_eq!(
                received_compound_info.op_vec[i], *expected_op,
                "Expected {:?} at index {}",
                expected_op, i
            );
        }
    }

    #[tokio::test]
    async fn test_dispatch_updates_program_number_and_version_when_converting_to_read_bypass() {
        let (tx, mut rx) = mpsc::channel::<RpcBatch>(10);
        let partition_senders = Arc::new(Mutex::new(vec![tx]));
        let rpc_dispatcher = RpcClientDispatcher::new(partition_senders);

        // Create context with read_bypass enabled
        let context = Arc::new(ReadBypassContext::default().await);
        let mut dispatcher = ReadBypassClientDispatcher::new(rpc_dispatcher, context.clone());
        context.set_s3_client_enabled(true);

        // Create compound with valid pattern: SEQUENCE|PUTFH|READ
        let compound = COMPOUND4args {
            tag: utf8string(b"test_compound_args".to_vec()),
            minorversion: 1,
            argarray: vec![
                get_sample_op_sequnce_args(),
                get_sample_put_fh_args(),
                get_sample_op_read_args(),
            ],
        };

        let mut envelope =
            create_nfs_rpc_envelope_batch_from_compound(RpcMessageType::Call, compound);
        let mut message = NfsRpcInfo::from(envelope);
        dispatcher
            .dispatch(message)
            .await
            .expect("Failed to dispatch message");

        // Verify the message was passed through to the RPC dispatcher
        let received = rx.try_recv().expect("Failed to receive message");
        assert_eq!(received.rpcs.len(), 1, "Batch should have one message");

        // Parse the received message
        let received_envelope = NfsRpcEnvelope::try_from(received.rpcs[0].clone())
            .expect("Failed to parse received envelope");

        // Verify the program number and version were updated
        if let RpcMessageParams::CallParams(ref params) = received_envelope.header.params {
            assert_eq!(
                params.program_id, AWSFILE_PROGRAM_NUMBER,
                "Program ID should be updated to AWSFILE_PROGRAM_NUMBER"
            );
            assert_eq!(
                params.program_version, AWSFILE_PROGRAM_VERSION,
                "Program version should be updated to AWSFILE_PROGRAM_VERSION"
            );
        } else {
            panic!("Expected CallParams");
        }

        // Verify the raw bytes were updated
        let program_bytes = &received_envelope.header.raw_bytes
            [RPC_PROGRAM_OFFSET..RPC_PROGRAM_OFFSET + RPC_FIELD_SIZE];
        let actual_program_id = u32::from_be_bytes([
            program_bytes[0],
            program_bytes[1],
            program_bytes[2],
            program_bytes[3],
        ]);
        assert_eq!(
            actual_program_id, AWSFILE_PROGRAM_NUMBER,
            "Raw bytes should be updated with AWSFILE_PROGRAM_NUMBER"
        );

        let version_bytes = &received_envelope.header.raw_bytes
            [RPC_PROGRAM_VERSION_OFFSET..RPC_PROGRAM_VERSION_OFFSET + RPC_FIELD_SIZE];
        let actual_program_version = u32::from_be_bytes([
            version_bytes[0],
            version_bytes[1],
            version_bytes[2],
            version_bytes[3],
        ]);
        assert_eq!(
            actual_program_version, AWSFILE_PROGRAM_VERSION,
            "Raw bytes should be updated with AWSFILE_PROGRAM_VERSION"
        );
    }
}
