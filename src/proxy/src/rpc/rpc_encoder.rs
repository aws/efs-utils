#![allow(unused)]
#[allow(dead_code)]
use bytes::{BufMut, Bytes, BytesMut};
use onc_rpc::{auth::AuthFlavor, AcceptedStatus, CallBody, MessageType, ReplyBody, RpcMessage};

use crate::rpc::rpc_envelope::Envelope;
use crate::rpc::rpc_envelope::EnvelopeHeader;
use crate::rpc::rpc_envelope::RpcMessageType;
use crate::{error::RpcError, rpc::rpc_envelope::RpcMessageParams};
/// RPC encoder for creating RPC call and reply messages

// RPC header program number field offset (in bytes)
// RFC5531 RPC Call header: [record_marker(4)] - [xid(4)] [msg_type(4)] [rpcvers(4)] [program(4)] [version(4)]
pub const RPC_PROGRAM_OFFSET: usize = 16;
pub const RPC_PROGRAM_VERSION_OFFSET: usize = 20;
pub const RPC_FIELD_SIZE: usize = 4;

pub struct RpcEncoder;

impl RpcEncoder {
    /// Encode an RPC call with the given header and payload
    ///
    /// # Arguments
    /// * `params` - The RPC message callparams containing auth info
    /// * `payload` - The XDR-encoded procedure arguments (e.g., NFS COMPOUND)
    ///
    /// # Returns
    /// * `Result<BytesMut, RpcError>` - The encoded RPC call message ready for transmission
    ///
    pub fn encode_rpc_call_with_payload(
        params: RpcMessageParams,
        payload: bytes::BytesMut,
    ) -> Result<Bytes, RpcError> {
        let RpcMessageParams::CallParams(call_params) = params else {
            return Err(RpcError::InvalidParams);
        };

        let call_body = CallBody::new(
            call_params.program_id,
            call_params.program_version,
            call_params.procedure,
            call_params.auth_credentials,
            call_params.auth_verifier,
            payload,
        );

        let rpc_message = RpcMessage::new(call_params.xid, MessageType::Call(call_body));

        let serialized = rpc_message.serialise().map_err(|e| {
            RpcError::SerializationError(format!("Failed to serialize RPC call: {}", e))
        })?;

        Ok(Bytes::from(serialized))
    }

    /// Encode an RPC accepted reply with the given params and payload
    ///
    /// # Arguments
    /// * `xid` - The XID from the corresponding RPC call
    /// * `params` - The RPC message replyparams containing auth info
    /// * `payload` - The XDR-encoded procedure results (e.g., NFS COMPOUND response)
    ///
    /// # Returns
    /// * `Result<BytesMut, RpcError>` - The encoded RPC reply message ready for transmission
    ///
    /// # Usage
    /// Used for ReadBypass responses and ECD HeartBeat replies.
    /// The header should be previously passed into the writer thread.
    pub fn encode_rpc_accepted_reply_with_payload(
        xid: u32,
        params: RpcMessageParams,
        payload: bytes::BytesMut,
    ) -> Result<BytesMut, RpcError> {
        let RpcMessageParams::ReplyParams(reply_params) = params else {
            return Err(RpcError::InvalidParams);
        };

        // Create accepted reply with success status
        let accepted_reply = onc_rpc::AcceptedReply::new(
            reply_params.auth_verifier,
            AcceptedStatus::Success(payload),
        );

        let reply_body: ReplyBody<Bytes, BytesMut> = ReplyBody::Accepted(accepted_reply);
        let rpc_message = RpcMessage::new(xid, MessageType::Reply(reply_body));

        // Serialize directly into a pre-allocated buffer to avoid an extra copy
        let mut buf = bytes::BytesMut::with_capacity(rpc_message.serialised_len() as usize);
        rpc_message
            .serialise_into((&mut buf).writer())
            .map_err(|e| {
                RpcError::SerializationError(format!("Failed to serialize RPC reply: {}", e))
            })?;

        Ok(buf)
    }

    /// Encode an RPC rejected reply for error handling cases
    ///
    /// # Arguments
    /// * `xid` - The XID from the corresponding RPC call
    /// * `rejection_reason` - The reason for rejection
    ///
    /// # Returns
    /// * `Result<BytesMut, RpcError>` - The encoded RPC rejected reply message
    ///
    /// # Usage
    /// Used for most error handling cases where the request cannot be processed.
    pub fn encode_rpc_rejected_reply(
        xid: u32,
        rejection_reason: onc_rpc::RejectedReply,
    ) -> Result<Bytes, RpcError> {
        let rejected_reply = match rejection_reason {
            onc_rpc::RejectedReply::RpcVersionMismatch { low, high } => {
                onc_rpc::RejectedReply::RpcVersionMismatch { low, high }
            }
            onc_rpc::RejectedReply::AuthError(auth_error) => {
                onc_rpc::RejectedReply::AuthError(auth_error.into())
            }
        };

        let reply_body: ReplyBody<Vec<u8>, Vec<u8>> = ReplyBody::Denied(rejected_reply);
        let rpc_message = RpcMessage::new(xid, MessageType::Reply(reply_body));

        // Serialize to bytes
        let serialized = rpc_message.serialise().map_err(|e| {
            RpcError::SerializationError(format!("Failed to serialize RPC rejected reply: {}", e))
        })?;

        Ok(Bytes::from(serialized))
    }

    /// Update RPC program number and version in-place within the raw RPC header bytes
    ///
    /// # Arguments
    /// * `header` - The RPC envelope header containing raw bytes and parsed params
    /// * `new_program_id` - The new program ID to set
    pub fn update_rpc_program_number_in_place(
        header: &mut EnvelopeHeader,
        new_program_id: u32,
        new_program_version: u32,
    ) -> Result<(), RpcError> {
        if let RpcMessageParams::CallParams(ref mut params) = header.params {
            params.program_id = new_program_id;
            params.program_version = new_program_version;
        } else {
            return Err(RpcError::InvalidParams);
        }

        if header.raw_bytes.len() < RPC_PROGRAM_OFFSET + 8 {
            return Err(RpcError::SerializationError(
                "RPC header too short to contain program fields".to_string(),
            ));
        }

        let program_bytes = new_program_id.to_be_bytes();
        header.raw_bytes[RPC_PROGRAM_OFFSET..RPC_PROGRAM_OFFSET + RPC_FIELD_SIZE]
            .copy_from_slice(&program_bytes);

        let version_bytes = new_program_version.to_be_bytes();
        header.raw_bytes[RPC_PROGRAM_VERSION_OFFSET..RPC_PROGRAM_VERSION_OFFSET + RPC_FIELD_SIZE]
            .copy_from_slice(&version_bytes);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        awsfile_rpc::{AWSFILE_PROGRAM_NUMBER, AWSFILE_PROGRAM_VERSION},
        nfs::nfs_test_utils::{
            create_basic_test_compound_args, create_rpc_message_and_nfs_payload_from_compound_args,
        },
        rpc::{
            rpc::{RpcBatch, NFS_PROGRAM},
            rpc_envelope::{Envelope, RpcCallParams, RpcEnvelope, RpcReplyParams},
        },
    };

    #[test]
    fn test_encode_rpc_call_with_payload() {
        let xid = 12345;
        let params = RpcMessageParams::CallParams(RpcCallParams {
            xid,
            program_id: 1,
            program_version: 1,
            procedure: 1,
            auth_credentials: onc_rpc::auth::AuthFlavor::AuthNone(None),
            auth_verifier: onc_rpc::auth::AuthFlavor::AuthNone(None),
        });

        let payload = BytesMut::from(&[1, 2, 3, 4][..]);

        let result = RpcEncoder::encode_rpc_call_with_payload(params, payload);
        assert!(result.is_ok());

        let encoded = result.unwrap();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_encode_rpc_accepted_reply_with_payload() {
        let xid = 12345;
        let payload = BytesMut::from(&[5, 6, 7, 8][..]);
        let params = RpcMessageParams::ReplyParams(RpcReplyParams {
            xid: xid,
            auth_verifier: onc_rpc::auth::AuthFlavor::AuthNone(None),
        });

        let result = RpcEncoder::encode_rpc_accepted_reply_with_payload(xid, params, payload);
        assert!(result.is_ok());

        let encoded = result.unwrap();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_encode_rpc_rejected_reply() {
        let xid = 12345;
        let rejection = onc_rpc::RejectedReply::AuthError(onc_rpc::AuthError::BadCredentials);

        let result = RpcEncoder::encode_rpc_rejected_reply(xid, rejection);
        assert!(result.is_ok());

        let encoded = result.unwrap();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_rpc_decode_encode_roundtrip() {
        let compound_args = create_basic_test_compound_args();
        let mut payload = Vec::new();
        let rpc_message =
            create_rpc_message_and_nfs_payload_from_compound_args(compound_args, &mut payload);

        // Start from RpcBatch:
        let serialized = rpc_message
            .serialise()
            .map_err(|e| {
                RpcError::SerializationError(format!("Failed to serialize RPC message: {}", e))
            })
            .unwrap();
        let mut serialized_mut = BytesMut::from(serialized.as_slice());
        let rpc_batch = RpcBatch::parse_batch(&mut serialized_mut).unwrap();

        let envelope = RpcEnvelope::try_from(rpc_batch.unwrap().rpcs[0].clone()).unwrap();

        let encoded =
            RpcEncoder::encode_rpc_call_with_payload(envelope.header.params, envelope.body);
        assert!(encoded.is_ok());
        let encoded = encoded.unwrap();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_update_program_number_in_place_success() {
        let original_program_id: u32 = NFS_PROGRAM;
        let original_program_version: u32 = 2;
        let new_program_id: u32 = AWSFILE_PROGRAM_NUMBER;
        let new_program_version: u32 = AWSFILE_PROGRAM_VERSION;

        // Create raw bytes for a RPC header
        let mut raw_bytes = BytesMut::with_capacity(28);
        raw_bytes.extend_from_slice(&[0x80, 0x00, 0x00, 0x18]);
        raw_bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        raw_bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // msg_type = 0 (CALL)
        raw_bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x02]);
        raw_bytes.extend_from_slice(&original_program_id.to_be_bytes());
        raw_bytes.extend_from_slice(&original_program_version.to_be_bytes());
        raw_bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);

        let mut header = EnvelopeHeader {
            raw_bytes,
            message_type: RpcMessageType::Call,
            params: RpcMessageParams::CallParams(RpcCallParams {
                xid: 1,
                program_id: original_program_id,
                program_version: original_program_version,
                procedure: 1,
                auth_credentials: AuthFlavor::AuthNone(None),
                auth_verifier: AuthFlavor::AuthNone(None),
            }),
        };

        // Update the program number and version
        let result = RpcEncoder::update_rpc_program_number_in_place(
            &mut header,
            new_program_id,
            new_program_version,
        );
        assert!(result.is_ok(), "Update should succeed");

        // Check that the raw bytes were updated at the correct offsets
        let program_bytes =
            &header.raw_bytes[RPC_PROGRAM_OFFSET..RPC_PROGRAM_OFFSET + RPC_FIELD_SIZE];
        let actual_program_id = u32::from_be_bytes([
            program_bytes[0],
            program_bytes[1],
            program_bytes[2],
            program_bytes[3],
        ]);
        assert_eq!(
            actual_program_id, new_program_id,
            "Raw bytes should be updated at program offset"
        );

        let version_bytes = &header.raw_bytes
            [RPC_PROGRAM_VERSION_OFFSET..RPC_PROGRAM_VERSION_OFFSET + RPC_FIELD_SIZE];
        let actual_program_version = u32::from_be_bytes([
            version_bytes[0],
            version_bytes[1],
            version_bytes[2],
            version_bytes[3],
        ]);
        assert_eq!(
            actual_program_version, new_program_version,
            "Raw bytes should be updated at version offset"
        );
    }

    #[test]
    fn test_update_program_number_in_place_with_reply_message_fails() {
        // Create a header with ReplyParams instead of CallParams
        let mut header = EnvelopeHeader {
            raw_bytes: BytesMut::from(&[0; 24][..]),
            message_type: RpcMessageType::Reply,
            params: RpcMessageParams::ReplyParams(RpcReplyParams {
                xid: 1,
                auth_verifier: AuthFlavor::AuthNone(None),
            }),
        };

        // Try to update the program number and version
        let result = RpcEncoder::update_rpc_program_number_in_place(
            &mut header,
            AWSFILE_PROGRAM_NUMBER,
            AWSFILE_PROGRAM_VERSION,
        );

        // Verify error
        assert!(matches!(result, Err(RpcError::InvalidParams)));
    }

    #[test]
    fn test_update_program_number_roundtrip() {
        let xid = 12345;
        let original_program_id: u32 = NFS_PROGRAM;
        let original_program_version: u32 = 4;
        let new_program_id: u32 = AWSFILE_PROGRAM_NUMBER;
        let new_program_version: u32 = AWSFILE_PROGRAM_VERSION;

        // Create RPC message with standard NFS program number
        let call_body = onc_rpc::CallBody::new(
            original_program_id,
            original_program_version,
            1,
            onc_rpc::auth::AuthFlavor::AuthNone::<Vec<_>>(None),
            onc_rpc::auth::AuthFlavor::AuthNone::<Vec<_>>(None),
            vec![1, 2, 3, 4],
        );

        let rpc_message = onc_rpc::RpcMessage::new(xid, onc_rpc::MessageType::Call(call_body));
        let serialized = rpc_message.serialise().unwrap();
        let mut raw_bytes = BytesMut::from(serialized.as_slice());
        let mut envelope = RpcEnvelope::try_from(raw_bytes).unwrap();

        // Update the program number to AWSFILE
        let result = RpcEncoder::update_rpc_program_number_in_place(
            &mut envelope.header,
            new_program_id,
            new_program_version,
        );
        assert!(result.is_ok(), "Update should succeed");

        let modified_bytes = <RpcEnvelope as Envelope<BytesMut>>::serialize(envelope);

        // Parse the modified bytes as an RpcMessage
        let modified_message = onc_rpc::RpcMessage::try_from(modified_bytes.as_ref()).unwrap();

        // Check that the program number was updated
        if let onc_rpc::MessageType::Call(call) = modified_message.message() {
            assert_eq!(
                call.program(),
                new_program_id,
                "Program ID should be updated in the parsed message"
            );
            assert_eq!(
                call.program_version(),
                new_program_version,
                "Program version should be updated in the parsed message"
            );
        } else {
            panic!("Expected Call message");
        }
    }
}
