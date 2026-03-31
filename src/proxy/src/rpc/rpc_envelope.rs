//! An "Envelope" represents a RPC message parsed into a struct for proxy processing.
//!
//! These structures provides a zero-copy way to handle RPC messages by separating the header
//! metadata from the payload body. This separation allows for efficient inspection and
//! modification of the payload without copying the entire message.
//!
//! An envelope header contains all RPC protocol metadata (XID, message type, auth info, etc.), the
//! envelope body contains just the RPC payload data.
//!
//! For example, in `RpcEnvelope` - NFS portion of the RPC message is stored as a `BytesMut` instance in its payload
//!
//! The `std::convert::TryFrom` trait is implemented for every Envelope implementations to
//! parse NFS messages from a BytesMut buffer.
//!
//! NOTE: In limits of this file we want to cover only generic Envelope structure and its RPC implementation,
//! NFS specific imnplementation is covered separately.
//!

#![allow(unused)]
#[allow(dead_code)]
use crate::rpc::rpc::{RpcBatch, LAST_RECORD_FRAGMENT_FLAG};
use crate::rpc::{rpc::NFS_PROGRAM, rpc_error::RpcParseErrorKind};
use bytes::{Bytes, BytesMut};
use log::{debug, warn};
use onc_rpc::{AcceptedStatus, MessageType, ReplyBody, RpcMessage};

use super::rpc_error::RpcParseError;

#[derive(Debug, Clone, Copy)]
pub enum RpcMessageType {
    Call,
    Reply,
}

#[derive(Debug, Clone)]
pub enum RpcMessageParams {
    CallParams(RpcCallParams),
    ReplyParams(RpcReplyParams),
    RejectedReplyParams(RpcRejectedReplyParams),
}

impl RpcCallParams {
    /// Create RpcCallParams with default values for testing
    pub fn new_for_test() -> Self {
        RpcCallParams {
            xid: 1,
            program_id: NFS_PROGRAM,
            program_version: 4,
            procedure: 1,
            auth_credentials: onc_rpc::auth::AuthFlavor::AuthNone(None),
            auth_verifier: onc_rpc::auth::AuthFlavor::AuthNone(None),
        }
    }
}

impl RpcReplyParams {
    /// Create RpcReplyParams with default values for testing
    pub fn new_for_test() -> Self {
        RpcReplyParams {
            xid: 1,
            auth_verifier: onc_rpc::auth::AuthFlavor::AuthNone(None),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RpcCallParams {
    pub xid: u32,
    pub program_id: u32,
    pub program_version: u32,
    pub procedure: u32,
    pub auth_credentials: onc_rpc::auth::AuthFlavor<Bytes>,
    pub auth_verifier: onc_rpc::auth::AuthFlavor<Bytes>,
}

#[derive(Debug, Clone)]
pub struct RpcReplyParams {
    pub xid: u32,
    pub auth_verifier: onc_rpc::auth::AuthFlavor<Bytes>,
}

#[derive(Debug, Clone)]
pub struct RpcRejectedReplyParams {
    pub xid: u32,
    pub rejected_reply: RejectedReason,
}

// Wrapper copied from one_rpc::RejectedReply to resolve cloning issue
#[derive(Debug, Clone)]
pub enum RejectedReason {
    RpcVersionMismatch { low: u32, high: u32 },
    AuthError(AuthError),
}

#[derive(Debug, Clone)]
pub struct EnvelopeHeader {
    /// Contains all RPC protocol metadata including record marker (4bytes), XID (4bytes), message
    /// type (call/reply), auth info (variable length), and other protocol headers.
    pub raw_bytes: BytesMut,

    // RPC metadata
    pub message_type: RpcMessageType,
    pub params: RpcMessageParams,
}

fn convert_auth_flavor_to_bytes(
    auth: &onc_rpc::auth::AuthFlavor<&[u8]>,
) -> onc_rpc::auth::AuthFlavor<Bytes> {
    use onc_rpc::auth::{AuthFlavor, AuthUnixParams};

    match auth {
        AuthFlavor::AuthNone(opt_data) => {
            AuthFlavor::AuthNone(opt_data.map(|data| Bytes::copy_from_slice(data)))
        }
        AuthFlavor::AuthUnix(unix_params) => {
            // Convert AuthUnixParams<&[u8]> to AuthUnixParams<Bytes>
            let converted_params = AuthUnixParams::new(
                unix_params.stamp(),
                Bytes::copy_from_slice(unix_params.machine_name().as_ref()),
                unix_params.uid(),
                unix_params.gid(),
                unix_params.gids().map_or(Vec::new(), |gids| gids.to_vec()),
            );
            AuthFlavor::AuthUnix(converted_params)
        }
        AuthFlavor::AuthShort(data) => AuthFlavor::AuthShort(Bytes::copy_from_slice(data.as_ref())),
        AuthFlavor::Unknown { id, data } => AuthFlavor::Unknown {
            id: *id,
            data: Bytes::copy_from_slice(data.as_ref()),
        },
        _ => AuthFlavor::AuthNone(None),
    }
}

pub fn get_rpc_message_params(view: &RpcMessage<&[u8], &[u8]>) -> RpcMessageParams {
    match view.message() {
        MessageType::Call(c) => RpcMessageParams::CallParams(RpcCallParams {
            xid: view.xid(),
            program_id: c.program(),
            program_version: c.program_version(),
            procedure: c.procedure(),
            auth_credentials: convert_auth_flavor_to_bytes(c.auth_credentials()),
            auth_verifier: convert_auth_flavor_to_bytes(c.auth_verifier()),
        }),
        MessageType::Reply(r) => match r {
            ReplyBody::Accepted(accepted_reply) => RpcMessageParams::ReplyParams(RpcReplyParams {
                xid: view.xid(),
                auth_verifier: convert_auth_flavor_to_bytes(accepted_reply.auth_verifier()),
            }),
            ReplyBody::Denied(denied_reply) => {
                RpcMessageParams::RejectedReplyParams(RpcRejectedReplyParams {
                    xid: view.xid(),
                    rejected_reply: match denied_reply {
                        onc_rpc::RejectedReply::RpcVersionMismatch { low, high } => {
                            RejectedReason::RpcVersionMismatch {
                                low: *low,
                                high: *high,
                            }
                        }
                        onc_rpc::RejectedReply::AuthError(auth_error) => {
                            RejectedReason::AuthError(AuthError::from(auth_error))
                        }
                    },
                })
            }
        },
    }
}

pub trait Envelope<T> {
    fn get_header(frame: &mut BytesMut) -> Result<EnvelopeHeader, RpcParseErrorKind> {
        let view = match RpcMessage::try_from(frame.as_ref()) {
            Ok(view) => view,
            Err(e) => {
                warn!(
                    "RpcMessage::try_from failed: {:?}, frame_len: {}, first_32_bytes: {:?}",
                    e,
                    frame.len(),
                    &frame.as_ref()[..frame.len().min(255)]
                );
                debug!("RpcMessage::try_from failed frame: {:?}", frame);
                return Err(RpcParseErrorKind::RpcMessageParseError);
            }
        };

        let message_type = match view.message() {
            MessageType::Call(_) => RpcMessageType::Call,
            MessageType::Reply(_) => RpcMessageType::Reply,
        };

        let params = get_rpc_message_params(&view);

        // 2. Locate payload inside `frame` (pointer arithmetic, no copy).
        let payload_slice: &[u8] = match view.message() {
            MessageType::Call(c) => c.payload(),
            MessageType::Reply(r) => {
                // Match the ReplyBody enum
                match r {
                    ReplyBody::Accepted(accepted_reply) => {
                        // Match the nested ReplyData enum
                        match accepted_reply.status() {
                            AcceptedStatus::Success(results) => results,
                            _ => &[],
                        }
                    }
                    // If it's not a accepted reply, return an empty slice (to be passed through)
                    // when Rpc is failed / not accepted, Reply contains only header.
                    ReplyBody::Denied(_) => &[],
                }
            }
        };

        let hdr_len = frame.len() - payload_slice.len();
        let header_bytes = frame.split_to(hdr_len);

        Ok(EnvelopeHeader {
            raw_bytes: header_bytes,
            message_type,
            params,
        })
    }

    fn into_header_and_body(self) -> (EnvelopeHeader, T);
    fn from_header_and_body(header: EnvelopeHeader, body: T) -> Self;
    fn serialize(self) -> BytesMut;
}

pub struct RpcEnvelope {
    pub header: EnvelopeHeader,

    /// The NFS payload of the RPC message
    pub body: BytesMut,
}

impl TryFrom<BytesMut> for RpcEnvelope {
    // We returning error kind here is enough, the caller will decide how to wrap it and the original batch in RpcParseError
    type Error = RpcParseErrorKind;

    fn try_from(mut frame: BytesMut) -> Result<Self, Self::Error> {
        let header = Self::get_header(&mut frame)?;
        let body = frame;
        Ok(Self { header, body })
    }
}

impl Envelope<BytesMut> for RpcEnvelope {
    fn into_header_and_body(self) -> (EnvelopeHeader, BytesMut) {
        (self.header, self.body)
    }

    fn from_header_and_body(header: EnvelopeHeader, body: BytesMut) -> Self {
        Self { header, body }
    }

    fn serialize(mut self) -> BytesMut {
        self.header.raw_bytes.unsplit(self.body);

        // 2) Update 4‑byte record marker (last‑fragment flag | length).
        let new_len = (self.header.raw_bytes.len() - 4) as u32;
        self.header.raw_bytes[..4]
            .copy_from_slice(&(LAST_RECORD_FRAGMENT_FLAG | new_len).to_be_bytes());

        // 3) Hand off ownership of the header to the caller.
        self.header.raw_bytes
    }
}

pub type RpcEnvelopeBatch = EnvelopeBatch<RpcEnvelope>;

pub struct EnvelopeBatch<E>
where
    E: for<'a> TryFrom<BytesMut, Error = RpcParseErrorKind>,
{
    pub envelopes: Vec<E>,
}

impl<E> TryFrom<RpcBatch> for EnvelopeBatch<E>
where
    E: for<'a> TryFrom<BytesMut, Error = RpcParseErrorKind>,
{
    type Error = RpcParseError;

    fn try_from(batch: RpcBatch) -> Result<Self, Self::Error> {
        let mut envelopes = Vec::with_capacity(batch.rpcs.len());
        let batch_clone = batch.clone(); // Clone for potential error cases

        for message in batch.rpcs {
            // Try to convert BytesMut to envelope type E
            match E::try_from(message) {
                Ok(envelope) => envelopes.push(envelope),
                Err(kind) => {
                    // Wrap the error with the batch information
                    let error_with_batch = RpcParseError {
                        rpc_batch: batch_clone,
                        kind,
                    };
                    return Err(error_with_batch);
                }
            }
        }

        if envelopes.is_empty() {
            Err(RpcParseError {
                rpc_batch: batch_clone,
                kind: RpcParseErrorKind::RpcMessageParseError,
            })
        } else {
            Ok(Self { envelopes })
        }
    }
}

/// Converts an EnvelopeBatch into an RpcBatch by serializing each envelope. This is useful when we
/// need to pass the batch to components that expect RpcBatch, like NFSClient and NFSServer
/// connection writers.
///
impl<E> From<EnvelopeBatch<E>> for RpcBatch
where
    E: for<'a> TryFrom<BytesMut, Error = RpcParseErrorKind> + Envelope<BytesMut>,
{
    fn from(batch: EnvelopeBatch<E>) -> Self {
        let mut rpcs = Vec::with_capacity(batch.envelopes.len());

        for envelope in batch.envelopes {
            // Serialize the envelope back to BytesMut
            let serialized = envelope.serialize();
            rpcs.push(serialized);
        }

        RpcBatch { rpcs }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum AuthError {
    Success,
    BadCredentials,
    RejectedCredentials,
    BadVerifier,
    RejectedVerifier,
    TooWeak,
    InvalidResponseVerifier,
    Failed,
}

impl From<&onc_rpc::AuthError> for AuthError {
    fn from(auth_error: &onc_rpc::AuthError) -> Self {
        match auth_error {
            onc_rpc::AuthError::Success => AuthError::Success,
            onc_rpc::AuthError::BadCredentials => AuthError::BadCredentials,
            onc_rpc::AuthError::RejectedCredentials => AuthError::RejectedCredentials,
            onc_rpc::AuthError::BadVerifier => AuthError::BadVerifier,
            onc_rpc::AuthError::RejectedVerifier => AuthError::RejectedVerifier,
            onc_rpc::AuthError::TooWeak => AuthError::TooWeak,
            onc_rpc::AuthError::InvalidResponseVerifier => AuthError::InvalidResponseVerifier,
            onc_rpc::AuthError::Failed => AuthError::Failed,
        }
    }
}

impl Into<onc_rpc::AuthError> for AuthError {
    fn into(self) -> onc_rpc::AuthError {
        match self {
            AuthError::Success => onc_rpc::AuthError::Success,
            AuthError::BadCredentials => onc_rpc::AuthError::BadCredentials,
            AuthError::RejectedCredentials => onc_rpc::AuthError::RejectedCredentials,
            AuthError::BadVerifier => onc_rpc::AuthError::BadVerifier,
            AuthError::RejectedVerifier => onc_rpc::AuthError::RejectedVerifier,
            AuthError::TooWeak => onc_rpc::AuthError::TooWeak,
            AuthError::InvalidResponseVerifier => onc_rpc::AuthError::InvalidResponseVerifier,
            AuthError::Failed => onc_rpc::AuthError::Failed,
        }
    }
}

#[cfg(test)]
mod tests {
    use core::assert_eq;

    use hex_literal::hex;
    use onc_rpc::{AuthError, RejectedReply};
    use xdr_codec::Pack;

    use crate::nfs::nfs_test_utils::{
        self, create_basic_test_compound_res, create_rpc_reply_message_from_compound_res,
    };
    use crate::rpc::rpc::NFS_PROGRAM;

    use super::*;

    #[test]
    fn test_rpc_envelope_try_from_bytes() {
        let mut nfs_payload = Vec::new();
        let compound_args = nfs_test_utils::create_basic_test_compound_args();
        compound_args
            .pack(&mut nfs_payload)
            .expect("failed to pack compound");

        let buffer = nfs_test_utils::create_default_rpc_message_from_payload(&nfs_payload)
            .serialise()
            .expect("msg");

        // Test conversion from BytesMut to RpcEnvelope
        let result = RpcEnvelope::try_from(BytesMut::from(buffer.as_slice()));
        assert!(result.is_ok());

        let envelope = result.unwrap();
        assert!(matches!(envelope.header.message_type, RpcMessageType::Call));

        // Verify body contains the payload
        assert_eq!(nfs_payload.len(), envelope.body.len());
        assert_eq!(&nfs_payload, &envelope.body);
    }

    #[test]
    fn test_rpc_envelope_serialize() {
        let mut nfs_payload = Vec::new();
        let compound_args = nfs_test_utils::create_basic_test_compound_args();
        compound_args
            .pack(&mut nfs_payload)
            .expect("failed to pack compound");
        let buffer = nfs_test_utils::create_default_rpc_message_from_payload(&nfs_payload)
            .serialise()
            .expect("msg");

        let original_len = buffer.len();

        // Convert to envelope and back
        let envelope = RpcEnvelope::try_from(BytesMut::from(buffer.as_slice())).unwrap();
        let serialized = envelope.serialize();

        // Verify the serialized data matches the original
        assert_eq!(serialized.len(), original_len);
        assert_eq!(buffer, serialized);
    }

    #[test]
    fn test_into_rpc_batch() {
        let header1_bytes = BytesMut::from(&[0x80, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01][..]);

        // Create first envelope
        let header1 = EnvelopeHeader {
            raw_bytes: header1_bytes.clone(),
            message_type: RpcMessageType::Call,
            params: RpcMessageParams::CallParams(RpcCallParams {
                xid: 1,
                program_id: NFS_PROGRAM,
                program_version: 0,
                procedure: 0,
                auth_credentials: onc_rpc::auth::AuthFlavor::AuthNone(None),
                auth_verifier: onc_rpc::auth::AuthFlavor::AuthNone(None),
            }),
        };
        let body1 = BytesMut::from(&[0x01, 0x02, 0x03, 0x04][..]);
        let envelope1 = RpcEnvelope::from_header_and_body(header1, body1.clone());

        // Create second envelope
        let header2_bytes = BytesMut::from(&[0x80, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x02][..]);
        let header2 = EnvelopeHeader {
            raw_bytes: header2_bytes.clone(),
            message_type: RpcMessageType::Reply,
            params: RpcMessageParams::ReplyParams(RpcReplyParams {
                xid: 2,
                auth_verifier: onc_rpc::auth::AuthFlavor::AuthNone(None),
            }),
        };
        let body2 = BytesMut::from(&[0x05, 0x06, 0x07, 0x08][..]);
        let envelope2 = RpcEnvelope::from_header_and_body(header2, body2.clone());

        // Create batch with both envelopes
        let envelope_batch = RpcEnvelopeBatch {
            envelopes: vec![envelope1, envelope2],
        };

        // Convert to RpcBatch
        let rpc_batch: RpcBatch = envelope_batch.into();

        // Verify the result
        assert_eq!(rpc_batch.rpcs.len(), 2);

        // Check first message
        assert_eq!(rpc_batch.rpcs[0][0..8], header1_bytes);
        assert_eq!(rpc_batch.rpcs[0][8..12], body1);

        // Check second message
        assert_eq!(rpc_batch.rpcs[1][0..8], header2_bytes);
        assert_eq!(rpc_batch.rpcs[1][8..12], body2);
    }

    #[test]
    fn test_into_rpc_batch_empty() {
        // Create an empty batch
        let envelope_batch = RpcEnvelopeBatch {
            envelopes: Vec::new(),
        };

        // Convert to RpcBatch
        let rpc_batch: RpcBatch = envelope_batch.into();

        // Verify the result
        assert_eq!(rpc_batch.rpcs.len(), 0);
    }

    #[test]
    fn test_rpc_envelope_parse_and_reunite() {
        // Sample RPC message (from onc-rpc tests)
        const RAW: [u8; 156] = hex!(
            "80000098265ec1060000000000000002000186a300000004000000010000000100
			0000180000000000000000000000000000000000000001000000000000000000000
			0000000000c6163636573732020202020200000000000000003000000160000001f
			4300004d1a436f6c452240ea4c70a1b52d7f97418e6601a10e02009cf2d59c00000
			000030000003f00000009000000021010011a00b0a23a"
        );

        let buf = BytesMut::from(&RAW[..]);
        let original_bytes = buf.clone().freeze(); // Keep a copy for comparison

        // Parse once just to find the payload start for length calculation
        let view: RpcMessage<&[u8], &[u8]> = RpcMessage::try_from(buf.as_ref()).unwrap();
        let payload_slice: &[u8] = match view.message() {
            onc_rpc::MessageType::Call(c) => c.payload().as_ref(),
            onc_rpc::MessageType::Reply(r) => match r {
                onc_rpc::ReplyBody::Accepted(a) => match a.status() {
                    onc_rpc::AcceptedStatus::Success(res) => res.as_ref(),
                    _ => &[],
                },
                onc_rpc::ReplyBody::Denied(_) => &[],
            },
        };
        let expected_hdr_len = (payload_slice.as_ptr() as usize) - (buf.as_ptr() as usize);
        let expected_body_len = buf.len() - expected_hdr_len;

        // Parse the buffer using the function under test
        let parse_result = RpcEnvelope::try_from(buf.clone()); // Use clone as parse consumes buf
        assert!(parse_result.is_ok(), "Parsing failed");
        let envelope = parse_result.unwrap();

        // Check header length against the calculated expected length
        assert_eq!(
            envelope.header.raw_bytes.len(),
            expected_hdr_len,
            "Header length mismatch"
        );
        // Check body length against the calculated expected length
        assert_eq!(
            envelope.body.len(),
            expected_body_len,
            "Body length mismatch"
        );

        // Reunite the envelope
        let serialized_bytes = envelope.serialize();

        // Verify the serialized bytes match the original
        assert_eq!(
            serialized_bytes, original_bytes,
            "Reunited bytes do not match original bytes"
        );
    }

    #[test]
    fn test_denied_reply() {
        // 1. Construct the XDR part of a "Denied" RPC reply message
        let xid = 0x12345678; // Example XID
        let denied_status = RejectedReply::AuthError(AuthError::BadVerifier);
        let reply_body: ReplyBody<&[u8], &[u8]> = ReplyBody::Denied(denied_status);
        let rpc_message_view: RpcMessage<_, _> =
            RpcMessage::new(xid, MessageType::Reply(reply_body));

        let xdr_message = rpc_message_view.serialise().unwrap();
        let original_record_bytes = BytesMut::from(xdr_message.as_slice());

        // 3. Parse the full record frame
        // Assuming the parse function signature is Result<Self, onc_rpc::Error> as per the initial context
        let parse_result = RpcEnvelope::try_from(BytesMut::from(xdr_message.as_slice()));
        assert!(
            parse_result.is_ok(),
            "Parsing denied reply record failed: {:?}",
            parse_result.err()
        );
        let envelope = parse_result.unwrap();

        // 4. Check envelope contents
        // For a denied reply, the NFS XDR payload is effectively empty for splitting purposes by RpcEnvelope.
        // The `header` field of RpcEnvelope should contain the entire original record.
        // The `body` field of RpcEnvelope should be empty.
        assert_eq!(
            envelope.header.raw_bytes.len(),
            original_record_bytes.len(),
            "Header length mismatch for denied reply. Expected {}, got {}",
            original_record_bytes.len(),
            envelope.header.raw_bytes.len(),
        );
        assert_eq!(
            envelope.header.raw_bytes,
            original_record_bytes.as_ref(),
            "Header content mismatch for denied reply"
        );
        assert!(
            envelope.body.is_empty(),
            "Body should be empty for denied reply, got: {:?}",
            envelope.body
        );

        // 5. Serialize the envelope
        let serialized_bytes = envelope.serialize();

        // 6. Verify the serialized message bytes match the original full record
        // Since the content (denied reply) hasn't changed length, the record marker should also be
        // the same after reunite.
        assert_eq!(
            serialized_bytes, original_record_bytes,
            "Reunited denied reply record does not match original"
        );
    }

    #[test]
    fn test_rpc_envelope_batch_try_from_rpc_batch() {
        let rpc_message_owned =
            create_rpc_reply_message_from_compound_res(create_basic_test_compound_res());
        let rpc_bytes = rpc_message_owned.serialise().unwrap();
        let rpc_bytes_mut = BytesMut::from(rpc_bytes.as_slice());
        let rpc_batch = RpcBatch {
            rpcs: vec![rpc_bytes_mut.clone(), rpc_bytes_mut.clone()],
        };
        let rpc_envelope_batch =
            RpcEnvelopeBatch::try_from(rpc_batch).expect("Failed to parse RpcBatch");
        assert_eq!(
            2,
            rpc_envelope_batch.envelopes.len(),
            "Expected 2 envelopes"
        );

        for envelope in rpc_envelope_batch.envelopes.into_iter() {
            assert_eq!(envelope.serialize(), rpc_bytes_mut);
        }
    }
}
