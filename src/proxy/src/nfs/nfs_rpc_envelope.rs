//! # NFS RPC Envelope
//! Specialization of RpcEnvelope for working specifically with NFS payloads.
//! `NfsRpcEnvelope` - NFS portion of the RPC message is parsed to a rust struct using `xdr_codec`
//!
//! These structures provides a zero-copy way to handle RPC messages by separating the header
//!
//! The `std::convert::TryFrom` trait is implemented for every Envelope implementations to
//! parse NFS messages from a BytesMut buffer.
//!

use bytes::BytesMut;

use crate::awsfile_rpc::AWSFILE_PROGRAM_NUMBER;
use crate::nfs::nfs_compound::{NfsCompoundType, RefNfsCompound};
use crate::nfs::nfs_parser::NfsMessageParser;
use crate::rpc::rpc::RpcBatch;
use crate::rpc::rpc::{NFS_BACKCHANNEL_PROGRAM, NFS_PROGRAM};
use crate::rpc::rpc_envelope::{
    Envelope, EnvelopeBatch, EnvelopeHeader, RpcEnvelope, RpcMessageParams,
};
use crate::rpc::rpc_error::RpcParseErrorKind;

#[derive(Clone)]
pub struct NfsRpcEnvelope {
    pub header: EnvelopeHeader,

    /// The parsed payload of the RPC message.
    pub body: RefNfsCompound,
}

impl NfsRpcEnvelope {
    pub fn get_nfs_compound_type(
        header: &EnvelopeHeader,
    ) -> Result<NfsCompoundType, RpcParseErrorKind> {
        match &header.params {
            RpcMessageParams::CallParams(params) => match params.program_id {
                NFS_PROGRAM | AWSFILE_PROGRAM_NUMBER => Ok(NfsCompoundType::Compound4args),
                NFS_BACKCHANNEL_PROGRAM => Ok(NfsCompoundType::CbCompound4args),
                _ => Err(RpcParseErrorKind::UnsupportedCallProgram {
                    program_id: params.program_id,
                }),
            },
            RpcMessageParams::ReplyParams(_) => {
                // For now we only support parsing compound4res. If we want to support other
                // compound types, we need to match the type from RPC XID
                Ok(NfsCompoundType::Compound4res)
            }
            RpcMessageParams::RejectedReplyParams(_) => Err(RpcParseErrorKind::RpcRejectedReply),
        }
    }
}

impl TryFrom<BytesMut> for NfsRpcEnvelope {
    type Error = RpcParseErrorKind;

    fn try_from(mut frame: BytesMut) -> Result<Self, Self::Error> {
        let header =
            Self::get_header(&mut frame).map_err(|_e| RpcParseErrorKind::RpcMessageParseError)?;

        // Empty payload, skip parsing (NFS null procedure)
        if frame.is_empty() {
            return Err(RpcParseErrorKind::EmptyPayload);
        }

        let compound_type = Self::get_nfs_compound_type(&header)?;
        let body = NfsMessageParser::parse_from_rpc_payload(compound_type, frame)
            .map_err(|_| RpcParseErrorKind::RpcMessageParseError)?;
        Ok(Self { header, body })
    }
}

// Implement Envelope<OtherType> for NfsRpcEnvelope
impl Envelope<RefNfsCompound> for NfsRpcEnvelope {
    fn into_header_and_body(self) -> (EnvelopeHeader, RefNfsCompound) {
        (self.header, self.body)
    }

    fn from_header_and_body(header: EnvelopeHeader, body: RefNfsCompound) -> Self {
        Self { header, body }
    }

    /// Serialization of NfsRpcEnvelope into BytesMut buffer.
    /// Self-consuming method, i.e. NfsRpcEnvelope object does not exist after serialization
    fn serialize(self) -> BytesMut {
        let nfs_bytes = match self.body {
            RefNfsCompound::Compound4args(info) => info.into_bytes_mut(),
            RefNfsCompound::Compound4res(info) => info.into_bytes_mut(),
            RefNfsCompound::CbCompound4args(info) => info.into_bytes_mut(),
            RefNfsCompound::CbCompound4res(info) => info.into_bytes_mut(),
        };

        // Create an RPC envelope from the header and the NFS bytes
        let rpc_envelope = RpcEnvelope::from_header_and_body(self.header, nfs_bytes);

        // Serialize the RPC envelope
        rpc_envelope.serialize()
    }
}

impl From<NfsRpcEnvelopeBatch> for RpcBatch {
    fn from(batch: NfsRpcEnvelopeBatch) -> Self {
        let mut rpcs = Vec::with_capacity(batch.envelopes.len());

        for envelope in batch.envelopes {
            let serialized: BytesMut = envelope.serialize();
            rpcs.push(serialized);
        }

        RpcBatch { rpcs }
    }
}

impl TryFrom<RpcEnvelope> for NfsRpcEnvelope {
    type Error = RpcParseErrorKind;

    fn try_from(value: RpcEnvelope) -> Result<Self, Self::Error> {
        let (header, body) = value.into_header_and_body();

        // Empty payload (e.g., NULL procedure call/reply) - skip NFS parsing
        if body.is_empty() {
            return Err(RpcParseErrorKind::EmptyPayload);
        }

        let compound_type = Self::get_nfs_compound_type(&header)?;
        let body = NfsMessageParser::parse_from_rpc_payload(compound_type, body)
            .map_err(|_| RpcParseErrorKind::RpcMessageParseError)?;
        Ok(NfsRpcEnvelope { header, body })
    }
}

pub type NfsRpcEnvelopeBatch = EnvelopeBatch<NfsRpcEnvelope>;
pub type NfsRpcInfo = NfsRpcEnvelopeBatch;

#[cfg(test)]
mod tests {
    use xdr_codec::Pack;

    use super::*;
    use crate::{
        nfs::{
            nfs4_1_xdr::{COMPOUND4args, COMPOUND4res},
            nfs_test_utils,
        },
        rpc::rpc_envelope::{
            EnvelopeHeader, RpcCallParams, RpcEnvelopeBatch, RpcMessageType, RpcReplyParams,
        },
    };

    fn get_default_rpc_call_params() -> RpcCallParams {
        RpcCallParams {
            program_id: NFS_PROGRAM,
            xid: 1,
            program_version: 1,
            procedure: 1,
            auth_credentials: onc_rpc::auth::AuthFlavor::AuthNone(None),
            auth_verifier: onc_rpc::auth::AuthFlavor::AuthNone(None),
        }
    }

    fn get_default_rpc_reply_params() -> RpcReplyParams {
        RpcReplyParams {
            xid: 1,
            auth_verifier: onc_rpc::auth::AuthFlavor::AuthNone(None),
        }
    }

    fn get_default_nfs_call_back_rpc_call_params() -> RpcCallParams {
        RpcCallParams {
            program_id: NFS_BACKCHANNEL_PROGRAM,
            xid: 1,
            program_version: 1,
            procedure: 1,
            auth_credentials: onc_rpc::auth::AuthFlavor::AuthNone(None),
            auth_verifier: onc_rpc::auth::AuthFlavor::AuthNone(None),
        }
    }

    #[test]
    fn test_nfs_rpc_envelope_try_from_bytes() {
        let mut nfs_payload = Vec::new();
        let compound_args = nfs_test_utils::create_basic_test_compound_args();
        compound_args
            .pack(&mut nfs_payload)
            .expect("failed to pack compound");

        let buffer = nfs_test_utils::create_default_rpc_message_from_payload(&nfs_payload)
            .serialise()
            .expect("msg");

        // Test conversion from BytesMut to RpcEnvelope
        let result = NfsRpcEnvelope::try_from(BytesMut::from(buffer.as_slice()));
        assert!(result.is_ok());

        let envelope = result.unwrap();
        assert!(matches!(envelope.header.message_type, RpcMessageType::Call));

        // Verify body contains the payload
        assert!(
            matches!(envelope.body, RefNfsCompound::Compound4args(args) if args.compound == compound_args)
        );
    }

    #[test]
    fn test_nfs_rpc_envelope_try_from_rpc_envelope() {
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

        let nfs_rpc_envelope =
            NfsRpcEnvelope::try_from(envelope).expect("failed to convert to nfs rpc envelope");
        assert!(matches!(
            nfs_rpc_envelope.header.message_type,
            RpcMessageType::Call
        ));
        assert!(
            matches!(nfs_rpc_envelope.body, RefNfsCompound::Compound4args(args) if args.compound == compound_args)
        );
    }

    #[test]
    fn test_get_nfs_compound_type() {
        let nfs_call_header = EnvelopeHeader {
            raw_bytes: BytesMut::new(),
            message_type: RpcMessageType::Call,
            params: RpcMessageParams::CallParams(get_default_rpc_call_params()),
        };
        assert_eq!(
            NfsRpcEnvelope::get_nfs_compound_type(&nfs_call_header),
            Ok(NfsCompoundType::Compound4args)
        );

        let nfs_reply_header = EnvelopeHeader {
            raw_bytes: BytesMut::new(),
            message_type: RpcMessageType::Reply,
            params: RpcMessageParams::ReplyParams(get_default_rpc_reply_params()),
        };
        assert_eq!(
            NfsRpcEnvelope::get_nfs_compound_type(&nfs_reply_header),
            Ok(NfsCompoundType::Compound4res)
        );

        let cb_call_header = EnvelopeHeader {
            raw_bytes: BytesMut::new(),
            message_type: RpcMessageType::Call,
            params: RpcMessageParams::CallParams(get_default_nfs_call_back_rpc_call_params()),
        };
        assert_eq!(
            NfsRpcEnvelope::get_nfs_compound_type(&cb_call_header),
            Ok(NfsCompoundType::CbCompound4args)
        );

        let cb_reply_header = EnvelopeHeader {
            raw_bytes: BytesMut::new(),
            message_type: RpcMessageType::Reply,
            params: RpcMessageParams::ReplyParams(get_default_rpc_reply_params()),
        };
        assert_eq!(
            NfsRpcEnvelope::get_nfs_compound_type(&cb_reply_header),
            // We always think it's Compound4res even regardless of the program ID
            Ok(NfsCompoundType::Compound4res)
        );

        let unknown_header = EnvelopeHeader {
            raw_bytes: BytesMut::new(),
            message_type: RpcMessageType::Call,
            params: RpcMessageParams::CallParams(RpcCallParams {
                program_id: 999999, // Some other program
                xid: 1,
                program_version: 1,
                procedure: 1,
                auth_credentials: onc_rpc::auth::AuthFlavor::AuthNone(None),
                auth_verifier: onc_rpc::auth::AuthFlavor::AuthNone(None),
            }),
        };
        assert_eq!(
            NfsRpcEnvelope::get_nfs_compound_type(&unknown_header),
            Err(RpcParseErrorKind::UnsupportedCallProgram { program_id: 999999 })
        );
    }

    #[test]
    fn test_rpc_envelope_parse_and_reunite_with_nfs_call_payload() {
        let compound_args = nfs_test_utils::create_basic_test_compound_args();
        let mut buffer = Vec::<u8>::new();
        let rpc_message_owned =
            nfs_test_utils::create_rpc_message_and_nfs_payload_from_compound_args(
                compound_args,
                &mut buffer,
            );

        let rpc_bytes = rpc_message_owned.serialise().unwrap();
        let rpc_bytes_mut = BytesMut::from(rpc_bytes.as_slice());
        let envelope = RpcEnvelope::try_from(rpc_bytes_mut);
        assert!(envelope.is_ok(), "Parsing failed");
        let (header, body) = envelope.unwrap().into_header_and_body();
        // parse NFS payload
        let nfs_info = NfsMessageParser::parse_compound::<COMPOUND4args>(body);
        assert!(nfs_info.is_ok(), "Parsing failed");
        let nfs_info = nfs_info.unwrap();
        let nfs_bytes = nfs_info.into_bytes_mut();
        let envelope = RpcEnvelope::from_header_and_body(header, nfs_bytes);
        let serialized_bytes = envelope.serialize();
        assert_eq!(
            serialized_bytes, rpc_bytes,
            "Serialized bytes do not match original bytes"
        );
    }

    #[test]
    fn test_rpc_envelope_parse_and_reunite_with_nfs_reply_payload() {
        let compound_res = nfs_test_utils::create_basic_test_compound_res();
        let rpc_message_owned =
            nfs_test_utils::create_rpc_reply_message_from_compound_res(compound_res);

        let rpc_bytes = rpc_message_owned.serialise().unwrap();
        let rpc_bytes_mut = BytesMut::from(rpc_bytes.as_slice());
        let envelope = RpcEnvelope::try_from(rpc_bytes_mut);
        assert!(envelope.is_ok(), "Parsing failed");
        let (header, body) = envelope.unwrap().into_header_and_body();
        let nfs_info = NfsMessageParser::parse_compound::<COMPOUND4res>(body);
        assert!(nfs_info.is_ok(), "Parsing failed");
        let nfs_info = nfs_info.unwrap();
        let nfs_bytes = nfs_info.into_bytes_mut();
        let envelope = RpcEnvelope::from_header_and_body(header, nfs_bytes);

        let serialized_bytes = envelope.serialize();
        assert_eq!(
            serialized_bytes, rpc_bytes,
            "Serialized bytes do not match original bytes"
        );
    }

    #[test]
    fn test_nfs_rpc_envelope_into_rpc_batch() {
        let mut nfs_payload = Vec::new();
        let compound_args = nfs_test_utils::create_basic_test_compound_args();
        compound_args
            .pack(&mut nfs_payload)
            .expect("failed to pack compound");
        let buffer = nfs_test_utils::create_default_rpc_message_from_payload(&nfs_payload)
            .serialise()
            .expect("msg");

        let nfs_rpc_envelope1 =
            NfsRpcEnvelope::try_from(BytesMut::from(buffer.as_slice())).unwrap();
        let nfs_rpc_envelope2 =
            NfsRpcEnvelope::try_from(BytesMut::from(buffer.as_slice())).unwrap();

        let nfs_envelopes = vec![nfs_rpc_envelope1, nfs_rpc_envelope2];
        let nfs_envelope_batch = NfsRpcEnvelopeBatch {
            envelopes: nfs_envelopes,
        };

        // Convert to RpcBatch
        let rpc_batch: RpcBatch = nfs_envelope_batch.into();

        // Verify the result
        assert_eq!(rpc_batch.rpcs.len(), 2);
        assert_eq!(rpc_batch.rpcs[0], buffer);
        assert_eq!(rpc_batch.rpcs[1], buffer);
    }

    #[test]
    fn test_nfs_rpc_envelope_serialize() {
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
        let nfs_rpc_envelope = NfsRpcEnvelope::try_from(BytesMut::from(buffer.as_slice())).unwrap();
        let serialized = nfs_rpc_envelope.serialize();

        // Verify the serialized data matches the original
        assert_eq!(serialized.len(), original_len);
        assert_eq!(buffer, serialized);
    }

    #[test]
    fn test_nfs_rpc_envelope_batch_try_from_rpc_batch() {
        let compound_res = nfs_test_utils::create_basic_test_compound_res();
        let rpc_message_owned =
            nfs_test_utils::create_rpc_reply_message_from_compound_res(compound_res.clone());

        // Serialize the RPC message
        let rpc_bytes = rpc_message_owned.serialise().unwrap();
        let rpc_bytes_mut = BytesMut::from(rpc_bytes.as_slice());

        // Create an RPC batch with two identical messages
        let rpc_batch = RpcBatch {
            rpcs: vec![rpc_bytes_mut.clone(), rpc_bytes_mut.clone()],
        };

        // Convert RpcBatch to RpcEnvelopeBatch
        let rpc_envelope_batch =
            RpcEnvelopeBatch::try_from(rpc_batch).expect("Failed to parse RpcBatch");

        // Convert RpcEnvelopeBatch to NfsRpcEnvelopeBatch
        let mut nfs_envelopes = Vec::with_capacity(rpc_envelope_batch.envelopes.len());
        for envelope in rpc_envelope_batch.envelopes {
            let nfs_envelope =
                NfsRpcEnvelope::try_from(envelope).expect("Failed to convert to NfsRpcEnvelope");
            nfs_envelopes.push(nfs_envelope);
        }

        let nfs_envelope_batch = NfsRpcEnvelopeBatch {
            envelopes: nfs_envelopes,
        };

        // Verify the batch
        assert_eq!(
            2,
            nfs_envelope_batch.envelopes.len(),
            "Expected 2 envelopes"
        );

        // Verify each envelope contains the expected NFS compound
        for envelope in nfs_envelope_batch.envelopes {
            assert!(matches!(
                envelope.body,
                RefNfsCompound::Compound4res(res) if res.compound.status == compound_res.status &&
                                                    res.compound.tag == compound_res.tag
            ));
        }
    }

    #[test]
    fn test_nfs_rpc_envelope_empty_payload_returns_error() {
        // Create an RPC message with empty payload (simulates NULL procedure)
        let buffer = nfs_test_utils::create_default_rpc_message_from_payload(&[])
            .serialise()
            .expect("msg");

        let result = NfsRpcEnvelope::try_from(BytesMut::from(buffer.as_slice()));
        assert!(matches!(result, Err(RpcParseErrorKind::EmptyPayload)));
    }
}
