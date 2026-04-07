#![allow(unused)]

use log::{debug, warn};

use crate::rpc::rpc::RpcBatch;

#[derive(Debug, PartialEq, Clone)]
pub enum RpcFragmentParseError {
    InvalidSizeTooSmall,
    SizeLimitExceeded,
    Incomplete,
}

#[derive(Debug, PartialEq, Clone)]
pub struct RpcParseError {
    pub rpc_batch: RpcBatch,
    pub kind: RpcParseErrorKind,
}

#[derive(Debug, PartialEq, Clone)]
pub enum RpcParseErrorKind {
    RpcMessageParseError,
    RpcRejectedReply,
    RpcEnvelopeParseError { error: RpcFragmentParseError },
    UnsupportedCallProgram { program_id: u32 },
    UnsupportedMessage,
    EmptyPayload, // Allows support of NFS NULL compounds
}

impl RpcParseError {
    pub fn into_rpc_batch(self) -> RpcBatch {
        self.rpc_batch
    }

    /// Log parse error details for debugging and monitoring
    pub fn log_parse_error(&self, context: &str) {
        match &self.kind {
            RpcParseErrorKind::UnsupportedMessage => {
                debug!(
                    "{}: Handling unsupported message, forwarding as raw RpcBatch",
                    context
                );
            }
            RpcParseErrorKind::RpcMessageParseError => {
                warn!("{}: RPC message parse error encountered", context);
            }
            RpcParseErrorKind::RpcRejectedReply => {
                warn!("{}: RPC rejected reply encountered", context);
            }
            RpcParseErrorKind::RpcEnvelopeParseError {
                error: envelope_error,
            } => {
                warn!(
                    "{}: RPC envelope parse error: {:?}",
                    context, envelope_error
                );
            }
            RpcParseErrorKind::UnsupportedCallProgram { program_id } => {
                warn!("{}: Unsupported call program: {}", context, program_id);
            }
            RpcParseErrorKind::EmptyPayload => {
                debug!("{}: Empty payload, forwarding without parsing", context);
            }
        }
    }
}
