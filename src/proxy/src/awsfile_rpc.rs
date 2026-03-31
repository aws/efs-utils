//! # This module contains utilities for making 'awsfile' RPC requests
//!
//! Currently, the following API's are supported:
//!
//! - `bind_client_to_partition` - API which enables multiplexed connections to the AWS file server
//!   to enable higher per-client throughput
//! - `channel_init` - API which enables client side performance optimizations
//!

use async_trait::async_trait;
use std::io::Cursor;
use tokio::io::AsyncWriteExt;
use tokio::time::Instant;

use crate::awsfile_prot::{
    AwsFileChannelInitArgs, AwsFileChannelInitRes, BindClientResponse, OperationType,
    ProxyIdentifier,
};
use crate::config::channel_init_config::ChannelInitConfig;
use crate::connections::ProxyStream;
use crate::error::RpcError;
use crate::rpc::rpc::read_rpc_bytes;

pub const AWSFILE_PROGRAM_NUMBER: u32 = 400123;
pub const AWSFILE_PROGRAM_VERSION: u32 = 1;
pub const AWSFILE_NFSPROC4_COMPOUND: u32 = 1;

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct PartitionId {
    pub id: [u8; 64],
}

pub struct AwsFileRpcClient;

#[async_trait]
pub trait RpcClient {
    async fn bind_client_to_partition(
        proxy_id: &ProxyIdentifier,
        stream: &mut dyn ProxyStream,
    ) -> Result<BindClientResponse, RpcError>;

    async fn channel_init(
        &self,
        deadline: Instant,
        channel_init_args: &AwsFileChannelInitArgs,
        stream: &mut dyn ProxyStream,
    ) -> Result<ChannelInitConfig, RpcError>;
}

#[async_trait]
impl RpcClient for AwsFileRpcClient {
    async fn bind_client_to_partition(
        proxy_id: &ProxyIdentifier,
        stream: &mut dyn ProxyStream,
    ) -> Result<BindClientResponse, RpcError> {
        let request = create_rpc_request(proxy_id, OperationType::OP_BIND_CLIENT_TO_PARTITION)?;
        call_rpc::<BindClientResponse>(request, stream).await
    }

    async fn channel_init(
        &self,
        deadline: Instant,
        channel_init_args: &AwsFileChannelInitArgs,
        stream: &mut dyn ProxyStream,
    ) -> Result<ChannelInitConfig, RpcError> {
        let request =
            create_rpc_request(channel_init_args, OperationType::OP_AWS_FILE_CHANNEL_INIT)?;
        let config =
            tokio::time::timeout_at(deadline, call_rpc::<AwsFileChannelInitRes>(request, stream))
                .await
                .map_err(|_| {
                    RpcError::AwsFileChannelInitFailure(String::from("request timed out"))
                })??
                .try_into()?;
        Ok(config)
    }
}

fn create_rpc_request<T>(arg: &T, operation_type: OperationType) -> Result<Vec<u8>, RpcError>
where
    T: xdr_codec::Pack<Vec<u8>>,
{
    let mut payload = Vec::new();
    xdr_codec::pack(arg, &mut payload)?;

    let call_body = onc_rpc::CallBody::new(
        AWSFILE_PROGRAM_NUMBER,
        AWSFILE_PROGRAM_VERSION,
        operation_type as u32,
        onc_rpc::auth::AuthFlavor::AuthNone::<Vec<_>>(None),
        onc_rpc::auth::AuthFlavor::AuthNone::<Vec<_>>(None),
        payload,
    );

    let xid = rand::random::<u32>();
    onc_rpc::RpcMessage::new(xid, onc_rpc::MessageType::Call(call_body))
        .serialise()
        .map_err(|e| e.into())
}

async fn call_rpc<T>(request: Vec<u8>, stream: &mut dyn ProxyStream) -> Result<T, RpcError>
where
    T: for<'a> xdr_codec::Unpack<Cursor<&'a [u8]>>,
{
    stream.write_all(&request).await?;
    stream.flush().await?;
    let response_bytes = read_rpc_bytes(stream).await?;
    let response_rpc = onc_rpc::RpcMessage::try_from(response_bytes.as_slice())?;
    parse_rpc_response::<T>(&response_rpc)
}

pub fn parse_rpc_response<T>(response: &onc_rpc::RpcMessage<&[u8], &[u8]>) -> Result<T, RpcError>
where
    T: for<'a> xdr_codec::Unpack<Cursor<&'a [u8]>>,
{
    let Some(reply_body) = response.reply_body() else {
        Err(RpcError::MalformedResponse)?
    };

    let accepted_status = match reply_body {
        onc_rpc::ReplyBody::Accepted(reply) => reply.status(),
        onc_rpc::ReplyBody::Denied(_m) => Err(RpcError::Denied)?,
    };

    let payload = match accepted_status {
        onc_rpc::AcceptedStatus::Success(p) => p,
        onc_rpc::AcceptedStatus::GarbageArgs => Err(RpcError::GarbageArgs)?,
        onc_rpc::AcceptedStatus::ProgramUnavailable => Err(RpcError::ProgramUnavailable)?,
        onc_rpc::AcceptedStatus::ProgramMismatch { low, high } => Err(RpcError::ProgramMismatch {
            low: *low,
            high: *high,
        })?,
        onc_rpc::AcceptedStatus::ProcedureUnavailable => Err(RpcError::ProcedureUnavailable)?,
        onc_rpc::AcceptedStatus::SystemError => Err(RpcError::SystemError)?,
    };

    xdr_codec::unpack::<_, T>(&mut Cursor::new(payload)).map_err(|e| e.into())
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::awsfile_prot::{self, AwsFileReadBypassConfigArgs, BindResponse, ChannelConfigArgs};
    use crate::controller::DEFAULT_SCALE_UP_CONFIG;
    use crate::proxy_identifier;
    use crate::test_utils::*;
    use onc_rpc::{AuthError, RejectedReply};

    const XID: u32 = 1;

    #[test]
    fn test_bind_client_to_partition_request_serde() -> Result<(), RpcError> {
        let proxy_id = proxy_identifier::ProxyIdentifier::new();
        let request = create_rpc_request::<ProxyIdentifier>(
            &proxy_id.into(),
            OperationType::OP_BIND_CLIENT_TO_PARTITION,
        )?;

        let deserialized = onc_rpc::RpcMessage::try_from(request.as_slice())?;
        let deserialized_proxy_id = parse_bind_client_to_partition_request(&deserialized)?;

        assert_eq!(proxy_id.uuid, deserialized_proxy_id.uuid);
        assert_eq!(proxy_id.incarnation, deserialized_proxy_id.incarnation);
        Ok(())
    }

    #[test]
    fn test_channel_init_request_serde() -> Result<(), RpcError> {
        let minor_version = 1;

        let config =
            ChannelConfigArgs::AWSFILE_READ_BYPASS(AwsFileReadBypassConfigArgs { enabled: true });
        let channel_args = awsfile_prot::AwsFileChannelInitArgs {
            minor_version,
            configs: vec![config.clone()],
        };
        let request = create_rpc_request(&channel_args, OperationType::OP_AWS_FILE_CHANNEL_INIT)?;

        let deserialized = onc_rpc::RpcMessage::try_from(request.as_slice())?;
        let deserialized_arg = parse_channel_init_request(&deserialized)?;

        assert_eq!(minor_version, deserialized_arg.minor_version);
        assert_eq!(vec![config], deserialized_arg.configs);
        Ok(())
    }

    #[test]
    fn test_bind_client_to_partition_response_serde() -> Result<(), RpcError> {
        let partition_id = generate_partition_id();
        let partition_id_copy = awsfile_prot::NfsStatePartitionId(partition_id.0);

        let response = create_bind_client_to_partition_response(
            XID,
            BindResponse::READY(partition_id_copy),
            DEFAULT_SCALE_UP_CONFIG,
        )?;

        let deserialized = onc_rpc::RpcMessage::try_from(response.as_slice())?;
        let deserialized_response = parse_rpc_response::<BindClientResponse>(&deserialized)?;

        assert!(
            matches!(deserialized_response.bind_response, BindResponse::READY(id) if id.0 == partition_id.0)
        );
        Ok(())
    }

    #[test]
    fn test_rpc_response_missing_reply() -> Result<(), RpcError> {
        // Create a call message, which will error when parsed as a response
        let proxy_id = ProxyIdentifier {
            identifier: vec![],
            incarnation: vec![],
        };
        let malformed_response =
            create_rpc_request(&proxy_id, OperationType::OP_BIND_CLIENT_TO_PARTITION)?;
        let deserialized = onc_rpc::RpcMessage::try_from(malformed_response.as_slice())?;

        let result = parse_rpc_response::<BindClientResponse>(&deserialized);
        assert!(matches!(result, Err(RpcError::MalformedResponse)));
        Ok(())
    }

    #[test]
    fn test_rpc_response_denied() -> Result<(), RpcError> {
        let reply_body =
            onc_rpc::ReplyBody::Denied(RejectedReply::AuthError(AuthError::BadCredentials));
        let rpc_message = onc_rpc::RpcMessage::new(XID, onc_rpc::MessageType::Reply(reply_body));

        let result = parse_rpc_response::<BindClientResponse>(&rpc_message);
        assert!(matches!(result, Err(RpcError::Denied)));
        Ok(())
    }

    #[test]
    fn test_rpc_response_garbage_args() -> Result<(), RpcError> {
        let parse_result = generate_parse_bind_client_to_partition_response_result(
            onc_rpc::AcceptedStatus::GarbageArgs,
        );
        assert!(matches!(parse_result, Err(RpcError::GarbageArgs)));
        Ok(())
    }

    #[test]
    fn test_rpc_response_program_unavailable() -> Result<(), RpcError> {
        let parse_result = generate_parse_bind_client_to_partition_response_result(
            onc_rpc::AcceptedStatus::ProcedureUnavailable,
        );
        assert!(matches!(parse_result, Err(RpcError::ProcedureUnavailable)));
        Ok(())
    }

    #[test]
    fn test_rpc_response_program_mismatch() -> Result<(), RpcError> {
        let program_version_low = 10;
        let program_version_high = 100;
        let parse_result = generate_parse_bind_client_to_partition_response_result(
            onc_rpc::AcceptedStatus::ProgramMismatch {
                low: program_version_low,
                high: program_version_high,
            },
        );
        assert!(matches!(
            parse_result,
            Err(RpcError::ProgramMismatch { low: l, high: h }) if program_version_low == l && program_version_high == h));
        Ok(())
    }

    #[test]
    fn test_rpc_response_procedure_unavailable() -> Result<(), RpcError> {
        let parse_result = generate_parse_bind_client_to_partition_response_result(
            onc_rpc::AcceptedStatus::ProcedureUnavailable,
        );
        assert!(matches!(parse_result, Err(RpcError::ProcedureUnavailable)));
        Ok(())
    }

    #[test]
    fn test_rpc_response_system_error() -> Result<(), RpcError> {
        let parse_result = generate_parse_bind_client_to_partition_response_result(
            onc_rpc::AcceptedStatus::SystemError,
        );
        assert!(matches!(parse_result, Err(RpcError::SystemError)));
        Ok(())
    }
}
