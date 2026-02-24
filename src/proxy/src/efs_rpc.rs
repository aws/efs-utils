use std::io::Cursor;
use tokio::io::AsyncWriteExt;

use crate::connections::ProxyStream;
use crate::efs_prot;
use crate::efs_prot::{BindClientResponse, OperationType};
use crate::error::RpcError;
use crate::proxy_identifier::ProxyIdentifier;
use crate::rpc;
use log::info;

pub const EFS_PROGRAM_NUMBER: u32 = 100200;
pub const EFS_PROGRAM_VERSION: u32 = 1;

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct PartitionId {
    pub id: [u8; 64],
}

pub async fn bind_client_to_partition(
    proxy_id: ProxyIdentifier,
    stream: &mut dyn ProxyStream,
    csi_driver_version: Option<String>,
) -> Result<BindClientResponse, RpcError> {
    let request = create_bind_client_to_partition_request(&proxy_id, csi_driver_version)?;
    stream.write_all(&request).await?;
    stream.flush().await?;

    let response_bytes = rpc::read_rpc_bytes(stream).await?;
    let response = onc_rpc::RpcMessage::try_from(response_bytes.as_slice())?;

    parse_bind_client_to_partition_response(&response)
}

pub fn create_bind_client_to_partition_request(
    proxy_id: &ProxyIdentifier,
    csi_driver_version: Option<String>
) -> Result<Vec<u8>, RpcError> {
    let payload = efs_prot::ProxyIdentifier {
        identifier: proxy_id.uuid.as_bytes().to_vec(),
        incarnation: proxy_id.incarnation.to_be_bytes().to_vec(),
    };
    let mut payload_buf = Vec::new();
    xdr_codec::pack(&payload, &mut payload_buf)?;
    match csi_driver_version {
        Some(version) => {
            let connection_metrics = efs_prot::ConnectionMetrics {
                csi_driver_version: version.as_bytes().to_vec(),
            };
            xdr_codec::pack(&connection_metrics, &mut payload_buf)?;
            info!("CSI Driver Version from create bind client to partion: {}", version)
        },
        None => info!("CSI Driver Version fom create bind client to partion not provided."),
    }

    let call_body = onc_rpc::CallBody::new(
        EFS_PROGRAM_NUMBER,
        EFS_PROGRAM_VERSION,
        OperationType::OP_BIND_CLIENT_TO_PARTITION as u32,
        onc_rpc::auth::AuthFlavor::AuthNone::<Vec<_>>(None),
        onc_rpc::auth::AuthFlavor::AuthNone::<Vec<_>>(None),
        payload_buf,
    );

    let xid = rand::random::<u32>();
    onc_rpc::RpcMessage::new(xid, onc_rpc::MessageType::Call(call_body))
        .serialise()
        .map_err(|e| e.into())
}

pub fn parse_bind_client_to_partition_response(
    response: &onc_rpc::RpcMessage<&[u8], &[u8]>,
) -> Result<BindClientResponse, RpcError> {
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

    xdr_codec::unpack::<_, BindClientResponse>(&mut Cursor::new(payload)).map_err(|e| e.into())
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::efs_prot::BindResponse;

    use crate::controller::DEFAULT_SCALE_UP_CONFIG;
    use crate::test_utils::*;
    use onc_rpc::{AuthError, RejectedReply};

    const XID: u32 = 1;

    #[test]
    fn test_request_serde() -> Result<(), RpcError> {
        let proxy_id = ProxyIdentifier::new();
        let csi_driver_version = Some("v9.9.9".to_string());
        let request = create_bind_client_to_partition_request(&proxy_id, csi_driver_version.clone())?;

        let deserialized = onc_rpc::RpcMessage::try_from(request.as_slice())?;
        let (deserialized_proxy_id, deserialized_metrics) = parse_bind_client_to_partition_request(&deserialized)?;

        assert_eq!(proxy_id.uuid, deserialized_proxy_id.uuid);
        assert_eq!(proxy_id.incarnation, deserialized_proxy_id.incarnation);
        assert_eq!(deserialized_metrics.csi_driver_version, csi_driver_version.unwrap_or_default().as_bytes().to_vec());
        Ok(())
    }

    #[test]
    fn test_request_serde_with_no_driver_version() -> Result<(), RpcError> {
        let proxy_id = ProxyIdentifier::new();
        let request = create_bind_client_to_partition_request(&proxy_id, None)?;

        let deserialized = onc_rpc::RpcMessage::try_from(request.as_slice())?;
        let deserialized_proxy_id = parse_bind_client_to_partition_request_with_no_driver_version(&deserialized)?;

        assert_eq!(proxy_id.uuid, deserialized_proxy_id.uuid);
        assert_eq!(proxy_id.incarnation, deserialized_proxy_id.incarnation);
        Ok(())
    }
    
    #[test]
    fn test_response_serde() -> Result<(), RpcError> {
        let partition_id = generate_partition_id();
        let partition_id_copy = efs_prot::PartitionId(partition_id.0);

        let response = create_bind_client_to_partition_response(
            XID,
            BindResponse::READY(partition_id_copy),
            DEFAULT_SCALE_UP_CONFIG,
        )?;

        let deserialized = onc_rpc::RpcMessage::try_from(response.as_slice())?;
        let deserialized_response = parse_bind_client_to_partition_response(&deserialized)?;

        assert!(
            matches!(deserialized_response.bind_response, BindResponse::READY(id) if id.0 == partition_id.0)
        );
        Ok(())
    }

    #[test]
    fn test_parse_bind_client_to_partition_response_missing_reply() -> Result<(), RpcError> {
        // Create a call message, which will error when parsed as a response
        let malformed_response = create_bind_client_to_partition_request(&ProxyIdentifier::new(), None)?;
        let deserialized = onc_rpc::RpcMessage::try_from(malformed_response.as_slice())?;

        let result = parse_bind_client_to_partition_response(&deserialized);
        assert!(matches!(result, Err(RpcError::MalformedResponse)));
        Ok(())
    }

    #[test]
    fn test_parse_bind_client_to_partition_response_denied() -> Result<(), RpcError> {
        let reply_body =
            onc_rpc::ReplyBody::Denied(RejectedReply::AuthError(AuthError::BadCredentials));
        let rpc_message = onc_rpc::RpcMessage::new(XID, onc_rpc::MessageType::Reply(reply_body));

        let result = parse_bind_client_to_partition_response(&rpc_message);
        assert!(matches!(result, Err(RpcError::Denied)));
        Ok(())
    }

    #[test]
    fn test_parse_bind_client_to_partition_response_garbage_args() -> Result<(), RpcError> {
        let parse_result = generate_parse_bind_client_to_partition_response_result(
            onc_rpc::AcceptedStatus::GarbageArgs,
        );
        assert!(matches!(parse_result, Err(RpcError::GarbageArgs)));
        Ok(())
    }

    #[test]
    fn test_parse_bind_client_to_partition_response_program_unavailable() -> Result<(), RpcError> {
        let parse_result = generate_parse_bind_client_to_partition_response_result(
            onc_rpc::AcceptedStatus::ProcedureUnavailable,
        );
        assert!(matches!(parse_result, Err(RpcError::ProcedureUnavailable)));
        Ok(())
    }

    #[test]
    fn test_parse_bind_client_to_partition_response_program_mismatch() -> Result<(), RpcError> {
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
    fn test_parse_bind_client_to_partition_response_procedure_unavailable() -> Result<(), RpcError>
    {
        let parse_result = generate_parse_bind_client_to_partition_response_result(
            onc_rpc::AcceptedStatus::ProcedureUnavailable,
        );
        assert!(matches!(parse_result, Err(RpcError::ProcedureUnavailable)));
        Ok(())
    }

    #[test]
    fn test_parse_bind_client_to_partition_response_system_error() -> Result<(), RpcError> {
        let parse_result = generate_parse_bind_client_to_partition_response_result(
            onc_rpc::AcceptedStatus::SystemError,
        );
        assert!(matches!(parse_result, Err(RpcError::SystemError)));
        Ok(())
    }
}
