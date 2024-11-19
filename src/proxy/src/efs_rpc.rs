use std::io::Cursor;
use tokio::io::AsyncWriteExt;

use crate::connections::ProxyStream;
use crate::efs_prot;
use crate::efs_prot::BindClientResponse;
use crate::efs_prot::OperationType;
use crate::error::RpcError;
use crate::proxy_identifier::ProxyIdentifier;
use crate::rpc;

const PROGRAM_NUMBER: u32 = 100200;
const PROGRAM_VERSION: u32 = 1;

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct PartitionId {
    pub id: [u8; 64],
}

pub async fn bind_client_to_partition(
    proxy_id: ProxyIdentifier,
    stream: &mut dyn ProxyStream,
) -> Result<BindClientResponse, RpcError> {
    let request = create_bind_client_to_partition_request(&proxy_id)?;
    stream.write_all(&request).await?;
    stream.flush().await?;

    let response_bytes = rpc::read_rpc_bytes(stream).await?;
    let response = onc_rpc::RpcMessage::try_from(response_bytes.as_slice())?;

    parse_bind_client_to_partition_response(&response)
}

pub fn create_bind_client_to_partition_request(
    proxy_id: &ProxyIdentifier,
) -> Result<Vec<u8>, RpcError> {
    let payload = efs_prot::ProxyIdentifier {
        identifier: proxy_id.uuid.as_bytes().to_vec(),
        incarnation: proxy_id.incarnation.to_be_bytes().to_vec(),
    };
    let mut payload_buf = Vec::new();
    xdr_codec::pack(&payload, &mut payload_buf)?;

    let call_body = onc_rpc::CallBody::new(
        PROGRAM_NUMBER,
        PROGRAM_VERSION,
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
    use crate::controller::tests::TestService;
    use crate::controller::DEFAULT_SCALE_UP_CONFIG;
    use crate::efs_prot::BindResponse;
    use crate::efs_prot::ScaleUpConfig;
    use crate::tls::tests::get_client_config;
    use onc_rpc::{AuthError, RejectedReply};
    use rand::RngCore;
    use s2n_tls_tokio::TlsConnector;
    use tokio::net::TcpStream;

    const XID: u32 = 1;

    pub fn parse_bind_client_to_partition_request(
        request: &onc_rpc::RpcMessage<&[u8], &[u8]>,
    ) -> Result<ProxyIdentifier, RpcError> {
        let call_body = request.call_body().expect("not a call rpc");

        if PROGRAM_NUMBER != call_body.program() || PROGRAM_VERSION != call_body.program_version() {
            return Err(RpcError::GarbageArgs);
        }

        let mut payload = Cursor::new(call_body.payload());
        let raw_proxy_id = xdr_codec::unpack::<_, efs_prot::ProxyIdentifier>(&mut payload)?;

        Ok(ProxyIdentifier {
            uuid: uuid::Builder::from_bytes(
                raw_proxy_id
                    .identifier
                    .try_into()
                    .expect("Failed not convert vec to sized array"),
            )
            .into_uuid(),
            incarnation: i64::from_be_bytes(
                raw_proxy_id
                    .incarnation
                    .try_into()
                    .expect("Failed to convert vec to sized array"),
            ),
        })
    }

    pub fn create_bind_client_to_partition_response(
        xid: u32,
        bind_response: BindResponse,
        scale_up_config: ScaleUpConfig,
    ) -> Result<Vec<u8>, RpcError> {
        let mut payload_buf = Vec::new();

        let response = BindClientResponse {
            bind_response,
            scale_up_config,
        };
        xdr_codec::pack(&response, &mut payload_buf)?;

        create_bind_client_to_partition_response_from_accepted_status(
            xid,
            onc_rpc::AcceptedStatus::Success(payload_buf),
        )
    }

    pub fn create_bind_client_to_partition_response_from_accepted_status(
        xid: u32,
        accepted_status: onc_rpc::AcceptedStatus<Vec<u8>>,
    ) -> Result<Vec<u8>, RpcError> {
        let reply_body = onc_rpc::ReplyBody::Accepted(onc_rpc::AcceptedReply::new(
            onc_rpc::auth::AuthFlavor::AuthNone::<Vec<_>>(None),
            accepted_status,
        ));

        onc_rpc::RpcMessage::new(xid, onc_rpc::MessageType::Reply(reply_body))
            .serialise()
            .map_err(|e| e.into())
    }

    fn generate_parse_bind_client_to_partition_response_result(
        accepted_status: onc_rpc::AcceptedStatus<Vec<u8>>,
    ) -> Result<BindClientResponse, RpcError> {
        let response =
            create_bind_client_to_partition_response_from_accepted_status(XID, accepted_status)?;
        let deserialized = onc_rpc::RpcMessage::try_from(response.as_slice())?;
        parse_bind_client_to_partition_response(&deserialized)
    }

    pub fn generate_partition_id() -> efs_prot::PartitionId {
        let mut bytes = [0u8; efs_prot::PARTITION_ID_LENGTH as usize];
        rand::thread_rng().fill_bytes(&mut bytes);
        efs_prot::PartitionId(bytes)
    }

    #[tokio::test]
    async fn test_bind_client_to_partition() {
        let server = TestService::new(true).await;
        let tcp_stream = TcpStream::connect(("127.0.0.1", server.listen_port))
            .await
            .expect("Could not connect to test server.");

        let connector =
            TlsConnector::new(get_client_config().await.expect("Failed to read config"));
        let mut tls_stream = connector
            .connect("localhost", tcp_stream)
            .await
            .expect("Failed to establish TLS Connection");

        let response = bind_client_to_partition(ProxyIdentifier::new(), &mut tls_stream)
            .await
            .expect("bind_client_to_partition request failed");

        let partition_id = match response.bind_response {
            BindResponse::READY(id) => PartitionId { id: id.0 },
            _ => panic!(),
        };

        assert_eq!(
            server
                .partition_ids
                .get(1)
                .expect("Service has no partition IDs"),
            &partition_id
        );
        server.shutdown().await;
    }

    #[test]
    fn test_request_serde() -> Result<(), RpcError> {
        let proxy_id = ProxyIdentifier::new();
        let request = create_bind_client_to_partition_request(&proxy_id)?;

        let deserialized = onc_rpc::RpcMessage::try_from(request.as_slice())?;
        let deserialized_proxy_id = parse_bind_client_to_partition_request(&deserialized)?;

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
        let malformed_response = create_bind_client_to_partition_request(&ProxyIdentifier::new())?;
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
