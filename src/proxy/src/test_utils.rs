// Testing utility used for both unit and integration tests.
//

// Using #[allow(dead_code)] is a common and acceptable practice for test utility functions.
#![allow(dead_code)]

use crate::{
    config_parser::ProxyConfig,
    efs_prot::{self, BindClientResponse, BindResponse, ScaleUpConfig},
    efs_rpc::{parse_bind_client_to_partition_response, EFS_PROGRAM_NUMBER, EFS_PROGRAM_VERSION},
    error::RpcError,
    proxy_identifier::ProxyIdentifier,
    tls::{create_config_builder, InsecureAcceptAllCertificatesHandler, TlsConfig},
};
use anyhow::Result;
use rand::{Rng, RngCore};
use s2n_tls::config::Config;
use std::{io::Cursor, path::Path};
use tokio::net::TcpListener;

// Proxy Configuration testing utils
//

pub static TEST_CONFIG_PATH: &str = "tests/certs/test_config.ini";
const XID: u32 = 1;

pub fn get_test_config() -> ProxyConfig {
    ProxyConfig::from_path(Path::new(TEST_CONFIG_PATH)).expect("Could not parse test config.")
}

pub async fn get_client_config() -> Result<Config> {
    let tls_config = TlsConfig::new_from_config(&get_test_config()).await?;
    let builder = create_config_builder(&tls_config);

    let config = builder.build()?;
    Ok(config)
}

pub async fn get_server_config() -> Result<Config> {
    let tls_config = TlsConfig::new_from_config(&get_test_config()).await?;
    let mut builder = create_config_builder(&tls_config);

    // Accept all client certificates
    builder.set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})?;

    let config = builder.build()?;
    Ok(config)
}

pub async fn find_available_port() -> (TcpListener, u16) {
    for port in 10000..15000 {
        match TcpListener::bind(("127.0.0.1", port)).await {
            Ok(v) => {
                return (v, port);
            }
            Err(_) => continue,
        }
    }
    panic!("Failed to find port");
}

/// generate_rpc_msg_fragments: Generates message fragments for tests
///
/// This function generates a set of message fragments from random data. The fragments are constructed
/// in a way that they can be later assembled  into the full long message data
/// function.
///
/// # Arguments
/// * `size` - The total size of the message.
/// * `num_fragments` - The number of fragments to generate.
///
pub fn generate_rpc_msg_fragments(size: usize, num_fragments: usize) -> (bytes::BytesMut, Vec<u8>) {
    let mut rng = rand::thread_rng();
    let data: Vec<u8> = (0..size).map(|_| rng.gen()).collect();

    let fragment_data_size = data.len() / num_fragments;

    let mut data_buffer = bytes::BytesMut::new();
    for i in 0..num_fragments {
        let start_idx = i * fragment_data_size;
        let end_idx = std::cmp::min(size, start_idx + fragment_data_size);
        let fragment_data = &data[start_idx..end_idx];

        let mut header = (end_idx - start_idx) as u32;
        if end_idx == size {
            header |= 1 << 31;
        }

        data_buffer.extend_from_slice(&header.to_be_bytes());
        data_buffer.extend_from_slice(fragment_data);
    }
    assert_eq!(data_buffer.len(), (num_fragments * 4) + data.len());

    (data_buffer, data)
}

pub fn generate_partition_id() -> efs_prot::PartitionId {
    let mut bytes = [0u8; efs_prot::PARTITION_ID_LENGTH as usize];
    rand::thread_rng().fill_bytes(&mut bytes);
    efs_prot::PartitionId(bytes)
}

pub fn parse_bind_client_to_partition_request(
    request: &onc_rpc::RpcMessage<&[u8], &[u8]>,
) -> Result<(ProxyIdentifier, efs_prot::ConnectionMetrics), RpcError> {
    let call_body = request.call_body().expect("not a call rpc");

    if EFS_PROGRAM_NUMBER != call_body.program()
        || EFS_PROGRAM_VERSION != call_body.program_version()
    {
        return Err(RpcError::GarbageArgs);
    }

    let mut payload = Cursor::new(call_body.payload());
    let raw_proxy_id = xdr_codec::unpack::<_, efs_prot::ProxyIdentifier>(&mut payload)?;
    let connection_metrics = xdr_codec::unpack::<_, efs_prot::ConnectionMetrics>(&mut payload)?;

    Ok((
        ProxyIdentifier {
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
        },
        connection_metrics
    ))
}

pub fn parse_bind_client_to_partition_request_with_no_driver_version(
    request: &onc_rpc::RpcMessage<&[u8], &[u8]>,
) -> Result<ProxyIdentifier, RpcError> {
    let call_body = request.call_body().expect("not a call rpc");

    if EFS_PROGRAM_NUMBER != call_body.program()
        || EFS_PROGRAM_VERSION != call_body.program_version()
    {
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

pub fn generate_parse_bind_client_to_partition_response_result(
    accepted_status: onc_rpc::AcceptedStatus<Vec<u8>>,
) -> Result<BindClientResponse, RpcError> {
    let response =
        create_bind_client_to_partition_response_from_accepted_status(XID, accepted_status)?;
    let deserialized = onc_rpc::RpcMessage::try_from(response.as_slice())?;
    parse_bind_client_to_partition_response(&deserialized)
}
