// Testing utility used for both unit and integration tests.
//

// Using #[allow(dead_code)] is a common and acceptable practice for test utility functions.
#![allow(dead_code)]

use crate::{
    awsfile_prot::{
        self, AwsFileChannelInitArgs, AwsFileChannelInitRes, BindClientResponse, BindResponse,
        ScaleUpConfig,
    },
    awsfile_rpc::{parse_rpc_response, AWSFILE_PROGRAM_NUMBER, AWSFILE_PROGRAM_VERSION},
    config_parser::ProxyConfig,
    error::RpcError,
    nfs::{
        nfs4_1_xdr,
        nfs_compound::{NfsMetadata, RefNfsCompoundInfo},
    },
    proxy_identifier::ProxyIdentifier,
    tls::{create_config_builder, InsecureAcceptAllCertificatesHandler, TlsConfig},
};
use anyhow::Result;
use bytes::BytesMut;
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

    let base_fragment_size = data.len() / num_fragments;
    let remainder = data.len() % num_fragments;

    let mut data_buffer = bytes::BytesMut::new();
    let mut start_idx = 0;

    for i in 0..num_fragments {
        let current_fragment_size = if i < remainder {
            base_fragment_size + 1
        } else {
            base_fragment_size
        };

        let end_idx = start_idx + current_fragment_size;
        let fragment_data = &data[start_idx..end_idx];

        let mut header = current_fragment_size as u32;
        if i == num_fragments - 1 {
            header |= 1 << 31;
        }

        data_buffer.extend_from_slice(&header.to_be_bytes());
        data_buffer.extend_from_slice(fragment_data);

        start_idx = end_idx;
    }

    assert_eq!(start_idx, data.len());
    assert_eq!(data_buffer.len(), (num_fragments * 4) + data.len());

    (data_buffer, data)
}

pub fn generate_partition_id() -> awsfile_prot::NfsStatePartitionId {
    let mut bytes = [0u8; awsfile_prot::NFS_STATE_PARTITION_ID_LENGTH as usize];
    rand::thread_rng().fill_bytes(&mut bytes);
    awsfile_prot::NfsStatePartitionId(bytes)
}

pub fn parse_bind_client_to_partition_request(
    request: &onc_rpc::RpcMessage<&[u8], &[u8]>,
) -> Result<ProxyIdentifier, RpcError> {
    let call_body = request.call_body().expect("not a call rpc");

    if AWSFILE_PROGRAM_NUMBER != call_body.program()
        || AWSFILE_PROGRAM_VERSION != call_body.program_version()
    {
        return Err(RpcError::GarbageArgs);
    }

    let mut payload = Cursor::new(call_body.payload());
    let raw_proxy_id = xdr_codec::unpack::<_, awsfile_prot::ProxyIdentifier>(&mut payload)?;
    Ok(raw_proxy_id.try_into()?)
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

pub fn parse_channel_init_request(
    request: &onc_rpc::RpcMessage<&[u8], &[u8]>,
) -> Result<AwsFileChannelInitArgs, RpcError> {
    let call_body = request.call_body().expect("not a call rpc");

    if AWSFILE_PROGRAM_NUMBER != call_body.program()
        || AWSFILE_PROGRAM_VERSION != call_body.program_version()
    {
        return Err(RpcError::GarbageArgs);
    }

    let mut payload = Cursor::new(call_body.payload());
    Ok(xdr_codec::unpack::<_, AwsFileChannelInitArgs>(
        &mut payload,
    )?)
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
    parse_rpc_response::<BindClientResponse>(&deserialized)
}

pub fn create_test_compound_info(
    op_vec: Vec<nfs4_1_xdr::nfs_opnum4>,
) -> RefNfsCompoundInfo<nfs4_1_xdr::COMPOUND4args> {
    let nfs_metadata = NfsMetadata {
        session_id: nfs4_1_xdr::sessionid4([0; nfs4_1_xdr::NFS4_SESSIONID_SIZE as usize]),
        slot_id: 1,
        sequence_id: 1,
    };

    let compound = nfs4_1_xdr::COMPOUND4args {
        tag: nfs4_1_xdr::utf8string(vec![]),
        minorversion: 1,
        argarray: vec![],
    };

    RefNfsCompoundInfo::new(nfs_metadata, compound, op_vec, BytesMut::new())
}

pub fn create_channel_init_response(
    xid: u32,
    channel_init_res: AwsFileChannelInitRes,
) -> Result<Vec<u8>, RpcError> {
    let mut payload = Vec::new();
    xdr_codec::pack(&channel_init_res, &mut payload)?;

    let accepted_reply = onc_rpc::AcceptedReply::new(
        onc_rpc::auth::AuthFlavor::AuthNone::<Vec<_>>(None),
        onc_rpc::AcceptedStatus::Success(payload),
    );

    let reply_body = onc_rpc::ReplyBody::Accepted(accepted_reply);
    onc_rpc::RpcMessage::new(xid, onc_rpc::MessageType::Reply(reply_body))
        .serialise()
        .map_err(|e| e.into())
}

/// Mock S3DataReader that returns position-encoded data and tracks call count.
/// Used by readahead cache and file readahead state tests.
#[derive(Clone)]
pub struct CountingS3DataReader {
    pub call_count: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl CountingS3DataReader {
    pub fn new() -> Self {
        Self {
            call_count: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    pub fn calls(&self) -> u64 {
        self.call_count.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl crate::util::s3_data_reader::S3DataReader for CountingS3DataReader {
    async fn spawn_read_task(
        &self,
        s3_data_locator: crate::nfs::nfs4_1_xdr::awsfile_bypass_data_locator,
        _read_bypass_context: std::sync::Arc<crate::util::read_bypass_context::ReadBypassContext>,
    ) -> tokio::task::JoinHandle<Result<bytes::Bytes, crate::aws::s3_client::S3ClientError>> {
        self.call_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let count = s3_data_locator.count as usize;
        let offset = s3_data_locator.offset;
        tokio::spawn(async move {
            let data: Vec<u8> = (0..count)
                .map(|i| ((offset as usize + i) % 256) as u8)
                .collect();
            Ok(bytes::Bytes::from(data))
        })
    }
}
