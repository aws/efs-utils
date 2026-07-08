//! ReadBypassAgent is a component performing data reads from S3 buckets ("bypass reads"), based on locations received from ReadBypassServerDispatcher
//!

#![allow(unused)]

use std::{
    collections::HashMap,
    future::Future,
    sync::{Arc, Mutex},
};

use bytes::{BufMut, Bytes, BytesMut};
use futures::FutureExt;
use log::{debug, error, info, trace, warn};
use tokio::sync::mpsc;
use xdr_codec::Pack;

use crate::{
    aws::s3_client::{S3Client, S3ClientError},
    nfs::{
        nfs4_1_xdr::{
            awsfile_bypass_data_locator, nfs_fh4, nfs_opnum4, nfs_resop4, nfsstat4, utf8string,
            AWSFILE_READ_BYPASS4res, COMPOUND4res, DataPayload, READ4res, READ4resok,
        },
        nfs_compound::{PackableNfsCompoundInfo, RefNfsCompound, RefNfsCompoundInfo},
        nfs_encoder::NfsMessageEncoder,
        nfs_rpc_envelope::{NfsRpcEnvelope, NfsRpcInfo},
    },
    proxy_task::ConnectionMessage,
    read_ahead::{error::ReadAheadCacheError, readahead_cache::FileReadAheadCache},
    rpc::{rpc::RpcBatch, rpc_encoder::RpcEncoder, rpc_envelope::RpcMessageParams},
    shutdown::ShutdownHandle,
    util::{
        read_bypass_context::{ReadBypassContext, ReadBypassMessage},
        read_bypass_request_context::ReadBypassRequestContext,
        s3_data_reader::{S3DataReader, S3ReadBypassReader},
    },
};
use crate::{ctx_debug, ctx_error, ctx_trace, ctx_warn, util::fh_denylist::FileHandle};

#[derive(Debug, thiserror::Error)]
pub enum ReadBypassAgentError {
    #[error("Error during dispatching message to NFSClient writer")]
    DispatchingError,
    #[error("ReadBypass has failed due to invalid compound")]
    InvalidCompound,
    #[error("Error during joining S3 Reader task")]
    JoinFailure,
    #[error("Error during encoding NFS response for NFSClient")]
    NfsResponseEncodingError,
    #[error("ReadBypass has failed due to operation conversion failure")]
    OperationConversionFailure,
    #[error("S3 read failed: {0}")]
    S3Error(S3ClientError),
    #[error("Cache read failed due to cache error: {0}")]
    CacheInternalError(ReadAheadCacheError),
    #[error("Data evicted before read completed")]
    DataEvicted,
    #[error("Unsupported message")]
    UnsupportedMessage,
}

#[async_trait::async_trait]
pub trait S3Reader: Send + Sync {
    async fn read_data(
        &self,
        read_bypass_request_context: Arc<ReadBypassRequestContext>,
        s3_data_locator: awsfile_bypass_data_locator,
        filehandle: nfs_fh4,
        file_size: u64,
    ) -> Result<Option<Bytes>, ReadBypassAgentError>;
}

pub struct DirectS3Reader {
    pub s3_data_reader: Box<dyn S3DataReader>,
}

#[async_trait::async_trait]
impl S3Reader for DirectS3Reader {
    async fn read_data(
        &self,
        read_bypass_request_context: Arc<ReadBypassRequestContext>,
        s3_data_locator: awsfile_bypass_data_locator,
        _filehandle: nfs_fh4,
        _file_size: u64,
    ) -> Result<Option<Bytes>, ReadBypassAgentError> {
        ctx_debug!(
            read_bypass_request_context,
            "Reading data directly from S3 for s3key={} offset={} count={}",
            String::from_utf8_lossy(&s3_data_locator.s3_key),
            s3_data_locator.offset,
            s3_data_locator.count
        );
        let join_handle = self
            .s3_data_reader
            .spawn_read_task(
                s3_data_locator,
                read_bypass_request_context.read_bypass_context.clone(),
            )
            .await;

        match join_handle.await {
            Ok(s3_result) => match s3_result {
                Ok(data) => Ok(Some(data)),
                Err(e) => Err(ReadBypassAgentError::S3Error(e)),
            },
            Err(_) => Err(ReadBypassAgentError::JoinFailure),
        }
    }
}

pub struct CachedS3Reader {
    pub readahead_cache: Arc<FileReadAheadCache>,
}

#[async_trait::async_trait]
impl S3Reader for CachedS3Reader {
    async fn read_data(
        &self,
        read_bypass_request_context: Arc<ReadBypassRequestContext>,
        s3_data_locator: awsfile_bypass_data_locator,
        filehandle: nfs_fh4,
        file_size: u64,
    ) -> Result<Option<Bytes>, ReadBypassAgentError> {
        ctx_debug!(
            read_bypass_request_context,
            "Attempting to read data through cache for s3key={} offset={} count={}",
            String::from_utf8_lossy(&s3_data_locator.s3_key),
            s3_data_locator.offset,
            s3_data_locator.count
        );
        match self
            .readahead_cache
            .process_read_request(
                read_bypass_request_context.clone(),
                filehandle,
                file_size,
                s3_data_locator.clone(),
            )
            .await
        {
            Ok(data) => Ok(data),
            Err(e) if e.message.contains("Data evicted") => Err(ReadBypassAgentError::DataEvicted),
            Err(e) => Err(ReadBypassAgentError::CacheInternalError(e)),
        }
    }
}

pub struct ReadBypassAgent {
    // ReadBypassContext is stored in Arc since it is shared between multiple components and can
    // change dynamically
    pub read_bypass_context: Arc<ReadBypassContext>,
    // S3 reader for handling read operations (cached or direct)
    pub s3_reader: Arc<dyn S3Reader>,
}

impl ReadBypassAgent {
    pub fn new(read_bypass_context: Arc<ReadBypassContext>, s3_reader: Arc<dyn S3Reader>) -> Self {
        Self {
            read_bypass_context,
            s3_reader,
        }
    }

    /// Running ReadBypassAgent
    ///
    pub async fn run(
        mut read_bypass_agent: ReadBypassAgent,
        message_queue: mpsc::Receiver<ReadBypassMessage>,
        nfs_client_sender: mpsc::Sender<ConnectionMessage>,
        shutdown: ShutdownHandle,
    ) {
        let shutdown = shutdown.clone();

        // Using a pair of shutdown sender/receiver to share with other tasks spawned from ReadBypassAgent,
        // particularly ones for S3 accesses and responses to NFSClient
        let (rba_shutdown_sender, mut rba_shutdown_receiver) = mpsc::channel::<u8>(1);

        let shutdown_sender_clone = rba_shutdown_sender.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = read_bypass_agent.run_message_loop(message_queue, nfs_client_sender, shutdown_sender_clone) => info!("ReadBypassAgent stopped"),
                _ = shutdown.cancellation_token.cancelled() => info!("ReadBypassAgent stopped by ShutdownHandle"),
            }
        });

        drop(rba_shutdown_sender);
        // Wait until all of the tasks spawned from RBA are done
        rba_shutdown_receiver.recv().await;
    }

    /// Main event loop
    ///
    pub async fn run_message_loop(
        &mut self,
        mut message_queue: mpsc::Receiver<ReadBypassMessage>,
        nfs_client_sender: mpsc::Sender<ConnectionMessage>,
        _shutdown_sender: mpsc::Sender<u8>,
    ) {
        info!("ReadBypassAgent message loop is started.");
        loop {
            let Some(mut message) = message_queue.recv().await else {
                debug!("Message sender for ReadBypassAgent is dropped");
                break;
            };

            if !Self::is_message_supported(&message) {
                error!(
                    "Unsupported message is detected, it might by a sign of a bug in efs-utils \
                     software: consider disabling ReadBypass functionality."
                );
                continue;
            }

            let s3_reader = self.s3_reader.clone();
            let read_bypass_context = self.read_bypass_context.clone();
            let nfs_client_sender = nfs_client_sender.clone();

            // Extract RPC XID from the message
            let rpc_xid = message
                .envelopes
                .first()
                .and_then(|env| {
                    if let RpcMessageParams::ReplyParams(params) = &env.header.params {
                        Some(params.xid)
                    } else {
                        None
                    }
                })
                .unwrap_or(0);

            tokio::spawn(async move {
                // Create request context with RPC XID
                let read_bypass_request_context =
                    Arc::new(ReadBypassRequestContext::new(read_bypass_context, rpc_xid));
                let nfs_client_sender_clone = nfs_client_sender.clone();
                let original_message = NfsRpcInfo {
                    envelopes: vec![message.envelopes[0].clone()],
                };
                let ctx_clone = read_bypass_request_context.clone();

                let result = std::panic::AssertUnwindSafe(Self::process_message(
                    read_bypass_request_context,
                    message,
                    s3_reader,
                    nfs_client_sender,
                ))
                .catch_unwind()
                .await;

                if result.is_err() {
                    ctx_error!(ctx_clone, "ReadBypass task panicked, sending NFS4ERR_DELAY and denylisting filehandle");
                    // Denylist the filehandle so future reads go through normal NFS path
                    if let Some(RefNfsCompound::Compound4res(compound_info)) =
                        original_message.envelopes.first().map(|e| &e.body)
                    {
                        for op in &compound_info.compound.resarray {
                            if let nfs_resop4::OP_AWSFILE_READ_BYPASS(
                                AWSFILE_READ_BYPASS4res::NFS4ERR_AWSFILE_BYPASS(res),
                            ) = op
                            {
                                ctx_clone.fh_denylist.add(res.filehandle.clone());
                                break;
                            }
                        }
                    }
                    let _ = Self::respond_failure_to_nfs_client(
                        ctx_clone,
                        original_message,
                        nfs_client_sender_clone,
                    )
                    .await;
                }
            });
        }
    }

    /// Since ReadBypass is a best effort performance optimization, we do not want to support all
    /// possible combinations of messages, just the ones which bring the performance benefit It
    /// helps to keep implementation simple.
    /// Unsupported messages are not expected here, and might happen only due to bugs, so we report them as Errors.
    ///
    fn is_message_supported(message: &ReadBypassMessage) -> bool {
        if (message.envelopes.len() != 1) {
            error!("ReadBypassAgent is expecting to have one compound in the batch!");
            return false;
        }

        let envelope = message
            .envelopes
            .first()
            .expect("ReadBypassAgent is expecting to have one compound in the batch!");

        if let RefNfsCompound::Compound4res(compound_info) = &envelope.body {
            let num_accepted_bypass_ops = compound_info
                .compound
                .resarray
                .iter()
                .filter(|op| {
                    matches!(
                        op,
                        nfs_resop4::OP_AWSFILE_READ_BYPASS(
                            AWSFILE_READ_BYPASS4res::NFS4ERR_AWSFILE_BYPASS(_)
                        )
                    )
                })
                .count();
            if num_accepted_bypass_ops != 1 {
                error!("ReadBypassAgent supports only one ReadBypass operation per compound");
                return false;
            }
        } else {
            error!("Unsupported compound type!");
            return false;
        }
        return true;
    }

    /// Asynchronously process message received from Dispatcher and respond to NFS Client
    ///    
    async fn process_message(
        read_bypass_request_context: Arc<ReadBypassRequestContext>,
        mut message: ReadBypassMessage,
        s3_reader: Arc<dyn S3Reader>,
        nfs_client_sender: mpsc::Sender<ConnectionMessage>,
    ) {
        let mut envelope = message
            .envelopes
            .first_mut()
            .expect("ReadBypassAgent is expecting to have one compound in the batch!");

        if let RefNfsCompound::Compound4res(compound_info) = &mut envelope.body {
            match Self::process_compound(
                read_bypass_request_context.clone(),
                &compound_info,
                s3_reader.clone(),
            )
            .await
            {
                Ok(res) => {
                    if let Some(response_compound) = res {
                        match Self::respond_success_to_nfs_client(
                            read_bypass_request_context.clone(),
                            message,
                            response_compound,
                            nfs_client_sender,
                        )
                        .await
                        {
                            Ok(_) => {
                                ctx_debug!(
                                    read_bypass_request_context,
                                    "ReadBypassAgent successfully processed compound"
                                )
                            }
                            Err(e) => {
                                match e {
                                    ReadBypassAgentError::DispatchingError => {
                                        ctx_debug!(read_bypass_request_context,
                                            "ReadBypassAgent failed to dispatch message to NFSClient: channel might be closed.")
                                    }
                                    _ => {
                                        ctx_error!(
                                            read_bypass_request_context,
                                            "Failure during attempt to send message to NFSClient,\
                                            it might by a sign of a bug in efs-utils \
                                            software: consider disabling ReadBypass functionality."
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    match e {
                        ReadBypassAgentError::InvalidCompound => {
                            ctx_error!(read_bypass_request_context,
                                "Failure during attempt to process message received from NFS server, \
                                 it might by a sign of a bug in efs-utils \
                                 software: consider disabling ReadBypass functionality."
                            );
                        }
                        ReadBypassAgentError::DataEvicted => {
                            // Transient memory pressure - send delay, don't denylist
                            ctx_warn!(
                                read_bypass_request_context,
                                "Data evicted, sending NFS4ERR_DELAY without denylisting"
                            );
                            let _ = Self::respond_failure_to_nfs_client(
                                read_bypass_request_context.clone(),
                                message,
                                nfs_client_sender,
                            )
                            .await;
                        }
                        _ => {
                            ctx_warn!(
                                read_bypass_request_context,
                                "Error while processing ReadBypass compound: {e}"
                            );

                            // Denylist file handle, assuming that any failure during processing
                            // compound at this phase is caused by issues with S3 access and highly
                            // likely will repeat itself, so we want to deny list filehandle to
                            // avoid availability issues.
                            for (size, op) in compound_info.compound.resarray.iter_mut().enumerate()
                            {
                                if let nfs_resop4::OP_AWSFILE_READ_BYPASS(
                                    AWSFILE_READ_BYPASS4res::NFS4ERR_AWSFILE_BYPASS(err_op),
                                ) = op
                                {
                                    read_bypass_request_context
                                        .fh_denylist
                                        .add(err_op.filehandle.clone());
                                    break;
                                }
                            }

                            match Self::respond_failure_to_nfs_client(
                                read_bypass_request_context.clone(),
                                message,
                                nfs_client_sender,
                            )
                            .await
                            {
                                Ok(_) => {
                                    ctx_debug!(
                                        read_bypass_request_context,
                                        "ReadBypassAgent successfully sent failure message"
                                    )
                                }
                                Err(e) => {
                                    ctx_error!(
                                        read_bypass_request_context,
                                        "Failure during attempt to send failure message to \
                                                NFSClient, it might by a sign of a bug in \
                                                efs-utils software: consider disabling ReadBypass \
                                                functionality."
                                    );
                                }
                            }
                        }
                    };
                }
            }
        }
    }

    /// Auxiliary function to create compound with READ operations for every AWSFILE_READ_BYPASS,
    /// with the data received from S3
    ///
    pub fn create_compound_with_s3_data(
        read_results: HashMap<usize, bytes::Bytes>,
        mut compound: COMPOUND4res,
    ) -> Result<COMPOUND4res, ReadBypassAgentError> {
        if read_results.is_empty() {
            warn!("No S3 data provided for generating compound");
            return Err(ReadBypassAgentError::InvalidCompound);
        }

        for (index, data) in read_results {
            let op = &compound.resarray[index];
            if let nfs_resop4::OP_AWSFILE_READ_BYPASS(
                AWSFILE_READ_BYPASS4res::NFS4ERR_AWSFILE_BYPASS(read_bypass_res),
            ) = op
            {
                let eof = (read_bypass_res.data_locator.offset
                    + read_bypass_res.data_locator.count as u64)
                    >= read_bypass_res.file_size;
                compound.resarray[index] = nfs_resop4::OP_READ(READ4res::NFS4_OK(READ4resok {
                    eof,
                    data: DataPayload::Data(data),
                }));
            } else {
                warn!("Unexpected operation type in ReadBypass compound");
                return Err(ReadBypassAgentError::InvalidCompound);
            }
        }
        Ok(compound)
    }

    /// Processing incoming compound:
    /// - request data from S3
    /// - receive data from S3
    /// - pack results into a new compound
    ///
    pub async fn process_compound(
        read_bypass_request_context: Arc<ReadBypassRequestContext>,
        compound_info: &RefNfsCompoundInfo<COMPOUND4res>,
        s3_reader: Arc<dyn S3Reader>,
    ) -> Result<Option<COMPOUND4res>, ReadBypassAgentError> {
        ctx_debug!(
            read_bypass_request_context,
            "Handling accepted ReadBypass operations"
        );

        // Read data directly (no spawn) — only one ReadBypass op per compound is supported
        let mut read_results: HashMap<usize, bytes::Bytes> = HashMap::new();
        for (index, op) in compound_info.compound.resarray.iter().enumerate() {
            if let nfs_resop4::OP_AWSFILE_READ_BYPASS(
                AWSFILE_READ_BYPASS4res::NFS4ERR_AWSFILE_BYPASS(readbypass_op_res),
            ) = op
            {
                ctx_debug!(
                    read_bypass_request_context,
                    "ReadBypass accepted for s3_key={}",
                    String::from_utf8_lossy(&readbypass_op_res.data_locator.s3_key)
                );

                // A read at or past EOF returns empty
                if readbypass_op_res.data_locator.offset >= readbypass_op_res.file_size {
                    read_results.insert(index, Bytes::new());
                    break;
                }

                match s3_reader
                    .read_data(
                        read_bypass_request_context.clone(),
                        readbypass_op_res.data_locator.clone(),
                        readbypass_op_res.filehandle.clone(),
                        readbypass_op_res.file_size,
                    )
                    .await
                {
                    Ok(Some(data)) => {
                        read_results.insert(index, data);
                        // Only expecting one readbypass op in a compound
                        break;
                    }
                    Ok(None) => {
                        ctx_error!(
                            read_bypass_request_context,
                            "No data returned from read operation at index {}",
                            index
                        );
                        return Err(ReadBypassAgentError::CacheInternalError(
                            ReadAheadCacheError {
                                message: "No data returned from read operation".to_string(),
                            },
                        ));
                    }
                    Err(ReadBypassAgentError::DataEvicted) => {
                        ctx_warn!(
                            read_bypass_request_context,
                            "Data evicted at index {}, returning delay",
                            index
                        );
                        return Err(ReadBypassAgentError::DataEvicted);
                    }
                    Err(e) => {
                        ctx_warn!(read_bypass_request_context, "Failed to read data: {:?}", e);
                        return Err(e);
                    }
                }
            }
        }
        if read_results.is_empty() {
            ctx_error!(read_bypass_request_context,
                "No ReadBypass operations found in compound, it might by a sign of a bug in efs-utils \
                 software: consider disabling ReadBypass functionality."
            );
            return Err(ReadBypassAgentError::InvalidCompound);
        }

        ctx_debug!(
            read_bypass_request_context,
            "S3 requests are completed, updating compound with S3 data..."
        );
        match Self::create_compound_with_s3_data(read_results, compound_info.compound.clone()) {
            Ok(out_compound) => {
                ctx_debug!(
                    read_bypass_request_context,
                    "Successfully updated compound with S3 data."
                );
                Ok(Some(out_compound))
            }
            Err(e) => Err(e),
        }
    }

    pub fn compound_has_readbypass(compound: &COMPOUND4res) -> bool {
        compound
            .resarray
            .iter()
            .any(|op| matches!(op, nfs_resop4::OP_AWSFILE_READ_BYPASS(_)))
    }

    async fn respond_success_to_nfs_client(
        read_bypass_request_context: Arc<ReadBypassRequestContext>,
        original_message: NfsRpcInfo,
        response_compound: COMPOUND4res,
        nfs_client_sender: mpsc::Sender<ConnectionMessage>,
    ) -> Result<(), ReadBypassAgentError> {
        ctx_trace!(
            read_bypass_request_context,
            "Sending success message to NFSClient writer..."
        );

        // Paranoia check: at this moment expectation is that compound is already converted to
        // regular NFS and should not have readbypass operations.
        // Fail immediately if READBYPASS operation is detected.
        if Self::compound_has_readbypass(&response_compound) {
            ctx_error!(read_bypass_request_context,
                "Unexpected ReadBypass operations are detected in compound before sending to NfsClient");
            return Err(ReadBypassAgentError::UnsupportedMessage);
        }
        let rpc_params = original_message.envelopes[0].header.params.clone();

        return Self::send_rpc_to_client(
            read_bypass_request_context.clone(),
            rpc_params,
            nfs_client_sender,
            response_compound,
        )
        .await;
    }

    async fn respond_failure_to_nfs_client(
        read_bypass_request_context: Arc<ReadBypassRequestContext>,
        message: NfsRpcInfo,
        nfs_client_sender: mpsc::Sender<ConnectionMessage>,
    ) -> Result<(), ReadBypassAgentError> {
        // When any read failed, return NFS4ERR_DELAY for entire sequence
        // Readbypass operations should be converted to READ, to avoid parsing errors
        ctx_trace!(
            read_bypass_request_context,
            "Sending failure message to NFSClient writer..."
        );

        let mut out_compound = COMPOUND4res {
            status: nfsstat4::NFS4ERR_DELAY,
            tag: utf8string(b"".to_vec()),
            resarray: Vec::new(),
        };
        let rpc_params = message.envelopes[0].header.params.clone();

        return Self::send_rpc_to_client(
            read_bypass_request_context.clone(),
            rpc_params,
            nfs_client_sender,
            out_compound,
        )
        .await;
    }

    async fn send_rpc_to_client(
        read_bypass_request_context: Arc<ReadBypassRequestContext>,
        rpc_params: RpcMessageParams,
        nfs_client_sender: mpsc::Sender<ConnectionMessage>,
        compound_to_send: COMPOUND4res,
    ) -> Result<(), ReadBypassAgentError> {
        // Serialize response compound directly into BytesMut to avoid an extra copy
        let mut writer = BytesMut::new().writer();
        compound_to_send
            .pack(&mut writer)
            .map_err(|_| ReadBypassAgentError::NfsResponseEncodingError)?;
        let nfs_payload_buffer = writer.into_inner();
        let RpcMessageParams::ReplyParams(rpc_reply_params) = rpc_params.clone() else {
            return Err(ReadBypassAgentError::UnsupportedMessage);
        };
        let encoded_rpc = RpcEncoder::encode_rpc_accepted_reply_with_payload(
            rpc_reply_params.xid,
            rpc_params,
            nfs_payload_buffer,
        )
        .map_err(|_| ReadBypassAgentError::NfsResponseEncodingError)?;
        let rpc_batch: RpcBatch = RpcBatch {
            rpcs: vec![BytesMut::from(encoded_rpc)],
        };
        ctx_trace!(
            read_bypass_request_context,
            "About to actually send a message....."
        );
        if let Err(e) = nfs_client_sender
            .send(ConnectionMessage::Response(rpc_batch))
            .await
        {
            ctx_warn!(
                read_bypass_request_context,
                "Error while sending message to NFS Client writer: {:?}",
                e
            );
            return Err(ReadBypassAgentError::DispatchingError);
        }
        Ok(())
    }

    #[cfg(test)]
    async fn default() -> Self {
        use crate::config_parser::DEFAULT_READ_BYPASS_MAX_IN_FLIGHT_S3_BYTES;
        Self::new(
            Arc::new(ReadBypassContext::default().await),
            Arc::new(DirectS3Reader {
                s3_data_reader: Box::new(S3ReadBypassReader::new(
                    DEFAULT_READ_BYPASS_MAX_IN_FLIGHT_S3_BYTES(),
                )),
            }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logger;
    use crate::nfs::nfs4_1_xdr::*;
    use crate::nfs::nfs4_1_xdr_ext::opnum_from_resop;
    use crate::nfs::nfs_compound::*;
    use crate::nfs::nfs_parser::NfsMessageParser;
    use crate::nfs::nfs_test_utils::{
        create_nfs_rpc_envelope_batch_from_compound, create_nfs_rpc_envelope_from_compound,
        get_sample_compound_res, get_sample_op_getattr_res, get_sample_op_read_bypass_accepted_res,
        get_sample_op_read_bypass_rejected_res, get_sample_op_read_res_with_data,
        get_sample_op_sequence_res,
    };
    use crate::rpc::rpc_envelope::{
        EnvelopeHeader, RpcMessageParams, RpcMessageType, RpcReplyParams,
    };
    use crate::test_utils::get_test_config;
    use crate::util::read_bypass_request_context;
    use bytes::{Bytes, BytesMut};
    use mockall::predicate::le;
    use tokio::sync::mpsc;
    use tokio::task::JoinHandle;
    use tokio_util::sync::CancellationToken;
    use xdr_codec::Pack;

    /////////////////////////////////////////////////////////////////////////////////////
    /// Auxiliary test functions
    ///

    fn create_compound_res_without_readbypass() -> COMPOUND4res {
        COMPOUND4res {
            status: nfsstat4::NFS4_OK,
            tag: utf8string(b"test".to_vec()),
            resarray: vec![get_sample_op_sequence_res(), get_sample_op_getattr_res()],
        }
    }

    fn create_compound_res_with_read() -> COMPOUND4res {
        COMPOUND4res {
            status: nfsstat4::NFS4_OK,
            tag: utf8string(b"test".to_vec()),
            resarray: vec![
                get_sample_op_sequence_res(),
                get_sample_op_read_res_with_data(),
                get_sample_op_getattr_res(),
            ],
        }
    }

    fn create_compound_res_with_readbypass() -> COMPOUND4res {
        COMPOUND4res {
            status: nfsstat4::NFS4_OK,
            tag: utf8string(b"test".to_vec()),
            resarray: vec![
                get_sample_op_sequence_res(),
                get_sample_op_read_bypass_accepted_res(0, 1024, 2048),
                get_sample_op_getattr_res(),
            ],
        }
    }

    fn create_test_compound_res_with_read_bypass(
        offset: u64,
        count: u32,
        file_size: u64,
    ) -> RefNfsCompoundInfo<COMPOUND4res> {
        let compound = COMPOUND4res {
            status: nfsstat4::NFS4_OK,
            tag: utf8string(b"test".to_vec()),
            resarray: vec![
                get_sample_op_sequence_res(),
                get_sample_op_read_bypass_accepted_res(offset, count, file_size),
                get_sample_op_getattr_res(),
            ],
        };
        let mut nfs_payload = Vec::new();
        compound.pack(&mut nfs_payload);
        RefNfsCompoundInfo::new(
            NfsMetadata::default(),
            compound,
            vec![
                nfs_opnum4::OP_SEQUENCE,
                nfs_opnum4::OP_AWSFILE_READ_BYPASS,
                nfs_opnum4::OP_GETATTR,
            ],
            BytesMut::from(nfs_payload.as_slice()),
        )
    }

    fn create_test_compound_res_with_multiple_read_bypass() -> RefNfsCompoundInfo<COMPOUND4res> {
        let compound = COMPOUND4res {
            status: nfsstat4::NFS4_OK,
            tag: utf8string(b"test".to_vec()),
            resarray: vec![
                get_sample_op_sequence_res(),
                get_sample_op_read_bypass_accepted_res(0, 512, 2048),
                get_sample_op_getattr_res(),
                get_sample_op_read_bypass_accepted_res(512, 512, 2048),
                get_sample_op_getattr_res(),
            ],
        };
        let mut nfs_payload = Vec::new();
        compound.pack(&mut nfs_payload);
        RefNfsCompoundInfo::new(
            NfsMetadata::default(),
            compound,
            vec![
                nfs_opnum4::OP_SEQUENCE,
                nfs_opnum4::OP_AWSFILE_READ_BYPASS,
                nfs_opnum4::OP_GETATTR,
                nfs_opnum4::OP_AWSFILE_READ_BYPASS,
                nfs_opnum4::OP_GETATTR,
            ],
            BytesMut::from(nfs_payload.as_slice()),
        )
    }

    fn create_test_compound_res_no_readbypass() -> RefNfsCompoundInfo<COMPOUND4res> {
        let compound = get_sample_compound_res();
        RefNfsCompoundInfo::new(
            NfsMetadata::default(),
            compound,
            vec![
                nfs_opnum4::OP_SEQUENCE,
                nfs_opnum4::OP_GETATTR,
                nfs_opnum4::OP_LOOKUP,
                nfs_opnum4::OP_WRITE,
            ],
            BytesMut::new(),
        )
    }

    pub fn compound_has_accepted_readbypass(compound: &COMPOUND4res) -> bool {
        compound.resarray.iter().any(|op| {
            matches!(
                op,
                nfs_resop4::OP_AWSFILE_READ_BYPASS(
                    AWSFILE_READ_BYPASS4res::NFS4ERR_AWSFILE_BYPASS(_)
                )
            )
        })
    }

    #[derive(Clone)]
    struct MockS3DataReader {
        should_succeed: bool,
        return_data: Bytes,
    }

    /////////////////////////////////////////////////////////////////////////////////////
    /// Mocks
    ///

    impl MockS3DataReader {
        fn new(should_succeed: bool, data: Bytes) -> Self {
            Self {
                should_succeed,
                return_data: data,
            }
        }
    }

    #[async_trait::async_trait]
    impl S3DataReader for MockS3DataReader {
        async fn spawn_read_task(
            &self,
            _s3_data_locator: awsfile_bypass_data_locator,
            _read_bypass_context: Arc<ReadBypassContext>,
        ) -> JoinHandle<Result<Bytes, S3ClientError>> {
            let data_clone = self.return_data.clone();
            let should_succeed_clone = self.should_succeed;
            tokio::spawn(async move {
                if should_succeed_clone {
                    Ok(data_clone)
                } else {
                    Err(S3ClientError::ETagMismatchError)
                }
            })
        }
    }

    ////////////////////////////////////////////////////////////////////////////////
    /// Test cases
    ///

    #[tokio::test]
    async fn test_read_bypass_agent_exits_on_channel_close() {
        let mut agent = ReadBypassAgent::default().await;

        let (tx, rx) = mpsc::channel::<ReadBypassMessage>(10);
        let (shutdown_tx, _) = mpsc::channel::<u8>(1);

        let (nfs_client_sender, mut nfs_client_receiver) = mpsc::channel::<ConnectionMessage>(10);

        // Close the message channels
        drop(tx);

        // Run the message loop - should exit because channel is closed
        let handle = tokio::spawn(async move {
            agent
                .run_message_loop(rx, nfs_client_sender, shutdown_tx)
                .await;
        });

        // Wait for the task to complete
        let _ = tokio::time::timeout(std::time::Duration::from_millis(100), handle)
            .await
            .expect("Timed out waiting for ReadBypassAgent to shut down");
    }

    #[tokio::test]
    async fn test_read_bypass_agent_exits_on_shutdown() {
        let agent = ReadBypassAgent::default().await;

        let (tx, rx) = mpsc::channel::<ReadBypassMessage>(10);
        let (nfs_client_sender, mut nfs_client_receiver) = mpsc::channel::<ConnectionMessage>(10);
        let (shutdown_handle, _waiter) = ShutdownHandle::new(CancellationToken::new());

        // Start the agent and then signal through shutdown handle
        let handle = tokio::spawn(ReadBypassAgent::run(
            agent,
            rx,
            nfs_client_sender,
            shutdown_handle.clone(),
        ));
        shutdown_handle.cancellation_token.cancel();

        // Wait for the task to complete
        let _ = tokio::time::timeout(std::time::Duration::from_millis(100), handle)
            .await
            .expect("Timed out waiting for ReadBypassAgent to shut down");

        drop(tx);
    }

    // Test cases for create_compound_with_s3_data

    #[tokio::test]
    async fn test_create_compound_with_s3_data_empty() {
        let mut compound_info = create_test_compound_res_with_read_bypass(0, 1024, 2048);
        let mut read_results = HashMap::new();
        assert!(compound_has_accepted_readbypass(&compound_info.compound));
        let result = ReadBypassAgent::create_compound_with_s3_data(
            read_results,
            compound_info.compound.clone(),
        );
        assert!(matches!(result, Err(ReadBypassAgentError::InvalidCompound)));
    }

    #[tokio::test]
    async fn test_update_compound_with_s3_data_success() {
        let mut compound_info = create_test_compound_res_with_read_bypass(0, 1024, 2048);
        let mut read_results = HashMap::new();
        let op_index = 1;
        let test_data = Bytes::from_static(b"test data");
        read_results.insert(op_index, test_data.clone());
        assert!(compound_has_accepted_readbypass(&compound_info.compound));
        let result = ReadBypassAgent::create_compound_with_s3_data(
            read_results,
            compound_info.compound.clone(),
        );
        assert!(result.is_ok());

        let res_compound = result.expect("Valid COMPOUND4Res is expected");
        assert!(!compound_has_accepted_readbypass(&res_compound));
        assert_eq!(
            res_compound.resarray[op_index],
            nfs_resop4::OP_READ(READ4res::NFS4_OK(READ4resok {
                eof: false,
                data: DataPayload::Data(test_data),
            }))
        );
    }

    #[tokio::test]
    async fn test_update_compound_with_s3_data_success_eof() {
        let mut compound_info = create_test_compound_res_with_read_bypass(0, 4096, 2048);
        let mut read_results = HashMap::new();
        let test_data = Bytes::from_static(b"test data");
        let op_index = 1;
        read_results.insert(op_index, test_data.clone());
        assert!(compound_has_accepted_readbypass(&compound_info.compound));
        let result = ReadBypassAgent::create_compound_with_s3_data(
            read_results,
            compound_info.compound.clone(),
        );
        assert!(result.is_ok());

        let res_compound = result.expect("Valid COMPOUND4Res is expected");
        assert!(!compound_has_accepted_readbypass(&res_compound));
        assert_eq!(
            res_compound.resarray[op_index],
            nfs_resop4::OP_READ(READ4res::NFS4_OK(READ4resok {
                eof: true,
                data: DataPayload::Data(test_data),
            }))
        );
    }

    #[tokio::test]
    async fn test_create_compound_with_s3_data_invalid_operation() {
        let mut compound_info = create_test_compound_res_no_readbypass();
        let mut read_results = HashMap::new();
        read_results.insert(0, Bytes::from_static(b"test data"));
        let result = ReadBypassAgent::create_compound_with_s3_data(
            read_results,
            compound_info.compound.clone(),
        );
        assert!(matches!(result, Err(ReadBypassAgentError::InvalidCompound)));
    }

    #[tokio::test]
    async fn test_process_compound_read_at_eof_returns_empty_without_s3_call() {
        // Request offset == file_size (read at EOF)
        let compound_info = create_test_compound_res_with_read_bypass(1024, 512, 1024);
        // Mock reader that fails if called - proves we skip S3
        let mock_reader = MockS3DataReader::new(false, Bytes::new());

        let read_bypass_context = Arc::new(ReadBypassContext::default().await);
        let read_bypass_request_context =
            Arc::new(ReadBypassRequestContext::new(read_bypass_context, 0));
        let s3_reader: Arc<dyn S3Reader> = Arc::new(DirectS3Reader {
            s3_data_reader: Box::new(mock_reader),
        });

        let result = ReadBypassAgent::process_compound(
            read_bypass_request_context,
            &compound_info,
            s3_reader,
        )
        .await;

        // Should succeed without calling S3 (mock would fail if called)
        assert!(result.is_ok(), "EOF read should succeed without S3 call");
        let result_compound = result.unwrap().expect("Expected compound response");

        if let nfs_resop4::OP_READ(READ4res::NFS4_OK(read_op_res)) = &result_compound.resarray[1] {
            if let DataPayload::Data(res_data) = &read_op_res.data {
                assert!(res_data.is_empty(), "EOF read should return empty data");
            } else {
                panic!("Expected data payload");
            }
        } else {
            panic!("Expected READ operation result");
        }
    }

    #[tokio::test]
    async fn test_update_compound_with_s3_data_multiple_operations() {
        let mut compound_info = create_test_compound_res_with_multiple_read_bypass();
        let mut read_results = HashMap::new();
        read_results.insert(1, Bytes::from_static(b"data1"));
        read_results.insert(3, Bytes::from_static(b"data2"));
        assert!(compound_has_accepted_readbypass(&compound_info.compound));

        let result = ReadBypassAgent::create_compound_with_s3_data(
            read_results,
            compound_info.compound.clone(),
        );
        assert!(result.is_ok());

        let res_compound = result.expect("Valid COMPOUND4Res is expected");
        assert!(!compound_has_accepted_readbypass(&res_compound));
    }

    // Test cases for process_compound

    #[tokio::test]
    async fn test_process_compound_success() {
        let compound_info = create_test_compound_res_with_read_bypass(0, 1024, 2048);
        let test_data = Bytes::from_static(b"test s3 data");
        let mock_reader = MockS3DataReader::new(true, test_data.clone());
        let read_bypass_context = Arc::new(ReadBypassContext::default().await);
        let read_bypass_request_context =
            Arc::new(ReadBypassRequestContext::new(read_bypass_context, 0));
        let s3_reader: Arc<dyn S3Reader> = Arc::new(DirectS3Reader {
            s3_data_reader: Box::new(mock_reader),
        });

        assert!(compound_has_accepted_readbypass(&compound_info.compound));

        let result = ReadBypassAgent::process_compound(
            read_bypass_request_context.clone(),
            &compound_info,
            s3_reader,
        )
        .await;

        assert!(result.is_ok());
        let result_compound = result
            .unwrap()
            .expect("Expected non-empty compound as a response!");
        assert!(!ReadBypassAgent::compound_has_readbypass(&result_compound));

        if let nfs_resop4::OP_READ(READ4res::NFS4_OK(read_op_res)) =
            result_compound.resarray[1].clone()
        {
            if let DataPayload::Data(res_data) = read_op_res.data {
                assert_eq!(res_data, test_data);
            } else {
                panic!("Expected data payload");
            }
        } else {
            panic!("Expected READ operation result");
        }
    }

    #[tokio::test]
    async fn test_process_compound_s3_failure() {
        let compound_info = create_test_compound_res_with_read_bypass(0, 1024, 2048);
        let mock_reader = MockS3DataReader::new(false, Bytes::new());

        let read_bypass_context = Arc::new(ReadBypassContext::default().await);
        let read_bypass_request_context =
            Arc::new(ReadBypassRequestContext::new(read_bypass_context, 0));
        let s3_reader: Arc<dyn S3Reader> = Arc::new(DirectS3Reader {
            s3_data_reader: Box::new(mock_reader),
        });
        let result = ReadBypassAgent::process_compound(
            read_bypass_request_context,
            &compound_info,
            s3_reader,
        )
        .await;

        assert!(matches!(result, Err(ReadBypassAgentError::S3Error(_))));
    }

    #[tokio::test]
    async fn test_process_compound_no_readbypass() {
        //
        let mut compound_info = create_test_compound_res_no_readbypass();
        let mock_reader = MockS3DataReader::new(true, Bytes::new());

        let read_bypass_context = Arc::new(ReadBypassContext::default().await);
        let read_bypass_request_context =
            Arc::new(ReadBypassRequestContext::new(read_bypass_context, 0));
        let s3_reader: Arc<dyn S3Reader> = Arc::new(DirectS3Reader {
            s3_data_reader: Box::new(mock_reader),
        });
        let result = ReadBypassAgent::process_compound(
            read_bypass_request_context,
            &mut compound_info,
            s3_reader,
        )
        .await;
        assert!(matches!(result, Err(ReadBypassAgentError::InvalidCompound)));
    }

    // Test cases for respond_success_to_nfs_client

    #[tokio::test]
    async fn test_respond_success_to_nfs_client_success() {
        let (nfs_client_sender, mut nfs_client_receiver) = mpsc::channel(1);
        let original_message = create_nfs_rpc_envelope_batch_from_compound(
            RpcMessageType::Reply,
            create_compound_res_with_readbypass(),
        );
        let response_compound = create_compound_res_with_read();
        let read_bypass_context = Arc::new(ReadBypassContext::default().await);
        let read_bypass_request_context =
            Arc::new(ReadBypassRequestContext::new(read_bypass_context, 0));
        let result = ReadBypassAgent::respond_success_to_nfs_client(
            read_bypass_request_context,
            original_message,
            response_compound,
            nfs_client_sender,
        )
        .await;

        assert!(result.is_ok());
        let ConnectionMessage::Response(rpc_batch) = nfs_client_receiver.recv().await.unwrap();
        let rpc_envelope = &rpc_batch.rpcs[0];
        let res = NfsRpcEnvelope::try_from(rpc_envelope.clone());
        assert!(res.is_ok(), "Failed to parse NfsRpcEnvelope");
        let nfs_envelope = res.unwrap();

        if let RefNfsCompound::Compound4res(compound_info) = &nfs_envelope.body {
            let ops = &compound_info.compound.resarray;
            assert_eq!(ops.len(), 3, "Should have 3 operations");

            // Check operations: SEQUENCE, READ, READ, GETATTR
            assert!(matches!(ops[0], nfs_resop4::OP_SEQUENCE(_)));
            assert!(matches!(ops[1], nfs_resop4::OP_READ(_)));
            assert!(matches!(ops[2], nfs_resop4::OP_GETATTR(_)));
        } else {
            panic!("Expected Compound4res");
        }
    }

    #[tokio::test]
    async fn test_respond_success_to_nfs_client_with_readbypass() {
        // Test that we do not send compounds with READBYPASS operations to NFS Client
        let (nfs_client_sender, mut nfs_client_receiver) = mpsc::channel(1);
        let original_message = create_nfs_rpc_envelope_batch_from_compound(
            RpcMessageType::Reply,
            create_compound_res_with_readbypass(),
        );
        let response_compound = create_compound_res_with_readbypass();
        let read_bypass_context = Arc::new(ReadBypassContext::default().await);
        let read_bypass_request_context =
            Arc::new(ReadBypassRequestContext::new(read_bypass_context, 0));
        let result = ReadBypassAgent::respond_success_to_nfs_client(
            read_bypass_request_context,
            original_message,
            response_compound,
            nfs_client_sender,
        )
        .await;

        assert!(matches!(
            result,
            Err(ReadBypassAgentError::UnsupportedMessage)
        ));
        assert!(nfs_client_receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_respond_success_to_nfs_client_channel_closed() {
        let (nfs_client_sender, receiver) = mpsc::channel(1);
        drop(receiver); // Close the receiver

        let original_message = create_nfs_rpc_envelope_batch_from_compound(
            RpcMessageType::Reply,
            create_compound_res_with_read(),
        );
        let response_compound = create_compound_res_without_readbypass();
        let read_bypass_context = Arc::new(ReadBypassContext::default().await);
        let read_bypass_request_context =
            Arc::new(ReadBypassRequestContext::new(read_bypass_context, 0));
        let result = ReadBypassAgent::respond_success_to_nfs_client(
            read_bypass_request_context,
            original_message,
            response_compound,
            nfs_client_sender,
        )
        .await;

        assert!(matches!(
            result,
            Err(ReadBypassAgentError::DispatchingError)
        ));
    }

    // Test cases for entire RBA

    #[tokio::test]
    async fn test_read_bypass_agent_mixed_compound() {
        // Create compound with 3 operations: SEQUENCE, ReadBypass NFS4ERR_AWSFILE_BYPASS, GETATTR
        let efs_data = Bytes::from_static(b"existing data");
        let compound_res = COMPOUND4res {
            status: nfsstat4::NFS4_OK,
            tag: utf8string(b"test".to_vec()),
            resarray: vec![
                get_sample_op_sequence_res(),
                get_sample_op_read_bypass_accepted_res(0, 1024, 2048),
                get_sample_op_getattr_res(),
            ],
        };

        let message =
            create_nfs_rpc_envelope_batch_from_compound(RpcMessageType::Reply, compound_res);

        // Create channels
        let (rba_sender, rba_receiver) = mpsc::channel::<ReadBypassMessage>(10);
        let (nfs_client_sender, mut nfs_client_receiver) = mpsc::channel::<ConnectionMessage>(10);
        let (shutdown_handle, _waiter) = ShutdownHandle::new(CancellationToken::new());

        // Create agent with mock S3 reader
        let s3_data = Bytes::from_static(b"s3 data");
        let mock_reader = MockS3DataReader::new(true, s3_data.clone());
        let agent = ReadBypassAgent::new(
            Arc::new(ReadBypassContext::default().await),
            Arc::new(DirectS3Reader {
                s3_data_reader: Box::new(mock_reader),
            }),
        );

        // Start agent
        let agent_handle = tokio::spawn(ReadBypassAgent::run(
            agent,
            rba_receiver,
            nfs_client_sender,
            shutdown_handle.clone(),
        ));

        // Send message to RBA
        rba_sender.send(message).await.unwrap();

        // Wait for response from NFS Client channel
        let response = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            nfs_client_receiver.recv(),
        )
        .await
        .expect("Timeout waiting for response")
        .expect("No response received");

        // Verify response
        let ConnectionMessage::Response(rpc_batch) = response;
        assert_eq!(rpc_batch.rpcs.len(), 1, "Should have one RPC");

        // Parse the compound from the response
        let rpc_envelope = &rpc_batch.rpcs[0];
        let res = NfsRpcEnvelope::try_from(rpc_envelope.clone());
        assert!(res.is_ok(), "Failed to parse NfsRpcEnvelope");
        let nfs_envelope = res.unwrap();

        if let RefNfsCompound::Compound4res(compound_info) = &nfs_envelope.body {
            let ops = &compound_info.compound.resarray;
            assert_eq!(ops.len(), 3, "Should have 3 operations");

            // Check operations: SEQUENCE, READ, READ, GETATTR
            assert!(matches!(ops[0], nfs_resop4::OP_SEQUENCE(_)));
            assert!(matches!(ops[1], nfs_resop4::OP_READ(_)));
            assert!(matches!(ops[2], nfs_resop4::OP_GETATTR(_)));
        } else {
            panic!("Expected Compound4res");
        }

        // Cleanup
        shutdown_handle.cancellation_token.cancel();
        let _ = tokio::time::timeout(std::time::Duration::from_millis(100), agent_handle).await;
    }

    #[tokio::test]
    async fn test_process_compound_cache_enabled_path() {
        test_process_compound_with_settings(true, false).await;
    }

    #[tokio::test]
    async fn test_process_compound_cache_disabled_path() {
        test_process_compound_with_settings(false, false).await;
    }

    #[tokio::test]
    async fn test_process_compound_cache_disabled_s3_failure() {
        test_process_compound_with_settings(false, true).await;
    }

    async fn test_process_compound_with_settings(cache_enabled: bool, s3_should_fail: bool) {
        let compound_info = create_test_compound_res_with_read_bypass(0, 1024, 2048);
        let test_data = Bytes::from(vec![b'T'; 1024]);
        let mock_reader = MockS3DataReader::new(!s3_should_fail, test_data.clone());
        let mut read_bypass_context = ReadBypassContext::default().await;
        read_bypass_context.cache_enabled = cache_enabled;
        let read_bypass_context = Arc::new(read_bypass_context);
        let read_bypass_request_context =
            Arc::new(ReadBypassRequestContext::new(read_bypass_context, 0));
        assert!(compound_has_accepted_readbypass(&compound_info.compound));

        let s3_reader: Arc<dyn S3Reader> = if cache_enabled {
            Arc::new(CachedS3Reader {
                readahead_cache: Arc::new(FileReadAheadCache::new(
                    0,
                    0,
                    Arc::new(mock_reader),
                    &read_bypass_request_context.read_bypass_config,
                )),
            })
        } else {
            Arc::new(DirectS3Reader {
                s3_data_reader: Box::new(mock_reader),
            })
        };

        let result = ReadBypassAgent::process_compound(
            read_bypass_request_context,
            &compound_info,
            s3_reader,
        )
        .await;

        if s3_should_fail {
            if cache_enabled {
                assert!(matches!(
                    result,
                    Err(ReadBypassAgentError::CacheInternalError(_))
                ));
            } else {
                assert!(matches!(result, Err(ReadBypassAgentError::S3Error(_))));
            }
        } else {
            assert!(result.is_ok());
            let result_compound = result
                .unwrap()
                .expect("Expected non-empty compound as a response!");
            assert!(!ReadBypassAgent::compound_has_readbypass(&result_compound));
        }
    }

    #[tokio::test]
    async fn test_process_message_success() {
        let mock_reader = MockS3DataReader::new(true, Bytes::new());
        let s3_data_reader = Arc::new(DirectS3Reader {
            s3_data_reader: Box::new(mock_reader),
        });
        let read_bypass_context = Arc::new(ReadBypassContext::default().await);
        let read_bypass_request_context =
            Arc::new(ReadBypassRequestContext::new(read_bypass_context, 0));
        let (nfs_client_sender, mut nfs_client_receiver) = mpsc::channel::<ConnectionMessage>(10);

        let compound_res = COMPOUND4res {
            status: nfsstat4::NFS4_OK,
            tag: utf8string(b"test".to_vec()),
            resarray: vec![
                get_sample_op_sequence_res(),
                get_sample_op_read_bypass_accepted_res(0, 1024, 2048),
                get_sample_op_getattr_res(),
            ],
        };
        let message =
            create_nfs_rpc_envelope_batch_from_compound(RpcMessageType::Reply, compound_res);

        ReadBypassAgent::process_message(
            read_bypass_request_context,
            message,
            s3_data_reader,
            nfs_client_sender,
        )
        .await;

        let message = nfs_client_receiver.recv().await;
        if let Some(ConnectionMessage::Response(batch)) = message {
            assert!(batch.rpcs.len() == 1);

            let res = NfsRpcEnvelope::try_from(batch.rpcs[0].clone());
            assert!(res.is_ok(), "Failed to parse NfsRpcEnvelope");
            let nfs_envelope = res.unwrap();

            if let RefNfsCompound::Compound4res(compound_info) = &nfs_envelope.body {
                assert!(matches!(compound_info.compound.status, nfsstat4::NFS4_OK));
            } else {
                panic!("Expected Compound4res");
            }
        } else {
            panic!("Nfs client hit an unexpected error");
        }
    }

    #[tokio::test]
    async fn test_process_message_s3_client_failures() {
        let mock_reader = MockS3DataReader::new(false, Bytes::new());
        let s3_data_reader = Arc::new(DirectS3Reader {
            s3_data_reader: Box::new(mock_reader),
        });
        let read_bypass_context = Arc::new(ReadBypassContext::default().await);
        let read_bypass_request_context =
            Arc::new(ReadBypassRequestContext::new(read_bypass_context, 0));
        let (nfs_client_sender, mut nfs_client_receiver) = mpsc::channel::<ConnectionMessage>(10);
        let compound_res = COMPOUND4res {
            status: nfsstat4::NFS4_OK,
            tag: utf8string(b"test".to_vec()),
            resarray: vec![
                get_sample_op_sequence_res(),
                get_sample_op_read_bypass_accepted_res(0, 1024, 2048),
                get_sample_op_getattr_res(),
            ],
        };
        let message = create_nfs_rpc_envelope_batch_from_compound(
            RpcMessageType::Reply,
            compound_res.clone(),
        );

        ReadBypassAgent::process_message(
            read_bypass_request_context.clone(),
            message,
            s3_data_reader,
            nfs_client_sender,
        )
        .await;

        if let nfs_resop4::OP_AWSFILE_READ_BYPASS(
            AWSFILE_READ_BYPASS4res::NFS4ERR_AWSFILE_BYPASS(err_op),
        ) = &compound_res.resarray[1]
        {
            assert!(&read_bypass_request_context
                .fh_denylist
                .contains(&err_op.filehandle));
        } else {
            panic!("Expected read bypass file error");
        }

        let message = nfs_client_receiver.recv().await;
        if let Some(ConnectionMessage::Response(batch)) = message {
            assert!(batch.rpcs.len() == 1);

            let res = NfsRpcEnvelope::try_from(batch.rpcs[0].clone());
            assert!(res.is_ok(), "Failed to parse NfsRpcEnvelope");
            let nfs_envelope = res.unwrap();

            if let RefNfsCompound::Compound4res(compound_info) = &nfs_envelope.body {
                assert!(matches!(
                    compound_info.compound.status,
                    nfsstat4::NFS4ERR_DELAY
                ));
            } else {
                panic!("Expected Compound4res");
            }
        } else {
            panic!("Nfs client hit an unexpected error");
        }
    }

    /// Mock S3Reader that returns DataEvicted errors for testing retry logic
    struct DataEvictedMockReader {
        call_count: std::sync::atomic::AtomicUsize,
        evict_until: usize, // Return DataEvicted for first N calls
    }

    impl DataEvictedMockReader {
        fn new(evict_until: usize) -> Self {
            Self {
                call_count: std::sync::atomic::AtomicUsize::new(0),
                evict_until,
            }
        }
    }

    #[async_trait::async_trait]
    impl S3Reader for DataEvictedMockReader {
        async fn read_data(
            &self,
            _read_bypass_request_context: Arc<ReadBypassRequestContext>,
            _s3_data_locator: awsfile_bypass_data_locator,
            _filehandle: nfs_fh4,
            _file_size: u64,
        ) -> Result<Option<Bytes>, ReadBypassAgentError> {
            let count = self
                .call_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if count < self.evict_until {
                Err(ReadBypassAgentError::DataEvicted)
            } else {
                Ok(Some(Bytes::from(vec![0u8; 1024])))
            }
        }
    }

    #[tokio::test]
    async fn test_data_evicted_does_not_denylist() {
        // DataEvicted should send NFS4ERR_DELAY but NOT denylist
        let mock_reader: Arc<dyn S3Reader> = Arc::new(DataEvictedMockReader::new(2));
        let read_bypass_context = Arc::new(ReadBypassContext::default().await);
        let read_bypass_request_context =
            Arc::new(ReadBypassRequestContext::new(read_bypass_context, 0));
        let (nfs_client_sender, mut nfs_client_receiver) = mpsc::channel::<ConnectionMessage>(10);

        let compound_res = COMPOUND4res {
            status: nfsstat4::NFS4_OK,
            tag: utf8string(b"test".to_vec()),
            resarray: vec![
                get_sample_op_sequence_res(),
                get_sample_op_read_bypass_accepted_res(0, 1024, 2048),
                get_sample_op_getattr_res(),
            ],
        };
        let message = create_nfs_rpc_envelope_batch_from_compound(
            RpcMessageType::Reply,
            compound_res.clone(),
        );

        ReadBypassAgent::process_message(
            read_bypass_request_context.clone(),
            message,
            mock_reader,
            nfs_client_sender,
        )
        .await;

        // Should NOT be denylisted - eviction is transient
        if let nfs_resop4::OP_AWSFILE_READ_BYPASS(
            AWSFILE_READ_BYPASS4res::NFS4ERR_AWSFILE_BYPASS(err_op),
        ) = &compound_res.resarray[1]
        {
            assert!(
                !read_bypass_request_context
                    .fh_denylist
                    .contains(&err_op.filehandle),
                "Should NOT denylist on eviction"
            );
        }

        // Should receive NFS4ERR_DELAY response
        let message = nfs_client_receiver.recv().await;
        assert!(message.is_some(), "Should receive response");
        if let Some(ConnectionMessage::Response(batch)) = message {
            let nfs_envelope = NfsRpcEnvelope::try_from(batch.rpcs[0].clone()).unwrap();
            if let RefNfsCompound::Compound4res(compound_info) = &nfs_envelope.body {
                assert!(matches!(
                    compound_info.compound.status,
                    nfsstat4::NFS4ERR_DELAY
                ));
            }
        }
    }

    /// Mock S3Reader that panics to test panic recovery
    struct PanickingS3Reader;

    #[async_trait::async_trait]
    impl S3Reader for PanickingS3Reader {
        async fn read_data(
            &self,
            _read_bypass_request_context: Arc<ReadBypassRequestContext>,
            _s3_data_locator: awsfile_bypass_data_locator,
            _filehandle: nfs_fh4,
            _file_size: u64,
        ) -> Result<Option<Bytes>, ReadBypassAgentError> {
            panic!("simulated panic in S3 reader");
        }
    }

    #[tokio::test]
    async fn test_task_panic_sends_nfs4err_delay() {
        let s3_reader: Arc<dyn S3Reader> = Arc::new(PanickingS3Reader);
        let read_bypass_context = Arc::new(ReadBypassContext::default().await);
        let agent_context = read_bypass_context.clone();

        let (rba_sender, rba_receiver) = mpsc::channel::<ReadBypassMessage>(10);
        let (nfs_client_sender, mut nfs_client_receiver) = mpsc::channel::<ConnectionMessage>(10);
        let (shutdown_handle, _waiter) = ShutdownHandle::new(CancellationToken::new());

        let agent = ReadBypassAgent::new(read_bypass_context, s3_reader);

        let agent_handle = tokio::spawn(ReadBypassAgent::run(
            agent,
            rba_receiver,
            nfs_client_sender,
            shutdown_handle.clone(),
        ));

        let compound_res = COMPOUND4res {
            status: nfsstat4::NFS4_OK,
            tag: utf8string(b"test".to_vec()),
            resarray: vec![
                get_sample_op_sequence_res(),
                get_sample_op_read_bypass_accepted_res(0, 1024, 2048),
                get_sample_op_getattr_res(),
            ],
        };
        let message = create_nfs_rpc_envelope_batch_from_compound(
            RpcMessageType::Reply,
            compound_res.clone(),
        );

        rba_sender.send(message).await.unwrap();

        // Should receive NFS4ERR_DELAY despite the panic
        let response = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            nfs_client_receiver.recv(),
        )
        .await
        .expect("Timeout waiting for response")
        .expect("No response received");

        let ConnectionMessage::Response(batch) = response;
        let nfs_envelope = NfsRpcEnvelope::try_from(batch.rpcs[0].clone())
            .expect("Failed to parse NfsRpcEnvelope");

        if let RefNfsCompound::Compound4res(compound_info) = &nfs_envelope.body {
            assert!(
                matches!(compound_info.compound.status, nfsstat4::NFS4ERR_DELAY),
                "Expected NFS4ERR_DELAY after panic, got {:?}",
                compound_info.compound.status
            );
        } else {
            panic!("Expected Compound4res");
        }

        // Verify the filehandle was denylisted
        if let nfs_resop4::OP_AWSFILE_READ_BYPASS(
            AWSFILE_READ_BYPASS4res::NFS4ERR_AWSFILE_BYPASS(err_op),
        ) = &compound_res.resarray[1]
        {
            assert!(
                agent_context.fh_denylist.contains(&err_op.filehandle),
                "Filehandle should be denylisted after panic"
            );
        } else {
            panic!("Expected read bypass op");
        }

        shutdown_handle.cancellation_token.cancel();
        let _ = tokio::time::timeout(std::time::Duration::from_millis(100), agent_handle).await;
    }
}
