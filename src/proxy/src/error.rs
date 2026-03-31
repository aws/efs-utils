use thiserror::Error as ThisError;

#[derive(Debug, ThisError)]
pub enum ConnectError {
    #[error("Connect attempt cancelled")]
    Cancelled,
    #[error("{0}")]
    IoError(#[from] tokio::io::Error),
    #[error("{0}")]
    JoinError(#[from] tokio::task::JoinError),
    #[error("Connect attempt failed - Maximum attempt count exceeded")]
    MaxAttemptsExceeded,
    #[error("Attempt to acquire additional connections to EFS failed.")]
    MultiplexFailure,
    #[error(transparent)]
    Tls(#[from] s2n_tls::error::Error),
    #[error("Connect attempt failed - Timeout")]
    Timeout,
}

#[derive(Debug, ThisError)]
pub enum RpcError {
    #[error("not a rpc response")]
    MalformedResponse,
    #[error("rpc reply_stat: MSG_DENIED")]
    Denied,
    #[error("rpc accept_stat: GARBAGE_ARGS")]
    GarbageArgs,
    #[error("rpc accept_stat: PROG_UNAVAIL")]
    ProgramUnavailable,
    #[error("rpc accept_stat: PROG_MISMATCH low: {} high: {}", .low, .high)]
    ProgramMismatch { low: u32, high: u32 },
    #[error("rpc accept_stat: PROC_UNAVAIL")]
    ProcedureUnavailable,
    #[error("rpc accept_stat: SystemError")]
    SystemError,
    #[error("RPC serialization failed: {0}")]
    SerializationError(String),
    #[error("Invalid RPC message params")]
    InvalidParams,
    #[error(transparent)]
    IoError(#[from] tokio::io::Error),
    #[error(transparent)]
    XdrCodecError(#[from] xdr_codec::Error),
    #[error(transparent)]
    OncRpc(#[from] onc_rpc::Error),
    #[error("awsfile_channel_init rpc failed. Reason: `{0}`")]
    AwsFileChannelInitFailure(String),
}
