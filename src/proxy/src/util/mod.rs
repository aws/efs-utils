// The read-bypass utility submodules were relocated into amzn-efs-client-core.
// Re-export them here so `crate::util::{fh_denylist, read_bypass_request_context,
// s3_data_reader}` references across efs-proxy keep compiling unchanged.
pub use efs_client_core::util::{fh_denylist, read_bypass_request_context, s3_data_reader};

pub mod time_utils;

// read_bypass_context also lives in amzn-efs-client-core, but two type aliases
// (NfsDispatcherError, ReadBypassMessage) reference proxy-only types
// (crate::rpc::rpc::RpcBatch and crate::nfs::nfs_rpc_envelope::NfsRpcInfo) that
// do not exist in the core crate. Re-export the core module's contents here and
// re-add those two aliases so `crate::util::read_bypass_context::*` resolves
// unchanged for efs-proxy.
pub mod read_bypass_context {
    pub use efs_client_core::util::read_bypass_context::*;

    use tokio::sync::mpsc::error::SendError;

    // Message data structure for ReadBypass domain to work with
    pub type NfsDispatcherError = SendError<crate::rpc::rpc::RpcBatch>;

    // Message to be sent from ReadBypassServerDispatcher to ReadBypassAgent
    pub type ReadBypassMessage = crate::nfs::nfs_rpc_envelope::NfsRpcInfo;
}
