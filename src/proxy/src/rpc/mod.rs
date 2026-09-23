// clippy: renaming this submodule would churn crate::rpc::rpc paths across the crate
#[allow(clippy::module_inception)]
pub mod rpc;
pub mod rpc_domain;
pub mod rpc_encoder;
pub mod rpc_envelope;
pub mod rpc_error;
