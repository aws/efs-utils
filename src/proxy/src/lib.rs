// EFS Proxy modules are made visible such that they can be reused in the Integration tests.
// EFS proxy Integration tests are implemented in a white box testing manner.
// We want to keep all the proxy internals visible and accessible.
//
#![warn(rust_2018_idioms)]

// These modules live in the amzn-efs-client-core member crate and are
// re-exported at the crate root so efs-proxy code addresses them as local
// modules (`crate::aws::*`, `crate::config::*`, `crate::config_parser::*`,
// `crate::memory::*`, `crate::proxy_identifier::*`, `crate::read_ahead::*`,
// `crate::utils::*`, `crate::error::*`, `crate::awsfile_prot::*`).
pub use efs_client_core::{
    aws, awsfile_prot, config, config_parser, error, memory, proxy_identifier, read_ahead, utils,
};

// The ctx_* logging macros are `#[macro_export]`ed by amzn-efs-client-core, so
// they live at that crate's root. Re-export them into efs-proxy's crate root so
// existing `crate::{ctx_debug, ctx_info, ctx_warn, ctx_error, ctx_trace}`
// references keep resolving unchanged.
pub use efs_client_core::{ctx_debug, ctx_error, ctx_info, ctx_trace, ctx_warn};

pub mod awsfile_rpc;
pub mod connection_task;
pub mod connections;
pub mod controller;
pub mod domain;
pub mod log_encoder;
pub mod logger;
pub mod nfs;
pub mod proxy;
pub mod proxy_builder;
pub mod proxy_task;
pub mod read_bypass;
pub mod rpc;
pub mod shutdown;
pub mod status_reporter;
pub mod test_utils;
pub mod tls;
pub mod util;
