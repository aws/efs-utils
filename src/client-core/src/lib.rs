//! # amzn-efs-client-core
//!
//! Shared library holding modules that are reused by efs-proxy:
//! the AWS/S3 clients, proxy config parsing, the read-bypass request context,
//! and the generated AWS-file XDR protocol. efs-proxy re-exports these modules
//! under their original crate paths so existing references keep compiling.
#![warn(rust_2018_idioms)]

pub mod aws;
pub mod config;
pub mod config_parser;
pub mod error;
pub mod memory;
pub mod proxy_identifier;
pub mod read_ahead;
pub mod util;
pub mod utils;

// Test helpers (CountingS3DataReader, create_test_read_bypass_context, ...) are
// additionally compiled under the `test-util` feature so that consuming
// binaries' test suites can reuse them.
#[cfg(any(test, feature = "test-util"))]
pub mod test_utils;

// NFSv4.1 XDR wire bindings live in the amzn-nfs-xdr-bindings crate. Re-export
// them under crate::nfs so that existing `crate::nfs::{nfs4_1_xdr, ...}`
// references in the moved modules resolve unchanged.
pub use amzn_nfs_xdr_bindings::nfs;

// The AWS-file protocol XDR bindings also live in amzn-nfs-xdr-bindings now;
// re-export so the moved modules' `crate::awsfile_prot::*` references resolve.
pub use amzn_nfs_xdr_bindings::awsfile_prot;
