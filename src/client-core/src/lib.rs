//! # amzn-efs-client-core
//!
//! Shared library holding modules that are reused by efs-proxy:
//! the AWS/S3 clients, proxy config parsing, the read-bypass request context,
//! and the generated AWS-file XDR protocol. efs-proxy re-exports these modules
//! under their original crate paths so existing references keep compiling.
#![warn(rust_2018_idioms)]

// The Shuttle synchronization bans listed in the workspace's clippy.toml are only
// meaningful under the `shuttle` feature: that is the build in which `crate::sync`
// resolves to Shuttle's instrumented types, so a `std::sync::…` path is a genuinely
// different type. In the default build `crate::sync` re-exports std, the two spellings
// resolve to the same type, and the lint cannot tell them apart -- so it is off there.
// `cargo clippy --features shuttle` is what enforces the convention; see DEVELOPMENT.md.
//
// A deliberate exception is an allow on the smallest enclosing item:
//
//     #[allow(clippy::disallowed_types, reason = "why a real std primitive here")]
#![cfg_attr(
    feature = "shuttle",
    deny(clippy::disallowed_types, clippy::disallowed_methods)
)]
#![cfg_attr(
    not(feature = "shuttle"),
    allow(clippy::disallowed_types, clippy::disallowed_methods)
)]

pub mod aws;
pub mod config;
pub mod config_parser;
pub mod error;
pub mod memory;
pub mod proxy_identifier;
pub mod read_ahead;
pub mod sync;
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
