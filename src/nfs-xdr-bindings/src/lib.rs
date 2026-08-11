//! Rust XDR wire bindings for the NFSv4.1 (+4.2 / AWS EFS extension) protocol.
//!
//! This crate is the shared protocol-type substrate for the EFS proxy. It
//! contains the xdrgen-generated `nfs4_1_xdr` module, the hand-written
//! `nfs4_1_xdr_ext` helpers, and the `NfsError` type.
//!
//! Consumers typically `use amzn_nfs_xdr_bindings::nfs::nfs4_1_xdr::*`.
#![allow(clippy::all)]

pub mod nfs;

// AWS-file protocol XDR bindings (an NFSv4.1 extension), generated from
// src/xdr/awsfile_prot.x by build.rs.
#[allow(warnings)]
#[allow(clippy::all)]
pub mod awsfile_prot {
    include!(concat!(env!("OUT_DIR"), "/awsfile_prot_xdr.rs"));
}
