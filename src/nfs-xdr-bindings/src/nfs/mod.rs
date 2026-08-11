//! NFSv4.1 XDR wire bindings.
//!
//! `nfs4_1_xdr` is generated from `src/xdr/nfs_4_1_prot.x` by xdrgen; regenerate
//! with `tools/apply_nfs4_prot.sh`, which reapplies the local overrides in
//! `tools/nfs4_xdr_override.diff`. `nfs4_1_xdr_ext` holds hand-written helpers
//! layered on top of the generated types, and `error` carries the shared
//! `NfsError` used by both.
pub mod error;
#[rustfmt::skip]
pub mod nfs4_1_xdr;
pub mod nfs4_1_xdr_ext;
