use crate::nfs::nfs4_1_xdr::nfsstat4;
use thiserror::Error as ThisError;

#[derive(Debug, ThisError, PartialEq)]
pub enum NfsError {
    #[error("NFS error: {0:?}")]
    Error(#[from] nfsstat4),
    #[error("Failed to parse NFS compound message")]
    ParseError,
    #[error("Failed to encode NFS compound message")]
    #[allow(dead_code)]
    EncodeError,
    #[error("Invalid NFS operation replacement")]
    InvalidOperationReplacement,
    #[error("Replacement operation not found")]
    ReplacementOperationNotFound,
}
