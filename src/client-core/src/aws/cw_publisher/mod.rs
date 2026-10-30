//! ### CloudWatch metrics and logs emission
//!
//! Without the `cloudwatch` feature nothing is published: [`new_publisher`] returns `None`.

#[cfg(feature = "cloudwatch")]
mod publisher;
#[cfg(not(feature = "cloudwatch"))]
#[path = "disabled.rs"]
mod publisher;

pub use publisher::*;

/// Metrics names and namespaces
///
pub const CW_NAMESPACE_S3FILES: &str = "efs-utils/S3Files";
pub const CW_NAMESPACE_EFS: &str = "efs-utils/EFS";

pub const S3_BUCKET_IS_REACHABLE: &str = "S3BucketReachable";
pub const S3_BUCKET_IS_PERMITTED: &str = "S3BucketAccessible";
pub const NFS_CONNECTION_ACCESSIBLE: &str = "NFSConnectionAccessible";

pub const DEFAULT_EFS_CLOUDWATCH_LOG_GROUP: &str = "/aws/efs/utils";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
}

/// Trait for CloudWatch operations (logs and metrics), enabling testability.
/// All methods are fire-and-forget (non-blocking) — they spawn background tasks
/// and return immediately.
pub trait CloudWatchClient: Send + Sync {
    fn emit_log(&self, level: LogLevel, message: &str);
    fn publish_s3_reachable(&self, bucket: &str, is_reachable: bool);
    fn publish_s3_permitted(&self, bucket: &str, is_permitted: bool);
    fn publish_nfs_reachability(&self, is_reachable: bool, fs_id: &str);
}
