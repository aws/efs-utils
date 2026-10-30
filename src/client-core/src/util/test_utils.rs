//! Read-bypass test helpers, re-exported from `crate::test_utils`.
#![allow(dead_code)]

use crate::nfs::nfs4_1_xdr::awsfile_bypass_data_locator;
use crate::util::read_bypass_context::ReadBypassContext;
use crate::util::s3_data_reader::S3DataReader;

/// Mock S3DataReader that returns position-encoded data and tracks call count.
/// Used by readahead cache and file readahead state tests.
#[derive(Clone)]
pub struct CountingS3DataReader {
    pub call_count: crate::sync::Arc<crate::sync::atomic::AtomicU64>,
}

impl Default for CountingS3DataReader {
    fn default() -> Self {
        Self::new()
    }
}

impl CountingS3DataReader {
    pub fn new() -> Self {
        Self {
            call_count: crate::sync::Arc::new(crate::sync::atomic::AtomicU64::new(0)),
        }
    }

    pub fn calls(&self) -> u64 {
        self.call_count.load(crate::sync::atomic::Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl S3DataReader for CountingS3DataReader {
    async fn spawn_read_task(
        &self,
        s3_data_locator: awsfile_bypass_data_locator,
        _read_bypass_context: crate::sync::Arc<ReadBypassContext>,
    ) -> tokio::task::JoinHandle<Result<bytes::Bytes, crate::aws::s3_client::S3ClientError>> {
        self.call_count
            .fetch_add(1, crate::sync::atomic::Ordering::SeqCst);
        let count = s3_data_locator.count as usize;
        let offset = s3_data_locator.offset;
        tokio::spawn(async move {
            let data: Vec<u8> = (0..count)
                .map(|i| ((offset as usize + i) % 256) as u8)
                .collect();
            Ok(bytes::Bytes::from(data))
        })
    }
}

/// Mock S3DataReader whose reads always fail with a fixed error class. Used to verify
/// the class survives the readahead cache's error plumbing instead of being flattened
/// into an opaque cache-error message.
#[derive(Clone)]
pub struct FailingS3DataReader {
    pub make_error: fn() -> crate::aws::s3_client::S3ClientError,
}

#[async_trait::async_trait]
impl S3DataReader for FailingS3DataReader {
    async fn spawn_read_task(
        &self,
        _s3_data_locator: awsfile_bypass_data_locator,
        _read_bypass_context: crate::sync::Arc<ReadBypassContext>,
    ) -> tokio::task::JoinHandle<Result<bytes::Bytes, crate::aws::s3_client::S3ClientError>> {
        let make_error = self.make_error;
        tokio::spawn(async move { Err(make_error()) })
    }
}

pub fn create_test_s3_data_locator(offset: u64, count: u32) -> awsfile_bypass_data_locator {
    awsfile_bypass_data_locator {
        bucket_name: b"test-bucket".to_vec(),
        s3_key: b"test-key".to_vec(),
        etag: b"test-etag".to_vec(),
        version_id: b"test-version-id".to_vec(),
        offset,
        count,
    }
}

/// Builds a ReadBypassContext backed by a mocked S3 client. `#[cfg(test)]`-only
/// (not `test-util`) because `aws_smithy_mocks` is a dev-dependency; external
/// consumers construct their own contexts via `ReadBypassContext::default()`.
#[cfg(test)]
pub async fn create_test_read_bypass_context() -> crate::sync::Arc<ReadBypassContext> {
    use aws_sdk_s3::operation::get_object::GetObjectOutput;
    use aws_sdk_s3::primitives::ByteStream;
    use aws_smithy_mocks::{mock, mock_client};

    let get_object_rule = mock!(aws_sdk_s3::Client::get_object)
        .match_requests(|_req| true)
        .then_output(|| {
            GetObjectOutput::builder()
                .content_length(100)
                .body(ByteStream::from(vec![0u8; 100]))
                .e_tag("test-etag")
                .build()
        });

    let mock_client = crate::sync::Arc::new(mock_client!(aws_sdk_s3, [&get_object_rule]));
    let s3_client =
        crate::aws::s3_client::S3Client::new_with_client("test-bucket", "test-prefix", mock_client)
            .await;

    let proxy_config = crate::config_parser::ProxyConfig::default();
    crate::sync::Arc::new(ReadBypassContext::new(
        &proxy_config,
        "test-bucket".to_string(),
        "test-prefix".to_string(),
        s3_client,
        false,
    ))
}
