//! S3DataReader trait and implementation for reading data from S3 buckets.
//! Auxiliary abstraction level between ReadBypassAgent and S3Client.
//!

use crate::{
    aws::s3_client::S3ClientError, nfs::nfs4_1_xdr::awsfile_bypass_data_locator,
    util::read_bypass_context::ReadBypassContext,
};
use async_trait::async_trait;
use bytes::Bytes;
use dyn_clone::{clone_trait_object, DynClone};
use log::warn;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

#[async_trait]
pub trait S3DataReader: DynClone + Send + Sync {
    async fn spawn_read_task(
        &self,
        s3_data_locator: awsfile_bypass_data_locator,
        read_bypass_context: Arc<ReadBypassContext>,
    ) -> JoinHandle<Result<Bytes, S3ClientError>>;
}

clone_trait_object!(S3DataReader);

#[derive(Clone)]
pub struct S3ReadBypassReader {
    semaphore: Arc<Semaphore>,
}

impl S3ReadBypassReader {
    pub fn new(max_in_flight_bytes: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(max_in_flight_bytes)),
        }
    }
}

#[async_trait]
impl S3DataReader for S3ReadBypassReader {
    async fn spawn_read_task(
        &self,
        s3_data_locator: awsfile_bypass_data_locator,
        read_bypass_context: Arc<ReadBypassContext>,
    ) -> JoinHandle<Result<Bytes, S3ClientError>> {
        let semaphore = self.semaphore.clone();
        let permit_size = s3_data_locator.count as usize;
        tokio::spawn(async move {
            let _permit = semaphore
                .acquire_many(permit_size as u32)
                .await
                .map_err(|_| S3ClientError::SemaphoreClosed)?;
            let locator_bucket_name =
                std::str::from_utf8(&s3_data_locator.bucket_name).map_err(|_| {
                    warn!("S3 read failed: invalid UTF-8 in bucket name");
                    S3ClientError::InvalidBucket
                })?;
            if locator_bucket_name != read_bypass_context.s3_bucket {
                warn!(
                    "S3 read failed: bucket name mismatch, expected='{}', got='{}'",
                    read_bypass_context.s3_bucket, locator_bucket_name
                );
                return Err(S3ClientError::InvalidBucket);
            }
            // Taking the key as is, S3Client will add bucket and prefix before request
            let s3_key = std::str::from_utf8(&s3_data_locator.s3_key).map_err(|_| {
                warn!("S3 read failed: invalid UTF-8 in s3_key");
                S3ClientError::InvalidKey
            })?;
            let etag = std::str::from_utf8(&s3_data_locator.etag).map_err(|_| {
                warn!("S3 read failed: invalid UTF-8 in etag");
                S3ClientError::InvalidETag
            })?;
            let version_id = std::str::from_utf8(&s3_data_locator.version_id).map_err(|_| {
                warn!("S3 read failed: invalid UTF-8 in version_id");
                S3ClientError::InvalidKey
            })?;
            let count = s3_data_locator.count;
            let offset = s3_data_locator.offset;
            read_bypass_context
                .s3_client
                .get_object_if_match(s3_key, etag, version_id, count, offset)
                .await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::read_bypass_context::ReadBypassContext;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Notify;

    fn create_test_locator() -> awsfile_bypass_data_locator {
        create_test_locator_with_count(1024)
    }

    fn create_test_locator_with_count(count: u32) -> awsfile_bypass_data_locator {
        awsfile_bypass_data_locator {
            bucket_name: Vec::new(),
            s3_key: b"test-key".to_vec(),
            etag: b"test-etag".to_vec(),
            version_id: vec![],
            offset: 0,
            count,
        }
    }

    /// A mock S3DataReader that wraps S3ReadBypassReader's semaphore but blocks
    /// after acquiring the permit until released, allowing us to observe concurrency.
    #[derive(Clone)]
    struct BlockingS3Reader {
        semaphore: Arc<Semaphore>,
        in_flight: Arc<AtomicUsize>,
        max_observed: Arc<AtomicUsize>,
        release: Arc<Notify>,
    }

    #[async_trait]
    impl S3DataReader for BlockingS3Reader {
        async fn spawn_read_task(
            &self,
            s3_data_locator: awsfile_bypass_data_locator,
            _read_bypass_context: Arc<ReadBypassContext>,
        ) -> JoinHandle<Result<Bytes, S3ClientError>> {
            let semaphore = self.semaphore.clone();
            let in_flight = self.in_flight.clone();
            let max_observed = self.max_observed.clone();
            let release = self.release.clone();
            let permit_size = s3_data_locator.count as u32;
            tokio::spawn(async move {
                let _permit = semaphore
                    .acquire_many(permit_size)
                    .await
                    .map_err(|_| S3ClientError::SemaphoreClosed)?;
                let val = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                max_observed.fetch_max(val, Ordering::SeqCst);
                // Hold the permit until test releases us
                release.notified().await;
                in_flight.fetch_sub(1, Ordering::SeqCst);
                Ok(Bytes::new())
            })
        }
    }

    #[tokio::test]
    async fn test_spawn_read_task_limits_concurrency() {
        // Each task requests 1000 bytes, total budget is 2000 bytes
        // So only 2 tasks can run concurrently
        let bytes_per_task: u32 = 1000;
        let max_in_flight_bytes: usize = 2000;
        let total_tasks: usize = 5;
        let reader = S3ReadBypassReader::new(max_in_flight_bytes);
        let ctx = Arc::new(ReadBypassContext::default().await);

        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_observed = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(Notify::new());

        let blocking_reader = BlockingS3Reader {
            semaphore: reader.semaphore.clone(),
            in_flight: in_flight.clone(),
            max_observed: max_observed.clone(),
            release: release.clone(),
        };

        // Spawn all tasks — they share the same semaphore as the real reader
        let mut handles = Vec::new();
        for _ in 0..total_tasks {
            let handle = blocking_reader
                .spawn_read_task(create_test_locator_with_count(bytes_per_task), ctx.clone())
                .await;
            handles.push(handle);
        }

        // Give tasks time to acquire permits
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Only 2 tasks should fit (2000 bytes / 1000 bytes per task)
        let expected_concurrent = 2;
        assert_eq!(
            in_flight.load(Ordering::SeqCst),
            expected_concurrent,
            "Expected exactly {} in-flight tasks, got {}",
            expected_concurrent,
            in_flight.load(Ordering::SeqCst)
        );
        assert_eq!(
            reader.semaphore.available_permits(),
            0,
            "All permits should be taken"
        );

        // Release all blocked tasks
        for _ in 0..total_tasks {
            release.notify_one();
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }

        for h in handles {
            let _ = h.await;
        }

        assert!(
            max_observed.load(Ordering::SeqCst) <= expected_concurrent,
            "Observed {} concurrent tasks, expected at most {}",
            max_observed.load(Ordering::SeqCst),
            expected_concurrent
        );
        assert_eq!(reader.semaphore.available_permits(), max_in_flight_bytes);
    }

    #[tokio::test]
    async fn test_semaphore_closed_returns_error() {
        let reader = S3ReadBypassReader::new(1024);
        let ctx = Arc::new(ReadBypassContext::default().await);

        reader.semaphore.close();

        let handle = reader.spawn_read_task(create_test_locator(), ctx).await;

        let result = handle.await.unwrap();
        assert!(
            matches!(result, Err(S3ClientError::SemaphoreClosed)),
            "Expected SemaphoreClosed, got {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_permits_released_after_task_completes() {
        let max_bytes: usize = 2048;
        let reader = S3ReadBypassReader::new(max_bytes);
        let ctx = Arc::new(ReadBypassContext::default().await);

        // Locator requests 1024 bytes
        let handle = reader.spawn_read_task(create_test_locator(), ctx).await;
        let _ = handle.await;

        assert_eq!(reader.semaphore.available_permits(), max_bytes);
    }

    #[tokio::test]
    async fn test_clone_shares_semaphore() {
        let reader = S3ReadBypassReader::new(1024);
        let cloned = reader.clone();

        let permit = reader.semaphore.acquire_many(512).await.unwrap();
        assert_eq!(cloned.semaphore.available_permits(), 512);

        drop(permit);
        assert_eq!(cloned.semaphore.available_permits(), 1024);
    }
}
