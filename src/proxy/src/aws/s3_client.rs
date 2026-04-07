#![allow(unused)]

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{Error, Result};
use async_trait::async_trait;
use aws_config::{default_provider::credentials::DefaultCredentialsChain, BehaviorVersion, Region};
use aws_sdk_s3::{operation::get_object::GetObjectError, Client};
use aws_smithy_types::timeout::TimeoutConfig;
use bytes::Bytes;
use futures::stream::StreamExt;
use regex::Regex;

use log::{debug, error, info, warn};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::{
    aws::{
        credentials::{get_aws_config_loader, ProxyCredentialsChain},
        cw_publisher::{CloudWatchClient, CloudWatchPublisher, LogLevel, CW_NAMESPACE_S3FILES},
    },
    config_parser::{ProxyConfig, ReadBypassConfig},
};

const DEFAULT_PERMISSION_VALIDATION_SECONDS: u64 = 60;

const MAX_CONCURRENT_S3_REQUESTS: usize = 32;

/// Result of a bucket permission check, separating reachability from the
/// conservative enable/disable decision.
#[derive(Debug, Clone, PartialEq)]
pub struct PermissionCheckResult {
    /// Whether the S3 endpoint was reachable (request got an HTTP response).
    pub is_reachable: bool,
    /// Whether the request was denied with a 403.
    pub is_permission_denied: bool,
    /// Whether read bypass should be enabled, using the existing conservative logic.
    pub should_enable: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum S3ClientError {
    #[error("S3 Bucket is currently inaccessible.")]
    NotEnabled,

    #[error("An error occurred (NoSuchKey) when calling the GetObject operation: The specified key does not exist.")]
    NoSuchKey,

    #[error("ETag provided in GetObject request does not match object's ETag")]
    ETagMismatchError,

    #[error("S3 returned {actual} bytes, expected {expected}")]
    SizeMismatch { expected: u64, actual: u64 },

    #[error(transparent)]
    NoAccess(#[from] Box<dyn std::error::Error + Send + Sync>),

    #[error("Permission Validator is already running")]
    ValidatorAlreadyRunning,

    #[error("Invalid Bucket provided for S3 access")]
    InvalidBucket,

    #[error("Invalid ETag provided for S3 access")]
    InvalidETag,

    #[error("Invalid key provided for S3 access")]
    InvalidKey,

    #[error("S3 fetch semaphore closed")]
    SemaphoreClosed,
}

pub struct S3Client {
    bucket: String,
    prefix: String,
    client: Arc<Client>,
    cw_publisher: Option<Arc<dyn CloudWatchClient>>,
    enabled: Arc<AtomicBool>,
    validator_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    read_bypass_config: ReadBypassConfig,
    cancellation_token: CancellationToken,
}

// Only used for testing
#[cfg(debug_assertions)]
impl Clone for S3Client {
    fn clone(&self) -> Self {
        Self {
            bucket: self.bucket.clone(),
            prefix: self.prefix.clone(),
            client: self.client.clone(),
            cw_publisher: self.cw_publisher.clone(),
            enabled: self.enabled.clone(),
            validator_task: Mutex::new(None), // New instance gets a fresh validator task handle
            read_bypass_config: self.read_bypass_config.clone(),
            cancellation_token: CancellationToken::new(),
        }
    }
}

impl S3Client {
    pub async fn new(bucket: &str, prefix: &str, proxy_config: &ProxyConfig) -> Result<Self> {
        let mut aws_config_loader = get_aws_config_loader(proxy_config).await;

        let read_bypass_config = proxy_config.nested_config.read_bypass_config.clone();
        let timeout_config = TimeoutConfig::builder()
            .operation_timeout(Duration::from_secs(
                read_bypass_config.s3_operation_timeout_seconds,
            ))
            .operation_attempt_timeout(Duration::from_millis(
                read_bypass_config.s3_operation_attempt_timeout_ms,
            ))
            .build();
        aws_config_loader = aws_config_loader.timeout_config(timeout_config);

        let crypto_mode = if proxy_config.fips {
            aws_smithy_http_client::tls::rustls_provider::CryptoMode::AwsLcFips
        } else {
            aws_smithy_http_client::tls::rustls_provider::CryptoMode::AwsLc
        };
        let http_client = aws_smithy_http_client::Builder::new()
            .pool_idle_timeout(Duration::from_secs(
                read_bypass_config.s3_idle_timeout_seconds,
            ))
            .tls_provider(aws_smithy_http_client::tls::Provider::Rustls(crypto_mode))
            .build_https();
        aws_config_loader = aws_config_loader.http_client(http_client);

        let aws_sdk_config: aws_config::SdkConfig = aws_config_loader.load().await;
        let s3_config = aws_sdk_s3::config::Builder::from(&aws_sdk_config).build();
        let inner_client = Client::from_conf(s3_config);

        let cw_publisher: Arc<dyn CloudWatchClient> = Arc::new(
            CloudWatchPublisher::new_from_aws_config(
                &aws_sdk_config,
                Some(bucket.to_string()),
                proxy_config,
                CW_NAMESPACE_S3FILES,
            )
            .await,
        );

        if (!Self::is_bucket_name_valid(bucket)) {
            let err_message = format!("Invalid bucket name '{}'", bucket);
            warn!("{}", err_message);
            cw_publisher.publish_s3_reachable(bucket, false);
            cw_publisher.emit_log(LogLevel::Error, &err_message);
            return Err(Error::msg(err_message));
        }

        let s3_client = Self {
            bucket: bucket.to_string(),
            prefix: prefix.to_string(),
            client: Arc::new(inner_client),
            cw_publisher: Some(cw_publisher),
            enabled: Arc::new(AtomicBool::new(true)),
            validator_task: Mutex::new(None),
            read_bypass_config: read_bypass_config,
            cancellation_token: CancellationToken::new(),
        };

        s3_client
            .start_permission_validator(DEFAULT_PERMISSION_VALIDATION_SECONDS)
            .await;
        Ok(s3_client)
    }

    /// Create S3Client with a pre-configured AWS SDK client (only used for testing)
    #[cfg(debug_assertions)]
    pub async fn new_with_client(bucket: &str, prefix: &str, aws_client: Arc<Client>) -> Self {
        // For testing, we don't start the permission validator
        Self {
            bucket: bucket.to_string(),
            prefix: prefix.to_string(),
            client: aws_client,
            cw_publisher: None,
            enabled: Arc::new(AtomicBool::new(true)), // Start enabled for testing
            validator_task: Mutex::new(None),
            read_bypass_config: ReadBypassConfig::default(),
            cancellation_token: CancellationToken::new(),
        }
    }

    pub fn is_enabled(&self) -> bool {
        // This is "best effort" check, we do not care if we are catching "wrong" value nanosecond
        // after it was disabled or enabled. It is still safe to get an extra ReadBypass request
        // right after feature was disabled or skip one right after feature was enabled. Feature
        // flag updated only after permission check which is O(10)ms, we do not expect it
        // to have any kind of flapping behavior.
        self.enabled.load(Ordering::Relaxed)
    }

    /// Checks bucket permissions for read bypassing via S3 GetObject.
    ///
    /// Returns a `PermissionCheckResult` with two independent signals:
    /// - `is_reachable`: whether the S3 request got any HTTP response (true even for 403/404).
    ///   Only false for network-level failures (DNS, timeout, connection refused).
    /// - `should_enable`: the conservative enable/disable decision. When currently enabled,
    ///   only disables on 403. When currently disabled, only enables on 200 or NoSuchKey.
    pub async fn check_bucket_permissions(
        client: &Client,
        bucket: &String,
        prefix: &String,
        currently_enabled: bool,
    ) -> PermissionCheckResult {
        let key = format!("{}/", prefix);
        match client.get_object().bucket(bucket).key(key).send().await {
            Ok(_) => PermissionCheckResult {
                is_reachable: true,
                is_permission_denied: false,
                should_enable: true,
            },
            Err(e) => {
                let is_reachable = e.raw_response().is_some();
                let is_permission_denied =
                    matches!(e.raw_response().map(|r| r.status().as_u16()), Some(403));
                let should_enable = if currently_enabled {
                    !is_permission_denied
                } else {
                    matches!(e.as_service_error(), Some(GetObjectError::NoSuchKey(_)))
                };
                PermissionCheckResult {
                    is_reachable,
                    is_permission_denied,
                    should_enable,
                }
            }
        }
    }

    /// Start the permission validator that periodically checks bucket permissions until the s3
    /// client can be enabled
    ///
    /// # Arguments
    /// * `check_interval_seconds` - The interval in seconds between permission checks
    pub async fn start_permission_validator(
        &self,
        check_interval_seconds: u64,
    ) -> Result<(), S3ClientError> {
        // Check if a validator task is already running
        let mut task_guard = self.validator_task.lock().await;
        if let Some(handle) = &*task_guard {
            if !handle.is_finished() {
                info!("Permission validator task is already running");
                return Err(S3ClientError::ValidatorAlreadyRunning);
            }
        }

        // Clone references for the periodic task
        let client = self.client.clone();
        let bucket = self.bucket.clone();
        let prefix = self.prefix.clone();
        let enabled = self.enabled.clone();
        let cw_publisher = self.cw_publisher.clone();
        let cancellation_token = self.cancellation_token.clone();

        // Start the task to check bucket permissions. This continuously monitors bucket
        // accessibility and updates enabled state accordingly.
        let handle = tokio::spawn(async move {
            let interval_duration = std::time::Duration::from_secs(check_interval_seconds);
            let mut interval = tokio::time::interval(interval_duration);
            let mut is_first_check = true;

            loop {
                // From `tokio::time::interval` docs: "The first tick completes immediately"
                tokio::select! {
                    _ = cancellation_token.cancelled() => {
                        info!("Permission validator cancelled");
                        break;
                    }
                    _ = interval.tick() => {}
                }
                let was_enabled = enabled.load(Ordering::Relaxed);
                let result =
                    Self::check_bucket_permissions(&client, &bucket, &prefix, was_enabled).await;

                debug!(
                    "S3 bucket stats: is_reachable={}, is_permission_denied={}, should_enable={}.",
                    result.is_reachable, result.is_permission_denied, result.should_enable
                );

                if result.should_enable {
                    enabled.store(true, Ordering::Relaxed);
                    info!("S3 bucket accessible. ReadBypass enabled.");
                } else {
                    enabled.store(false, Ordering::Relaxed);
                    error!(
                        "S3 bucket inaccessible: bucket='{}', prefix='{}'. ReadBypass disabled.",
                        bucket, prefix
                    );
                }
                Self::emit_permission_metrics_and_logs(
                    &result,
                    &cw_publisher,
                    &bucket,
                    &prefix,
                    was_enabled,
                    is_first_check,
                )
                .await;
                is_first_check = false;
            }
        });

        // Store the task handle for ensuring that only a single validator tasks runs at a given time.
        *task_guard = Some(handle);

        Ok(())
    }

    async fn emit_permission_metrics_and_logs(
        result: &PermissionCheckResult,
        cw_publisher: &Option<Arc<dyn CloudWatchClient>>,
        bucket: &String,
        prefix: &String,
        was_enabled: bool,
        is_first_check: bool,
    ) {
        if let Some(publisher) = cw_publisher {
            publisher.publish_s3_reachable(&bucket, result.is_reachable);
            publisher.publish_s3_permitted(&bucket, !result.is_permission_denied);

            // We emit logs when bucket accessibility changes or on the very first check
            let became_enabled = !was_enabled && result.should_enable;
            let became_disabled = was_enabled && !result.should_enable;

            if became_enabled || (is_first_check && result.should_enable) {
                publisher.emit_log(
                    LogLevel::Info,
                    &format!(
                        "S3 bucket accessible. ReadBypass enabled. bucket='{}', prefix='{}'",
                        bucket, prefix
                    ),
                );
            } else if became_disabled || (is_first_check && !result.should_enable) {
                let reason = if !result.is_reachable {
                    "bucket is not reachable"
                } else if result.is_permission_denied {
                    "bucket acccess is not permitted (403)"
                } else {
                    "bucket check failed"
                };
                publisher.emit_log(
                    LogLevel::Error,
                    &format!(
                        "S3 bucket inaccessible: {}. ReadBypass disabled. bucket='{}', prefix='{}'",
                        reason, bucket, prefix
                    ),
                );
            }
        }
    }

    fn extract_s3_error(
        &self,
        e: aws_sdk_s3::error::SdkError<GetObjectError>,
        object_name: &str,
        etag: &str,
        context: &str,
    ) -> S3ClientError {
        let error = if let Some(GetObjectError::NoSuchKey(_)) = e.as_service_error() {
            S3ClientError::NoSuchKey
        } else if let Some(resp) = e.raw_response() {
            if resp.status().as_u16() == 412 {
                S3ClientError::ETagMismatchError
            } else {
                S3ClientError::NoAccess(e.into())
            }
        } else {
            S3ClientError::NoAccess(e.into())
        };

        let msg = format!(
            "S3 GetObject failed: key='{}', etag='{}', {}, error='{:?}'",
            object_name, etag, context, error
        );
        if let Some(publisher) = &self.cw_publisher {
            publisher.emit_log(LogLevel::Error, &msg);
        }
        error
    }

    pub async fn get_object_if_match(
        &self,
        object_name: &str,
        etag: &str,
        version_id: &str,
        count: u32,
        offset: u64,
    ) -> Result<Bytes, S3ClientError> {
        if !self.is_enabled() {
            return Err(S3ClientError::NotEnabled);
        }

        let total_size = count as u64;
        let s3_chunk_size_bytes = self.read_bypass_config.s3_read_chunk_size_bytes;

        let end = offset + total_size;
        let mut chunks = Vec::new();
        let mut chunk_start = offset;
        while chunk_start < end {
            let chunk_size = s3_chunk_size_bytes.min(end - chunk_start);
            chunks.push((chunk_start, chunk_size));
            chunk_start += chunk_size;
        }

        let client = self.client.clone();
        let bucket = self.bucket.clone();
        let key = object_name.to_string();
        let etag_owned = etag.to_string();
        let version_id_owned = version_id.to_string();

        let results: Vec<_> = futures::stream::iter(chunks.clone())
            .map(|(start, chunk_size)| {
                let client = client.clone();
                let bucket = bucket.clone();
                let key = key.clone();
                let etag = etag_owned.clone();
                let version_id = version_id_owned.clone();
                async move {
                    let mut req = client.get_object().bucket(&bucket).key(&key).range(format!(
                        "bytes={}-{}",
                        start,
                        start + chunk_size - 1
                    ));
                    req = if Self::is_version_id_set(&version_id) {
                        req.version_id(&version_id)
                    } else {
                        req.if_match(&etag)
                    };
                    (chunk_size, req.send().await)
                }
            })
            .buffered(MAX_CONCURRENT_S3_REQUESTS)
            .collect()
            .await;

        let mut result = bytes::BytesMut::with_capacity(total_size as usize);
        for (expected_size_bytes, res) in results {
            let response =
                res.map_err(|e| self.extract_s3_error(e, object_name, etag, "GetObject"))?;
            let content_length = response.content_length().unwrap() as u64;
            if content_length != expected_size_bytes {
                return Err(S3ClientError::SizeMismatch {
                    expected: expected_size_bytes,
                    actual: content_length,
                });
            }
            let chunk = response
                .body
                .collect()
                .await
                .map_err(|e| S3ClientError::NoAccess(e.into()))?;
            result.extend_from_slice(&chunk.into_bytes());
        }

        Ok(result.freeze())
    }

    fn is_version_id_set(version_id: &str) -> bool {
        !version_id.is_empty() && !version_id.eq_ignore_ascii_case("null")
    }

    pub fn is_bucket_name_valid(bucket_name: &str) -> bool {
        // Basic s3 bucket name checker. Lookahead not supported, so more complicated checks like
        // IP addresses and consecutive periods cannot be included
        let bucket_name_regex = Regex::new(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$").unwrap();
        bucket_name_regex.is_match(bucket_name)
    }

    #[cfg(test)]
    pub async fn default() -> Self {
        let config = aws_config::defaults(BehaviorVersion::latest()).load().await;
        let s3_config = aws_sdk_s3::config::Builder::from(&config).build();
        let inner_client = Client::from_conf(s3_config);
        Self {
            bucket: String::new(),
            prefix: String::new(),
            client: Arc::new(inner_client),
            cw_publisher: None,
            enabled: Arc::new(AtomicBool::new(false)),
            validator_task: Mutex::new(None),
            read_bypass_config: ReadBypassConfig::default(),
            cancellation_token: CancellationToken::new(),
        }
    }

    #[cfg(test)]
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }
}

impl Drop for S3Client {
    fn drop(&mut self) {
        self.cancellation_token.cancel();
    }
}

pub struct S3ClientStandardBuilder;

#[async_trait]
pub trait S3ClientBuilder {
    async fn build(
        &self,
        bucket: &str,
        prefix: &str,
        proxy_config: &ProxyConfig,
    ) -> Option<S3Client>;
}

#[async_trait]
impl S3ClientBuilder for S3ClientStandardBuilder {
    async fn build(
        &self,
        bucket: &str,
        prefix: &str,
        proxy_config: &ProxyConfig,
    ) -> Option<S3Client> {
        match S3Client::new(bucket, prefix, proxy_config).await {
            Ok(client) => Some(client),
            Err(e) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::nfs::nfs4_1_xdr::prev_entry4;
    use crate::test_utils::get_test_config;
    use test_case::test_case;

    use super::*;
    use aws_sdk_s3::config::http::HttpResponse;
    use aws_sdk_s3::error::SdkError;
    use aws_sdk_s3::operation::get_object::{GetObjectError, GetObjectOutput};
    use aws_sdk_s3::primitives::{ByteStream, SdkBody};
    use aws_sdk_s3::types::error::InvalidObjectState;
    use aws_smithy_mocks::{mock, mock_client};
    use aws_smithy_runtime_api::http::Response;
    use aws_smithy_runtime_api::http::StatusCode;
    use std::time::Duration;
    use tokio::time::{self, sleep};

    fn create_test_s3_client(
        client: Client,
        cw_publisher: Option<Arc<dyn CloudWatchClient>>,
        enabled: bool,
    ) -> S3Client {
        S3Client {
            bucket: "test_bucket".to_string(),
            prefix: "test_prefix".to_string(),
            client: Arc::new(client),
            cw_publisher,
            enabled: Arc::new(AtomicBool::new(enabled)),
            validator_task: Mutex::new(None),
            read_bypass_config: ReadBypassConfig::default(),
            cancellation_token: CancellationToken::new(),
        }
    }

    #[test_case(false; "when disabled")]
    #[test_case(true; "when enabled")]
    #[tokio::test]
    pub async fn test_s3_client_check_permission_success(currently_enabled: bool) {
        let get_object_rule = mock!(aws_sdk_s3::Client::get_object).then_output(|| {
            GetObjectOutput::builder()
                .body(ByteStream::from_static(b"test-content"))
                .build()
        });

        let client = Arc::new(mock_client!(aws_sdk_s3, [&get_object_rule]));
        let bucket = "test_bucket".to_string();
        let prefix = "test_prefix".to_string();

        let result =
            S3Client::check_bucket_permissions(&client, &bucket, &prefix, currently_enabled).await;
        assert!(result.is_reachable);
        assert!(result.should_enable);
    }

    #[test_case(false; "when disabled")]
    #[test_case(true; "when enabled")]
    #[tokio::test]
    pub async fn test_s3_client_check_permission_no_such_key(currently_enabled: bool) {
        let get_object_rule = mock!(aws_sdk_s3::Client::get_object).then_error(|| {
            GetObjectError::NoSuchKey(aws_sdk_s3::types::error::NoSuchKey::builder().build())
        });

        let client = Arc::new(mock_client!(aws_sdk_s3, [&get_object_rule]));
        let bucket = "test_bucket".to_string();
        let prefix = "test_prefix".to_string();

        let result =
            S3Client::check_bucket_permissions(&client, &bucket, &prefix, currently_enabled).await;
        assert!(result.should_enable);
    }

    #[tokio::test]
    pub async fn test_s3_client_check_permission_object_invalid_state_when_disabled() {
        let get_object_rule_invalid_state =
            mock!(aws_sdk_s3::Client::get_object).then_error(|| {
                GetObjectError::InvalidObjectState(InvalidObjectState::builder().build())
            });

        let client = Arc::new(mock_client!(aws_sdk_s3, [&get_object_rule_invalid_state]));
        let bucket = "test_bucket".to_string();
        let prefix = "test_prefix".to_string();

        let result = S3Client::check_bucket_permissions(&client, &bucket, &prefix, false).await;
        assert!(!result.should_enable);
    }

    #[tokio::test]
    pub async fn test_s3_client_check_permission_object_invalid_state_when_enabled() {
        let get_object_rule_invalid_state =
            mock!(aws_sdk_s3::Client::get_object).then_error(|| {
                GetObjectError::InvalidObjectState(InvalidObjectState::builder().build())
            });

        let client = Arc::new(mock_client!(aws_sdk_s3, [&get_object_rule_invalid_state]));
        let bucket = "test_bucket".to_string();
        let prefix = "test_prefix".to_string();

        let result = S3Client::check_bucket_permissions(&client, &bucket, &prefix, true).await;
        assert!(result.should_enable);
    }

    #[test_case(false; "when disabled")]
    #[test_case(true; "when enabled")]
    #[tokio::test]
    pub async fn test_s3_client_check_permission_access_denied(currently_enabled: bool) {
        let get_object_rule = mock!(aws_sdk_s3::Client::get_object).then_http_response(|| {
            HttpResponse::new(
                StatusCode::try_from(403).unwrap(),
                SdkBody::from("Forbidden"),
            )
        });

        let client = Arc::new(mock_client!(aws_sdk_s3, [&get_object_rule]));
        let bucket = "test_bucket".to_string();
        let prefix = "test_prefix".to_string();

        let result =
            S3Client::check_bucket_permissions(&client, &bucket, &prefix, currently_enabled).await;
        assert!(result.is_reachable);
        assert!(!result.should_enable);
    }

    #[tokio::test]
    pub async fn test_s3_client_check_permission_service_unavailable_when_disabled() {
        let get_object_rule = mock!(aws_sdk_s3::Client::get_object).then_http_response(|| {
            HttpResponse::new(
                StatusCode::try_from(503).unwrap(),
                SdkBody::from("Service Unavailable"),
            )
        });

        let client = Arc::new(mock_client!(aws_sdk_s3, [&get_object_rule]));
        let bucket = "test_bucket".to_string();
        let prefix = "test_prefix".to_string();

        let result = S3Client::check_bucket_permissions(&client, &bucket, &prefix, false).await;
        assert!(result.is_reachable);
        assert!(!result.should_enable);
    }

    #[tokio::test]
    pub async fn test_s3_client_check_permission_service_unavailable_when_enabled() {
        let get_object_rule = mock!(aws_sdk_s3::Client::get_object).then_http_response(|| {
            HttpResponse::new(
                StatusCode::try_from(503).unwrap(),
                SdkBody::from("Service Unavailable"),
            )
        });

        let client = Arc::new(mock_client!(aws_sdk_s3, [&get_object_rule]));
        let bucket = "test_bucket".to_string();
        let prefix = "test_prefix".to_string();

        let result = S3Client::check_bucket_permissions(&client, &bucket, &prefix, true).await;
        assert!(result.is_reachable);
        assert!(result.should_enable);
    }

    #[tokio::test]
    pub async fn test_get_object_if_match_success() {
        let expected_content = b"test-content";
        let get_object_rule = mock!(aws_sdk_s3::Client::get_object).then_output(|| {
            GetObjectOutput::builder()
                .content_length(expected_content.len() as i64)
                .body(ByteStream::from_static(expected_content))
                .build()
        });

        let mock_client =
            create_test_s3_client(mock_client!(aws_sdk_s3, [&get_object_rule]), None, true);

        let result = mock_client
            .get_object_if_match(
                "test_object",
                "test-etag",
                "",
                expected_content.len() as u32,
                0,
            )
            .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Bytes::from_static(expected_content));
    }

    #[tokio::test]
    pub async fn test_get_object_with_version_id() {
        let expected_content = b"versioned-content";
        let get_object_rule = mock!(aws_sdk_s3::Client::get_object)
            .match_requests(|req| req.version_id() == Some("v1"))
            .then_output(|| {
                GetObjectOutput::builder()
                    .content_length(expected_content.len() as i64)
                    .body(ByteStream::from_static(expected_content))
                    .build()
            });

        let mock_client =
            create_test_s3_client(mock_client!(aws_sdk_s3, [&get_object_rule]), None, true);

        let result = mock_client
            .get_object_if_match(
                "test_object",
                "test-etag",
                "v1",
                expected_content.len() as u32,
                0,
            )
            .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Bytes::from_static(expected_content));
    }

    #[tokio::test]
    pub async fn test_get_object_falls_back_to_if_match_when_version_id_empty() {
        let expected_content = b"etag-content";
        let get_object_rule = mock!(aws_sdk_s3::Client::get_object)
            .match_requests(|req| req.if_match() == Some("test-etag"))
            .then_output(|| {
                GetObjectOutput::builder()
                    .content_length(expected_content.len() as i64)
                    .body(ByteStream::from_static(expected_content))
                    .build()
            });

        let mock_client =
            create_test_s3_client(mock_client!(aws_sdk_s3, [&get_object_rule]), None, true);

        let result = mock_client
            .get_object_if_match(
                "test_object",
                "test-etag",
                "",
                expected_content.len() as u32,
                0,
            )
            .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Bytes::from_static(expected_content));
    }

    #[tokio::test]
    pub async fn test_get_object_if_match_etag_mismatch() {
        let get_object_rule = mock!(aws_sdk_s3::Client::get_object).then_http_response(|| {
            HttpResponse::new(
                StatusCode::try_from(412).unwrap(),
                SdkBody::from("Precondition Failed"),
            )
        });

        let mock_client =
            create_test_s3_client(mock_client!(aws_sdk_s3, [&get_object_rule]), None, true);

        let result = mock_client
            .get_object_if_match("test_object", "wrong-etag", "", 50, 0)
            .await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            S3ClientError::ETagMismatchError
        ));
    }

    #[tokio::test]
    pub async fn test_get_object_if_match_no_such_key() {
        let get_object_rule = mock!(aws_sdk_s3::Client::get_object).then_error(|| {
            GetObjectError::NoSuchKey(aws_sdk_s3::types::error::NoSuchKey::builder().build())
        });

        let mock_client =
            create_test_s3_client(mock_client!(aws_sdk_s3, [&get_object_rule]), None, true);

        let result = mock_client
            .get_object_if_match("test_object", "test-etag", "", 50, 0)
            .await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), S3ClientError::NoSuchKey));
    }

    #[tokio::test]
    pub async fn test_get_object_if_match_size_mismatch() {
        // S3 returns 8 bytes when we requested 100
        let get_object_rule = mock!(aws_sdk_s3::Client::get_object).then_output(|| {
            GetObjectOutput::builder()
                .content_length(8)
                .body(ByteStream::from_static(b"12345678"))
                .build()
        });

        let mock_client =
            create_test_s3_client(mock_client!(aws_sdk_s3, [&get_object_rule]), None, true);

        let result = mock_client
            .get_object_if_match("test_object", "test-etag", "", 100, 0)
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(
                err,
                S3ClientError::SizeMismatch {
                    expected: 100,
                    actual: 8
                }
            ),
            "Expected SizeMismatch error, got {:?}",
            err
        );
    }

    #[tokio::test]
    pub async fn test_get_object_if_match_not_enabled() {
        let mock_client = create_test_s3_client(mock_client!(aws_sdk_s3, []), None, false);

        let result = mock_client
            .get_object_if_match("test_object", "test-etag", "", 50, 0)
            .await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), S3ClientError::NotEnabled));
    }

    #[tokio::test]
    pub async fn test_permission_validator_task() {
        // First call fails, second call succeeds
        let get_object_rule = mock!(aws_sdk_s3::Client::get_object)
            .sequence()
            .http_response(|| {
                HttpResponse::new(
                    StatusCode::try_from(403).unwrap(),
                    SdkBody::from("Forbidden"),
                )
            })
            .output(|| {
                GetObjectOutput::builder()
                    .body(ByteStream::from_static(b"test-content"))
                    .build()
            })
            .build();

        let mock_client =
            create_test_s3_client(mock_client!(aws_sdk_s3, [&get_object_rule]), None, false);

        tokio::time::pause();
        let interval_seconds = 100;
        mock_client
            .start_permission_validator(interval_seconds)
            .await
            .unwrap();

        // Initial check should fail, client should be disabled
        assert!(!mock_client.is_enabled());

        tokio::time::advance(Duration::from_secs(interval_seconds * 2)).await;

        // wait for retry to succeed
        mock_client
            .validator_task
            .lock()
            .await
            .as_mut()
            .unwrap()
            .await;
        tokio::time::resume();

        // After the second check, client should be enabled
        assert!(mock_client.is_enabled());
        assert_eq!(2, get_object_rule.num_calls());
    }

    #[tokio::test]
    pub async fn test_only_one_validator_task_runs() {
        // Both calls succeed
        let get_object_rule = mock!(aws_sdk_s3::Client::get_object)
            .sequence()
            .http_response(|| {
                HttpResponse::new(
                    StatusCode::try_from(403).unwrap(),
                    SdkBody::from("Forbidden"),
                )
            })
            .output(|| {
                GetObjectOutput::builder()
                    .body(ByteStream::from_static(b"test-content"))
                    .build()
            })
            .build();

        tokio::time::pause();
        let mock_client =
            create_test_s3_client(mock_client!(aws_sdk_s3, [&get_object_rule]), None, false);

        // Start the validator twice
        mock_client.start_permission_validator(10).await.unwrap();
        assert!(matches!(
            mock_client.start_permission_validator(100).await,
            Err(S3ClientError::ValidatorAlreadyRunning)
        ));

        // Wait for the first validator task to succeed
        tokio::time::advance(Duration::from_secs(10 * 2)).await;
        mock_client
            .validator_task
            .lock()
            .await
            .as_mut()
            .unwrap()
            .await;
        tokio::time::resume();

        // Client should be enabled
        assert!(mock_client.is_enabled());
    }

    #[tokio::test]
    pub async fn test_permission_validator_enabled_to_disabled_transition() {
        // Test validator handling permission revocation and restoration
        // First call succeeds (enabled), second call fails with 403 (disabled), third call succeeds (enabled again)
        let get_object_rule = mock!(aws_sdk_s3::Client::get_object)
            .sequence()
            .output(|| {
                GetObjectOutput::builder()
                    .body(ByteStream::from_static(b"test-content"))
                    .build()
            })
            .http_response(|| {
                HttpResponse::new(
                    StatusCode::try_from(403).unwrap(),
                    SdkBody::from("Forbidden"),
                )
            })
            .output(|| {
                GetObjectOutput::builder()
                    .body(ByteStream::from_static(b"test-content"))
                    .build()
            })
            .build();

        tokio::time::pause();
        let mock_client =
            create_test_s3_client(mock_client!(aws_sdk_s3, [&get_object_rule]), None, false);

        let interval_seconds = 5;
        mock_client
            .start_permission_validator(interval_seconds)
            .await
            .unwrap();

        // Advance time and yield sufficiently for first enablement to succeed
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert!(mock_client.is_enabled());

        // Second check should fail with 403 - read bypass disabled
        tokio::time::advance(Duration::from_secs(interval_seconds)).await;
        tokio::task::yield_now().await;
        assert!(!mock_client.is_enabled());

        // Third check should succeed - read bypasss enabled again
        tokio::time::advance(Duration::from_secs(interval_seconds)).await;
        tokio::task::yield_now().await;
        assert!(mock_client.is_enabled());

        mock_client
            .validator_task
            .lock()
            .await
            .as_mut()
            .unwrap()
            .abort();
        tokio::time::resume();

        assert_eq!(3, get_object_rule.num_calls());
    }

    #[tokio::test]
    async fn test_get_object_mismatched_prefix() {
        // Confirm that we always use a key with prefix returned by a server
        let expected_content = b"test-content";
        let get_object_rule = mock!(aws_sdk_s3::Client::get_object)
            .match_requests(|req| {
                let request_key = req.key().unwrap().to_string();
                request_key == "test_prefix/test_object"
            })
            .then_output(|| {
                GetObjectOutput::builder()
                    .content_length(expected_content.len() as i64)
                    .body(ByteStream::from_static(expected_content))
                    .build()
            });

        let mock_client = S3Client {
            bucket: "test_bucket".to_string(),
            prefix: "bad_prefix/".to_string(),
            client: Arc::new(mock_client!(aws_sdk_s3, [&get_object_rule])),
            enabled: Arc::new(AtomicBool::new(true)),
            cw_publisher: None,
            validator_task: Mutex::new(None),
            read_bypass_config: ReadBypassConfig::default(),
            cancellation_token: CancellationToken::new(),
        };

        let result = mock_client
            .get_object_if_match(
                "test_prefix/test_object",
                "test-etag",
                "",
                expected_content.len() as u32,
                0,
            )
            .await;

        assert!(result.is_ok());
        assert_eq!(get_object_rule.num_calls(), 1);
    }

    #[tokio::test]
    async fn test_large_request_splits_into_chunks() {
        let s3_chunk_size_bytes = ReadBypassConfig::default().s3_read_chunk_size_bytes;
        let total_size = (s3_chunk_size_bytes * 2) as u32;
        let get_object_rule = mock!(aws_sdk_s3::Client::get_object)
            .sequence()
            .output(move || {
                GetObjectOutput::builder()
                    .content_length(s3_chunk_size_bytes as i64)
                    .body(ByteStream::from(vec![0u8; s3_chunk_size_bytes as usize]))
                    .build()
            })
            .output(move || {
                GetObjectOutput::builder()
                    .content_length(s3_chunk_size_bytes as i64)
                    .body(ByteStream::from(vec![0u8; s3_chunk_size_bytes as usize]))
                    .build()
            })
            .build();

        let mock_client =
            create_test_s3_client(mock_client!(aws_sdk_s3, [&get_object_rule]), None, true);
        let _ = mock_client
            .get_object_if_match("obj", "etag", "", total_size, 0)
            .await;

        assert_eq!(get_object_rule.num_calls(), 2);
    }

    #[tokio::test]
    async fn test_chunked_results_reassembled_in_order() {
        let chunk_size = ReadBypassConfig::default().s3_read_chunk_size_bytes as usize;
        let chunk1: Vec<u8> = vec![1u8; chunk_size];
        let chunk2: Vec<u8> = vec![2u8; chunk_size];
        let chunk1_clone = chunk1.clone();
        let chunk2_clone = chunk2.clone();

        let get_object_rule = mock!(aws_sdk_s3::Client::get_object)
            .sequence()
            .output(move || {
                GetObjectOutput::builder()
                    .content_length(chunk_size as i64)
                    .body(ByteStream::from(chunk1_clone.clone()))
                    .build()
            })
            .output(move || {
                GetObjectOutput::builder()
                    .content_length(chunk_size as i64)
                    .body(ByteStream::from(chunk2_clone.clone()))
                    .build()
            })
            .build();

        let mock_client =
            create_test_s3_client(mock_client!(aws_sdk_s3, [&get_object_rule]), None, true);
        let result = mock_client
            .get_object_if_match("obj", "etag", "", (chunk_size * 2) as u32, 0)
            .await
            .unwrap();

        assert!(result[0..chunk_size].iter().all(|&b| b == 1));
        assert!(result[chunk_size..chunk_size * 2].iter().all(|&b| b == 2));
    }

    #[tokio::test]
    async fn test_chunk_failure_fails_whole_request() {
        let chunk_size = ReadBypassConfig::default().s3_read_chunk_size_bytes as usize;
        let chunk1: Vec<u8> = vec![0u8; chunk_size];

        let get_object_rule = mock!(aws_sdk_s3::Client::get_object)
            .sequence()
            .output(move || {
                GetObjectOutput::builder()
                    .content_length(chunk_size as i64)
                    .body(ByteStream::from(chunk1.clone()))
                    .build()
            })
            .http_response(|| {
                HttpResponse::new(
                    StatusCode::try_from(500).unwrap(),
                    SdkBody::from("Internal Error"),
                )
            })
            .build();

        let mock_client =
            create_test_s3_client(mock_client!(aws_sdk_s3, [&get_object_rule]), None, true);
        let total_size = (chunk_size * 2) as u32;
        let result = mock_client
            .get_object_if_match("obj", "etag", "", total_size, 0)
            .await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), S3ClientError::NoAccess(_)));
    }

    #[tokio::test]
    async fn test_chunk_etag_mismatch_returns_etag_error() {
        let chunk_size = ReadBypassConfig::default().s3_read_chunk_size_bytes as usize;
        let chunk1: Vec<u8> = vec![0u8; chunk_size];

        let get_object_rule = mock!(aws_sdk_s3::Client::get_object)
            .sequence()
            .output(move || {
                GetObjectOutput::builder()
                    .content_length(chunk_size as i64)
                    .body(ByteStream::from(chunk1.clone()))
                    .build()
            })
            .http_response(|| {
                HttpResponse::new(
                    StatusCode::try_from(412).unwrap(),
                    SdkBody::from("Precondition Failed"),
                )
            })
            .build();

        let mock_client =
            create_test_s3_client(mock_client!(aws_sdk_s3, [&get_object_rule]), None, true);
        let total_size = (chunk_size * 2) as u32;
        let result = mock_client
            .get_object_if_match("obj", "etag", "", total_size, 0)
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            S3ClientError::ETagMismatchError
        ));
    }

    #[tokio::test]
    async fn test_partial_last_chunk_size() {
        let s3_chunk_size = ReadBypassConfig::default().s3_read_chunk_size_bytes;
        let last_chunk_size = 1024 * 1024; // 1MiB
                                           // 17MiB = 8MiB + 8MiB + 1MiB (3 chunks)
        let total_size = (s3_chunk_size * 2 + last_chunk_size) as u32;
        let get_object_rule = mock!(aws_sdk_s3::Client::get_object)
            .sequence()
            .output(move || {
                GetObjectOutput::builder()
                    .content_length(s3_chunk_size as i64)
                    .body(ByteStream::from(vec![0u8; s3_chunk_size as usize]))
                    .build()
            })
            .output(move || {
                GetObjectOutput::builder()
                    .content_length(s3_chunk_size as i64)
                    .body(ByteStream::from(vec![0u8; s3_chunk_size as usize]))
                    .build()
            })
            .output(move || {
                GetObjectOutput::builder()
                    .content_length(last_chunk_size as i64)
                    .body(ByteStream::from(vec![0u8; last_chunk_size as usize]))
                    .build()
            })
            .build();

        let mock_client =
            create_test_s3_client(mock_client!(aws_sdk_s3, [&get_object_rule]), None, true);
        let _ = mock_client
            .get_object_if_match("obj", "etag", "", total_size, 0)
            .await;

        assert_eq!(get_object_rule.num_calls(), 3);
    }

    // --- #1: is_reachable assertions on existing tests ---
    // Note: `then_error()` produces modeled errors without a raw HTTP response,
    // so `is_reachable` is false. In production, NoSuchKey comes as HTTP 404
    // (is_reachable=true). This is a mock framework limitation, not a code bug.

    #[tokio::test]
    pub async fn test_check_permission_no_such_key_is_reachable_via_http() {
        // Use then_http_response to simulate a real 404 NoSuchKey (has raw_response)
        let get_object_rule = mock!(aws_sdk_s3::Client::get_object).then_http_response(|| {
            HttpResponse::new(
                StatusCode::try_from(404).unwrap(),
                SdkBody::from(r#"<?xml version="1.0"?><Error><Code>NoSuchKey</Code></Error>"#),
            )
        });

        let client = Arc::new(mock_client!(aws_sdk_s3, [&get_object_rule]));
        let bucket = "test_bucket".to_string();
        let prefix = "test_prefix".to_string();

        let result = S3Client::check_bucket_permissions(&client, &bucket, &prefix, false).await;
        assert!(result.is_reachable);
    }

    #[tokio::test]
    pub async fn test_check_permission_modeled_error_is_reachable() {
        // then_error() with modeled errors still produces a raw HTTP response in the mock
        // framework, so is_reachable = true. A real transport failure (DNS, timeout) would
        // have raw_response() = None and is_reachable = false, but cannot be simulated
        // with aws-smithy-mocks.
        let get_object_rule = mock!(aws_sdk_s3::Client::get_object).then_error(|| {
            GetObjectError::InvalidObjectState(InvalidObjectState::builder().build())
        });

        let client = Arc::new(mock_client!(aws_sdk_s3, [&get_object_rule]));
        let bucket = "test_bucket".to_string();
        let prefix = "test_prefix".to_string();

        let result = S3Client::check_bucket_permissions(&client, &bucket, &prefix, false).await;
        assert!(result.is_reachable);
        assert!(!result.should_enable);
    }

    // --- #2: Metric emission tests ---

    struct MockCloudWatchClient {
        calls: Arc<std::sync::Mutex<Vec<(String, bool)>>>,
        log_calls: Arc<std::sync::Mutex<Vec<(LogLevel, String)>>>,
    }

    impl MockCloudWatchClient {
        fn new() -> (
            Self,
            Arc<std::sync::Mutex<Vec<(String, bool)>>>,
            Arc<std::sync::Mutex<Vec<(LogLevel, String)>>>,
        ) {
            let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
            let log_calls = Arc::new(std::sync::Mutex::new(Vec::new()));
            (
                Self {
                    calls: calls.clone(),
                    log_calls: log_calls.clone(),
                },
                calls,
                log_calls,
            )
        }
    }

    impl CloudWatchClient for MockCloudWatchClient {
        fn emit_log(&self, level: LogLevel, message: &str) {
            self.log_calls
                .lock()
                .unwrap()
                .push((level, message.to_string()));
        }
        fn publish_s3_reachable(&self, bucket: &str, is_reachable: bool) {
            self.calls
                .lock()
                .unwrap()
                .push((bucket.to_string(), is_reachable));
        }
        fn publish_s3_permitted(&self, _bucket: &str, _is_permitted: bool) {}
        fn publish_nfs_reachability(&self, _is_reachable: bool, _fs_id: &str) {}
    }

    #[tokio::test]
    pub async fn test_metric_emitted_on_initial_check() {
        let get_object_rule = mock!(aws_sdk_s3::Client::get_object).then_output(|| {
            GetObjectOutput::builder()
                .body(ByteStream::from_static(b"test-content"))
                .build()
        });

        let (publisher, calls, _log_calls) = MockCloudWatchClient::new();
        let mock_client = create_test_s3_client(
            mock_client!(aws_sdk_s3, [&get_object_rule]),
            Some(Arc::new(publisher)),
            false,
        );

        tokio::time::pause();
        mock_client.start_permission_validator(100).await.unwrap();

        // Let the first tick run — multiple yields needed for the spawned task
        // to complete the S3 call and metric publish
        for _ in 0..10 {
            tokio::time::advance(Duration::from_millis(10)).await;
            tokio::task::yield_now().await;
        }

        let recorded = calls.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0], ("test_bucket".to_string(), true));
    }

    #[tokio::test]
    pub async fn test_metric_emitted_every_check() {
        // Two consecutive successes — metric should fire twice (once per check)
        let get_object_rule = mock!(aws_sdk_s3::Client::get_object)
            .sequence()
            .output(|| {
                GetObjectOutput::builder()
                    .body(ByteStream::from_static(b"ok"))
                    .build()
            })
            .output(|| {
                GetObjectOutput::builder()
                    .body(ByteStream::from_static(b"ok"))
                    .build()
            })
            .build();

        let (publisher, calls, _log_calls) = MockCloudWatchClient::new();
        let mock_client = create_test_s3_client(
            mock_client!(aws_sdk_s3, [&get_object_rule]),
            Some(Arc::new(publisher)),
            false,
        );

        tokio::time::pause();
        let interval = 10;
        mock_client
            .start_permission_validator(interval)
            .await
            .unwrap();

        // First tick
        for _ in 0..10 {
            tokio::time::advance(Duration::from_millis(10)).await;
            tokio::task::yield_now().await;
        }
        // Second tick
        tokio::time::advance(Duration::from_secs(interval)).await;
        for _ in 0..10 {
            tokio::time::advance(Duration::from_millis(10)).await;
            tokio::task::yield_now().await;
        }

        mock_client
            .validator_task
            .lock()
            .await
            .as_mut()
            .unwrap()
            .abort();
        tokio::time::resume();

        let recorded = calls.lock().unwrap();
        assert_eq!(recorded.len(), 2);
        assert_eq!(recorded[0], ("test_bucket".to_string(), true));
        assert_eq!(recorded[1], ("test_bucket".to_string(), true));
    }

    #[tokio::test]
    pub async fn test_log_emitted_on_first_check_when_enabled() {
        let get_object_rule = mock!(aws_sdk_s3::Client::get_object).then_output(|| {
            GetObjectOutput::builder()
                .body(ByteStream::from_static(b"ok"))
                .build()
        });

        let (publisher, _calls, log_calls) = MockCloudWatchClient::new();
        let mock_client = create_test_s3_client(
            mock_client!(aws_sdk_s3, [&get_object_rule]),
            Some(Arc::new(publisher)),
            false,
        );

        tokio::time::pause();
        mock_client.start_permission_validator(100).await.unwrap();

        for _ in 0..10 {
            tokio::time::advance(Duration::from_millis(10)).await;
            tokio::task::yield_now().await;
        }

        let logs = log_calls.lock().unwrap();
        assert_eq!(logs.len(), 1);
        assert!(matches!(logs[0].0, LogLevel::Info));
        assert!(logs[0].1.contains("S3 bucket accessible"));
    }

    #[tokio::test]
    pub async fn test_log_emitted_on_first_check_when_disabled() {
        let get_object_rule = mock!(aws_sdk_s3::Client::get_object).then_http_response(|| {
            HttpResponse::new(
                StatusCode::try_from(403).unwrap(),
                SdkBody::from("Forbidden"),
            )
        });

        let (publisher, _calls, log_calls) = MockCloudWatchClient::new();
        let mock_client = create_test_s3_client(
            mock_client!(aws_sdk_s3, [&get_object_rule]),
            Some(Arc::new(publisher)),
            false,
        );

        tokio::time::pause();
        mock_client.start_permission_validator(100).await.unwrap();

        for _ in 0..10 {
            tokio::time::advance(Duration::from_millis(10)).await;
            tokio::task::yield_now().await;
        }

        let logs = log_calls.lock().unwrap();
        assert_eq!(logs.len(), 1);
        assert!(matches!(logs[0].0, LogLevel::Error));
        assert!(logs[0].1.contains("S3 bucket inaccessible"));
    }

    // --- #3: is_reachable assertions on existing permission tests ---

    #[tokio::test]
    pub async fn test_check_permission_403_is_reachable() {
        let get_object_rule = mock!(aws_sdk_s3::Client::get_object).then_http_response(|| {
            HttpResponse::new(
                StatusCode::try_from(403).unwrap(),
                SdkBody::from("Forbidden"),
            )
        });

        let client = Arc::new(mock_client!(aws_sdk_s3, [&get_object_rule]));
        let result =
            S3Client::check_bucket_permissions(&client, &"b".to_string(), &"p".to_string(), true)
                .await;
        assert!(result.is_reachable);
        assert!(!result.should_enable);
    }

    #[tokio::test]
    pub async fn test_check_permission_503_is_reachable() {
        let get_object_rule = mock!(aws_sdk_s3::Client::get_object).then_http_response(|| {
            HttpResponse::new(
                StatusCode::try_from(503).unwrap(),
                SdkBody::from("Service Unavailable"),
            )
        });

        let client = Arc::new(mock_client!(aws_sdk_s3, [&get_object_rule]));
        let result =
            S3Client::check_bucket_permissions(&client, &"b".to_string(), &"p".to_string(), false)
                .await;
        assert!(result.is_reachable);
        assert!(!result.should_enable);
    }

    #[tokio::test]
    pub async fn test_check_permission_success_is_reachable() {
        let get_object_rule = mock!(aws_sdk_s3::Client::get_object).then_output(|| {
            GetObjectOutput::builder()
                .body(ByteStream::from_static(b"ok"))
                .build()
        });

        let client = Arc::new(mock_client!(aws_sdk_s3, [&get_object_rule]));
        let result =
            S3Client::check_bucket_permissions(&client, &"b".to_string(), &"p".to_string(), false)
                .await;
        assert!(result.is_reachable);
        assert!(result.should_enable);
    }

    #[tokio::test]
    pub async fn test_valid_bucket_names() {
        assert!(
            S3Client::is_bucket_name_valid("bucket"),
            "Bucket name 'bucket' should be valid"
        );
        assert!(
            S3Client::is_bucket_name_valid("bucket.1.2.3"),
            "Bucket name 'bucket.1.2.3' should be valid"
        );
        assert!(
            S3Client::is_bucket_name_valid("bucket-1-2-3"),
            "Bucket name 'bucket-1-2-3' should be valid"
        );
        let long_bucket_name = "bucket.max63characters----------------------------------------x";
        assert!(
            S3Client::is_bucket_name_valid(long_bucket_name),
            "Bucket name {} should be valid",
            long_bucket_name
        );
    }

    #[tokio::test]
    pub async fn test_invalid_bucket_names() {
        assert!(
            !S3Client::is_bucket_name_valid(""),
            "Bucket name '' should be invalid"
        );
        assert!(
            !S3Client::is_bucket_name_valid(".bucket"),
            "Bucket name '.bucket' should be invalid"
        );
        assert!(
            !S3Client::is_bucket_name_valid("bucket."),
            "Bucket name 'bucket.' should be invalid"
        );
        assert!(
            !S3Client::is_bucket_name_valid("-bucket"),
            "Bucket name '-bucket' should be invalid"
        );
        assert!(
            !S3Client::is_bucket_name_valid("bucket-"),
            "Bucket name 'bucket-' should be invalid"
        );
        let long_bucket_name = "bucket.overmax63characters--------------------------------------";
        assert!(
            !S3Client::is_bucket_name_valid(long_bucket_name),
            "Bucket name {} should be invalid",
            long_bucket_name
        );
    }

    #[tokio::test]
    pub async fn test_build_returns_error_with_illegal_bucket_name() {
        let proxy_config = get_test_config();
        let s3_client = S3Client::new("-", "prefix", &proxy_config).await;
        assert!(s3_client.is_err())
    }

    #[tokio::test]
    pub async fn test_validator_thread_drop() {
        let mut seq = mock!(aws_sdk_s3::Client::get_object).sequence();
        for _ in 0..4 {
            seq = seq.output(|| {
                GetObjectOutput::builder()
                    .body(ByteStream::from_static(b"ok"))
                    .build()
            });
        }
        let get_object_rule = seq.build();

        let (publisher, calls, _log_calls) = MockCloudWatchClient::new();
        let calls_clone = calls.clone();

        let s3_client = create_test_s3_client(
            mock_client!(aws_sdk_s3, [&get_object_rule]),
            Some(Arc::new(publisher)),
            false,
        );

        tokio::time::pause();
        let interval_seconds = 5;
        s3_client
            .start_permission_validator(interval_seconds)
            .await
            .unwrap();

        // Let the first tick run
        for _ in 0..5 {
            tokio::time::advance(Duration::from_millis(10)).await;
            tokio::task::yield_now().await;
        }
        let count_before_drop = calls.lock().unwrap().len();
        assert!(
            count_before_drop >= 1,
            "validator should have run at least once"
        );

        // Drop the S3Client — the background task should stop, but it won't.
        drop(s3_client);

        // Advance time so the task would tick several more times
        for _ in 0..3 {
            tokio::time::advance(Duration::from_secs(interval_seconds)).await;
            tokio::task::yield_now().await;
        }

        let count_after_drop = calls_clone.lock().unwrap().len();
        assert_eq!(
            count_after_drop, count_before_drop,
            "Validator task should have stopped after S3Client was dropped"
        );

        tokio::time::resume();
    }
}
