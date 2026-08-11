//! ### CloudWatch metrics and logs emission
//!

use crate::{
    aws::credentials::get_aws_config_loader, aws::utils::get_ec2_instance_id,
    config_parser::ProxyConfig, utils::is_running_on_lambda,
};
use aws_sdk_cloudwatchlogs::{
    error::SdkError,
    operation::{create_log_group::CreateLogGroupError, create_log_stream::CreateLogStreamError},
    types::InputLogEvent,
};
use log::{info, warn};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Metrics names and namespaces
///
pub const CW_NAMESPACE_S3FILES: &str = "efs-utils/S3Files";
pub const CW_NAMESPACE_EFS: &str = "efs-utils/EFS";

pub const S3_BUCKET_IS_REACHABLE: &str = "S3BucketReachable";
pub const S3_BUCKET_IS_PERMITTED: &str = "S3BucketAccessible";
pub const NFS_CONNECTION_ACCESSIBLE: &str = "NFSConnectionAccessible";

pub const DEFAULT_EFS_CLOUDWATCH_LOG_GROUP: &str = "/aws/efs/utils";

/// Dimensions
///
const BUCKET_DIMENSION: &str = "Bucket";
const INSTANCE_DIMENSION: &str = "InstanceId";
const FS_ID_DIMENSION: &str = "FileSystemId";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
}

impl LogLevel {
    fn as_str(&self) -> &str {
        match self {
            LogLevel::Error => "ERROR",
            LogLevel::Warn => "WARN",
            LogLevel::Info => "INFO",
        }
    }
}

/// Trait for CloudWatch Logs operations, enabling testability.
#[async_trait::async_trait]
pub trait CWLogsHelper: Send + Sync {
    async fn create_log_group(
        &self,
        log_group_name: &str,
    ) -> Result<(), SdkError<CreateLogGroupError>>;

    async fn create_log_stream(
        &self,
        log_group_name: &str,
        log_stream_name: &str,
    ) -> Result<(), SdkError<CreateLogStreamError>>;

    async fn put_retention_policy(
        &self,
        log_group_name: &str,
        retention_days: i32,
    ) -> Result<(), Box<dyn std::error::Error>>;

    async fn put_log_events(
        &self,
        log_group_name: &str,
        log_stream_name: &str,
        log_event: InputLogEvent,
    ) -> Result<(), Box<dyn std::error::Error>>;
}

/// Wrapper for AWS SDK CloudWatch Logs client
pub struct CWLogsClient {
    client: aws_sdk_cloudwatchlogs::Client,
}

impl CWLogsClient {
    pub fn new(client: aws_sdk_cloudwatchlogs::Client) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl CWLogsHelper for CWLogsClient {
    async fn create_log_group(
        &self,
        log_group_name: &str,
    ) -> Result<(), SdkError<CreateLogGroupError>> {
        self.client
            .create_log_group()
            .log_group_name(log_group_name)
            .send()
            .await
            .map(|_| ())
    }

    async fn create_log_stream(
        &self,
        log_group_name: &str,
        log_stream_name: &str,
    ) -> Result<(), SdkError<CreateLogStreamError>> {
        self.client
            .create_log_stream()
            .log_group_name(log_group_name)
            .log_stream_name(log_stream_name)
            .send()
            .await
            .map(|_| ())
    }

    async fn put_retention_policy(
        &self,
        log_group_name: &str,
        retention_days: i32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.client
            .put_retention_policy()
            .log_group_name(log_group_name)
            .retention_in_days(retention_days)
            .send()
            .await
            .map(|_| ())
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }

    async fn put_log_events(
        &self,
        log_group_name: &str,
        log_stream_name: &str,
        log_event: InputLogEvent,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.client
            .put_log_events()
            .log_group_name(log_group_name)
            .log_stream_name(log_stream_name)
            .log_events(log_event)
            .send()
            .await
            .map(|_| ())
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
    }
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

/// CloudWatch-backed publisher for metrics and logs.
pub struct CloudWatchPublisher {
    metrics_client: Option<aws_sdk_cloudwatch::Client>,
    metrics_namespace: String,
    logs_client: Option<aws_sdk_cloudwatchlogs::Client>,
    logs_ready: Arc<AtomicBool>,
    log_group_name: Option<String>,
    log_stream_name: Option<String>,
    instance_id: Option<String>,
}

impl CloudWatchPublisher {
    pub async fn new_from_aws_config(
        aws_sdk_config: &aws_config::SdkConfig,
        bucket: Option<String>,
        proxy_config: &ProxyConfig,
        namespace: &str,
    ) -> Self {
        let (instance_id, metrics_client, logs_client, logs_ready, log_group_name, log_stream_name) =
            if is_running_on_lambda() {
                info!("Running on AWS Lambda, CloudWatch publishing and IMDS call are disabled.");
                (
                    None,
                    None,
                    None,
                    Arc::new(AtomicBool::new(false)),
                    None,
                    None,
                )
            } else {
                let instance_id = match get_ec2_instance_id().await {
                    Ok(id) => Some(id),
                    Err(_) => {
                        warn!("Failed to retrieve EC2 instance ID for metrics");
                        None
                    }
                };

                let metrics_client = Self::init_metrics_client(
                    &aws_sdk_config,
                    &proxy_config.nested_config.telemetry_config,
                );

                let (logs_client, logs_ready, log_group_name, log_stream_name) =
                    Self::init_logs_client(
                        &aws_sdk_config,
                        &proxy_config.nested_config.telemetry_config,
                        &proxy_config.nested_config.fs_id,
                        instance_id.as_deref(),
                        bucket,
                    );

                (
                    instance_id,
                    metrics_client,
                    logs_client,
                    logs_ready,
                    log_group_name,
                    log_stream_name,
                )
            };

        Self {
            metrics_client,
            metrics_namespace: namespace.to_string(),
            logs_client,
            logs_ready,
            log_group_name,
            log_stream_name,
            instance_id,
        }
    }

    pub async fn new_from_config(
        proxy_config: &ProxyConfig,
        bucket: Option<String>,
        namespace: &str,
    ) -> Self {
        let aws_config_loader = get_aws_config_loader(proxy_config).await;
        let aws_sdk_config = aws_config_loader.load().await;

        return Self::new_from_aws_config(&aws_sdk_config, bucket, &proxy_config, namespace).await;
    }

    fn init_metrics_client(
        aws_sdk_config: &aws_config::SdkConfig,
        telemetry_config: &crate::config_parser::TelemetryConfig,
    ) -> Option<aws_sdk_cloudwatch::Client> {
        if !telemetry_config.cloud_watch_metrics_enabled {
            return None;
        }
        Some(aws_sdk_cloudwatch::Client::new(aws_sdk_config))
    }

    fn init_logs_client(
        aws_sdk_config: &aws_config::SdkConfig,
        telemetry_config: &crate::config_parser::TelemetryConfig,
        fs_id: &str,
        instance_id: Option<&str>,
        bucket: Option<String>,
    ) -> (
        Option<aws_sdk_cloudwatchlogs::Client>,
        Arc<AtomicBool>,
        Option<String>,
        Option<String>,
    ) {
        let logs_ready = Arc::new(AtomicBool::new(false));

        if !telemetry_config.cloud_watch_logs_enabled {
            return (None, logs_ready, None, None);
        }

        let logs_client = aws_sdk_cloudwatchlogs::Client::new(aws_sdk_config);
        let log_group_name = if telemetry_config.log_group_name.is_empty() {
            DEFAULT_EFS_CLOUDWATCH_LOG_GROUP.to_string()
        } else {
            telemetry_config.log_group_name.clone()
        };
        let log_stream_name = Self::generate_log_stream_name(fs_id, instance_id, bucket.as_deref());

        let bg_client = logs_client.clone();
        let bg_group = log_group_name.clone();
        let bg_stream = log_stream_name.clone();
        let bg_ready = logs_ready.clone();
        let retention_days = telemetry_config.cloud_watch_logs_retention_days as i32;
        tokio::spawn(async move {
            match Self::ensure_log_group_and_stream_static(
                &bg_client,
                &bg_group,
                &bg_stream,
                retention_days,
            )
            .await
            {
                Ok(_) => bg_ready.store(true, Ordering::Release),
                Err(e) => {
                    warn!("Failed to initialize CloudWatch logs publishing: {:?}", e);
                }
            }
        });

        (
            Some(logs_client),
            logs_ready,
            Some(log_group_name),
            Some(log_stream_name),
        )
    }

    fn generate_log_stream_name(
        fs_id: &str,
        instance_id: Option<&str>,
        bucket: Option<&str>,
    ) -> String {
        match (bucket, instance_id) {
            (Some(b), Some(i)) => format!("{}-{}-efs-utils", b, i),
            (Some(b), None) => format!("{}-efs-utils", b),
            (None, Some(i)) => format!("{}-{}-efs-utils", fs_id, i),
            (None, None) => format!("{}-efs-utils", fs_id),
        }
    }

    async fn ensure_log_group_and_stream_static(
        logs_client: &aws_sdk_cloudwatchlogs::Client,
        log_group_name: &str,
        log_stream_name: &str,
        retention_days: i32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let helper = CWLogsClient::new(logs_client.clone());
        Self::ensure_log_group_and_stream(&helper, log_group_name, log_stream_name, retention_days)
            .await
    }

    async fn ensure_log_group_and_stream(
        logs_helper: &dyn CWLogsHelper,
        log_group_name: &str,
        log_stream_name: &str,
        retention_days: i32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Create log group if it doesn't exist
        match logs_helper.create_log_group(log_group_name).await {
            Ok(_) => {
                log::info!("Created log group: {}", log_group_name);
                // Set retention policy
                if let Err(e) = logs_helper
                    .put_retention_policy(log_group_name, retention_days)
                    .await
                {
                    warn!("Failed to set retention policy: {:?}", e);
                }
            }
            Err(error) => {
                if let SdkError::ServiceError(ref e) = error {
                    if matches!(
                        e.err(),
                        CreateLogGroupError::ResourceAlreadyExistsException(_)
                    ) {
                        log::debug!("LogGroup {} already exists.", log_group_name);
                    } else {
                        warn!("Failed to create log group: {:?}", error);
                        return Err(Box::new(error));
                    }
                } else {
                    warn!("Failed to create log group: {:?}", error);
                    return Err(Box::new(error));
                }
            }
        }

        // Create log stream if it doesn't exist
        match logs_helper
            .create_log_stream(log_group_name, log_stream_name)
            .await
        {
            Ok(_) => log::info!("Created log stream: {}", log_stream_name),
            Err(error) => {
                if let SdkError::ServiceError(ref e) = error {
                    if !matches!(
                        e.err(),
                        CreateLogStreamError::ResourceAlreadyExistsException(_)
                    ) {
                        warn!("Failed to create log stream: {:?}", error);
                        return Err(Box::new(error));
                    }
                } else {
                    warn!("Failed to create log stream: {:?}", error);
                    return Err(Box::new(error));
                }
            }
        }

        Ok(())
    }

    fn build_datum(
        name: &str,
        value: bool,
    ) -> aws_sdk_cloudwatch::types::builders::MetricDatumBuilder {
        aws_sdk_cloudwatch::types::MetricDatum::builder()
            .metric_name(name)
            .value(if value { 1.0 } else { 0.0 })
            .unit(aws_sdk_cloudwatch::types::StandardUnit::None)
    }

    fn build_s3_reachable_datum(
        &self,
        bucket: &str,
        is_reachable: bool,
    ) -> aws_sdk_cloudwatch::types::MetricDatum {
        let datum = Self::build_datum(S3_BUCKET_IS_REACHABLE, is_reachable).dimensions(
            aws_sdk_cloudwatch::types::Dimension::builder()
                .name(BUCKET_DIMENSION)
                .value(bucket)
                .build(),
        );
        self.add_instance_dimension(datum).build()
    }

    fn build_s3_permitted_datum(
        &self,
        bucket: &str,
        is_permitted: bool,
    ) -> aws_sdk_cloudwatch::types::MetricDatum {
        let datum = Self::build_datum(S3_BUCKET_IS_PERMITTED, is_permitted).dimensions(
            aws_sdk_cloudwatch::types::Dimension::builder()
                .name(BUCKET_DIMENSION)
                .value(bucket)
                .build(),
        );
        self.add_instance_dimension(datum).build()
    }

    fn build_nfs_reachability_datum(
        &self,
        is_reachable: bool,
        fs_id: &str,
    ) -> aws_sdk_cloudwatch::types::MetricDatum {
        let datum = Self::build_datum(NFS_CONNECTION_ACCESSIBLE, is_reachable).dimensions(
            aws_sdk_cloudwatch::types::Dimension::builder()
                .name(FS_ID_DIMENSION)
                .value(fs_id)
                .build(),
        );
        self.add_instance_dimension(datum).build()
    }

    fn add_instance_dimension(
        &self,
        builder: aws_sdk_cloudwatch::types::builders::MetricDatumBuilder,
    ) -> aws_sdk_cloudwatch::types::builders::MetricDatumBuilder {
        if let Some(instance_id) = &self.instance_id {
            builder.dimensions(
                aws_sdk_cloudwatch::types::Dimension::builder()
                    .name(INSTANCE_DIMENSION)
                    .value(instance_id)
                    .build(),
            )
        } else {
            builder
        }
    }

    fn emit_metric(&self, datum: aws_sdk_cloudwatch::types::MetricDatum) {
        if let Some(metrics_client) = self.metrics_client.clone() {
            let namespace = self.metrics_namespace.clone();
            tokio::spawn(async move {
                if let Err(e) = metrics_client
                    .put_metric_data()
                    .namespace(&namespace)
                    .metric_data(datum)
                    .send()
                    .await
                {
                    warn!("Failed to emit CloudWatch metric: {:?}", e);
                }
            });
        }
    }

    async fn emit_log_internal(
        logs_client: &aws_sdk_cloudwatchlogs::Client,
        log_group_name: &str,
        log_stream_name: &str,
        level: LogLevel,
        message: &str,
    ) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        let msg = format!("{}: {}", level.as_str(), message);

        let log_event = InputLogEvent::builder()
            .message(msg)
            .timestamp(timestamp)
            .build()
            .expect("Failed to build InputLogEvent");

        if let Err(e) = logs_client
            .put_log_events()
            .log_group_name(log_group_name)
            .log_stream_name(log_stream_name)
            .log_events(log_event)
            .send()
            .await
        {
            warn!("Failed to publish log to CloudWatch: {:?}", e);
        }
    }
}

impl CloudWatchClient for CloudWatchPublisher {
    fn emit_log(&self, level: LogLevel, message: &str) {
        if !self.logs_ready.load(Ordering::Acquire) {
            return;
        }
        if let (Some(logs_client), Some(log_group_name), Some(log_stream_name)) = (
            self.logs_client.clone(),
            self.log_group_name.clone(),
            self.log_stream_name.clone(),
        ) {
            let message = message.to_string();
            tokio::task::spawn(async move {
                Self::emit_log_internal(
                    &logs_client,
                    &log_group_name,
                    &log_stream_name,
                    level,
                    &message,
                )
                .await;
            });
        }
    }

    fn publish_s3_reachable(&self, bucket: &str, is_reachable: bool) {
        let datum = self.build_s3_reachable_datum(bucket, is_reachable);
        self.emit_metric(datum);
    }

    fn publish_s3_permitted(&self, bucket: &str, is_permitted: bool) {
        let datum = self.build_s3_permitted_datum(bucket, is_permitted);
        self.emit_metric(datum);
    }

    fn publish_nfs_reachability(&self, is_reachable: bool, fs_id: &str) {
        let datum = self.build_nfs_reachability_datum(is_reachable, fs_id);
        self.emit_metric(datum);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_s3_reachable_datum_with_instance_id() {
        let config = aws_sdk_cloudwatch::Config::builder()
            .behavior_version(aws_sdk_cloudwatch::config::BehaviorVersion::latest())
            .build();
        let metrics_client = aws_sdk_cloudwatch::Client::from_conf(config);
        let publisher = CloudWatchPublisher {
            metrics_client: Some(metrics_client),
            metrics_namespace: CW_NAMESPACE_S3FILES.to_string(),
            logs_client: None,
            logs_ready: Arc::new(AtomicBool::new(false)),
            log_group_name: None,
            log_stream_name: None,
            instance_id: Some("i-test123".to_string()),
        };

        let datum = publisher.build_s3_reachable_datum("test-bucket", true);

        assert_eq!(datum.metric_name(), Some(S3_BUCKET_IS_REACHABLE));
        assert_eq!(datum.value(), Some(1.0));

        let dimensions = datum.dimensions();
        assert_eq!(dimensions.len(), 2);

        let bucket_dim = dimensions
            .iter()
            .find(|d| d.name() == Some(BUCKET_DIMENSION));
        assert!(bucket_dim.is_some());
        assert_eq!(bucket_dim.unwrap().value(), Some("test-bucket"));

        let instance_dim = dimensions
            .iter()
            .find(|d| d.name() == Some(INSTANCE_DIMENSION));
        assert!(instance_dim.is_some());
        assert_eq!(instance_dim.unwrap().value(), Some("i-test123"));
    }

    #[test]
    fn test_build_s3_permitted_datum_with_instance_id() {
        let config = aws_sdk_cloudwatch::Config::builder()
            .behavior_version(aws_sdk_cloudwatch::config::BehaviorVersion::latest())
            .build();
        let metrics_client = aws_sdk_cloudwatch::Client::from_conf(config);
        let publisher = CloudWatchPublisher {
            metrics_client: Some(metrics_client),
            metrics_namespace: CW_NAMESPACE_S3FILES.to_string(),
            logs_client: None,
            logs_ready: Arc::new(AtomicBool::new(false)),
            log_group_name: None,
            log_stream_name: None,
            instance_id: Some("i-test456".to_string()),
        };

        let datum = publisher.build_s3_permitted_datum("my-bucket", false);

        assert_eq!(datum.metric_name(), Some(S3_BUCKET_IS_PERMITTED));
        assert_eq!(datum.value(), Some(0.0));

        let dimensions = datum.dimensions();
        assert_eq!(dimensions.len(), 2);

        let bucket_dim = dimensions
            .iter()
            .find(|d| d.name() == Some(BUCKET_DIMENSION));
        assert!(bucket_dim.is_some());
        assert_eq!(bucket_dim.unwrap().value(), Some("my-bucket"));

        let instance_dim = dimensions
            .iter()
            .find(|d| d.name() == Some(INSTANCE_DIMENSION));
        assert!(instance_dim.is_some());
        assert_eq!(instance_dim.unwrap().value(), Some("i-test456"));
    }

    #[test]
    fn test_build_nfs_reachability_datum_with_instance_id() {
        let config = aws_sdk_cloudwatch::Config::builder()
            .behavior_version(aws_sdk_cloudwatch::config::BehaviorVersion::latest())
            .build();
        let metrics_client = aws_sdk_cloudwatch::Client::from_conf(config);
        let publisher = CloudWatchPublisher {
            metrics_client: Some(metrics_client),
            metrics_namespace: CW_NAMESPACE_EFS.to_string(),
            logs_client: None,
            logs_ready: Arc::new(AtomicBool::new(false)),
            log_group_name: None,
            log_stream_name: None,
            instance_id: Some("i-nfs789".to_string()),
        };

        let datum = publisher.build_nfs_reachability_datum(true, "fs-12345678");

        assert_eq!(datum.metric_name(), Some(NFS_CONNECTION_ACCESSIBLE));
        assert_eq!(datum.value(), Some(1.0));

        let dimensions = datum.dimensions();
        assert_eq!(dimensions.len(), 2);

        let fs_dim = dimensions
            .iter()
            .find(|d| d.name() == Some(FS_ID_DIMENSION));
        assert!(fs_dim.is_some());
        assert_eq!(fs_dim.unwrap().value(), Some("fs-12345678"));

        let instance_dim = dimensions
            .iter()
            .find(|d| d.name() == Some(INSTANCE_DIMENSION));
        assert!(instance_dim.is_some());
        assert_eq!(instance_dim.unwrap().value(), Some("i-nfs789"));
    }

    #[test]
    fn test_build_nfs_reachability_datum_without_instance_id() {
        let config = aws_sdk_cloudwatch::Config::builder()
            .behavior_version(aws_sdk_cloudwatch::config::BehaviorVersion::latest())
            .build();
        let metrics_client = aws_sdk_cloudwatch::Client::from_conf(config);
        let publisher = CloudWatchPublisher {
            metrics_client: Some(metrics_client),
            metrics_namespace: CW_NAMESPACE_EFS.to_string(),
            logs_client: None,
            logs_ready: Arc::new(AtomicBool::new(false)),
            log_group_name: None,
            log_stream_name: None,
            instance_id: None,
        };

        let datum = publisher.build_nfs_reachability_datum(false, "fs-87654321");

        assert_eq!(datum.metric_name(), Some(NFS_CONNECTION_ACCESSIBLE));
        assert_eq!(datum.value(), Some(0.0));

        let dimensions = datum.dimensions();
        assert_eq!(dimensions.len(), 1);

        let fs_dim = dimensions
            .iter()
            .find(|d| d.name() == Some(FS_ID_DIMENSION));
        assert!(fs_dim.is_some());
        assert_eq!(fs_dim.unwrap().value(), Some("fs-87654321"));
    }

    #[test]
    fn test_generate_log_stream_name_with_bucket_and_instance() {
        let result = CloudWatchPublisher::generate_log_stream_name(
            "fs-12345678",
            Some("i-1234567890abcdef0"),
            Some("my-bucket"),
        );
        assert_eq!(result, "my-bucket-i-1234567890abcdef0-efs-utils");
    }

    #[test]
    fn test_generate_log_stream_name_with_bucket_only() {
        let result =
            CloudWatchPublisher::generate_log_stream_name("fs-12345678", None, Some("my-bucket"));
        assert_eq!(result, "my-bucket-efs-utils");
    }

    #[test]
    fn test_generate_log_stream_name_with_instance_only() {
        let result = CloudWatchPublisher::generate_log_stream_name(
            "fs-12345678",
            Some("i-1234567890abcdef0"),
            None,
        );
        assert_eq!(result, "fs-12345678-i-1234567890abcdef0-efs-utils");
    }

    #[test]
    fn test_generate_log_stream_name_with_neither() {
        let result = CloudWatchPublisher::generate_log_stream_name("fs-12345678", None, None);
        assert_eq!(result, "fs-12345678-efs-utils");
    }

    #[test]
    fn test_log_level_as_str() {
        assert_eq!(LogLevel::Error.as_str(), "ERROR");
        assert_eq!(LogLevel::Warn.as_str(), "WARN");
        assert_eq!(LogLevel::Info.as_str(), "INFO");
    }

    #[tokio::test]
    async fn test_customer_logs_publisher_disabled() {
        use crate::config_parser::{EfsConfig, ProxyConfig};

        let mut proxy_config = ProxyConfig {
            nested_config: EfsConfig::default(),
            ..Default::default()
        };
        proxy_config
            .nested_config
            .telemetry_config
            .cloud_watch_logs_enabled = false;

        let publisher =
            CloudWatchPublisher::new_from_config(&proxy_config, None, CW_NAMESPACE_EFS).await;
        assert!(publisher.logs_client.is_none());

        publisher.emit_log(LogLevel::Info, "test message");
    }

    #[tokio::test]
    async fn test_customer_logs_publisher_clone() {
        use crate::config_parser::{EfsConfig, ProxyConfig};

        let mut proxy_config = ProxyConfig {
            nested_config: EfsConfig::default(),
            ..Default::default()
        };
        proxy_config
            .nested_config
            .telemetry_config
            .cloud_watch_logs_enabled = false;

        let publisher =
            CloudWatchPublisher::new_from_config(&proxy_config, None, CW_NAMESPACE_EFS).await;
        assert!(publisher.logs_client.is_none());
    }

    #[tokio::test]
    async fn test_new_from_config_logs_disabled() {
        use crate::config_parser::{EfsConfig, ProxyConfig};

        let mut proxy_config = ProxyConfig {
            nested_config: EfsConfig::default(),
            ..Default::default()
        };
        proxy_config
            .nested_config
            .telemetry_config
            .cloud_watch_logs_enabled = false;

        let publisher =
            CloudWatchPublisher::new_from_config(&proxy_config, None, CW_NAMESPACE_EFS).await;
        assert!(publisher.logs_client.is_none());
    }

    // Tests for ensure_log_group_and_stream
    use std::sync::Arc;
    use tokio::sync::Mutex;

    struct MockCWLogsHelper {
        create_group_calls: Arc<Mutex<Vec<String>>>,
        create_stream_calls: Arc<Mutex<Vec<(String, String)>>>,
        create_group_result: fn() -> Result<(), SdkError<CreateLogGroupError>>,
        create_stream_result: fn() -> Result<(), SdkError<CreateLogStreamError>>,
        put_retention_result: fn() -> Result<(), String>,
    }

    impl MockCWLogsHelper {
        fn new(
            create_group_result: fn() -> Result<(), SdkError<CreateLogGroupError>>,
            create_stream_result: fn() -> Result<(), SdkError<CreateLogStreamError>>,
            put_retention_result: fn() -> Result<(), String>,
        ) -> Self {
            Self {
                create_group_calls: Arc::new(Mutex::new(Vec::new())),
                create_stream_calls: Arc::new(Mutex::new(Vec::new())),
                create_group_result,
                create_stream_result,
                put_retention_result,
            }
        }
    }

    #[async_trait::async_trait]
    impl CWLogsHelper for MockCWLogsHelper {
        async fn create_log_group(
            &self,
            log_group_name: &str,
        ) -> Result<(), SdkError<CreateLogGroupError>> {
            self.create_group_calls
                .lock()
                .await
                .push(log_group_name.to_string());
            (self.create_group_result)()
        }

        async fn create_log_stream(
            &self,
            log_group_name: &str,
            log_stream_name: &str,
        ) -> Result<(), SdkError<CreateLogStreamError>> {
            self.create_stream_calls
                .lock()
                .await
                .push((log_group_name.to_string(), log_stream_name.to_string()));
            (self.create_stream_result)()
        }

        async fn put_retention_policy(
            &self,
            _: &str,
            _: i32,
        ) -> Result<(), Box<dyn std::error::Error>> {
            (self.put_retention_result)().map_err(|e| e.into())
        }

        async fn put_log_events(
            &self,
            _: &str,
            _: &str,
            _: InputLogEvent,
        ) -> Result<(), Box<dyn std::error::Error>> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_ensure_log_group_and_stream_success() {
        let mock = MockCWLogsHelper::new(|| Ok(()), || Ok(()), || Ok(()));

        let result =
            CloudWatchPublisher::ensure_log_group_and_stream(&mock, "test-group", "test-stream", 7)
                .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_ensure_log_group_already_exists() {
        use aws_sdk_cloudwatchlogs::types::error::ResourceAlreadyExistsException;
        use aws_smithy_runtime_api::client::orchestrator::HttpResponse;

        let mock = MockCWLogsHelper::new(
            || {
                Err(SdkError::service_error(
                    CreateLogGroupError::ResourceAlreadyExistsException(
                        ResourceAlreadyExistsException::builder().build(),
                    ),
                    HttpResponse::new(
                        aws_smithy_runtime_api::http::StatusCode::try_from(400).unwrap(),
                        aws_smithy_types::body::SdkBody::empty(),
                    ),
                ))
            },
            || Ok(()),
            || Ok(()),
        );

        let result = CloudWatchPublisher::ensure_log_group_and_stream(
            &mock,
            "existing-group",
            "test-stream",
            7,
        )
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_ensure_log_stream_already_exists() {
        use aws_sdk_cloudwatchlogs::types::error::ResourceAlreadyExistsException;
        use aws_smithy_runtime_api::client::orchestrator::HttpResponse;

        let mock = MockCWLogsHelper::new(
            || Ok(()),
            || {
                Err(SdkError::service_error(
                    CreateLogStreamError::ResourceAlreadyExistsException(
                        ResourceAlreadyExistsException::builder().build(),
                    ),
                    HttpResponse::new(
                        aws_smithy_runtime_api::http::StatusCode::try_from(400).unwrap(),
                        aws_smithy_types::body::SdkBody::empty(),
                    ),
                ))
            },
            || Ok(()),
        );

        let result = CloudWatchPublisher::ensure_log_group_and_stream(
            &mock,
            "test-group",
            "existing-stream",
            7,
        )
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_ensure_log_group_fails_with_other_error() {
        use aws_sdk_cloudwatchlogs::types::error::InvalidParameterException;
        use aws_smithy_runtime_api::client::orchestrator::HttpResponse;

        let mock = MockCWLogsHelper::new(
            || {
                Err(SdkError::service_error(
                    CreateLogGroupError::InvalidParameterException(
                        InvalidParameterException::builder().build(),
                    ),
                    HttpResponse::new(
                        aws_smithy_runtime_api::http::StatusCode::try_from(400).unwrap(),
                        aws_smithy_types::body::SdkBody::empty(),
                    ),
                ))
            },
            || Ok(()),
            || Ok(()),
        );

        let result =
            CloudWatchPublisher::ensure_log_group_and_stream(&mock, "test-group", "test-stream", 7)
                .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_ensure_log_stream_fails_with_other_error() {
        use aws_sdk_cloudwatchlogs::types::error::InvalidParameterException;
        use aws_smithy_runtime_api::client::orchestrator::HttpResponse;

        let mock = MockCWLogsHelper::new(
            || Ok(()),
            || {
                Err(SdkError::service_error(
                    CreateLogStreamError::InvalidParameterException(
                        InvalidParameterException::builder().build(),
                    ),
                    HttpResponse::new(
                        aws_smithy_runtime_api::http::StatusCode::try_from(400).unwrap(),
                        aws_smithy_types::body::SdkBody::empty(),
                    ),
                ))
            },
            || Ok(()),
        );

        let result =
            CloudWatchPublisher::ensure_log_group_and_stream(&mock, "test-group", "test-stream", 7)
                .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_ensure_retention_policy_failure_does_not_fail() {
        let mock = MockCWLogsHelper::new(
            || Ok(()),
            || Ok(()),
            || Err("retention policy failed".into()),
        );

        let result =
            CloudWatchPublisher::ensure_log_group_and_stream(&mock, "test-group", "test-stream", 7)
                .await;

        // Should succeed even if retention policy fails
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_ensure_both_already_exist() {
        use aws_sdk_cloudwatchlogs::types::error::ResourceAlreadyExistsException;
        use aws_smithy_runtime_api::client::orchestrator::HttpResponse;

        let mock = MockCWLogsHelper::new(
            || {
                Err(SdkError::service_error(
                    CreateLogGroupError::ResourceAlreadyExistsException(
                        ResourceAlreadyExistsException::builder().build(),
                    ),
                    HttpResponse::new(
                        aws_smithy_runtime_api::http::StatusCode::try_from(400).unwrap(),
                        aws_smithy_types::body::SdkBody::empty(),
                    ),
                ))
            },
            || {
                Err(SdkError::service_error(
                    CreateLogStreamError::ResourceAlreadyExistsException(
                        ResourceAlreadyExistsException::builder().build(),
                    ),
                    HttpResponse::new(
                        aws_smithy_runtime_api::http::StatusCode::try_from(400).unwrap(),
                        aws_smithy_types::body::SdkBody::empty(),
                    ),
                ))
            },
            || Ok(()),
        );

        let result = CloudWatchPublisher::ensure_log_group_and_stream(
            &mock,
            "existing-group",
            "existing-stream",
            7,
        )
        .await;

        assert!(result.is_ok());
    }
}
