use log::LevelFilter;
use serde::{Deserialize, Serialize};
use std::{error::Error, path::Path, str::FromStr};

const DEFAULT_LOG_LEVEL: fn() -> String = || LevelFilter::Warn.to_string();

// This should be equal to DEFAULT_NFS_MOUNT_COMMAND_TIMEOUT_SEC in mount_efs/__init__.py
const DEFAULT_PROXY_INIT_TIMEOUT_SEC: fn() -> u64 = || 15;
const DEFAULT_READ_BYPASS_REQUESTED: fn() -> bool = || true;
const DEFAULT_S3_IDLE_TIMEOUT_SECONDS: fn() -> u64 = || 60;
const DEFAULT_S3_OPERATION_TIMEOUT_SECONDS: fn() -> u64 = || 5;
const DEFAULT_S3_OPERATION_ATTEMPT_TIMEOUT_MS: fn() -> u64 = || 1500;
const DEFAULT_S3_READ_CHUNK_SIZE_BYTES: fn() -> u64 = || 1024 * 1024; // 1 MiB
const DEFAULT_READAHEAD_CACHE_INIT_MEMORY_SIZE_MB: fn() -> usize = || 10; // 10 MiB
const DEFAULT_READAHEAD_CACHE_MAX_MEMORY_SIZE_MB: fn() -> usize = || 1024; // 1 GiB
const DEFAULT_READAHEAD_INIT_WINDOW_SIZE_BYTES: fn() -> u64 = || 8 * 1024 * 1024; // 8 MiB
const DEFAULT_READAHEAD_MAX_WINDOW_SIZE_BYTES: fn() -> u64 = || 8 * 1024 * 1024; // 8 MiB
const DEFAULT_READAHEAD_CACHE_EVICTION_INTERVAL_MS: fn() -> u64 = || 500;
const DEFAULT_READAHEAD_CACHE_ENABLED: fn() -> bool = || true;
const DEFAULT_READAHEAD_CACHE_TARGET_UTILIZATION_PERCENT: fn() -> usize = || 80;
pub const DEFAULT_READ_BYPASS_MAX_IN_FLIGHT_S3_BYTES: fn() -> usize = || 256 * 1024 * 1024; // 256 MiB
const DEFAULT_SMALL_FILE_CACHING_THRESHOLD: fn() -> u64 = || 1024 * 1024; // 1 MiB
pub const DEFAULT_READ_BYPASS_DENYLIST_SIZE: fn() -> u64 = || 10000;
pub const DEFAULT_READ_BYPASS_DENYLIST_TTL_SECONDS: fn() -> u64 = || 300;
// CLoudWatch metrics and logs are disabled by default for proxy.
// For S3Files they are enabled by default in s3files-utils.conf.jinja
const DEFAULT_CLOUDWATCH_METRICS_ENABLED: fn() -> bool = || false;
const DEFAULT_CLOUDWATCH_LOGS_ENABLED: fn() -> bool = || false;
const DEFAULT_CLOUD_WATCH_LOGS_RETENTION_DAYS: fn() -> usize = || 14;
const DEFAULT_PROXY_LOGGING_MAX_BYTES: fn() -> usize = || 1048576;
const DEFAULT_PROXY_LOGGING_FILE_COUNT: fn() -> usize = || 10;

fn deserialize_bool<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    match s.to_lowercase().as_str() {
        "true" | "yes" | "1" => Ok(true),
        "false" | "no" | "0" => Ok(false),
        _ => Err(serde::de::Error::custom(format!("Invalid value: {}", s))),
    }
}

fn deserialize_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    s.parse::<u64>()
        .map_err(|_| serde::de::Error::custom(format!("Invalid value: {}", s)))
}

fn deserialize_usize<'de, D>(deserializer: D) -> Result<usize, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    s.parse::<usize>()
        .map_err(|_| serde::de::Error::custom(format!("Invalid value: {}", s)))
}

fn default_log_format() -> Option<String> {
    Some("file".to_string())
}

#[derive(Default, Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    #[serde(alias = "fips", deserialize_with = "deserialize_bool")]
    pub fips: bool,

    /// Logging level. Values should correspond to the log::LevelFilter enum.
    #[serde(alias = "debug", default = "DEFAULT_LOG_LEVEL")]
    pub debug: String,

    /// Output path for log files. Logging is disabled if this value is not provided.
    #[serde(alias = "output")]
    pub output: Option<String>,

    /// The format to use for logging. Values can be "file", "stdout"
    /// Default is "file" if not specified.
    #[serde(alias = "log_format", default = "default_log_format")]
    pub log_format: Option<String>,

    /// The proxy process is responsible for writing it's PID into this file so that the Watchdog
    /// process can monitor it
    #[serde(alias = "pid")]
    pub pid_file_path: String,

    /// This nested structure is required for backwards compatibility
    #[serde(alias = "efs")]
    pub nested_config: EfsConfig,
}

impl FromStr for ProxyConfig {
    type Err = serde_ini::de::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_ini::from_str(s)
            // ReadBypass is initially enabled if requested, or disabled if not
            .map(|mut config: ProxyConfig| {
                config.nested_config.read_bypass_config.enabled =
                    config.nested_config.read_bypass_config.requested;
                config
            })
    }
}

impl ProxyConfig {
    pub fn from_path(config_path: &Path) -> Result<Self, Box<dyn Error>> {
        let config_string = std::fs::read_to_string(config_path)?;
        let config = ProxyConfig::from_str(&config_string)?;
        Ok(config)
    }
}

#[derive(Default, Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct EfsConfig {
    /// The mount target address - DNS name or IP address
    #[serde(alias = "connect")]
    pub mount_target_addr: String,

    /// Listen for and accept connections on the specified host:port
    #[serde(alias = "accept")]
    pub listen_addr: String,

    /// File path of the file that contains the client-side certificate and public key
    #[serde(alias = "cert", default)]
    pub client_cert_pem_file: String,

    /// File path of the file that contains the client private key
    #[serde(alias = "key", default)]
    pub client_private_key_pem_file: String,

    /// The hostname that is expected to be on the TLS certificate that the remote server presents
    #[serde(alias = "checkHost", default)]
    pub expected_server_hostname_tls: String,

    /// File path of the certificate authority file.
    /// This is used to verify the EFS server-side TLS certificate.
    #[serde(alias = "CAfile", default)]
    pub ca_file: String,

    /// File-system id, to be used for client-side telemetry purposes
    #[serde(alias = "fs_id", default)]
    pub fs_id: String,

    /// This is used to set a deadline for initializing this local proxy, and should be equal to
    /// the "retry_nfs_mount_command_timeout_sec" value in the `src/mount_efs/__init__.py`. That
    /// script will kill this process if mounting does not complete within that time. The config is
    /// propagated here to allow this proxy to emit logs that indicate a initialization timeout
    /// failure before it is killed.
    #[serde(
        alias = "retry_nfs_mount_command_timeout_sec",
        deserialize_with = "deserialize_u64",
        default = "DEFAULT_PROXY_INIT_TIMEOUT_SEC"
    )]
    pub proxy_init_timeout_sec: u64,

    /// Configuration for EFS-Proxy telemetry
    #[serde(flatten, default)]
    pub telemetry_config: TelemetryConfig,

    /// Configuration for ReadBypass feature
    #[serde(flatten, default)]
    pub read_bypass_config: ReadBypassConfig,

    /// Proxy logging level
    #[serde(alias = "proxy_logging_level", default)]
    pub proxy_logging_level: Option<String>,

    /// Proxy logging max bytes
    #[serde(
        alias = "proxy_logging_max_bytes",
        deserialize_with = "deserialize_usize",
        default = "DEFAULT_PROXY_LOGGING_MAX_BYTES"
    )]
    pub proxy_logging_max_bytes: usize,

    /// Proxy logging file count
    #[serde(
        alias = "proxy_logging_file_count",
        deserialize_with = "deserialize_usize",
        default = "DEFAULT_PROXY_LOGGING_FILE_COUNT"
    )]
    pub proxy_logging_file_count: usize,
}
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct ReadBypassConfig {
    /// Whether read-bypass is requested
    #[serde(
        alias = "read_bypass_requested",
        deserialize_with = "deserialize_bool",
        default = "DEFAULT_READ_BYPASS_REQUESTED"
    )]
    pub requested: bool,

    /// Whether read-bypass is currently enabled
    #[serde(skip)]
    pub enabled: bool,

    /// Maximum number of file handles in the denylist
    #[serde(
        alias = "read_bypass_denylist_size",
        deserialize_with = "deserialize_u64",
        default = "DEFAULT_READ_BYPASS_DENYLIST_SIZE"
    )]
    pub denylist_size: u64,

    /// TTL for denylisted file handles in seconds
    #[serde(
        alias = "read_bypass_denylist_ttl_seconds",
        deserialize_with = "deserialize_u64",
        default = "DEFAULT_READ_BYPASS_DENYLIST_TTL_SECONDS"
    )]
    pub denylist_ttl_seconds: u64,

    /// S3 connection pool idle timeout in seconds
    #[serde(
        alias = "s3_pool_idle_timeout_seconds",
        deserialize_with = "deserialize_u64",
        default = "DEFAULT_S3_IDLE_TIMEOUT_SECONDS"
    )]
    pub s3_idle_timeout_seconds: u64,

    /// S3 total operation timeout in seconds
    #[serde(
        alias = "s3_operation_timeout_seconds",
        deserialize_with = "deserialize_u64",
        default = "DEFAULT_S3_OPERATION_TIMEOUT_SECONDS"
    )]
    pub s3_operation_timeout_seconds: u64,

    /// S3 read chunk size
    #[serde(
        alias = "s3_read_chunk_size_bytes",
        deserialize_with = "deserialize_u64",
        default = "DEFAULT_S3_READ_CHUNK_SIZE_BYTES"
    )]
    pub s3_read_chunk_size_bytes: u64,

    /// readahead cache init memory size in MiB
    #[serde(
        alias = "readahead_cache_init_memory_size_mb",
        deserialize_with = "deserialize_usize",
        default = "DEFAULT_READAHEAD_CACHE_INIT_MEMORY_SIZE_MB"
    )]
    pub readahead_cache_init_memory_size_mb: usize,

    /// readahead cache max memory size in MiB
    #[serde(
        alias = "readahead_cache_max_memory_size_mb",
        deserialize_with = "deserialize_usize",
        default = "DEFAULT_READAHEAD_CACHE_MAX_MEMORY_SIZE_MB"
    )]
    pub readahead_cache_max_memory_size_mb: usize,

    /// readahead init read window in bytes
    #[serde(
        alias = "readahead_init_window_size_bytes",
        deserialize_with = "deserialize_u64",
        default = "DEFAULT_READAHEAD_INIT_WINDOW_SIZE_BYTES"
    )]
    pub readahead_init_window_size_bytes: u64,

    /// readahead max read window in bytes
    #[serde(
        alias = "readahead_max_window_size_bytes",
        deserialize_with = "deserialize_u64",
        default = "DEFAULT_READAHEAD_MAX_WINDOW_SIZE_BYTES"
    )]
    pub readahead_max_window_size_bytes: u64,

    /// readahead cache eviction interval in milliseconds
    #[serde(
        alias = "readahead_cache_eviction_interval_ms",
        deserialize_with = "deserialize_u64",
        default = "DEFAULT_READAHEAD_CACHE_EVICTION_INTERVAL_MS"
    )]
    pub readahead_cache_eviction_interval_ms: u64,

    /// readahead cache enabled
    #[serde(
        alias = "readahead_cache_enabled",
        deserialize_with = "deserialize_bool",
        default = "DEFAULT_READAHEAD_CACHE_ENABLED"
    )]
    pub readahead_cache_enabled: bool,

    /// readahead cache target utilization percent for proactive eviction
    #[serde(
        alias = "readahead_cache_target_utilization_percent",
        deserialize_with = "deserialize_usize",
        default = "DEFAULT_READAHEAD_CACHE_TARGET_UTILIZATION_PERCENT"
    )]
    pub readahead_cache_target_utilization_percent: usize,

    /// Files at or below this size (in bytes) bypass the readahead cache and are
    /// read directly from S3. Default: 1 MiB.
    #[serde(
        alias = "small_file_caching_threshold",
        deserialize_with = "deserialize_u64",
        default = "DEFAULT_SMALL_FILE_CACHING_THRESHOLD"
    )]
    pub small_file_caching_threshold: u64,

    /// Max bytes in-flight to S3 for read bypass
    #[serde(
        alias = "read_bypass_max_in_flight_s3_bytes",
        deserialize_with = "deserialize_usize",
        default = "DEFAULT_READ_BYPASS_MAX_IN_FLIGHT_S3_BYTES"
    )]
    pub read_bypass_max_in_flight_s3_bytes: usize,

    /// S3 operation attempt timeout in milliseconds
    #[serde(
        alias = "s3_operation_attempt_timeout_ms",
        deserialize_with = "deserialize_u64",
        default = "DEFAULT_S3_OPERATION_ATTEMPT_TIMEOUT_MS"
    )]
    pub s3_operation_attempt_timeout_ms: u64,

    /// For ReadBypass S3 client credentials
    #[serde(alias = "region")]
    pub region: Option<String>,

    /// For ReadBypass S3 client credentials  
    #[serde(alias = "profile")]
    pub profile: Option<String>,

    /// For ReadBypass S3 client credentials
    #[serde(alias = "role_arn")]
    pub role_arn: Option<String>,

    /// For ReadBypass S3 client credentials
    #[serde(alias = "jwt_path")]
    pub jwt_path: Option<String>,

    /// For ReadBypass S3 client credentials (ECS credentials URI)
    #[serde(alias = "aws_creds_uri")]
    pub aws_creds_uri: Option<String>,
}
impl Default for ReadBypassConfig {
    fn default() -> Self {
        Self {
            requested: DEFAULT_READ_BYPASS_REQUESTED(),
            enabled: DEFAULT_READ_BYPASS_REQUESTED(),
            denylist_size: DEFAULT_READ_BYPASS_DENYLIST_SIZE(),
            denylist_ttl_seconds: DEFAULT_READ_BYPASS_DENYLIST_TTL_SECONDS(),
            s3_idle_timeout_seconds: DEFAULT_S3_IDLE_TIMEOUT_SECONDS(),
            s3_operation_timeout_seconds: DEFAULT_S3_OPERATION_TIMEOUT_SECONDS(),
            s3_operation_attempt_timeout_ms: DEFAULT_S3_OPERATION_ATTEMPT_TIMEOUT_MS(),
            s3_read_chunk_size_bytes: DEFAULT_S3_READ_CHUNK_SIZE_BYTES(),
            readahead_cache_init_memory_size_mb: DEFAULT_READAHEAD_CACHE_INIT_MEMORY_SIZE_MB(),
            readahead_cache_max_memory_size_mb: DEFAULT_READAHEAD_CACHE_MAX_MEMORY_SIZE_MB(),
            readahead_init_window_size_bytes: DEFAULT_READAHEAD_INIT_WINDOW_SIZE_BYTES(),
            readahead_max_window_size_bytes: DEFAULT_READAHEAD_MAX_WINDOW_SIZE_BYTES(),
            readahead_cache_eviction_interval_ms: DEFAULT_READAHEAD_CACHE_EVICTION_INTERVAL_MS(),
            readahead_cache_enabled: DEFAULT_READAHEAD_CACHE_ENABLED(),
            readahead_cache_target_utilization_percent:
                DEFAULT_READAHEAD_CACHE_TARGET_UTILIZATION_PERCENT(),
            read_bypass_max_in_flight_s3_bytes: DEFAULT_READ_BYPASS_MAX_IN_FLIGHT_S3_BYTES(),
            small_file_caching_threshold: DEFAULT_SMALL_FILE_CACHING_THRESHOLD(),
            region: None,
            profile: None,
            role_arn: None,
            jwt_path: None,
            aws_creds_uri: None,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    /// CloudWatch metrics emission
    #[serde(
        alias = "cloud_watch_metrics",
        deserialize_with = "deserialize_bool",
        default = "DEFAULT_CLOUDWATCH_METRICS_ENABLED"
    )]
    pub cloud_watch_metrics_enabled: bool,

    /// CloudWatch logs emission
    #[serde(
        alias = "cloud_watch_logs",
        deserialize_with = "deserialize_bool",
        default = "DEFAULT_CLOUDWATCH_LOGS_ENABLED"
    )]
    pub cloud_watch_logs_enabled: bool,

    /// Group name for CloudWatch logs
    #[serde(alias = "log_group_name", default)]
    pub log_group_name: String,

    /// CloudWatch logs retention
    #[serde(
        alias = "cloud_watch_logs_retention_days",
        deserialize_with = "deserialize_usize",
        default = "DEFAULT_CLOUD_WATCH_LOGS_RETENTION_DAYS"
    )]
    pub cloud_watch_logs_retention_days: usize,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            cloud_watch_metrics_enabled: DEFAULT_CLOUDWATCH_METRICS_ENABLED(),
            cloud_watch_logs_enabled: DEFAULT_CLOUDWATCH_LOGS_ENABLED(),
            log_group_name: String::new(),
            cloud_watch_logs_retention_days: DEFAULT_CLOUD_WATCH_LOGS_RETENTION_DAYS(),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::test_utils::TEST_CONFIG_PATH;
    use rand::random;
    use std::{path::Path, string::String};

    #[test]
    fn test_read_config_from_file() {
        assert!(ProxyConfig::from_path(Path::new(TEST_CONFIG_PATH)).is_ok());
    }

    #[test]
    fn test_parse_config() {
        let config_string = r#"fips = yes
foreground = quiet
socket = l:SO_REUSEADDR=yes
socket = a:SO_BINDTODEVICE=lo
debug = debug
output = /var/log/amazon/efs/fs-12341234.home.ec2-user.efs.21036.efs-proxy.log
pid = /var/run/efs/fs-12341234.home.ec2-user.efs.21036+/stunnel.pid
port = 8081
initial_partition_ip = 127.0.0.1:2049

[efs]
accept = 127.0.0.1:21036
connect = fs-12341234.efs.us-east-1.amazonaws.com:2049
sslVersion = TLSv1.2
renegotiation = no
TIMEOUTbusy = 20
TIMEOUTclose = 0
TIMEOUTidle = 70
delay = yes
verify = 2
CAfile = /etc/amazon/efs/efs-utils.crt
fs_id = fs-12341234
cert = /var/run/efs/fs-12341234.home.ec2-user.efs.21036+/certificate.pem
key = /etc/amazon/efs/privateKey.pem
checkHost = fs-12341234.efs.us-east-1.amazonaws.com
"#;

        let result_config = ProxyConfig::from_str(config_string).unwrap();
        let expected_proxy_config = ProxyConfig {
            fips: true,
            pid_file_path: String::from(
                "/var/run/efs/fs-12341234.home.ec2-user.efs.21036+/stunnel.pid",
            ),
            debug: LevelFilter::Debug.to_string().to_ascii_lowercase(),
            output: Some(String::from(
                "/var/log/amazon/efs/fs-12341234.home.ec2-user.efs.21036.efs-proxy.log",
            )),
            log_format: Some(String::from("file")),
            nested_config: EfsConfig {
                listen_addr: String::from("127.0.0.1:21036"),
                mount_target_addr: String::from("fs-12341234.efs.us-east-1.amazonaws.com:2049"),
                ca_file: String::from("/etc/amazon/efs/efs-utils.crt"),
                client_cert_pem_file: String::from(
                    "/var/run/efs/fs-12341234.home.ec2-user.efs.21036+/certificate.pem",
                ),
                client_private_key_pem_file: String::from("/etc/amazon/efs/privateKey.pem"),
                expected_server_hostname_tls: String::from(
                    "fs-12341234.efs.us-east-1.amazonaws.com",
                ),
                proxy_init_timeout_sec: DEFAULT_PROXY_INIT_TIMEOUT_SEC(),
                fs_id: "fs-12341234".to_string(),
                telemetry_config: TelemetryConfig::default(),
                read_bypass_config: ReadBypassConfig::default(),
                proxy_logging_level: None,
                proxy_logging_max_bytes: DEFAULT_PROXY_LOGGING_MAX_BYTES(),
                proxy_logging_file_count: DEFAULT_PROXY_LOGGING_FILE_COUNT(),
            },
        };

        assert_eq!(result_config, expected_proxy_config);
    }

    // Test that features are properly disabled (fips, efsasync, etc)
    #[test]
    fn test_parse_config_features_disabled() {
        let config_string = r#"
fips = no
foreground = quiet
socket = l:SO_REUSEADDR=yes
socket = a:SO_BINDTODEVICE=lo
pid = /var/run/efs/fs-12341234.home.ec2-user.efs.21036+/stunnel.pid
port = 8081
initial_partition_ip = 127.0.0.1:2049
log_format = stdout

[efs]
accept = 127.0.0.1:21036
connect = fs-12341234.efs.us-east-1.amazonaws.com:2049
sslVersion = TLSv1.2
renegotiation = no
TIMEOUTbusy = 20
TIMEOUTclose = 0
TIMEOUTidle = 70
delay = yes
verify = 2
CAfile = /etc/amazon/efs/efs-utils.crt
fs_id = fs-12341234
cert = /var/run/efs/fs-12341234.home.ec2-user.efs.21036+/certificate.pem
key = /etc/amazon/efs/privateKey.pem
checkHost = fs-12341234.efs.us-east-1.amazonaws.com
read_bypass_requested = no
region = us-east-1
profile = foo
role_arn = bar
jwt_path = baz
"#;

        let result_config = ProxyConfig::from_str(config_string).unwrap();
        let expected_proxy_config = ProxyConfig {
            fips: false,
            pid_file_path: String::from(
                "/var/run/efs/fs-12341234.home.ec2-user.efs.21036+/stunnel.pid",
            ),
            debug: DEFAULT_LOG_LEVEL(),
            output: None,
            log_format: Some(String::from("stdout")),
            nested_config: EfsConfig {
                listen_addr: String::from("127.0.0.1:21036"),
                mount_target_addr: String::from("fs-12341234.efs.us-east-1.amazonaws.com:2049"),
                ca_file: String::from("/etc/amazon/efs/efs-utils.crt"),
                client_cert_pem_file: String::from(
                    "/var/run/efs/fs-12341234.home.ec2-user.efs.21036+/certificate.pem",
                ),
                client_private_key_pem_file: String::from("/etc/amazon/efs/privateKey.pem"),
                expected_server_hostname_tls: String::from(
                    "fs-12341234.efs.us-east-1.amazonaws.com",
                ),
                proxy_init_timeout_sec: DEFAULT_PROXY_INIT_TIMEOUT_SEC(),
                fs_id: "fs-12341234".to_string(),
                telemetry_config: TelemetryConfig::default(),
                read_bypass_config: ReadBypassConfig {
                    requested: false,
                    enabled: false,
                    denylist_size: DEFAULT_READ_BYPASS_DENYLIST_SIZE(),
                    denylist_ttl_seconds: DEFAULT_READ_BYPASS_DENYLIST_TTL_SECONDS(),
                    s3_idle_timeout_seconds: DEFAULT_S3_IDLE_TIMEOUT_SECONDS(),
                    s3_operation_timeout_seconds: DEFAULT_S3_OPERATION_TIMEOUT_SECONDS(),
                    s3_operation_attempt_timeout_ms: DEFAULT_S3_OPERATION_ATTEMPT_TIMEOUT_MS(),
                    s3_read_chunk_size_bytes: DEFAULT_S3_READ_CHUNK_SIZE_BYTES(),
                    readahead_cache_init_memory_size_mb:
                        DEFAULT_READAHEAD_CACHE_INIT_MEMORY_SIZE_MB(),
                    readahead_cache_max_memory_size_mb: DEFAULT_READAHEAD_CACHE_MAX_MEMORY_SIZE_MB(
                    ),
                    readahead_init_window_size_bytes: DEFAULT_READAHEAD_INIT_WINDOW_SIZE_BYTES(),
                    readahead_max_window_size_bytes: DEFAULT_READAHEAD_MAX_WINDOW_SIZE_BYTES(),
                    readahead_cache_eviction_interval_ms:
                        DEFAULT_READAHEAD_CACHE_EVICTION_INTERVAL_MS(),
                    readahead_cache_enabled: DEFAULT_READAHEAD_CACHE_ENABLED(),
                    read_bypass_max_in_flight_s3_bytes: DEFAULT_READ_BYPASS_MAX_IN_FLIGHT_S3_BYTES(
                    ),
                    readahead_cache_target_utilization_percent:
                        DEFAULT_READAHEAD_CACHE_TARGET_UTILIZATION_PERCENT(),
                    small_file_caching_threshold: DEFAULT_SMALL_FILE_CACHING_THRESHOLD(),
                    region: Some(String::from("us-east-1")),
                    profile: Some(String::from("foo")),
                    role_arn: Some(String::from("bar")),
                    jwt_path: Some(String::from("baz")),
                    aws_creds_uri: None,
                },
                proxy_logging_level: None,
                proxy_logging_max_bytes: DEFAULT_PROXY_LOGGING_MAX_BYTES(),
                proxy_logging_file_count: DEFAULT_PROXY_LOGGING_FILE_COUNT(),
            },
        };

        assert_eq!(result_config, expected_proxy_config);
    }

    #[test]
    fn test_parse_config_with_non_default_efs_async_configs() {
        let test_value: u32 = random::<u32>();
        let config_string = format!(
            r#"
fips = yes
foreground = quiet
socket = l:SO_REUSEADDR=yes
socket = a:SO_BINDTODEVICE=lo
debug = debug
output = /var/log/amazon/efs/fs-12341234.home.ec2-user.efs.21036.efs-proxy.log
pid = /var/run/efs/fs-12341234.home.ec2-user.efs.21036+/stunnel.pid
port = 8081
initial_partition_ip = 127.0.0.1:2049
log_format = stdout

[efs]
accept = 127.0.0.1:21036
connect = fs-12341234.efs.us-east-1.amazonaws.com:2049
sslVersion = TLSv1.2
renegotiation = no
TIMEOUTbusy = 20
TIMEOUTclose = 0
TIMEOUTidle = 70
delay = yes
verify = 2
CAfile = /etc/amazon/efs/efs-utils.crt
fs_id = fs-12341234
cert = /var/run/efs/fs-12341234.home.ec2-user.efs.21036+/certificate.pem
key = /etc/amazon/efs/privateKey.pem
checkHost = fs-12341234.efs.us-east-1.amazonaws.com
retry_nfs_mount_command_timeout_sec = {test_value}
read_bypass_requested = no
read_bypass_denylist_size = {test_value}
read_bypass_denylist_ttl_seconds = {test_value}
s3_read_chunk_size_bytes = {test_value}
readahead_cache_init_memory_size_mb = {test_value}
readahead_cache_max_memory_size_mb = {test_value}
readahead_init_window_size_bytes = {test_value}
readahead_max_window_size_bytes = {test_value}
"#
        );

        let result_config = ProxyConfig::from_str(&config_string).unwrap();
        let expected_proxy_config = ProxyConfig {
            fips: true,
            pid_file_path: String::from(
                "/var/run/efs/fs-12341234.home.ec2-user.efs.21036+/stunnel.pid",
            ),
            debug: LevelFilter::Debug.to_string().to_ascii_lowercase(),
            output: Some(String::from(
                "/var/log/amazon/efs/fs-12341234.home.ec2-user.efs.21036.efs-proxy.log",
            )),
            log_format: Some(String::from("stdout")),
            nested_config: EfsConfig {
                listen_addr: String::from("127.0.0.1:21036"),
                mount_target_addr: String::from("fs-12341234.efs.us-east-1.amazonaws.com:2049"),
                ca_file: String::from("/etc/amazon/efs/efs-utils.crt"),
                client_cert_pem_file: String::from(
                    "/var/run/efs/fs-12341234.home.ec2-user.efs.21036+/certificate.pem",
                ),
                client_private_key_pem_file: String::from("/etc/amazon/efs/privateKey.pem"),
                expected_server_hostname_tls: String::from(
                    "fs-12341234.efs.us-east-1.amazonaws.com",
                ),
                proxy_init_timeout_sec: test_value as u64,
                fs_id: "fs-12341234".to_string(),
                telemetry_config: TelemetryConfig::default(),
                read_bypass_config: ReadBypassConfig {
                    requested: false,
                    enabled: false,
                    denylist_size: test_value as u64,
                    denylist_ttl_seconds: test_value as u64,
                    s3_idle_timeout_seconds: DEFAULT_S3_IDLE_TIMEOUT_SECONDS(),
                    s3_operation_timeout_seconds: DEFAULT_S3_OPERATION_TIMEOUT_SECONDS(),
                    s3_operation_attempt_timeout_ms: DEFAULT_S3_OPERATION_ATTEMPT_TIMEOUT_MS(),
                    s3_read_chunk_size_bytes: test_value as u64,
                    readahead_cache_init_memory_size_mb: test_value as usize,
                    readahead_cache_max_memory_size_mb: test_value as usize,
                    readahead_init_window_size_bytes: test_value as u64,
                    readahead_max_window_size_bytes: test_value as u64,
                    readahead_cache_eviction_interval_ms:
                        DEFAULT_READAHEAD_CACHE_EVICTION_INTERVAL_MS(),
                    readahead_cache_enabled: DEFAULT_READAHEAD_CACHE_ENABLED(),
                    read_bypass_max_in_flight_s3_bytes: DEFAULT_READ_BYPASS_MAX_IN_FLIGHT_S3_BYTES(
                    ),
                    readahead_cache_target_utilization_percent:
                        DEFAULT_READAHEAD_CACHE_TARGET_UTILIZATION_PERCENT(),
                    small_file_caching_threshold: DEFAULT_SMALL_FILE_CACHING_THRESHOLD(),
                    region: None,
                    profile: None,
                    role_arn: None,
                    jwt_path: None,
                    aws_creds_uri: None,
                },
                proxy_logging_level: None,
                proxy_logging_max_bytes: DEFAULT_PROXY_LOGGING_MAX_BYTES(),
                proxy_logging_file_count: DEFAULT_PROXY_LOGGING_FILE_COUNT(),
            },
        };

        assert_eq!(result_config, expected_proxy_config);
    }

    #[test]
    fn test_parse_config_read_bypass_requested() {
        let config_string = r#"
fips = yes
output = /var/log/amazon/efs/fs-12341234.home.ec2-user.efs.21036.efs-proxy.log
pid = /var/run/efs/fs-12341234.home.ec2-user.efs.21036+/stunnel.pid
port = 8081

[efs]
accept = 127.0.0.1:21036
connect = fs-12341234.efs.us-east-1.amazonaws.com:2049
read_bypass_requested = yes
read_bypass_enabled = no
read_bypass_denylist_size = 54321
read_bypass_denylist_ttl_seconds = 543
"#;

        let result_config = ProxyConfig::from_str(config_string).unwrap();

        assert!(result_config.nested_config.read_bypass_config.requested);

        // read_bypass_enabled from INI should be ignored,
        // ProxyConfig value should match that of read_bypass_enabled
        assert!(result_config.nested_config.read_bypass_config.enabled);

        assert_eq!(
            result_config.nested_config.read_bypass_config.denylist_size,
            54321
        );
        assert_eq!(
            result_config
                .nested_config
                .read_bypass_config
                .denylist_ttl_seconds,
            543
        );
        assert_eq!(
            result_config
                .nested_config
                .read_bypass_config
                .readahead_cache_enabled,
            DEFAULT_READAHEAD_CACHE_ENABLED()
        );
    }

    #[test]
    fn test_parse_config_s3_settings_defaults() {
        let config_string = r#"
fips = no
pid = /var/run/efs/fs-12341234.home.ec2-user.efs.21036+/stunnel.pid

[efs]
accept = 127.0.0.1:21036
connect = fs-12341234.efs.us-east-1.amazonaws.com:2049
"#;

        let result_config = ProxyConfig::from_str(config_string).unwrap();
        let s3_config = &result_config.nested_config.read_bypass_config;

        // Verify S3 settings use defaults
        assert_eq!(
            s3_config.s3_idle_timeout_seconds,
            DEFAULT_S3_IDLE_TIMEOUT_SECONDS()
        );
        assert_eq!(
            s3_config.s3_operation_timeout_seconds,
            DEFAULT_S3_OPERATION_TIMEOUT_SECONDS()
        );
        assert_eq!(
            s3_config.s3_operation_attempt_timeout_ms,
            DEFAULT_S3_OPERATION_ATTEMPT_TIMEOUT_MS()
        );
    }

    #[test]
    fn test_parse_config_s3_settings_custom_values() {
        let config_string = r#"
fips = no
pid = /var/run/efs/fs-12341234.home.ec2-user.efs.21036+/stunnel.pid

[efs]
accept = 127.0.0.1:21036
connect = fs-12341234.efs.us-east-1.amazonaws.com:2049
s3_pool_idle_timeout_seconds = 120
s3_operation_timeout_seconds = 10
s3_operation_attempt_timeout_ms = 3000
"#;

        let result_config = ProxyConfig::from_str(config_string).unwrap();
        let s3_config = &result_config.nested_config.read_bypass_config;

        // Verify custom S3 settings
        assert_eq!(s3_config.s3_idle_timeout_seconds, 120);
        assert_eq!(s3_config.s3_operation_timeout_seconds, 10);
        assert_eq!(s3_config.s3_operation_attempt_timeout_ms, 3000);
    }

    #[test]
    fn test_parse_config_readahead_cache_disabled() {
        let config_string = r#"
fips = no
pid = /var/run/efs/fs-12341234.home.ec2-user.efs.21036+/stunnel.pid

[efs]
accept = 127.0.0.1:21036
connect = fs-12341234.efs.us-east-1.amazonaws.com:2049
readahead_cache_enabled = no
"#;

        let result_config = ProxyConfig::from_str(config_string).unwrap();

        assert!(
            !result_config
                .nested_config
                .read_bypass_config
                .readahead_cache_enabled
        );
    }

    #[test]
    fn test_parse_config_s3_settings_mixed_custom_and_defaults() {
        let config_string = r#"
fips = no
pid = /var/run/efs/fs-12341234.home.ec2-user.efs.21036+/stunnel.pid

[efs]
accept = 127.0.0.1:21036
connect = fs-12341234.efs.us-east-1.amazonaws.com:2049
# Only set some S3 parameters, others should use defaults
s3_operation_timeout_seconds = 15
"#;

        let result_config = ProxyConfig::from_str(config_string).unwrap();
        let s3_config = &result_config.nested_config.read_bypass_config;

        // Verify custom values are used
        assert_eq!(s3_config.s3_operation_timeout_seconds, 15);

        // Verify defaults are used for unspecified parameters
        assert_eq!(
            s3_config.s3_idle_timeout_seconds,
            DEFAULT_S3_IDLE_TIMEOUT_SECONDS()
        );
        assert_eq!(
            s3_config.s3_operation_attempt_timeout_ms,
            DEFAULT_S3_OPERATION_ATTEMPT_TIMEOUT_MS()
        );
    }
}
