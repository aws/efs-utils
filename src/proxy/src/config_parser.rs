use log::LevelFilter;
use serde::{Deserialize, Serialize};
use std::{error::Error, path::Path, str::FromStr};

const DEFAULT_LOG_LEVEL: LevelFilter = LevelFilter::Warn;

fn default_log_level() -> String {
    DEFAULT_LOG_LEVEL.to_string()
}

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

fn default_log_format() -> Option<String> {
    Some("file".to_string())
}

#[derive(Default, Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    #[serde(alias = "fips", deserialize_with = "deserialize_bool")]
    pub fips: bool,

    /// Logging level. Values should correspond to the log::LevelFilter enum.
    #[serde(alias = "debug", default = "default_log_level")]
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
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::test_utils::TEST_CONFIG_PATH;
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
            },
        };

        assert_eq!(result_config, expected_proxy_config);
    }

    #[test]
    fn test_parse_config_fips_disabled() {
        let config_string = r#"fips = no
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
cert = /var/run/efs/fs-12341234.home.ec2-user.efs.21036+/certificate.pem
key = /etc/amazon/efs/privateKey.pem
checkHost = fs-12341234.efs.us-east-1.amazonaws.com
"#;

        let result_config = ProxyConfig::from_str(config_string).unwrap();
        let expected_proxy_config = ProxyConfig {
            fips: false,
            pid_file_path: String::from(
                "/var/run/efs/fs-12341234.home.ec2-user.efs.21036+/stunnel.pid",
            ),
            debug: DEFAULT_LOG_LEVEL.to_string(),
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
            },
        };

        assert_eq!(result_config, expected_proxy_config);
    }
}
