use anyhow::{Context, Result};
use log::*;
use nix::NixPath;
use s2n_tls::enums::ClientAuthType::Optional;
use s2n_tls::security::Policy;
use s2n_tls::{config::Config, security::DEFAULT_TLS13};
use s2n_tls_tokio::TlsConnector;
use s2n_tls_tokio::TlsStream;
use std::path::Path;
use tokio::net::TcpStream;

use crate::connections::configure_stream;
use crate::error::ConnectError;

pub const FIPS_COMPLIANT_POLICY_VERSION: &str = "20230317";
pub struct InsecureAcceptAllCertificatesHandler;
impl s2n_tls::callbacks::VerifyHostNameCallback for InsecureAcceptAllCertificatesHandler {
    fn verify_host_name(&self, _host_name: &str) -> bool {
        true
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsConfig {
    pub fips_enabled: bool,

    /// Contents of the certificate authority file. E.g. /etc/amazon/efs/efs-utils.crt
    pub ca_file_contents: Vec<u8>,

    /// The client-side certificate and public key
    pub client_cert: Vec<u8>,

    /// The client private key
    pub client_private_key: Vec<u8>,

    /// The remote address to establish the TLS connection with
    pub remote_addr: String,

    /// The hostname that is expected to be on the remote server's TLS certificate
    pub server_domain: String,
}

// s2n-tls errors if there are comments in the certificate files. This function removes comments if
// they are present.
async fn read_file_with_comments_removed(path: &Path) -> Result<Vec<u8>> {
    let file = tokio::fs::File::open(path).await?;
    let reader = tokio::io::BufReader::new(file);
    let mut lines = tokio::io::AsyncBufReadExt::lines(reader);

    let mut output = Vec::new();
    while let Ok(Some(line)) = lines.next_line().await {
        if !line.starts_with("# ") {
            if !output.is_empty() {
                output.push(b'\n');
            }

            output.extend_from_slice(line.as_bytes());
        }
    }
    Ok(output)
}

impl TlsConfig {
    /// Create an instance of TlsConfig.
    ///
    /// This will return an error if the files could not be read or the remote address could not be resolved.
    ///
    /// # Arguments
    /// * `ca_file` - File path of the certificate authority file. E.g. /etc/amazon/efs/efs-utils.crt
    /// * `client_cert_pem_file` - File path of the file that contains the client-side certificate and public key
    /// * `client_private_key_pem_file` - File path of the file that contains the client private key
    /// * `remote_addr` - The remote address to establish the TLS connection with
    /// * `server_domain` - The hostname that is expected to be on the certificate that the remote server presents
    ///
    pub async fn new(
        fips_enabled: bool,
        ca_file: &Path,
        client_cert_pem_file: &Path,
        client_private_key_pem_file: &Path,
        remote_addr: &str,
        server_domain: &str,
    ) -> Result<Self> {
        let mut ca_file_contents: Vec<u8> = Vec::new();
        if !ca_file.is_empty() {
            ca_file_contents = read_file_with_comments_removed(ca_file).await.context(
                String::from("Error in TlsConfig::new. Unable to the CA File. Make sure it does not have any comments (lines that start with #)."))?;
        }
        let client_cert = read_file_with_comments_removed(client_cert_pem_file)
            .await
            .context(String::from(
                "Error in TlsConfig::new. Unable to read the client certificate file.",
            ))?;
        let client_private_key = read_file_with_comments_removed(client_private_key_pem_file)
            .await
            .context(String::from(
                "Error in TlsConfig::new. Unable to read private key file.",
            ))?;
        let server_domain = server_domain.to_string();
        let remote_addr = remote_addr.to_string();

        Ok(TlsConfig {
            fips_enabled,
            ca_file_contents,
            client_cert,
            client_private_key,
            remote_addr,
            server_domain,
        })
    }

    #[cfg(test)]
    pub async fn new_from_config(config: &crate::ProxyConfig) -> Result<TlsConfig> {
        let efs_config = &config.nested_config;

        let ca_file = Path::new(&efs_config.ca_file);
        let ca_cert_pem = Path::new(&efs_config.client_cert_pem_file);
        let private_key_pem = Path::new(&efs_config.client_private_key_pem_file);
        if !ca_file.exists() || !ca_cert_pem.exists() || !private_key_pem.exists() {
            let error_msg = "One or more required files for TLS config are missing";
            return Err(anyhow::Error::msg(error_msg));
        }
        TlsConfig::new(
            config.fips,
            &ca_file,
            &ca_cert_pem,
            &private_key_pem,
            efs_config.mount_target_addr.as_str(),
            efs_config.expected_server_hostname_tls.as_str(),
        )
        .await
    }
}

/// Establishes a TLS stream using the configuration and remote address specified in tls_config
pub async fn establish_tls_stream(
    tls_config: TlsConfig,
) -> Result<TlsStream<TcpStream>, ConnectError> {
    let config = create_config_builder(&tls_config).build()?;

    let tls_connector = TlsConnector::new(config);

    let tcp_stream = configure_stream(TcpStream::connect(tls_config.remote_addr).await?);

    let tls_stream = tls_connector
        .connect(&tls_config.server_domain, tcp_stream)
        .await?;

    debug!("{:#?}", tls_stream);
    Ok(tls_stream)
}

fn create_config_builder(tls_config: &TlsConfig) -> s2n_tls::config::Builder {
    let mut config = Config::builder();

    let policy = if tls_config.fips_enabled {
        Policy::from_version(FIPS_COMPLIANT_POLICY_VERSION).expect("Invalid policy")
    } else {
        DEFAULT_TLS13
    };
    config
        .set_security_policy(&policy)
        .expect("Error in create_tls_connector. Failed to set security policy.");
    config
        .set_client_auth_type(Optional)
        .expect("Error in create_tls_connector. Failed to set client auth type.");
    config
        .load_pem(&tls_config.client_cert, &tls_config.client_private_key)
        .expect(
            "Error in create_tls_connector. Failed to load the client certificate and private key.",
        );

    // If the customer is using the verify=0 mount option, we want to disable cert verification.
    if !tls_config.ca_file_contents.is_empty() {
        config
            .trust_pem(&tls_config.ca_file_contents)
            .expect("Error in create_tls_connector. Failed to add the CA file to the trust store.");
    } else {
        unsafe {
            config
                .disable_x509_verification()
                .expect("Error disabling x509 verification");
        };
    }

    // If stunnel_check_cert_hostname = false in efs-utils config, then we don't verify the hostname
    if tls_config.server_domain.is_empty() {
        config
            .set_verify_host_callback(InsecureAcceptAllCertificatesHandler)
            .expect("Unable to disable host name verification");
    }

    config
}

#[cfg(test)]
pub mod tests {

    use crate::config_parser::tests::get_test_config;

    use super::*;

    pub async fn get_client_config() -> Result<Config> {
        let tls_config = TlsConfig::new_from_config(&get_test_config()).await?;
        let builder = create_config_builder(&tls_config);

        let config = builder.build()?;
        Ok(config)
    }

    pub async fn get_server_config() -> Result<Config> {
        let tls_config = TlsConfig::new_from_config(&get_test_config()).await?;
        let mut builder = create_config_builder(&tls_config);

        // Accept all client certificates
        builder.set_verify_host_callback(InsecureAcceptAllCertificatesHandler {})?;

        let config = builder.build()?;
        Ok(config)
    }

    #[tokio::test]
    async fn test_remove_comments() {
        let comment_file = Path::new("tests/certs/cert_with_comments.pem");
        let decommented_output = read_file_with_comments_removed(comment_file).await;

        let expected = tokio::fs::read(&Path::new("tests/certs/cert.pem"))
            .await
            .expect("Could not read certificate file");
        assert_eq!(expected.len(), decommented_output.unwrap().len());
    }
}
