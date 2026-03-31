//! ### Credentials Chain for AWS SDK Clients
//!
//! This credential chain was written to closely follow existing the credential chain used in
//! efs-utils (python). This was done to reduce the likelihood that a different
//! credential source is used for the mounting in the python code of efs-utils and for the s3
//! client used here the in proxy. If the python code is migrated to rust, we could consider using
//! the "DefaultCredentialsChain" instead of this custom one.
//!
//! Notes:
//!
//! 1. In efs-utils, the "get_aws_security_credentials" method is only called if
//! use_iam is provided, a mount option that is only valid with TLS mounts to EFS. We want to get
//! creds for s3 client here for ReadBypass even if a non-tls mounts to EFS is used.
//!
//! 2. This credential chain now check environment variable credentials provider to support
//! AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN, and AWS_REGION only for lambda
//!

use aws_config::{
    environment::EnvironmentVariableCredentialsProvider,
    meta::credentials::CredentialsProviderChain, provider_config::ProviderConfig,
    web_identity_token::StaticConfiguration, BehaviorVersion, Region,
};
use aws_credential_types::{
    provider::{self, future, ProvideCredentials},
    Credentials,
};

use log::{debug, info, warn};

use crate::{config_parser::ProxyConfig, utils::is_running_on_lambda};

const AWS_CONTAINER_CREDENTIALS_RELATIVE_URI: &str = "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI";

#[derive(Debug)]
pub struct ProxyCredentialsChain {
    provider_chain: CredentialsProviderChain,
}

impl ProxyCredentialsChain {
    pub async fn new_from_config(proxy_config: &ProxyConfig) -> Self {
        if is_running_on_lambda() {
            info!("ProxyCredentialsChain: running on Lambda, using Environment provider only");
            let env_provider = EnvironmentVariableCredentialsProvider::new();
            return ProxyCredentialsChain {
                provider_chain: CredentialsProviderChain::first_try("Environment", env_provider),
            };
        }

        // Ensure HOME is set for AWS SDK profile credential resolution.
        // Mount helper / watchdog may launch proxy with a minimal environment (e.g., systemd)
        // where HOME is not set. The AWS SDK needs HOME to resolve ~/.aws/credentials.
        crate::utils::ensure_home_env_set();

        let region = resolve_region(proxy_config).await;

        let provider_config = ProviderConfig::default().with_region(region);

        let mut profile_provider_builder =
            aws_config::profile::credentials::Builder::default().configure(&provider_config);
        if let Some(profile) = &proxy_config.nested_config.read_bypass_config.profile {
            profile_provider_builder = profile_provider_builder.profile_name(profile);
        }
        let profile_provider = profile_provider_builder.build();

        // 2. ECS Credential Provider
        let ecs_provider = if let Some(relative_uri) =
            &proxy_config.nested_config.read_bypass_config.aws_creds_uri
        {
            // When aws_creds_uri is provided, set environment variable for ECS provider
            if let Ok(existing_uri) = std::env::var(AWS_CONTAINER_CREDENTIALS_RELATIVE_URI) {
                if existing_uri != *relative_uri {
                    warn!(
                        "Overriding {} from '{}' to '{}'",
                        AWS_CONTAINER_CREDENTIALS_RELATIVE_URI, existing_uri, relative_uri
                    );
                }
            }
            std::env::set_var(AWS_CONTAINER_CREDENTIALS_RELATIVE_URI, relative_uri);
            aws_config::ecs::EcsCredentialsProvider::builder()
                .configure(&provider_config)
                .build()
        } else {
            aws_config::ecs::EcsCredentialsProvider::builder()
                .configure(&provider_config)
                .build()
        };

        let web_identity_token_provider = if let (Some(jwt_path), Some(role_arn)) = (
            &proxy_config.nested_config.read_bypass_config.jwt_path,
            &proxy_config.nested_config.read_bypass_config.role_arn,
        ) {
            Some(
                aws_config::web_identity_token::Builder::default()
                    .configure(&provider_config)
                    .static_configuration(StaticConfiguration {
                        web_identity_token_file: jwt_path.into(),
                        role_arn: role_arn.clone(),
                        session_name: "efs-mount-helper".into(),
                    })
                    .build(),
            )
        } else {
            None
        };

        let web_identity_token_from_env_provider =
            aws_config::web_identity_token::Builder::default()
                .configure(&provider_config)
                .build();

        let imds_provider = aws_config::imds::credentials::Builder::default()
            .configure(&provider_config)
            .build();

        let mut chain = CredentialsProviderChain::first_try("Profile", profile_provider)
            .or_else("EcsContainer", ecs_provider);

        if let Some(web_identity_token_provider) = web_identity_token_provider {
            chain = chain.or_else("WebIdentityToken", web_identity_token_provider);
        }

        let provider_chain = chain
            .or_else(
                "WebIdentityTokenFromEnv",
                web_identity_token_from_env_provider,
            )
            .or_else("Ec2InstanceMetadata", imds_provider);

        ProxyCredentialsChain { provider_chain }
    }

    async fn credentials(&self) -> provider::Result {
        let result = self.provider_chain.provide_credentials().await;
        match &result {
            Ok(creds) => debug!("ProxyCredentialsChain: credentials resolved: {:?}", creds),
            Err(e) => warn!(
                "ProxyCredentialsChain: failed to resolve credentials: {}",
                e
            ),
        }
        result
    }
}

impl ProvideCredentials for ProxyCredentialsChain {
    fn provide_credentials<'a>(&'a self) -> provider::future::ProvideCredentials<'a>
    where
        Self: 'a,
    {
        future::ProvideCredentials::new(self.credentials())
    }

    fn fallback_on_interrupt(&self) -> Option<Credentials> {
        self.provider_chain.fallback_on_interrupt()
    }
}

/// Resolve region: read_bypass_config → AWS_REGION env (Lambda only) → default chain.
async fn resolve_region(proxy_config: &ProxyConfig) -> Option<Region> {
    if let Some(region) = &proxy_config.nested_config.read_bypass_config.region {
        return Some(Region::new(region.clone()));
    }
    if is_running_on_lambda() {
        if let Ok(region) = std::env::var("AWS_REGION") {
            return Some(Region::new(region));
        }
    }
    aws_config::default_provider::region::DefaultRegionChain::builder()
        .build()
        .region()
        .await
}

pub async fn get_aws_config_loader(proxy_config: &ProxyConfig) -> aws_config::ConfigLoader {
    let mut aws_config_loader = aws_config::defaults(BehaviorVersion::latest());

    if proxy_config.fips {
        aws_config_loader = aws_config_loader.use_fips(true);
    }

    if let Some(r) = resolve_region(proxy_config).await {
        aws_config_loader = aws_config_loader.region(r);
    }

    if let Some(p) = &proxy_config.nested_config.read_bypass_config.profile {
        aws_config_loader = aws_config_loader.profile_name(p.clone());
    }

    let credentials_chain = ProxyCredentialsChain::new_from_config(&proxy_config).await;
    aws_config_loader = aws_config_loader.credentials_provider(credentials_chain);

    return aws_config_loader;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_aws_creds_uri_override_existing() {
        std::env::set_var(
            AWS_CONTAINER_CREDENTIALS_RELATIVE_URI,
            "/v2/credentials/old",
        );

        let mut config = ProxyConfig::default();
        config.nested_config.read_bypass_config.aws_creds_uri =
            Some("/v2/credentials/new".to_string());

        let _chain = ProxyCredentialsChain::new_from_config(&config).await;

        assert_eq!(
            std::env::var(AWS_CONTAINER_CREDENTIALS_RELATIVE_URI).ok(),
            Some("/v2/credentials/new".to_string())
        );
    }
}
