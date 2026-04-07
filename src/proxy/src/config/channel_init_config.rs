use log::warn;

use crate::{
    awsfile_prot::{
        AwsFileChannelInitRes, AwsFileChannelInitResOK, AwsFileReadBypassConfigRes,
        ChannelConfigRes,
    },
    error::RpcError,
};

#[derive(Debug, Eq, PartialEq)]
pub struct ReadBypassConfig {
    pub enabled: bool,
    pub bucket_name: String,
    pub prefix: String,
}

impl Default for ReadBypassConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bucket_name: String::new(),
            prefix: String::new(),
        }
    }
}

impl TryFrom<AwsFileReadBypassConfigRes> for ReadBypassConfig {
    type Error = RpcError;

    fn try_from(value: AwsFileReadBypassConfigRes) -> Result<Self, Self::Error> {
        let bucket_name = String::from_utf8(value.bucket_name).map_err(|_| {
            RpcError::AwsFileChannelInitFailure(String::from("failed to parse bucket_name"))
        })?;
        let prefix = String::from_utf8(value.prefix).map_err(|_| {
            RpcError::AwsFileChannelInitFailure(String::from("failed to parse prefix"))
        })?;

        Ok(Self {
            enabled: value.enabled,
            bucket_name,
            prefix,
        })
    }
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct ChannelInitConfig {
    pub read_bypass_config: ReadBypassConfig,
}

impl TryFrom<AwsFileChannelInitRes> for ChannelInitConfig {
    type Error = RpcError;

    fn try_from(result: AwsFileChannelInitRes) -> Result<Self, Self::Error> {
        let configs = match result {
            AwsFileChannelInitRes::AWSFILE_OK(AwsFileChannelInitResOK { configs }) => configs,
            AwsFileChannelInitRes::default => {
                return Err(RpcError::AwsFileChannelInitFailure(String::from(
                    "response is AwsFileChannelInitRes::default",
                )));
            }
        };

        let mut read_bypass_config = ReadBypassConfig::default();

        for config in configs {
            match config {
                ChannelConfigRes::AWSFILE_READ_BYPASS(config) => match config.try_into() {
                    Ok(config) => read_bypass_config = config,
                    Err(e) => {
                        warn!(
                            "Failed to parse ChannelConfigRes::AWSFILE_READ_BYPASS \
                            configuration. S3 READ_BYPASS will not be enabled. Error:{:?}",
                            e
                        );
                    }
                },
            }
        }

        Ok(ChannelInitConfig { read_bypass_config })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::awsfile_prot::{
        AwsFileChannelInitRes, AwsFileChannelInitResOK, AwsFileReadBypassConfigRes,
        ChannelConfigRes,
    };

    const TEST_ENABLED: bool = true;
    const TEST_BUCKET_NAME: &str = "test-bucket";
    const TEST_PREFIX: &str = "test-prefix";

    fn get_test_read_bypass_config_res() -> AwsFileReadBypassConfigRes {
        AwsFileReadBypassConfigRes {
            enabled: TEST_ENABLED,
            bucket_name: TEST_BUCKET_NAME.as_bytes().to_vec(),
            prefix: TEST_PREFIX.as_bytes().to_vec(),
        }
    }

    #[test]
    fn test_empty_channel_init_res() {
        // Create an empty AwsFileChannelInitResOK with no configs
        let res = AwsFileChannelInitRes::AWSFILE_OK(AwsFileChannelInitResOK { configs: vec![] });

        // Convert to ChannelInitConfig
        let config = ChannelInitConfig::try_from(res).unwrap();

        // Verify default configs are used
        assert_eq!(ChannelInitConfig::default(), config);
    }

    #[test]
    fn test_read_bypass_config() -> Result<(), RpcError> {
        // Create a read bypass config
        let read_bypass_config = get_test_read_bypass_config_res();

        // Create AwsFileChannelInitResOK with read bypass config
        let res = AwsFileChannelInitRes::AWSFILE_OK(AwsFileChannelInitResOK {
            configs: vec![ChannelConfigRes::AWSFILE_READ_BYPASS(read_bypass_config)],
        });

        // Convert to ChannelInitConfig
        let config = ChannelInitConfig::try_from(res)?;

        // Verify read bypass config is correct
        assert_eq!(TEST_ENABLED, config.read_bypass_config.enabled);
        assert_eq!(TEST_BUCKET_NAME, config.read_bypass_config.bucket_name);
        assert_eq!(TEST_PREFIX, config.read_bypass_config.prefix);
        Ok(())
    }

    #[test]
    fn test_invalid_utf8() -> Result<(), RpcError> {
        // Create a read bypass config with invalid UTF-8
        let invalid_read_bypass_config = AwsFileReadBypassConfigRes {
            enabled: true,
            bucket_name: vec![0xFF, 0xFE, 0xFD], // Invalid UTF-8
            prefix: "test-prefix".as_bytes().to_vec(),
        };

        // Create AwsFileChannelInitResOK with invalid read bypass config
        let res = AwsFileChannelInitRes::AWSFILE_OK(AwsFileChannelInitResOK {
            configs: vec![ChannelConfigRes::AWSFILE_READ_BYPASS(
                invalid_read_bypass_config,
            )],
        });

        // Convert to ChannelInitConfig - should use default for read bypass
        let config = ChannelInitConfig::try_from(res)?;

        // Verify read bypass config is default due to parsing error
        assert_eq!(false, config.read_bypass_config.enabled);
        assert_eq!("", config.read_bypass_config.bucket_name);
        assert_eq!("", config.read_bypass_config.prefix);
        Ok(())
    }

    #[test]
    fn test_default_error() {
        // Test with default error response
        let res = AwsFileChannelInitRes::default;

        // Convert to ChannelInitConfig - should fail
        let result = ChannelInitConfig::try_from(res);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RpcError::AwsFileChannelInitFailure(_)
        ));
    }
}
