use log::warn;

use crate::{
    awsfile_prot::{
        AwsFileChannelInitRes, AwsFileChannelInitResOK, AwsFileReadBypassConfigResV2,
        ChannelConfigRes,
    },
    error::RpcError,
};

#[derive(Debug, Eq, PartialEq)]
pub struct ReadBypassConfig {
    pub enabled: bool,
    pub bucket_name: String,
    pub prefix: String,
    pub readahead_cache_enabled: bool,
}

impl Default for ReadBypassConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bucket_name: String::new(),
            prefix: String::new(),
            readahead_cache_enabled: false,
        }
    }
}

impl TryFrom<AwsFileReadBypassConfigResV2> for ReadBypassConfig {
    type Error = RpcError;

    fn try_from(value: AwsFileReadBypassConfigResV2) -> Result<Self, Self::Error> {
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
            readahead_cache_enabled: value.readahead_cache_enabled,
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
                ChannelConfigRes::AWSFILE_READ_BYPASS_V2(config) => match config.try_into() {
                    Ok(config) => read_bypass_config = config,
                    Err(e) => {
                        warn!(
                            "Failed to parse ChannelConfigRes::AWSFILE_READ_BYPASS_V2 \
                            configuration. S3 READ_BYPASS will not be enabled. Error:{:?}",
                            e
                        );
                    }
                },
                _ => {
                    warn!("Received unexpected channel config type, ignoring");
                }
            }
        }

        Ok(ChannelInitConfig { read_bypass_config })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::awsfile_prot::{
        AwsFileChannelInitRes, AwsFileChannelInitResOK, AwsFileReadBypassConfigResV2,
        ChannelConfigRes,
    };

    const TEST_ENABLED: bool = true;
    const TEST_BUCKET_NAME: &str = "test-bucket";
    const TEST_PREFIX: &str = "test-prefix";

    fn get_test_read_bypass_config_res_v2(readahead_enabled: bool) -> AwsFileReadBypassConfigResV2 {
        AwsFileReadBypassConfigResV2 {
            enabled: TEST_ENABLED,
            bucket_name: TEST_BUCKET_NAME.as_bytes().to_vec(),
            prefix: TEST_PREFIX.as_bytes().to_vec(),
            readahead_cache_enabled: readahead_enabled,
        }
    }

    #[test]
    fn test_empty_channel_init_res() {
        // Create an empty AwsFileChannelInitResOK with no configs
        let res = AwsFileChannelInitRes::AWSFILE_OK(AwsFileChannelInitResOK { configs: vec![] });

        // Convert to ChannelInitConfig and verify default configs are used
        let config = ChannelInitConfig::try_from(res).unwrap();
        assert_eq!(ChannelInitConfig::default(), config);
    }

    #[test]
    fn test_read_bypass_config_v2_with_readahead_enabled() -> Result<(), RpcError> {
        // Create a V2 read bypass config with readahead enabled
        let read_bypass_config = get_test_read_bypass_config_res_v2(true);

        // Create AwsFileChannelInitResOK with V2 read bypass config
        let res = AwsFileChannelInitRes::AWSFILE_OK(AwsFileChannelInitResOK {
            configs: vec![ChannelConfigRes::AWSFILE_READ_BYPASS_V2(read_bypass_config)],
        });

        // Convert to ChannelInitConfig and verify read bypass config is correct
        let config = ChannelInitConfig::try_from(res)?;

        assert_eq!(TEST_ENABLED, config.read_bypass_config.enabled);
        assert_eq!(TEST_BUCKET_NAME, config.read_bypass_config.bucket_name);
        assert_eq!(TEST_PREFIX, config.read_bypass_config.prefix);
        assert_eq!(true, config.read_bypass_config.readahead_cache_enabled);
        Ok(())
    }

    #[test]
    fn test_read_bypass_config_v2_with_readahead_disabled() -> Result<(), RpcError> {
        // Create a V2 read bypass config with readahead disabled
        let read_bypass_config = get_test_read_bypass_config_res_v2(false);

        // Create AwsFileChannelInitResOK with V2 read bypass config
        let res = AwsFileChannelInitRes::AWSFILE_OK(AwsFileChannelInitResOK {
            configs: vec![ChannelConfigRes::AWSFILE_READ_BYPASS_V2(read_bypass_config)],
        });

        // Convert to ChannelInitConfig and verify readahead is disabled
        let config = ChannelInitConfig::try_from(res)?;

        assert_eq!(TEST_ENABLED, config.read_bypass_config.enabled);
        assert_eq!(false, config.read_bypass_config.readahead_cache_enabled);
        Ok(())
    }

    #[test]
    fn test_invalid_utf8() -> Result<(), RpcError> {
        // Create a read bypass config with invalid UTF-8
        let invalid_read_bypass_config = AwsFileReadBypassConfigResV2 {
            enabled: true,
            bucket_name: vec![0xFF, 0xFE, 0xFD], // Invalid UTF-8
            prefix: "test-prefix".as_bytes().to_vec(),
            readahead_cache_enabled: false,
        };

        // Create AwsFileChannelInitResOK with invalid read bypass config
        let res = AwsFileChannelInitRes::AWSFILE_OK(AwsFileChannelInitResOK {
            configs: vec![ChannelConfigRes::AWSFILE_READ_BYPASS_V2(
                invalid_read_bypass_config,
            )],
        });

        // Convert to ChannelInitConfig - should use default for read bypass due to parsing error
        let config = ChannelInitConfig::try_from(res)?;

        assert_eq!(false, config.read_bypass_config.enabled);
        assert_eq!("", config.read_bypass_config.bucket_name);
        assert_eq!("", config.read_bypass_config.prefix);
        Ok(())
    }

    #[test]
    fn test_default_error() {
        // Test with default error response - should fail
        let res = AwsFileChannelInitRes::default;
        let result = ChannelInitConfig::try_from(res);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RpcError::AwsFileChannelInitFailure(_)
        ));
    }
}
