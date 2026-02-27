use log::LevelFilter;
use log4rs::{
    append::{
        console::{ConsoleAppender, Target},
        rolling_file::{
            policy::compound::{
                roll::fixed_window::FixedWindowRoller, trigger::size::SizeTrigger, CompoundPolicy,
            },
            RollingFileAppender,
        },
    },
    config::{Appender, Config, Root},
    encode::pattern::PatternEncoder,
    filter::threshold::ThresholdFilter,
};
use std::{path::Path, str::FromStr};

use crate::config_parser::ProxyConfig;
use crate::log_encoder::SingleLineEncoder;

const LOG_FILE_MAX_BYTES: u64 = 1048576;
const LOG_FILE_COUNT: u32 = 10;

pub fn create_config(config: &ProxyConfig) -> Config {
    let level_filter =
        LevelFilter::from_str(&config.debug).expect("config value for `debug` is invalid");

    let log_format = config.log_format.as_deref().unwrap_or("file");

    let mut config_builder = Config::builder();
    let mut root_builder = Root::builder();

    match log_format {
        "file" => {
            let log_file_path_string = config
                .output
                .clone()
                .expect("config value `output` is not set");

            let log_file_path = Path::new(&log_file_path_string);

            let stderr = ConsoleAppender::builder().target(Target::Stderr).build();

            config_builder = config_builder.appender(
                Appender::builder()
                    .filter(Box::new(ThresholdFilter::new(LevelFilter::Error)))
                    .build("stderr", Box::new(stderr)),
            );

            let trigger = SizeTrigger::new(LOG_FILE_MAX_BYTES);
            let mut pattern = log_file_path_string.clone();
            pattern.push_str(".{}");
            let roller = FixedWindowRoller::builder()
                .build(&pattern, LOG_FILE_COUNT)
                .expect("Unable to create roller");
            let policy = CompoundPolicy::new(Box::new(trigger), Box::new(roller));

            let log_file = RollingFileAppender::builder()
                .encoder(Box::new(PatternEncoder::new(
                    "{d(%Y-%m-%dT%H:%M:%S%.3fZ)(utc)} {P} {l} {M} {m}{n}",
                )))
                .build(log_file_path, Box::new(policy))
                .expect("Unable to create log file");

            config_builder =
                config_builder.appender(Appender::builder().build("logfile", Box::new(log_file)));

            root_builder = root_builder.appender("logfile").appender("stderr");
        }
        "stdout" => {
            let stderr = ConsoleAppender::builder()
                .target(Target::Stderr)
                .encoder(Box::new(SingleLineEncoder))
                .build();

            config_builder = config_builder.appender(
                Appender::builder()
                    .filter(Box::new(ThresholdFilter::new(LevelFilter::Error)))
                    .build("stderr", Box::new(stderr)),
            );

            let stdout = ConsoleAppender::builder()
                .target(Target::Stdout)
                .encoder(Box::new(SingleLineEncoder))
                .build();

            config_builder =
                config_builder.appender(Appender::builder().build("stdout", Box::new(stdout)));

            root_builder = root_builder.appender("stderr").appender("stdout");
        }
        _ => panic!("Invalid `log_format` value. Must be either 'file' or 'stdout'"),
    }

    config_builder
        .build(root_builder.build(level_filter))
        .expect("Invalid logger config")
}

pub fn init(config: &ProxyConfig) {
    let log_format = config.log_format.as_deref().unwrap_or("file");
    if log_format == "file" && config.output.is_none() {
        return;
    }

    let log_config = create_config(config);
    let _ = log4rs::init_config(log_config).expect("Unable to initialize logger");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config_parser::ProxyConfig;
    use std::panic;
    use tempfile::tempdir;

    #[test]
    fn test_logger_init_with_file() {
        let temp_dir = tempdir().expect("Failed to create temporary directory");
        let log_path = temp_dir.path().join("test.log");
        let log_path_str = log_path.to_str().expect("Failed to convert path to string");

        let config = ProxyConfig {
            fips: false,
            debug: "info".to_string(),
            output: Some(log_path_str.to_string()),
            log_format: Some("file".to_string()),
            pid_file_path: "".to_string(),
            nested_config: Default::default(),
        };

        let result = panic::catch_unwind(|| {
            init(&config);
        });

        let _ = temp_dir.close();

        assert!(
            result.is_ok(),
            "Logger initialization panicked with valid config"
        );
    }

    #[test]
    fn test_create_config_with_file() {
        let temp_dir = tempdir().expect("Failed to create temporary directory");
        let log_path = temp_dir.path().join("test.log");
        let log_path_str = log_path.to_str().expect("Failed to convert path to string");

        let config = ProxyConfig {
            fips: false,
            debug: "info".to_string(),
            output: Some(log_path_str.to_string()),
            log_format: Some("file".to_string()),
            pid_file_path: "".to_string(),
            nested_config: Default::default(),
        };

        let log_config = create_config(&config);

        assert_eq!(log_config.root().level(), LevelFilter::Info);

        let _ = temp_dir.close();
    }

    #[test]
    fn test_create_config_with_stdout() {
        let config = ProxyConfig {
            fips: false,
            debug: "debug".to_string(),
            output: None,
            log_format: Some("stdout".to_string()),
            pid_file_path: "".to_string(),
            nested_config: Default::default(),
        };

        let log_config = create_config(&config);

        assert_eq!(log_config.root().level(), LevelFilter::Debug);
    }

    #[test]
    fn test_init_skips_when_output_none() {
        let config = ProxyConfig {
            fips: false,
            debug: "info".to_string(),
            output: None,
            log_format: Some("file".to_string()),
            pid_file_path: "".to_string(),
            nested_config: Default::default(),
        };

        let result = panic::catch_unwind(|| {
            init(&config);
        });

        assert!(
            result.is_ok(),
            "Logger initialization should not panic when output is None"
        );
    }
}
