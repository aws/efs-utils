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

const LOG_FILE_MAX_BYTES: u64 = 1048576;
const LOG_FILE_COUNT: u32 = 10;

pub fn init(config: &ProxyConfig) {
    let log_file_path_string = config
        .output
        .clone()
        .expect("config value `output` is not set");
    let log_file_path = Path::new(&log_file_path_string);
    let level_filter =
        LevelFilter::from_str(&config.debug).expect("config value for `debug` is invalid");

    let stderr = ConsoleAppender::builder().target(Target::Stderr).build();

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

    let config = Config::builder()
        .appender(Appender::builder().build("logfile", Box::new(log_file)))
        .appender(
            Appender::builder()
                .filter(Box::new(ThresholdFilter::new(LevelFilter::Error)))
                .build("stderr", Box::new(stderr)),
        )
        .build(
            Root::builder()
                .appender("logfile")
                .appender("stderr")
                .build(level_filter),
        )
        .expect("Invalid logger config");

    let _ = log4rs::init_config(config).expect("Unable to initialize logger");
}
