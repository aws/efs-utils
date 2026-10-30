//! Testing utilities for the core crate's unit tests. The config helper lives
//! here and the read-bypass helpers used by the read_ahead tests are
//! re-exported from `util::test_utils`; the full proxy test_utils (TLS/RPC/NFS
//! helpers) stays in efs-proxy. The `test-util` feature additionally exposes
//! these helpers to the consuming binaries' test suites.
#![allow(dead_code)]

use crate::config_parser::ProxyConfig;
use std::path::Path;

pub static TEST_CONFIG_PATH: &str = "tests/certs/test_config.ini";

pub fn get_test_config() -> ProxyConfig {
    ProxyConfig::from_path(Path::new(TEST_CONFIG_PATH)).expect("Could not parse test config.")
}

#[cfg(feature = "read-bypass")]
pub use crate::util::test_utils::*;
