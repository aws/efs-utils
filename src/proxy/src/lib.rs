// EFS Proxy modules are made visible such that they can be reused in the Integration tests.
// EFS proxy Integration tests are implemented in a white box testing manner.
// We want to keep all the proxy internals visible and accessible.
//
#![warn(rust_2018_idioms)]

pub mod config_parser;
pub mod connection_task;
pub mod connections;
pub mod controller;
pub mod efs_rpc;
pub mod error;
pub mod log_encoder;
pub mod logger;
pub mod proxy;
pub mod proxy_identifier;
pub mod proxy_task;
pub mod rpc;
pub mod shutdown;
pub mod status_reporter;
pub mod test_utils;
pub mod tls;

#[allow(clippy::all)]
#[allow(deprecated)]
#[allow(invalid_value)]
#[allow(non_camel_case_types)]
#[allow(unused_assignments)]
pub mod efs_prot {
    include!(concat!(env!("OUT_DIR"), "/efs_prot_xdr.rs"));
}
