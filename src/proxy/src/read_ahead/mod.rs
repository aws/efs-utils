//! ReadAhead module provides functionality for caching and prefetching data
//! to improve read performance by reducing latency and increasing throughput.

pub(crate) mod cached_data;
pub mod error;
pub(crate) mod file_readahead_state;
pub mod readahead_cache;
