//! ReadAhead module provides functionality for caching and prefetching data
//! to improve read performance by reducing latency and increasing throughput.

pub(crate) mod cached_data;
pub mod error;
pub(crate) mod file_readahead_state;
pub mod readahead_cache;

use crate::utils::{is_running_on_ecs, is_running_on_lambda};

/// Minimum system memory in GiB required to enable readahead cache.
/// Targets modern 2xlarge instances (M*.2xlarge with 32 GiB) or larger.
pub const MIN_MEMORY_FOR_READAHEAD_GIB: u64 = 30;

/// Returns true if system has enough memory for readahead cache.
pub fn has_sufficient_memory_for_readahead_cache() -> bool {
    if platform_blocks_readahead_cache(is_running_on_lambda(), is_running_on_ecs()) {
        return false;
    }
    let total_memory = sysinfo::System::new_all().total_memory();
    if total_memory == 0 {
        log::warn!("Unable to determine system memory, disabling readahead cache");
    }
    total_memory >= MIN_MEMORY_FOR_READAHEAD_GIB * 1024 * 1024 * 1024
}

/// The readahead cache stays off on container platforms, where total-memory
/// detection sees the host rather than the container limit.
fn platform_blocks_readahead_cache(on_lambda: bool, on_ecs: bool) -> bool {
    on_ecs || on_lambda
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_readahead_cache_platform_gating() {
        assert!(platform_blocks_readahead_cache(false, true));
        assert!(platform_blocks_readahead_cache(true, false));
        assert!(platform_blocks_readahead_cache(true, true));

        // A plain host (EC2 etc.) is never blocked by platform.
        assert!(!platform_blocks_readahead_cache(false, false));
    }
}
