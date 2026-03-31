//! FileHandle Denylist is a data structure for tracking file handles for which S3 access has failed.
//! Based on that information we:
//! - skip READBYPASS for specific filehandles for configured duration
//!

#![allow(unused)]

use crate::nfs::nfs4_1_xdr::nfs_fh4;
use log::debug;
use moka::policy::EvictionPolicy;
use moka::sync::Cache;
use std::time::Duration;

pub type FileHandle = nfs_fh4;

use crate::config_parser::{
    DEFAULT_READ_BYPASS_DENYLIST_SIZE, DEFAULT_READ_BYPASS_DENYLIST_TTL_SECONDS,
};

/// FileHandle Denylist tracks file handles for which S3 access has failed.
///
/// Uses moka::sync::Cache for thread-safe access with automatic TTL expiration and size-based eviction.
/// When the cache reaches max_capacity, the cache will evict LRU entries
pub struct FileHandleDenyList {
    cache: Cache<FileHandle, ()>,
}

impl FileHandleDenyList {
    pub fn new(max_size: u64, ttl: Duration) -> Self {
        let cache = Cache::builder()
            .max_capacity(max_size)
            .time_to_live(ttl)
            .eviction_policy(EvictionPolicy::lru())
            .build();
        Self { cache }
    }

    pub fn contains(&self, fh: &FileHandle) -> bool {
        // Note: moka cache automatically handles TTL expiration during lookups.
        // Expired entries are treated as non-existent, and cleanup happens automatically.
        //
        // Unlike get(), contains_key() does NOT update the historic popularity estimator
        // or reset idle timers, so repeatedly checking denylisted files does not
        // reduce eviction chances during size or time based eviction
        self.cache.contains_key(fh)
    }

    pub fn add(&self, fh: FileHandle) {
        debug!(
            "Adding filehandle to denylist: {}",
            fh.0.iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        );
        self.cache.insert(fh, ());
    }

    pub fn clear(&self) {
        self.cache.invalidate_all();
    }

    pub fn size(&self) -> u64 {
        self.cache.entry_count()
    }

    /// Runs any pending maintenance operations such as removing expired entries,
    /// processing size-based evictions, and updating entry count.
    /// These tasks are typically triggered by cache operations and executed
    /// async in the background, but this method forces them to run immediately.
    /// Primarily useful for testing to ensure cache state is fully updated.
    #[cfg(test)]
    fn run_pending_tasks(&self) {
        self.cache.run_pending_tasks();
    }
}

impl Default for FileHandleDenyList {
    fn default() -> Self {
        Self::new(
            DEFAULT_READ_BYPASS_DENYLIST_SIZE(),
            Duration::from_secs(DEFAULT_READ_BYPASS_DENYLIST_TTL_SECONDS()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_denylist_operations() {
        let denylist = FileHandleDenyList::new(10, Duration::from_secs(300));
        assert_eq!(denylist.size(), 0);

        let fh: FileHandle = nfs_fh4(vec![1, 2, 3, 4]);
        assert!(!denylist.contains(&fh));

        denylist.add(fh.clone());
        assert!(denylist.contains(&fh));
        denylist.run_pending_tasks();
        assert_eq!(denylist.size(), 1);

        let fh2 = nfs_fh4(vec![5, 6, 7, 8]);
        denylist.add(fh2.clone());
        assert!(denylist.contains(&fh2));
        denylist.run_pending_tasks();
        assert_eq!(denylist.size(), 2);

        denylist.clear();
        denylist.run_pending_tasks();
        assert!(!denylist.contains(&fh));
        assert!(!denylist.contains(&fh2));
        assert_eq!(denylist.size(), 0);
    }

    #[test]
    fn test_denylist_duplicate_entries() {
        let denylist = FileHandleDenyList::new(10, Duration::from_secs(300));
        let fh = nfs_fh4(vec![1, 2, 3, 4]);

        denylist.add(fh.clone());
        denylist.run_pending_tasks();
        assert_eq!(denylist.size(), 1);

        denylist.add(fh.clone());
        denylist.run_pending_tasks();
        assert_eq!(denylist.size(), 1);
    }

    #[tokio::test]
    async fn test_denylist_size_based_eviction() {
        let max_size = 2;
        let denylist = FileHandleDenyList::new(max_size, Duration::from_secs(300));

        let fh1 = nfs_fh4(vec![1]);
        let fh2 = nfs_fh4(vec![2]);
        let fh3 = nfs_fh4(vec![3]);

        denylist.add(fh1.clone());
        denylist.add(fh2.clone());
        assert!(denylist.contains(&fh1));
        assert!(denylist.contains(&fh2));

        denylist.cache.run_pending_tasks();
        assert_eq!(denylist.size(), 2);

        // Add a third entry,  should trigger eviction
        denylist.add(fh3.clone());
        denylist.cache.run_pending_tasks();

        // Verify size = max_size entries and fh1 evicted
        assert_eq!(denylist.size(), max_size);
        assert!(!denylist.contains(&fh1));
        assert!(denylist.contains(&fh2));
        assert!(denylist.contains(&fh3));
    }

    #[tokio::test]
    async fn test_denylist_ttl_expiration() {
        let short_ttl = Duration::from_millis(100);
        let denylist = FileHandleDenyList::new(10, short_ttl);

        let fh = nfs_fh4(vec![1, 2, 3, 4]);
        denylist.add(fh.clone());
        assert!(denylist.contains(&fh));

        // Wait for 75 ms to verify timer not reset on contains()
        tokio::time::sleep(Duration::from_millis(75)).await;
        assert!(denylist.contains(&fh));

        // Wait 50 additional ms for TTL to expire
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Entry should be treated as expired
        assert!(!denylist.contains(&fh));

        // Force cleanup and verify size is updated
        denylist.cache.run_pending_tasks();
        assert_eq!(denylist.size(), 0);
    }
}
