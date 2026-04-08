//! ReadAheadCache is utilized to determine if a read should be handled via the cache
//! to allow for higher throughput of reads. The readahead cache should provide up to 10gib/s of read throughput.
//!
//! The ReadAheadCache is structured such that we have a map of "filehandle + s3_etag" to file read ahead state.
//! FileReadAheadCache
//!    Map<(FileHandle,S3 Etag), FileReadAheadState> file_states
//!
//! This file contains the top-level FileReadAheadCache which manages the collection of file states
//! and provides the main interface for the readahead system.

use bytes::Bytes;
use dashmap::DashMap;
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use tokio::sync::RwLock;

use crate::config_parser::ReadBypassConfig;
use crate::ctx_debug;
use crate::memory::memory_pool::{MemoryPool, MemoryPoolConfig};
use crate::nfs::nfs4_1_xdr::{awsfile_bypass_data_locator, nfs_fh4};
use crate::read_ahead::cached_data::get_current_time_ms;
use crate::read_ahead::error::ReadAheadCacheError;
use crate::read_ahead::file_readahead_state::{FileReadAheadState, LruKey, LruValue};
use crate::util::read_bypass_request_context::ReadBypassRequestContext;
use crate::util::s3_data_reader::S3DataReader;
use log::{debug, info};

/// How long to suppress readahead after hitting memory pressure (ms)
/// Longer than eviction interval (default 500ms) so memory may be freed before resuming
const READAHEAD_BACKOFF_MS: u64 = 3_000;

pub struct FileReadAheadCache {
    file_states: Arc<DashMap<(Vec<u8>, Vec<u8>), Arc<FileReadAheadState>>>, // (filehandle, etag)
    pub(crate) memory_pool: Arc<MemoryPool>,
    max_window_size: u64,
    s3_data_reader: Arc<dyn S3DataReader>,
    initial_window_size: u64,
    /// Timestamp (ms) until which readahead is suppressed due to memory pressure
    readahead_suppressed_until: AtomicU64,
    global_lru: Arc<Mutex<LruCache<LruKey, LruValue>>>,
    next_file_lru_id: AtomicU64,
    // Weak self-reference passed to FileReadAheadState so it can call back to cache
    // methods like evict_until_available when loading new data requires freeing memory.
    self_weak: RwLock<Weak<Self>>,
    /// Target utilization percentage for proactive LRU eviction
    target_utilization_percent: usize,
    /// Files at or below this size bypass the cache and are read directly from S3
    small_file_caching_threshold: u64,
}

impl FileReadAheadCache {
    // Based on a 1gib cache size with 1mib entries, but this just functions to allow for eviction in memory
    // constrained periods, so having 10000 elements to evict from should be sufficient with small IO.
    const DEFAULT_LRU_CAPACITY: usize = 10_000;

    pub fn new(
        max_window_size: u64,
        initial_window_size: u64,
        s3_data_reader: Arc<dyn S3DataReader>,
        read_bypass_config: &ReadBypassConfig,
    ) -> Self {
        Self {
            file_states: Arc::new(DashMap::new()),
            memory_pool: MemoryPool::new(MemoryPoolConfig {
                initial_capacity: read_bypass_config.readahead_cache_init_memory_size_mb,
                min_capacity: read_bypass_config.readahead_cache_init_memory_size_mb,
                resize_batch_size: read_bypass_config.readahead_cache_max_memory_size_mb / 10,
                max_capacity: read_bypass_config.readahead_cache_max_memory_size_mb,
                ..Default::default()
            }),
            s3_data_reader,
            max_window_size,
            initial_window_size,
            readahead_suppressed_until: AtomicU64::new(0),
            global_lru: Arc::new(Mutex::new(LruCache::new(
                NonZeroUsize::new(Self::DEFAULT_LRU_CAPACITY).unwrap(),
            ))),
            next_file_lru_id: AtomicU64::new(0),
            self_weak: RwLock::new(Weak::new()),
            target_utilization_percent: read_bypass_config
                .readahead_cache_target_utilization_percent,
            small_file_caching_threshold: read_bypass_config.small_file_caching_threshold,
        }
    }

    /// Must be called after wrapping in Arc to enable state creation with back-reference
    pub fn set_self_weak(&self, weak: Weak<Self>) {
        if let Ok(mut guard) = self.self_weak.try_write() {
            *guard = weak;
        }
    }

    // Main entry point for usage by the read bypass agent. Readahead cache either finds an existing file read ahead state or
    // creates a new one and then sends the work along down to the file.
    pub async fn process_read_request(
        &self,
        read_bypass_request_context: Arc<ReadBypassRequestContext>,
        filehandle: nfs_fh4,
        file_size: u64,
        s3_data_locator: awsfile_bypass_data_locator,
    ) -> Result<Option<Bytes>, ReadAheadCacheError> {
        // Skip cache for small files that fit within a single S3 chunk read
        if file_size <= self.small_file_caching_threshold
            && s3_data_locator.count as u64 == file_size
        {
            ctx_debug!(
                read_bypass_request_context,
                "Skipping readahead cache for small file (file_size={} <= threshold={})",
                file_size,
                self.small_file_caching_threshold
            );
            return self
                .read_directly_from_s3(read_bypass_request_context, s3_data_locator)
                .await;
        }

        let readahead_state =
            match self.get_file_read_ahead_state(&filehandle.0, &s3_data_locator.etag) {
                Some(state) => state,
                None => self.create_file_read_ahead_state(
                    filehandle.0,
                    s3_data_locator.s3_key.clone(),
                    s3_data_locator.etag.clone(),
                    s3_data_locator.version_id.clone(),
                    file_size,
                ),
            };

        let suppress_readahead = self.is_readahead_suppressed();
        let (result, hit_memory_pressure) = readahead_state
            .get_data(
                read_bypass_request_context.clone(),
                &s3_data_locator,
                file_size,
                self.s3_data_reader.clone(),
                suppress_readahead,
            )
            .await?;

        if hit_memory_pressure {
            ctx_debug!(
                read_bypass_request_context,
                "Suppressing readahead due to memory pressure for s3_key={:?} with backoff {}ms",
                String::from_utf8_lossy(&s3_data_locator.s3_key),
                READAHEAD_BACKOFF_MS
            );
            self.suppress_readahead();
        }

        Ok(result)
    }

    /// Read directly from S3, bypassing the readahead cache.
    async fn read_directly_from_s3(
        &self,
        read_bypass_request_context: Arc<ReadBypassRequestContext>,
        s3_data_locator: awsfile_bypass_data_locator,
    ) -> Result<Option<Bytes>, ReadAheadCacheError> {
        let read_task = self
            .s3_data_reader
            .spawn_read_task(
                s3_data_locator,
                read_bypass_request_context.read_bypass_context.clone(),
            )
            .await;
        let data = read_task
            .await
            .map_err(|e| ReadAheadCacheError {
                message: format!("Direct S3 read join error: {}", e),
            })?
            .map_err(|e| ReadAheadCacheError {
                message: format!("Direct S3 read error: {:?}", e),
            })?;
        Ok(Some(data))
    }

    fn get_file_read_ahead_state(
        &self,
        filehandle: &[u8],
        s3_etag: &[u8],
    ) -> Option<Arc<FileReadAheadState>> {
        self.file_states
            .get(&(filehandle.to_vec(), s3_etag.to_vec()))
            .map(|entry| entry.clone())
    }

    fn create_file_read_ahead_state(
        &self,
        filehandle: Vec<u8>,
        s3_key: Vec<u8>,
        s3_etag: Vec<u8>,
        s3_version_id: Vec<u8>,
        obj_size: u64,
    ) -> Arc<FileReadAheadState> {
        let cache_key = (filehandle, s3_etag.clone());
        let file_lru_id = self.next_file_lru_id.fetch_add(1, Ordering::Relaxed);

        let cache_weak = self
            .self_weak
            .try_read()
            .map(|g| g.clone())
            .unwrap_or_default();
        let new_state = Arc::new(FileReadAheadState::new(
            file_lru_id,
            Bytes::from(s3_key),
            Bytes::from(s3_etag),
            Bytes::from(s3_version_id),
            obj_size,
            self.initial_window_size,
            self.initial_window_size,
            self.max_window_size,
            Arc::clone(&self.memory_pool),
            Arc::clone(&self.global_lru),
            cache_weak,
        ));
        new_state.set_self_weak(Arc::downgrade(&new_state));

        // Handle race conditions by returning existing state if present
        match self.file_states.entry(cache_key) {
            dashmap::mapref::entry::Entry::Occupied(entry) => entry.get().clone(),
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                entry.insert(new_state.clone());
                new_state
            }
        }
    }

    pub fn get_num_files(&self) -> usize {
        self.file_states.len()
    }

    /// Called when caching fails due to memory pressure - suppresses readahead temporarily
    pub fn suppress_readahead(&self) {
        let until = get_current_time_ms() + READAHEAD_BACKOFF_MS;
        self.readahead_suppressed_until
            .store(until, Ordering::Relaxed);
    }

    /// Returns true if readahead is currently suppressed due to memory pressure
    pub fn is_readahead_suppressed(&self) -> bool {
        get_current_time_ms() < self.readahead_suppressed_until.load(Ordering::Relaxed)
    }

    /// Evict the least recently used entry from the global LRU.
    pub async fn evict_lru_entry(&self) -> bool {
        let max_attempts = self.global_lru.lock().map(|l| l.len()).unwrap_or(0);
        let mut attempts = 0;

        loop {
            let result = {
                let mut lru = match self.global_lru.lock() {
                    Ok(lru) => lru,
                    Err(_) => return false,
                };
                let Some(((_file_lru_id, offset), weak)) = lru.pop_lru() else {
                    return false;
                };
                match weak.upgrade() {
                    Some(state) => Some((offset, state)),
                    None => None, // Stale entry, retry
                }
            };

            match result {
                Some((offset, state)) => {
                    if state.evict_entry(offset).await {
                        debug!(
                            "Evicted LRU entry at offset {} for file {:?}",
                            offset, state.s3_key
                        );
                        return true;
                    }
                    // Couldn't evict (still loading). Re-insert at MRU position.
                    state.lru_insert(offset);
                    attempts += 1;
                    if attempts >= max_attempts {
                        return false; // Tried all entries, none evictable
                    }
                    continue;
                }
                None => continue, // Stale entry, retry
            }
        }
    }

    /// Evict LRU entries until we have room for `num_chunks`.
    /// Returns false if nothing left to evict.
    pub async fn evict_until_available(&self, num_chunks: usize) -> bool {
        loop {
            if !self.memory_pool.would_exceed_capacity(num_chunks) {
                return true;
            }
            if !self.evict_lru_entry().await {
                return false; // Nothing left to evict
            }
        }
    }

    /// Proactively evict via LRU to maintain target utilization.
    /// Returns the number of entries evicted.
    async fn evict_to_target_utilization(&self) -> usize {
        let capacity = self.memory_pool.capacity();
        let available = self.memory_pool.available_chunks();
        let in_use = capacity.saturating_sub(available);
        let target = (capacity * self.target_utilization_percent) / 100;

        if in_use <= target {
            return 0;
        }

        let chunks_to_free = in_use - target;
        let mut evicted = 0;

        // Each cache entry is at least 1 chunk, so evict up to chunks_to_free entries
        for _ in 0..chunks_to_free {
            if !self.evict_lru_entry().await {
                break;
            }
            evicted += 1;
        }

        evicted
    }

    /// Clean up stale entries (older than TTL) and remove empty file states.
    /// Returns (stale_removed, empty_removed).
    async fn cleanup_stale_and_empty(&self) -> (usize, usize) {
        const IDLE_TTL_MS: u64 = 60_000; // 1 minute

        let mut stale_removed = 0;
        let mut empty_files = Vec::new();

        // First pass: cleanup stale entries and identify empty files
        for entry in self.file_states.iter() {
            stale_removed += entry.value().cleanup_stale_entries(IDLE_TTL_MS).await;
            if entry.value().is_empty() {
                empty_files.push(entry.key().clone());
            }
        }

        // Remove empty file states
        let empty_removed = empty_files.len();
        for key in empty_files {
            self.file_states.remove(&key);
        }

        (stale_removed, empty_removed)
    }

    /// Run a single eviction cycle: proactive LRU eviction + stale entry cleanup.
    pub async fn run_eviction_cycle(&self) -> (usize, usize, usize) {
        let (stale_removed, empty_removed) = self.cleanup_stale_and_empty().await;
        let lru_evicted = self.evict_to_target_utilization().await;
        // Try to shrink the pool if idle
        self.memory_pool.try_shrink();
        (lru_evicted, stale_removed, empty_removed)
    }

    /// Start a background task that periodically runs eviction cycles.
    /// The task will stop when the cancellation token is triggered.
    pub fn start_eviction_task(
        self: Arc<Self>,
        interval_ms: u64,
        cancellation_token: tokio_util::sync::CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        let interval = tokio::time::Duration::from_millis(interval_ms);
        let target_utilization = self.target_utilization_percent;

        info!(
            "Starting eviction task with interval_ms={}, target_utilization={}%",
            interval_ms, target_utilization
        );

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(interval) => {
                        let (lru_evicted, stuck_removed, empty_removed) = self.run_eviction_cycle().await;
                        if lru_evicted > 0 || stuck_removed > 0 || empty_removed > 0 {
                            debug!(
                                "Eviction cycle: lru_evicted={}, stuck_removed={}, empty_files_removed={}",
                                lru_evicted, stuck_removed, empty_removed
                            );
                        }

                        debug!("total_number_of_memory_chunk_allocated={}, max_number_of_memory_chunk_can_be_allocated={}",
                            self.memory_pool.capacity(),
                            self.memory_pool.max_capacity()
                        );
                    }
                    _ = cancellation_token.cancelled() => {
                        info!("Eviction task stopped by cancellation token");
                        break;
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nfs::nfs4_1_xdr::nfs_fh4;
    use crate::test_utils::{
        create_test_read_bypass_context, create_test_s3_data_locator, CountingS3DataReader,
    };
    use crate::util::read_bypass_request_context::ReadBypassRequestContext;
    use crate::util::s3_data_reader::S3ReadBypassReader;
    use std::sync::atomic::Ordering;
    use test_case::test_case;

    #[tokio::test]
    async fn test_new_file_readahead_cache() {
        let cache = FileReadAheadCache::new(
            100,
            50,
            Arc::new(S3ReadBypassReader::new(128)),
            &ReadBypassConfig::default(),
        );
        assert_eq!(cache.max_window_size, 100);
        assert_eq!(cache.initial_window_size, 50);
        assert_eq!(cache.get_num_files(), 0);
    }

    #[tokio::test]
    async fn test_get_file_read_ahead_state() {
        let cache = FileReadAheadCache::new(
            100,
            50,
            Arc::new(S3ReadBypassReader::new(128)),
            &ReadBypassConfig::default(),
        );

        // Should return None when state doesn't exist
        assert!(cache
            .get_file_read_ahead_state(b"filehandle1", b"etag1")
            .is_none());

        // Create a state first
        let created_state = cache.create_file_read_ahead_state(
            b"filehandle1".to_vec(),
            b"key1".to_vec(),
            b"etag1".to_vec(),
            b"".to_vec(),
            1024,
        );

        // Now get should return the existing state
        let retrieved_state = cache
            .get_file_read_ahead_state(b"filehandle1", b"etag1")
            .unwrap();
        assert!(Arc::ptr_eq(&created_state, &retrieved_state));
    }

    #[tokio::test]
    async fn test_create_file_read_ahead_state() {
        let cache = FileReadAheadCache::new(
            100,
            50,
            Arc::new(S3ReadBypassReader::new(128)),
            &ReadBypassConfig::default(),
        );
        assert_eq!(cache.get_num_files(), 0);

        // Create a new state
        let state1 = cache.create_file_read_ahead_state(
            b"filehandle1".to_vec(),
            b"key1".to_vec(),
            b"etag1".to_vec(),
            b"".to_vec(),
            1024,
        );

        assert_eq!(cache.get_num_files(), 1);
        assert_eq!(state1.s3_key, b"key1".to_vec());
        assert_eq!(state1.s3_etag, b"etag1".to_vec());
        assert_eq!(state1.file_size, 1024);
        assert_eq!(state1.window_size.load(Ordering::SeqCst), 50);
        assert_eq!(state1.max_window_size, 100);

        // Try to create the same state again (should return existing state)
        let duplicate_result = cache.create_file_read_ahead_state(
            b"filehandle1".to_vec(),
            b"different_key".to_vec(),
            b"etag1".to_vec(),
            b"".to_vec(),
            2048,
        );
        // Should return the existing state, not create a new one
        assert!(Arc::ptr_eq(&state1, &duplicate_result));
        assert_eq!(cache.get_num_files(), 1); // Should still be 1

        // Create a different state
        let state2 = cache.create_file_read_ahead_state(
            b"filehandle2".to_vec(),
            b"key2".to_vec(),
            b"etag2".to_vec(),
            b"".to_vec(),
            2048,
        );

        assert_eq!(cache.get_num_files(), 2);
        assert!(!Arc::ptr_eq(&state1, &state2));
        assert_eq!(state2.s3_key, b"key2".to_vec());
        assert_eq!(state2.s3_etag, b"etag2".to_vec());
        assert_eq!(state2.file_size, 2048);
    }

    #[tokio::test]
    async fn test_evict_to_target_utilization() {
        let mut config = ReadBypassConfig::default();
        config.readahead_cache_target_utilization_percent = 50; // 50% target
        config.readahead_cache_init_memory_size_mb = 10;
        config.readahead_cache_max_memory_size_mb = 10;

        let cache = Arc::new(FileReadAheadCache::new(
            1024 * 1024,
            1024 * 1024,
            Arc::new(S3ReadBypassReader::new(128)),
            &config,
        ));
        cache.set_self_weak(Arc::downgrade(&cache));

        let state = cache.create_file_read_ahead_state(
            b"fh1".to_vec(),
            b"key1".to_vec(),
            b"etag1".to_vec(),
            b"".to_vec(),
            10 * 1024 * 1024,
        );
        state.set_self_weak(Arc::downgrade(&state));

        // Load 8 chunks (8MB) into a 10MB pool = 80% utilization
        for i in 0..8 {
            let start = i * 1024 * 1024;
            let end = start + 1024 * 1024;
            state.insert_range(start..end).await.unwrap();
            state
                .load_range(
                    start..end,
                    &state.memory_pool,
                    Bytes::from(vec![0u8; 1024 * 1024]),
                )
                .await
                .unwrap();
        }

        let capacity = cache.memory_pool.capacity();
        let target = (capacity * 50) / 100; // 5 chunks

        // With 8 chunks in use and target of 5, should evict exactly 3
        let evicted = cache.evict_to_target_utilization().await;
        assert_eq!(
            evicted, 3,
            "Should evict exactly 3 entries to reach 50% target"
        );

        let available_after = cache.memory_pool.available_chunks();
        let in_use_after = capacity - available_after;
        assert_eq!(in_use_after, target, "Should be at exactly 50% utilization");

        // Second call should be a no-op since we're already at target
        let evicted_again = cache.evict_to_target_utilization().await;
        assert_eq!(evicted_again, 0, "Should not evict when already at target");
    }

    #[tokio::test]
    async fn test_evict_lru_order_across_files() {
        let mut config = ReadBypassConfig::default();
        config.readahead_cache_target_utilization_percent = 50;
        config.readahead_cache_init_memory_size_mb = 10;
        config.readahead_cache_max_memory_size_mb = 10;

        let cache = Arc::new(FileReadAheadCache::new(
            1024 * 1024,
            1024 * 1024,
            Arc::new(S3ReadBypassReader::new(128)),
            &config,
        ));
        cache.set_self_weak(Arc::downgrade(&cache));

        // Create 3 file handles
        let state1 = cache.create_file_read_ahead_state(
            b"fh1".to_vec(),
            b"key1".to_vec(),
            b"etag1".to_vec(),
            b"".to_vec(),
            10 * 1024 * 1024,
        );
        state1.set_self_weak(Arc::downgrade(&state1));

        let state2 = cache.create_file_read_ahead_state(
            b"fh2".to_vec(),
            b"key2".to_vec(),
            b"etag2".to_vec(),
            b"".to_vec(),
            10 * 1024 * 1024,
        );
        state2.set_self_weak(Arc::downgrade(&state2));

        let state3 = cache.create_file_read_ahead_state(
            b"fh3".to_vec(),
            b"key3".to_vec(),
            b"etag3".to_vec(),
            b"".to_vec(),
            10 * 1024 * 1024,
        );
        state3.set_self_weak(Arc::downgrade(&state3));

        let chunk_size = 1024 * 1024;

        // Helper to load a chunk
        async fn load_chunk(state: &Arc<FileReadAheadState>, chunk_idx: u64, chunk_size: u64) {
            let start = chunk_idx * chunk_size;
            state.insert_range(start..start + chunk_size).await.unwrap();
            state
                .load_range(
                    start..start + chunk_size,
                    &state.memory_pool,
                    Bytes::from(vec![0u8; chunk_size as usize]),
                )
                .await
                .unwrap();
        }

        // Load chunks interleaved: fh1[0], fh2[0], fh3[0], fh1[1], fh2[1], fh3[1], fh1[2], fh2[2]
        load_chunk(&state1, 0, chunk_size).await;
        load_chunk(&state2, 0, chunk_size).await;
        load_chunk(&state3, 0, chunk_size).await;
        load_chunk(&state1, 1, chunk_size).await;
        load_chunk(&state2, 1, chunk_size).await;
        load_chunk(&state3, 1, chunk_size).await;
        load_chunk(&state1, 2, chunk_size).await;
        load_chunk(&state2, 2, chunk_size).await;

        // Total: 8 chunks, target 50% = 5 chunks, should evict 3 oldest
        // Eviction order: fh1[0], fh2[0], fh3[0]
        let evicted = cache.evict_to_target_utilization().await;
        assert_eq!(evicted, 3, "Should evict 3 chunks to reach 50% target");

        // Each file should have lost its oldest chunk (chunk 0)
        assert_eq!(
            state1.get_num_ranges(),
            2,
            "fh1 should have 2 chunks remaining"
        );
        assert_eq!(
            state2.get_num_ranges(),
            2,
            "fh2 should have 2 chunks remaining"
        );
        assert_eq!(
            state3.get_num_ranges(),
            1,
            "fh3 should have 1 chunk remaining"
        );

        // Verify the *newer* chunks remain, oldest (chunk 0) was evicted
        assert!(!state1.has_range_at(0), "fh1 chunk 0 should be evicted");
        assert!(state1.has_range_at(chunk_size), "fh1 chunk 1 should remain");
        assert!(
            state1.has_range_at(2 * chunk_size),
            "fh1 chunk 2 should remain"
        );

        assert!(!state2.has_range_at(0), "fh2 chunk 0 should be evicted");
        assert!(state2.has_range_at(chunk_size), "fh2 chunk 1 should remain");
        assert!(
            state2.has_range_at(2 * chunk_size),
            "fh2 chunk 2 should remain"
        );

        assert!(!state3.has_range_at(0), "fh3 chunk 0 should be evicted");
        assert!(state3.has_range_at(chunk_size), "fh3 chunk 1 should remain");
    }

    #[tokio::test]
    async fn test_load_evicts_lru_when_at_capacity() {
        let mut config = ReadBypassConfig::default();
        config.readahead_cache_init_memory_size_mb = 2; // Only 2 chunks capacity
        config.readahead_cache_max_memory_size_mb = 2;

        let cache = Arc::new(FileReadAheadCache::new(
            1024 * 1024,
            1024 * 1024,
            Arc::new(S3ReadBypassReader::new(128)),
            &config,
        ));
        cache.set_self_weak(Arc::downgrade(&cache));

        let chunk_size = 1024 * 1024u64;

        // Create file1 and fill cache to capacity (2 chunks)
        let state1 = cache.create_file_read_ahead_state(
            b"fh1".to_vec(),
            b"key1".to_vec(),
            b"etag1".to_vec(),
            b"".to_vec(),
            10 * 1024 * 1024,
        );
        state1.set_self_weak(Arc::downgrade(&state1));

        for i in 0..2 {
            let start = i * chunk_size;
            state1
                .insert_range(start..start + chunk_size)
                .await
                .unwrap();
            state1
                .load_range(
                    start..start + chunk_size,
                    &state1.memory_pool,
                    Bytes::from(vec![0u8; chunk_size as usize]),
                )
                .await
                .unwrap();
        }

        assert_eq!(state1.get_num_ranges(), 2);
        assert_eq!(
            cache.memory_pool.available_chunks(),
            0,
            "Pool should be full"
        );

        // Create file2 and load a chunk - should trigger eviction of oldest from file1
        let state2 = cache.create_file_read_ahead_state(
            b"fh2".to_vec(),
            b"key2".to_vec(),
            b"etag2".to_vec(),
            b"".to_vec(),
            10 * 1024 * 1024,
        );
        state2.set_self_weak(Arc::downgrade(&state2));

        state2.insert_range(0..chunk_size).await.unwrap();
        state2
            .load_range(
                0..chunk_size,
                &state2.memory_pool,
                Bytes::from(vec![0u8; chunk_size as usize]),
            )
            .await
            .unwrap();

        // file1's oldest chunk (0) should be evicted, chunk 1 remains
        assert_eq!(
            state1.get_num_ranges(),
            1,
            "file1 should have 1 chunk after eviction"
        );
        assert!(!state1.has_range_at(0), "file1 chunk 0 should be evicted");
        assert!(
            state1.has_range_at(chunk_size),
            "file1 chunk 1 should remain"
        );

        // file2 should have its chunk
        assert_eq!(state2.get_num_ranges(), 1);
        assert!(state2.has_range_at(0), "file2 chunk 0 should exist");
    }

    #[tokio::test]
    async fn test_cleanup_stale_and_empty() {
        let cache = FileReadAheadCache::new(
            100,
            50,
            Arc::new(S3ReadBypassReader::new(128)),
            &ReadBypassConfig::default(),
        );

        // Create file states
        cache.create_file_read_ahead_state(
            b"fh1".to_vec(),
            b"key1".to_vec(),
            b"etag1".to_vec(),
            b"".to_vec(),
            1024,
        );
        let state2 = cache.create_file_read_ahead_state(
            b"fh2".to_vec(),
            b"key2".to_vec(),
            b"etag2".to_vec(),
            b"".to_vec(),
            1024,
        );

        // Add data to state2 only
        state2.insert_range(0..100).await.unwrap();

        assert_eq!(cache.get_num_files(), 2);

        // Cleanup should remove empty state1 (stale entries won't be removed yet - TTL is 60s)
        let (stale_removed, empty_removed) = cache.cleanup_stale_and_empty().await;
        assert_eq!(stale_removed, 0); // Entry is not stale yet (created within TTL)
        assert_eq!(empty_removed, 1);
        assert_eq!(cache.get_num_files(), 1);

        // state2 should still exist
        assert!(cache.get_file_read_ahead_state(b"fh2", b"etag2").is_some());
    }

    #[test]
    fn test_readahead_suppression_timing() {
        let cache = FileReadAheadCache::new(
            100,
            50,
            Arc::new(S3ReadBypassReader::new(128)),
            &ReadBypassConfig::default(),
        );

        // Initially not suppressed
        assert!(!cache.is_readahead_suppressed());

        // Suppress readahead
        cache.suppress_readahead();

        // Should now be suppressed
        assert!(cache.is_readahead_suppressed());

        // Verify suppressed_until is set to eviction_interval + 1 seconds in the future
        let now = get_current_time_ms();
        let suppressed_until = cache.readahead_suppressed_until.load(Ordering::Relaxed);
        let backoff = suppressed_until - now;
        let expected_ms = READAHEAD_BACKOFF_MS;
        assert!(
            backoff > expected_ms - 1000 && backoff <= expected_ms,
            "Backoff should be ~{}ms, got {}ms",
            expected_ms,
            backoff
        );
    }

    #[tokio::test]
    async fn test_evict_skips_loading_entry_and_reinserts() {
        let mut config = ReadBypassConfig::default();
        config.readahead_cache_init_memory_size_mb = 10;
        config.readahead_cache_max_memory_size_mb = 10;

        let cache = Arc::new(FileReadAheadCache::new(
            1024 * 1024,
            1024 * 1024,
            Arc::new(S3ReadBypassReader::new(128)),
            &config,
        ));
        cache.set_self_weak(Arc::downgrade(&cache));

        let state = cache.create_file_read_ahead_state(
            b"fh1".to_vec(),
            b"key1".to_vec(),
            b"etag1".to_vec(),
            b"".to_vec(),
            10 * 1024 * 1024,
        );

        // Insert a range but don't load it - it stays in Loading state
        state.insert_range(0..1024u64).await.unwrap();

        // Should not evict loading entry, and should re-insert into LRU
        assert!(!cache.evict_lru_entry().await);
        assert_eq!(cache.global_lru.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_eviction_task_stops_on_cancellation() {
        let cache = Arc::new(FileReadAheadCache::new(
            100,
            50,
            Arc::new(S3ReadBypassReader::new(128)),
            &ReadBypassConfig::default(),
        ));

        let token = tokio_util::sync::CancellationToken::new();
        let handle = cache.clone().start_eviction_task(1, token.clone());

        // Cancel immediately
        token.cancel();

        // Task should complete quickly
        tokio::time::timeout(std::time::Duration::from_secs(1), handle)
            .await
            .expect("Task should stop on cancellation")
            .expect("Task should not panic");
    }

    fn create_test_locator(
        offset: u64,
        count: u32,
    ) -> crate::nfs::nfs4_1_xdr::awsfile_bypass_data_locator {
        crate::nfs::nfs4_1_xdr::awsfile_bypass_data_locator {
            bucket_name: b"bucket".to_vec(),
            s3_key: b"key".to_vec(),
            etag: b"etag".to_vec(),
            version_id: b"v1".to_vec(),
            offset,
            count,
        }
    }

    #[tokio::test]
    async fn test_small_file_bypasses_cache() {
        let mock_reader = Arc::new(CountingS3DataReader::new());
        let cache = Arc::new(FileReadAheadCache::new(
            64 * 1024,
            64 * 1024,
            mock_reader.clone(),
            &ReadBypassConfig::default(),
        ));
        cache.set_self_weak(Arc::downgrade(&cache));

        let read_bypass_context =
            Arc::new(crate::util::read_bypass_context::ReadBypassContext::default().await);
        let ctx = Arc::new(
            crate::util::read_bypass_request_context::ReadBypassRequestContext::new(
                read_bypass_context,
                0,
            ),
        );

        // File size (512B) fits within default small_file_caching_threshold (1 MiB)
        let file_size = 512u64;
        let locator = create_test_locator(0, 512);
        let fh = crate::nfs::nfs4_1_xdr::nfs_fh4(b"fh1".to_vec());

        let result = cache
            .process_read_request(ctx, fh, file_size, locator)
            .await;

        assert!(result.is_ok());
        assert!(
            result.unwrap().is_some(),
            "Should return data from direct S3 read"
        );
        assert_eq!(
            mock_reader.calls(),
            1,
            "Should have made exactly 1 direct S3 call"
        );
        assert_eq!(
            cache.get_num_files(),
            0,
            "Should not create any cache state for small file"
        );
    }

    #[tokio::test]
    async fn test_large_file_uses_cache() {
        let mock_reader = Arc::new(CountingS3DataReader::new());
        let cache = Arc::new(FileReadAheadCache::new(
            64 * 1024,
            64 * 1024,
            mock_reader.clone(),
            &ReadBypassConfig::default(),
        ));
        cache.set_self_weak(Arc::downgrade(&cache));

        let read_bypass_context =
            Arc::new(crate::util::read_bypass_context::ReadBypassContext::default().await);
        let ctx = Arc::new(
            crate::util::read_bypass_request_context::ReadBypassRequestContext::new(
                read_bypass_context,
                0,
            ),
        );

        // File size (2 MiB) exceeds default small_file_caching_threshold (1 MiB)
        let file_size = 2 * 1024 * 1024u64;
        let locator = create_test_locator(0, 8192);
        let fh = crate::nfs::nfs4_1_xdr::nfs_fh4(b"fh2".to_vec());

        let result = cache
            .process_read_request(ctx, fh, file_size, locator)
            .await;

        assert!(result.is_ok());
        assert!(result.unwrap().is_some(), "Should return data");
        assert_eq!(
            cache.get_num_files(),
            1,
            "Should create cache state for large file"
        );
    }

    /// Stress test for concurrent reads with cache eviction pressure.
    #[ignore]
    #[test_case(false, false ; "single_file_random")]
    #[test_case(false, true ; "single_file_sequential")]
    #[test_case(true, false ; "multi_file_random")]
    #[test_case(true, true ; "multi_file_sequential")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn test_concurrent_reads_and_evictions_stress(multi_file: bool, sequential: bool) {
        use tokio_util::sync::CancellationToken;

        const NUM_THREADS: u64 = 8;
        const FILE_SIZE: u64 = 4 * 1024 * 1024;
        const MIN_READ_SIZE: u64 = 4 * 1024;
        const MAX_READ_SIZE: u64 = 1024 * 1024;
        const TEST_DURATION_SECS: u64 = 15;

        let config = ReadBypassConfig {
            readahead_cache_init_memory_size_mb: 8,
            readahead_cache_max_memory_size_mb: 8,
            ..Default::default()
        };
        let reader = Arc::new(CountingS3DataReader::new());
        let cache = Arc::new(FileReadAheadCache::new(
            256 * 1024,
            64 * 1024,
            reader.clone(),
            &config,
        ));
        cache.set_self_weak(Arc::downgrade(&cache));

        let cancel = CancellationToken::new();

        let handles: Vec<_> = (0..NUM_THREADS)
            .map(|thread_id| {
                let cache = cache.clone();
                let cancel = cancel.clone();

                tokio::spawn(async move {
                    use rand::Rng;

                    let ctx = create_test_read_bypass_context().await;
                    let file_id = if multi_file { thread_id } else { 0 };
                    let fh = nfs_fh4(file_id.to_le_bytes().to_vec());
                    let mut seq_offset = 0u64;

                    while !cancel.is_cancelled() {
                        let read_size = rand::thread_rng().gen_range(MIN_READ_SIZE..MAX_READ_SIZE);
                        let offset = if sequential {
                            let o = seq_offset;
                            seq_offset = (seq_offset + read_size) % (FILE_SIZE - MAX_READ_SIZE);
                            o
                        } else {
                            rand::thread_rng().gen_range(0..FILE_SIZE - read_size)
                        };

                        let locator = create_test_s3_data_locator(offset, read_size as u32);
                        let req = Arc::new(ReadBypassRequestContext::new(ctx.clone(), 0));

                        if let Ok(Some(data)) = cache
                            .process_read_request(req, fh.clone(), FILE_SIZE, locator)
                            .await
                        {
                            assert!(
                                verify_data(&data, offset, read_size as usize),
                                "data corruption at offset={} expected_len={} actual_len={}",
                                offset,
                                read_size,
                                data.len()
                            );
                        }
                    }
                })
            })
            .collect();

        tokio::time::sleep(std::time::Duration::from_secs(TEST_DURATION_SECS)).await;
        cancel.cancel();
        for h in handles {
            h.await.expect("task panicked");
        }
    }

    /// Verify data matches expected pattern: byte at position i = (offset + i) % 256
    fn verify_data(data: &[u8], offset: u64, expected_len: usize) -> bool {
        if data.len() != expected_len {
            return false;
        }
        data.iter()
            .enumerate()
            .all(|(i, &b)| b == ((offset as usize + i) % 256) as u8)
    }
}
