//! CachedData represents data read from S3 for a specific range of a file.
//! CachedData can be created before the data is loaded from S3,
//! so we know we are in progress to fetch the data already.
//! A RwLock protects the data for the cached range. The write lock is held
//! while the data is initialized. This allows for concurrent reads of the same data,
//! improving performance for read-heavy workloads.

use atomic_enum::atomic_enum;
use bytes::Bytes;
use log::{error, warn};
use std::ops::Range;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{Notify, OwnedRwLockReadGuard, RwLock, RwLockWriteGuard};

use crate::memory::memory_pool::{self, MemoryChunk, MemoryPool};
use crate::read_ahead::error::ReadAheadCacheError;

pub const INVALID_U64: u64 = u64::MAX; // Used to indicate the value is unset
const DEFAULT_TIME_OUT_SECOND: u64 = 15; // 15 secs - S3 deadline is 5s allows for a few retries
const MAX_LOADING_TIME_MS: u64 = 30_000; // Double the timeout value, used to evict entries if they persist and aren't loaded

/// State machine for cache entries:
/// - Loading: Entry created, S3 fetch in progress. Readers wait on notify.
/// - Loaded: Data available. Readers can access via read lock.
/// - Failed: S3 fetch failed. Entry will be removed from index.
/// - Evicted: Entry marked for removal. Data cleared, memory returned to pool.
#[atomic_enum]
#[derive(PartialEq, Eq)]
pub enum CacheEntryState {
    Loading = 0,
    Loaded = 1,
    Failed = 2,
    Evicted = 3,
}

pub fn get_current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis() as u64
}

/// Zero-copy view into a single MemoryChunk, kept alive by an owned read guard.
struct ChunkSlice {
    guard: OwnedRwLockReadGuard<Vec<MemoryChunk>>,
    chunk_idx: usize,
    start: usize,
    len: usize,
}

// SAFETY: MemoryChunk data is immutable while the read guard is held.
unsafe impl Send for ChunkSlice {}
unsafe impl Sync for ChunkSlice {}

impl AsRef<[u8]> for ChunkSlice {
    fn as_ref(&self) -> &[u8] {
        &self.guard[self.chunk_idx][self.start..self.start + self.len]
    }
}

pub struct CachedData {
    /// Time when this entry was created (for detecting stuck loading entries)
    created_time_ms: u64,
    /// Time when data was successfully loaded (for TTL eviction)
    cached_time_ms: AtomicU64,
    last_read_end_position: AtomicU64,
    /// Cumulative bytes served from this range. When this reaches the range
    /// size the range is fully consumed regardless of read order.
    bytes_read: AtomicU64,
    /// Current state of this cache entry
    state: AtomicCacheEntryState,
    /// Notifies waiters when state changes occur
    state_notify: Arc<Notify>,
    data: Arc<RwLock<Vec<MemoryChunk>>>,
}

impl CachedData {
    pub fn new() -> Self {
        Self {
            created_time_ms: get_current_time_ms(),
            cached_time_ms: AtomicU64::new(0),
            last_read_end_position: AtomicU64::new(INVALID_U64),
            bytes_read: AtomicU64::new(0),
            state: AtomicCacheEntryState::new(CacheEntryState::Loading),
            state_notify: Arc::new(Notify::new()),
            data: Arc::new(RwLock::new(vec![])),
        }
    }

    pub fn get_state(&self) -> CacheEntryState {
        self.state.load(Ordering::Acquire)
    }

    /// Sets the state and notifies any waiters
    pub fn set_state(&self, new_state: CacheEntryState) {
        self.state.store(new_state, Ordering::Release);
        self.state_notify.notify_waiters();
    }

    pub fn is_loading(&self) -> bool {
        self.get_state() == CacheEntryState::Loading
    }

    /// Returns true if this entry was created within the last `ms` milliseconds
    pub fn is_created_within(&self, ms: u64) -> bool {
        get_current_time_ms().saturating_sub(self.created_time_ms) < ms
    }

    /// Returns true if this entry has been loading for longer than MAX_LOADING_TIME_MS (30s)
    pub fn is_stuck_loading(&self) -> bool {
        self.is_loading() && !self.is_created_within(MAX_LOADING_TIME_MS)
    }

    /// Returns true if this entry was loaded within the last `ms` milliseconds
    pub fn is_recently_loaded(&self, ms: u64) -> bool {
        let cached_time = self.cached_time_ms.load(Ordering::Relaxed);
        if cached_time == 0 {
            return false; // Not loaded yet
        }
        get_current_time_ms().saturating_sub(cached_time) < ms
    }

    /// Wait for loading to complete (state changes from Loading)
    /// Returns the final state (Loaded or Failed)
    async fn await_loading_completion(&self, range: &Range<u64>) -> CacheEntryState {
        // Fast path: check if already done loading
        let current_state = self.get_state();
        if current_state != CacheEntryState::Loading {
            return current_state;
        }

        let timeout = tokio::time::Duration::from_secs(DEFAULT_TIME_OUT_SECOND);
        match tokio::time::timeout(timeout, self.state_notify.notified()).await {
            Ok(_) => self.get_state(),
            Err(_) => {
                warn!(
                    "Timeout waiting for cache entry loading after {}s, range: {}..{}",
                    DEFAULT_TIME_OUT_SECOND, range.start, range.end
                );
                CacheEntryState::Failed
            }
        }
    }

    pub async fn load(&self, data: Vec<MemoryChunk>) -> Result<bool, ReadAheadCacheError> {
        let data_guard = self.acquire_write_lock().await?;
        let result = self.load_with_lock(data, data_guard).await;
        result
    }

    pub async fn load_with_lock(
        &self,
        data: Vec<MemoryChunk>,
        mut data_guard: tokio::sync::RwLockWriteGuard<'_, Vec<MemoryChunk>>,
    ) -> Result<bool, ReadAheadCacheError> {
        let current_time = get_current_time_ms();
        {
            // If there's already data, don't overwrite it
            if !data_guard.is_empty() {
                let error = ReadAheadCacheError {
                    message: "Cannot load data over existing cached data".to_string(),
                };
                error!("{}", error);
                return Err(error);
            }
            *data_guard = data;
        }

        // Relaxed ordering as we only use this for eviction purposes
        self.cached_time_ms.store(current_time, Ordering::Relaxed);
        self.set_state(CacheEntryState::Loaded);
        Ok(true)
    }

    pub async fn clear(&self, memory_pool: &Arc<MemoryPool>) -> Result<bool, ReadAheadCacheError> {
        // Mark as evicted and notify waiters so they don't wait forever
        self.set_state(CacheEntryState::Evicted);

        let data_guard = tokio::time::timeout(
            std::time::Duration::from_secs(DEFAULT_TIME_OUT_SECOND),
            self.data.write(),
        )
        .await;

        let mut data_guard = match data_guard {
            Ok(guard) => guard,
            Err(_) => {
                // Avoid holding write lock indefinitely during cleanup.
                // Entry is already removed from cache index; memory chunks
                // will be returned to pool when outstanding Bytes references drop.
                warn!("Timeout acquiring write lock in clear()");
                return Err(ReadAheadCacheError {
                    message: "Timeout acquiring write lock in clear()".to_string(),
                });
            }
        };

        if data_guard.is_empty() {
            return Ok(true); // NoOp
        }
        let data_to_free = std::mem::take(&mut *data_guard);
        memory_pool.free(data_to_free);
        Ok(true)
    }

    pub fn get_last_read_end_position(&self) -> u64 {
        self.last_read_end_position.load(Ordering::Relaxed)
    }

    pub fn set_last_read_end_position(
        &self,
        last_read_end_position: u64,
    ) -> Result<(), ReadAheadCacheError> {
        if last_read_end_position == 0 {
            let error = ReadAheadCacheError {
                message: "Read position must be greater than 0".to_string(),
            };
            error!("{}", error);
            return Err(error);
        }
        self.last_read_end_position
            .store(last_read_end_position, Ordering::Relaxed);
        Ok(())
    }

    /// Record that `n` bytes were served from this range. Order-independent.
    pub fn add_bytes_read(&self, n: u64) {
        self.bytes_read.fetch_add(n, Ordering::Relaxed);
    }

    pub fn get_bytes_read(&self) -> u64 {
        self.bytes_read.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub async fn has_data(&self) -> Result<bool, ReadAheadCacheError> {
        let data_guard = self.acquire_read_lock().await?;
        Ok(!data_guard.is_empty())
    }

    pub async fn acquire_write_lock(
        &self,
    ) -> Result<RwLockWriteGuard<'_, Vec<MemoryChunk>>, ReadAheadCacheError> {
        Ok(self.data.write().await)
    }

    // Extract data from a specific range within this cached data
    // The range is relative to the start of this cached data (offset 0 is the first byte of this cache entry)
    pub async fn get_data_range(&self, range: Range<u64>) -> Result<Bytes, ReadAheadCacheError> {
        let state = self.await_loading_completion(&range).await;

        match state {
            CacheEntryState::Loading => {
                return Err(ReadAheadCacheError {
                    message: format!(
                        "Timeout waiting for cache entry to load (start: {} end: {}) within {}s",
                        range.start, range.end, DEFAULT_TIME_OUT_SECOND
                    ),
                });
            }
            CacheEntryState::Failed => {
                return Err(ReadAheadCacheError {
                    message: "Cache entry failed to load".to_string(),
                });
            }
            CacheEntryState::Evicted => {
                return Err(ReadAheadCacheError {
                    message: "Data evicted before read completed".to_string(),
                });
            }
            CacheEntryState::Loaded => {}
        }

        let (offset, length) = self.validate_range(range)?;

        let offset_usize = offset as usize;
        let length_usize = length as usize;
        let start_chunk = offset_usize / memory_pool::CHUNK_SIZE;
        let start_byte = offset_usize % memory_pool::CHUNK_SIZE;
        let fits_single_chunk = start_byte + length_usize <= memory_pool::CHUNK_SIZE;

        // Fast path: single-chunk read — zero-copy via Bytes::from_owner.
        if fits_single_chunk {
            let guard = self.data.clone().read_owned().await;
            // Re-check state after acquiring lock - eviction sets state before clearing data
            if self.get_state() != CacheEntryState::Loaded {
                return Err(ReadAheadCacheError {
                    message: "Data evicted before read completed".to_string(),
                });
            }
            if guard.is_empty() {
                return Err(ReadAheadCacheError {
                    message: "Cache entry has no data despite Loaded state".to_string(),
                });
            }
            if start_chunk >= guard.len() {
                return Err(ReadAheadCacheError {
                    message: format!(
                        "Start chunk index ({}) is beyond available data length ({})",
                        start_chunk,
                        guard.len()
                    ),
                });
            }
            let slice = ChunkSlice {
                guard,
                chunk_idx: start_chunk,
                start: start_byte,
                len: length_usize,
            };
            return Ok(Bytes::from_owner(slice));
        }

        // Slow path: multi-chunk read — copy into Vec
        let data_guard = self.acquire_read_lock().await?;
        // Re-check state after acquiring lock - eviction sets state before clearing data
        if self.get_state() != CacheEntryState::Loaded {
            return Err(ReadAheadCacheError {
                message: "Data evicted before read completed".to_string(),
            });
        }
        if data_guard.is_empty() {
            // This shouldn't happen if state is Loaded, but handle defensively
            return Err(ReadAheadCacheError {
                message: "Cache entry has no data despite Loaded state".to_string(),
            });
        }

        self.copy_data_from_chunks(&data_guard, offset, length)
            .await
    }

    /// Copies data from memory chunks into a result vector
    async fn copy_data_from_chunks(
        &self,
        data_guard: &[MemoryChunk],
        offset: u64,
        length: u64,
    ) -> Result<Bytes, ReadAheadCacheError> {
        let offset_usize = offset as usize;
        let start_chunk_idx = offset_usize / memory_pool::CHUNK_SIZE;
        let start_byte_in_chunk = offset_usize % memory_pool::CHUNK_SIZE;

        if start_chunk_idx >= data_guard.len() {
            return Err(ReadAheadCacheError {
                message: format!(
                    "Start chunk index ({}) is beyond available data length ({})",
                    start_chunk_idx,
                    data_guard.len()
                ),
            });
        }

        let mut result_data = Vec::with_capacity(length as usize);
        let mut bytes_copied = 0u64;
        let mut chunk_idx = start_chunk_idx;

        while bytes_copied < length && chunk_idx < data_guard.len() {
            let chunk = &data_guard[chunk_idx];
            let start_pos = if chunk_idx == start_chunk_idx {
                start_byte_in_chunk
            } else {
                0
            };

            if start_pos >= memory_pool::CHUNK_SIZE {
                let error = ReadAheadCacheError {
                    message: format!(
                        "Invalid start position ({}) exceeds chunk size ({})",
                        start_pos,
                        memory_pool::CHUNK_SIZE
                    ),
                };
                error!("{}", error);
                return Err(error);
            }

            let bytes_remaining = length - bytes_copied;
            let bytes_remaining_usize = bytes_remaining as usize;

            let bytes_available_in_chunk = memory_pool::CHUNK_SIZE - start_pos;
            let bytes_to_copy = bytes_remaining_usize.min(bytes_available_in_chunk);
            if start_pos + bytes_to_copy > memory_pool::CHUNK_SIZE {
                let error = ReadAheadCacheError {
                    message: format!("Would read beyond chunk boundary: start_pos ({}) + bytes_to_copy ({}) > chunk_size ({})", 
                                    start_pos, bytes_to_copy, memory_pool::CHUNK_SIZE)
                };
                error!("{}", error);
                return Err(error);
            }

            result_data.extend_from_slice(&chunk[start_pos..start_pos + bytes_to_copy]);
            bytes_copied += bytes_to_copy as u64;
            chunk_idx += 1;
        }

        // If we couldn't get all the requested data fail the request
        if bytes_copied < length {
            let error = ReadAheadCacheError {
                message: format!(
                    "Could not satisfy entire read request: bytes_copied ({}) < length ({})",
                    bytes_copied, length
                ),
            };
            warn!("{}", error);
            return Err(error);
        }

        Ok(Bytes::from(result_data))
    }

    /// Validates that a range is valid for data access
    /// Returns the offset and length if valid, or an error if invalid
    fn validate_range(&self, range: Range<u64>) -> Result<(u64, u64), ReadAheadCacheError> {
        if range.start >= range.end {
            let error = ReadAheadCacheError {
                message: format!(
                    "Invalid range: start ({}) must be less than end ({})",
                    range.start, range.end
                ),
            };
            error!("{}", error);
            return Err(error);
        }

        let offset = range.start;
        let length = range.end - range.start;
        if length > usize::MAX as u64 {
            let error = ReadAheadCacheError {
                message: format!(
                    "Length ({}) too large for this system (max: {})",
                    length,
                    usize::MAX
                ),
            };
            error!("{}", error);
            return Err(error);
        }

        Ok((offset, length))
    }

    async fn acquire_read_lock(
        &self,
    ) -> Result<tokio::sync::RwLockReadGuard<'_, Vec<MemoryChunk>>, ReadAheadCacheError> {
        Ok(self.data.read().await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::memory_pool::MemoryPoolConfig;
    use std::sync::Arc;

    fn create_test_chunk(data: &[u8]) -> MemoryChunk {
        let memory_pool = create_test_memory_pool();
        let mut chunk = memory_pool.consume(1).pop().unwrap();
        let copy_size = std::cmp::min(data.len(), memory_pool::CHUNK_SIZE);
        chunk[..copy_size].copy_from_slice(&data[..copy_size]);
        chunk
    }

    fn create_test_memory_pool() -> Arc<MemoryPool> {
        MemoryPool::new(MemoryPoolConfig {
            initial_capacity: 5,
            min_capacity: 5,
            ..Default::default()
        })
    }

    #[tokio::test]
    async fn test_new_cached_data_is_empty() {
        let cached_data = CachedData::new();
        assert_eq!(cached_data.cached_time_ms.load(Ordering::SeqCst), 0);
        assert_eq!(
            cached_data.last_read_end_position.load(Ordering::SeqCst),
            INVALID_U64
        );
        assert!(cached_data.created_time_ms > 0);
        assert_eq!(cached_data.get_state(), CacheEntryState::Loading);
        assert!(cached_data.is_loading());

        let has_data = cached_data.has_data().await.unwrap();
        assert!(!has_data);
    }

    #[tokio::test]
    async fn test_load_data() {
        let cached_data = CachedData::new();
        let test_data = vec![create_test_chunk(b"test data")];

        let result = cached_data.load(test_data).await.unwrap();
        assert!(result);

        let has_data = cached_data.has_data().await.unwrap();
        assert!(has_data);

        let data_guard = cached_data.acquire_read_lock().await.unwrap();
        assert_eq!(&data_guard[0][..9], b"test data");
    }

    #[tokio::test]
    async fn test_load_data_twice() {
        let cached_data = CachedData::new();
        let test_data1 = vec![create_test_chunk(b"first data")];
        let test_data2 = vec![create_test_chunk(b"second data")];

        // First load should succeed
        let result1 = cached_data.load(test_data1).await.unwrap();
        assert!(result1);

        // Second load should fail
        let result2 = cached_data.load(test_data2).await;
        assert!(result2.is_err());
    }

    #[tokio::test]
    async fn test_clear_data() {
        let cached_data = CachedData::new();
        let memory_pool = create_test_memory_pool();

        // Use the same memory pool to create the chunk
        let mut chunk = memory_pool.consume(1).pop().unwrap();
        let test_data = b"test data";
        let copy_size = std::cmp::min(test_data.len(), memory_pool::CHUNK_SIZE);
        chunk[..copy_size].copy_from_slice(&test_data[..copy_size]);

        cached_data.load(vec![chunk]).await.unwrap();
        assert!(cached_data.has_data().await.unwrap());

        // Record available chunks before clearing
        let before_clear = memory_pool.available_chunks();

        let result = cached_data.clear(&memory_pool).await.unwrap();
        assert!(result);
        assert!(!cached_data.has_data().await.unwrap());

        // After clearing, we should have more chunks available than before
        assert!(
            memory_pool.available_chunks() > before_clear,
            "Expected more chunks after clearing, before: {}, after: {}",
            before_clear,
            memory_pool.available_chunks()
        );
    }

    #[tokio::test]
    async fn test_read_after_eviction_returns_retriable_error() {
        let cached_data = CachedData::new();
        let memory_pool = create_test_memory_pool();

        let mut chunk = memory_pool.consume(1).pop().unwrap();
        chunk[..10].copy_from_slice(b"0123456789");
        cached_data.load(vec![chunk]).await.unwrap();

        cached_data.clear(&memory_pool).await.unwrap();

        let err = cached_data.get_data_range(0..5).await.unwrap_err();
        assert!(
            err.message.contains("Data evicted"),
            "Error should trigger retry: {}",
            err.message
        );
    }

    #[tokio::test]
    async fn test_set_last_read_position() {
        let cached_data = CachedData::new();

        cached_data.set_last_read_end_position(100).unwrap();
        assert_eq!(
            cached_data.last_read_end_position.load(Ordering::SeqCst),
            100
        );
    }

    #[tokio::test]
    async fn test_get_last_read_end_position() {
        let cached_data = CachedData::new();
        assert_eq!(cached_data.get_last_read_end_position(), INVALID_U64);
        cached_data.set_last_read_end_position(150).unwrap();
        assert_eq!(cached_data.get_last_read_end_position(), 150);
    }

    #[tokio::test]
    async fn test_get_data_range() {
        let cached_data = CachedData::new();
        let test_data = "Hello, world!".as_bytes();
        let chunk = create_test_chunk(test_data);

        cached_data.load(vec![chunk]).await.unwrap();

        // Get the entire range
        let result = cached_data.get_data_range(0..13).await.unwrap();
        assert_eq!(result, test_data);

        // Get a partial range
        let result = cached_data.get_data_range(7..13).await.unwrap();
        assert_eq!(result, b"world!" as &[u8]);
    }

    #[tokio::test]
    async fn test_get_data_range_invalid() {
        let cached_data = CachedData::new();
        let test_data = "Hello, world!".as_bytes();
        let chunk = create_test_chunk(test_data);

        cached_data.load(vec![chunk]).await.unwrap();

        // Try to get an invalid range (start >= end)
        let result = cached_data.get_data_range(5..5).await;
        assert!(result.is_err());

        // Try to get a range that's beyond the data we actually wrote
        let chunk_size = memory_pool::CHUNK_SIZE as u64;
        let result = cached_data
            .get_data_range(chunk_size + 1..chunk_size + 10)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_data_range_multi_chunk() {
        let cached_data = CachedData::new();

        // Create two chunks with different data
        let chunk1 = create_test_chunk(b"First chunk data");
        let chunk2 = create_test_chunk(b"Second chunk data");

        cached_data.load(vec![chunk1, chunk2]).await.unwrap();

        // Get data that spans both chunks
        let chunk_size = memory_pool::CHUNK_SIZE as u64;
        let result = cached_data.get_data_range(0..chunk_size + 5).await.unwrap();

        // Check that we have data from both chunks
        assert!(result.len() > chunk_size as usize);

        // Check the first chunk data (only check what we actually wrote)
        let first_data = b"First chunk data";
        assert_eq!(&result[..first_data.len()], first_data);

        let second_data = b"Second";
        let second_start = chunk_size as usize;
        let second_end = std::cmp::min(second_start + second_data.len(), result.len());

        if second_end > second_start {
            assert_eq!(
                &result[second_start..second_end],
                &second_data[..second_end - second_start]
            );
        }
    }

    #[tokio::test]
    async fn test_clear_timeout_returns_error_when_read_guard_held() {
        let cached_data = Arc::new(CachedData::new());
        let memory_pool = Arc::new(MemoryPool::new(MemoryPoolConfig::default()));

        // Load some data
        let chunk = create_test_chunk(b"test data");
        cached_data.load(vec![chunk]).await.unwrap();

        // Acquire read guard via get_data_range (simulates Bytes holding a guard)
        let _bytes = cached_data.get_data_range(0..9).await.unwrap();

        // clear() should timeout and return error since we hold the read guard
        let cached_data_clone = cached_data.clone();
        let memory_pool_clone = memory_pool.clone();
        let handle = tokio::spawn(async move { cached_data_clone.clear(&memory_pool_clone).await });

        // Wait longer than the timeout would take in a real scenario, but use tokio's
        // test timeout to avoid waiting 15s. The spawn will block on the write lock.
        let result = tokio::time::timeout(std::time::Duration::from_millis(100), handle).await;

        // The spawned task should not complete because it's blocked on the write lock
        assert!(
            result.is_err(),
            "clear() should block when read guard is held"
        );
    }
}
