//! FileReadAheadState maintains the readahead state for a single file.
//! It tracks cached data ranges, read positions, and manages the readahead window.
//! The underlying data cache is protected by a read/write lock where the write lock
//! should only be held while inserting/removing from the cache. We expect there to be
//! concurrent reads to different ranges of the file which suits a read/write lock over a
//! mutex lock.
//!

use bytes::{Bytes, BytesMut};
use log::{error, trace};
use lru::LruCache;
use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::memory::memory_pool::{self, MemoryChunk, MemoryPool};
use crate::nfs::nfs4_1_xdr::awsfile_bypass_data_locator;
use crate::read_ahead::cached_data::{
    get_current_time_ms, CacheEntryState, CachedData, INVALID_U64,
};
use crate::read_ahead::error::ReadAheadCacheError;
use crate::read_ahead::readahead_cache::FileReadAheadCache;
use crate::util::read_bypass_request_context::ReadBypassRequestContext;
use crate::util::s3_data_reader::S3DataReader;
use crate::{ctx_debug, ctx_error, ctx_warn};

/// Minimum time (ms) after loading before an entry can be evicted, protects
// recently loaded items from being immediately evictedx
#[cfg(not(test))]
const MIN_EVICTION_AGE_MS: u64 = 500;
#[cfg(test)]
const MIN_EVICTION_AGE_MS: u64 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadPattern {
    RandomRead,
    StartOfFile,
    SequentialRead,
    /// First read within initial window of a large file - likely out-of-order sequential
    FirstWindowRead,
    /// Speculative readahead fetch - don't trigger further readahead or adjust window
    SpeculativeReadahead,
}

impl ReadPattern {
    pub fn invokes_readahead(&self) -> bool {
        matches!(
            self,
            ReadPattern::SequentialRead | ReadPattern::StartOfFile | ReadPattern::FirstWindowRead
        )
    }
}

/// LRU key: (file_lru_id, offset)
pub(crate) type LruKey = (u64, u64);
/// LRU value: Weak reference to FileReadAheadState for eviction lookup
pub(crate) type LruValue = Weak<FileReadAheadState>;

pub struct FileReadAheadState {
    file_lru_id: u64,
    pub s3_key: Bytes,
    pub s3_etag: Bytes,
    pub s3_version_id: Bytes,
    pub file_size: u64,
    // A BTreeMap is used because we need efficient range queries and ordered iteration:
    // - Maintains sorted order by offset for efficient overlap detection
    data_cache: RwLock<BTreeMap<u64, (u64, Arc<CachedData>)>>, // start_offset -> (end_offset, cached_data)
    last_read_time: AtomicU64,
    last_read_position: AtomicU64,
    last_readahead_position: AtomicU64,
    pub window_size: AtomicU64,
    pub min_window_size: u64,
    pub max_window_size: u64,
    pub memory_pool: Arc<MemoryPool>,
    global_lru: Arc<Mutex<LruCache<LruKey, LruValue>>>,
    // Weak self-reference stored in the global LRU so that during eviction we can
    // look up which FileReadAheadState owns the entry being evicted and call evict_entry on it.
    self_weak: RwLock<Option<Weak<Self>>>,
    cache: Weak<FileReadAheadCache>,
}

impl FileReadAheadState {
    pub fn new(
        file_lru_id: u64,
        s3_key: Bytes,
        s3_etag: Bytes,
        s3_version_id: Bytes,
        file_size: u64,
        window_size: u64,
        min_window_size: u64,
        max_window_size: u64,
        memory_pool: Arc<MemoryPool>,
        global_lru: Arc<Mutex<LruCache<LruKey, LruValue>>>,
        cache: Weak<FileReadAheadCache>,
    ) -> Self {
        Self {
            file_lru_id,
            s3_key,
            s3_etag,
            s3_version_id,
            file_size,
            data_cache: RwLock::new(BTreeMap::new()),
            last_read_time: AtomicU64::new(0),
            last_read_position: AtomicU64::new(INVALID_U64),
            last_readahead_position: AtomicU64::new(0),
            window_size: AtomicU64::new(window_size),
            min_window_size,
            max_window_size,
            memory_pool,
            global_lru,
            self_weak: RwLock::new(None),
            cache,
        }
    }

    /// Must be called after wrapping in Arc to enable LRU insertion
    pub fn set_self_weak(&self, weak: Weak<Self>) {
        if let Ok(mut guard) = self.self_weak.try_write() {
            *guard = Some(weak);
        }
    }

    fn grow_window(&self) {
        let current = self.window_size.load(Ordering::SeqCst);
        let new_window = (current * 2).min(self.max_window_size);
        self.window_size.store(new_window, Ordering::SeqCst);
    }

    fn shrink_window(&self) {
        let current = self.window_size.load(Ordering::SeqCst);
        // Shrink in the same order we grow: find largest (min_window_size * 2^n) < current.
        let mut new_window = self.min_window_size;
        while new_window * 2 < current {
            new_window *= 2;
        }
        self.window_size.store(new_window, Ordering::SeqCst);
    }

    fn lru_touch(&self, offset: u64) {
        if let Ok(mut lru) = self.global_lru.lock() {
            lru.promote(&(self.file_lru_id, offset));
        }
    }

    fn lru_demote(&self, offset: u64) {
        if let Ok(mut lru) = self.global_lru.lock() {
            lru.demote(&(self.file_lru_id, offset));
        }
    }

    pub fn lru_insert(&self, offset: u64) {
        let weak = match self.self_weak.try_read() {
            Ok(guard) => guard.clone(),
            Err(_) => return,
        };
        let Some(weak) = weak else { return };
        if let Ok(mut lru) = self.global_lru.lock() {
            lru.push((self.file_lru_id, offset), weak);
        }
    }

    fn lru_remove(&self, offset: u64) {
        if let Ok(mut lru) = self.global_lru.lock() {
            lru.pop_entry(&(self.file_lru_id, offset));
        }
    }

    fn validate_request(
        &self,
        s3_data_locator: &awsfile_bypass_data_locator,
    ) -> Result<(), ReadAheadCacheError> {
        if s3_data_locator.s3_key != self.s3_key {
            return Err(ReadAheadCacheError {
                message: format!(
                    "S3 key mismatch: expected {:?}, got {:?}",
                    self.s3_key, s3_data_locator.s3_key
                ),
            });
        }

        if s3_data_locator.etag != self.s3_etag {
            return Err(ReadAheadCacheError {
                message: format!(
                    "S3 etag mismatch: expected {:?}, got {:?}",
                    self.s3_etag, s3_data_locator.etag
                ),
            });
        }

        Ok(())
    }

    // Main entry point for interacting with a file readahead state
    // This function will either return cached data or fetch data as needed and populate the data cache with the results
    /// Returns (data, hit_memory_pressure)
    pub async fn get_data(
        self: Arc<Self>,
        read_bypass_request_context: Arc<ReadBypassRequestContext>,
        s3_data_locator: &awsfile_bypass_data_locator,
        file_size: u64,
        s3_data_reader: Arc<dyn S3DataReader>,
        suppress_readahead: bool,
    ) -> Result<(Option<Bytes>, bool), ReadAheadCacheError> {
        // We should not read outside of the file size, NFS allows for such request but only
        // returns data up to EOF
        let end = (s3_data_locator.offset + s3_data_locator.count as u64).min(file_size);
        let range = s3_data_locator.offset..end;

        // A read at or past EOF, or zero-length read, returns empty
        if range.start >= range.end {
            return Ok((Some(Bytes::new()), false));
        }

        let request_len = (range.end - range.start) as usize;

        // First check if we can serve from cache - collect refs while holding lock
        let (read_pattern, cached_ranges) = {
            let data_cache_read = self.acquire_read_lock().await?;
            let mut read_pattern = self.recognize_read_pattern(range.clone(), &data_cache_read);
            // Suppress readahead if requested (due to memory pressure)
            if suppress_readahead && read_pattern.invokes_readahead() {
                read_pattern = ReadPattern::RandomRead;
            }
            // Update position for all reads so that the next read can detect
            // sequential access via last_read_position. Without this, reads
            // starting beyond window_size (e.g. offset 9MB with 8MB window)
            // would never transition from RandomRead to SequentialRead.
            self.update_read_position(range.end);
            let cached_ranges = self.collect_cached_ranges(
                &read_bypass_request_context,
                range.clone(),
                &data_cache_read,
            )?;
            (read_pattern, cached_ranges)
        };
        // Lock released - now fetch data (may wait for loading entries)

        let fetched = self
            .fetch_from_cached_ranges(&read_bypass_request_context, cached_ranges, true)
            .await?;

        // Check if we have full cache hit
        let cached_len: usize = fetched.iter().map(|(_, b)| b.len()).sum();
        if cached_len == request_len {
            let result = Self::combine_ranges(fetched, range.clone())?;
            ctx_debug!(
                read_bypass_request_context,
                "Cache hit: offset={} len={} pattern={:?}",
                range.start,
                result.len(),
                read_pattern
            );
            // Data was cached - trigger speculative readahead for next window
            if read_pattern.invokes_readahead() {
                self.clone().trigger_speculative_readahead(
                    read_bypass_request_context.clone(),
                    range.clone(),
                    read_pattern,
                    s3_data_reader,
                );
            } else {
                self.shrink_window();
            }

            return Ok((Some(result), false));
        }

        // Data not cached - fetch from S3 with readahead
        // Drop fetched to release any embedded read guards before S3 fetch,
        // which may trigger eviction that needs write locks on the same entries.
        drop(fetched);
        ctx_debug!(
            read_bypass_request_context,
            "Cache miss: offset={} len={} pattern={:?}",
            range.start,
            range.end - range.start,
            read_pattern
        );
        let result = self
            .fetch_and_cache_data_internal(
                read_bypass_request_context,
                s3_data_locator,
                file_size,
                s3_data_reader,
                range.clone(),
                read_pattern,
            )
            .await;

        result
    }

    /// Returns (data, hit_memory_pressure)
    async fn fetch_and_cache_data_internal(
        &self,
        read_bypass_request_context: Arc<ReadBypassRequestContext>,
        s3_data_locator: &awsfile_bypass_data_locator,
        file_size: u64,
        s3_data_reader: Arc<dyn S3DataReader>,
        range: Range<u64>,
        read_pattern: ReadPattern,
    ) -> Result<(Option<Bytes>, bool), ReadAheadCacheError> {
        self.validate_request(s3_data_locator)?;

        // 1. Get what's cached (may be partial)
        // Convert to owned bytes immediately to release any cache locks before S3 fetch,
        // which may trigger eviction that needs write locks on the same entries.
        let cached_data: Vec<(Range<u64>, Bytes)> = {
            let data_cache = self.acquire_read_lock().await?;
            let ranges = self.collect_cached_ranges(
                &read_bypass_request_context,
                range.clone(),
                &data_cache,
            )?;
            drop(data_cache);
            self.fetch_from_cached_ranges(&read_bypass_request_context, ranges, false)
                .await?
                .into_iter()
                .map(|(r, b)| (r, Bytes::copy_from_slice(&b)))
                .collect()
        };

        // 2. Compute what's missing
        let mut data_cache_write = self.acquire_write_lock().await?;
        let fetch_range = self.get_range_to_fetch(range.clone(), read_pattern, file_size);
        let fetch_end = fetch_range.end;
        let missing_ranges = self.get_missing_ranges(fetch_range.clone(), &data_cache_write)?;

        // 3. If there is nothing missing then we can just return the data
        if missing_ranges.is_empty() {
            drop(data_cache_write);
            ctx_debug!(
                read_bypass_request_context,
                "fetch data from cache: start ({}) - end ({})",
                range.start,
                range.end
            );
            return Ok((
                Some(Self::combine_ranges(cached_data, range.clone())?),
                false,
            ));
        }

        // 4. We need to fetch from S3 for what is missing, add place holders in the cache
        let readahead_bytes = fetch_end.saturating_sub(range.end);
        ctx_debug!(
            read_bypass_request_context,
            "Cache miss: fetching from S3, requested={}..{} ({}B), readahead={}B, total fetch={}..{} ({}B), window={}B",
            range.start,
            range.end,
            range.end - range.start,
            readahead_bytes,
            fetch_range.start,
            fetch_end,
            fetch_end - fetch_range.start,
            self.window_size.load(Ordering::SeqCst)
        );

        let mut cached_data_objects = Vec::new();
        for missing_range in &missing_ranges {
            let cached_data = Arc::new(CachedData::new());
            cached_data_objects.push(cached_data.clone());

            if !self.insert_range_with_guard(
                missing_range.clone(),
                cached_data,
                &mut data_cache_write,
            )? {
                let error = ReadAheadCacheError {
                    message: format!("Failed to insert missing range: {:?}", missing_range),
                };
                ctx_error!(read_bypass_request_context, "{}", error);
                return Err(error);
            }
        }

        drop(data_cache_write);

        // 5. Perform the fetch from S3
        let (s3_ranges, hit_memory_pressure) = self
            .fetch_missing_ranges_from_s3(
                read_bypass_request_context.clone(),
                missing_ranges,
                cached_data_objects,
                range.clone(),
                s3_data_reader.as_ref(),
                s3_data_locator,
            )
            .await?;

        self.last_readahead_position
            .store(fetch_end, Ordering::SeqCst);

        if read_pattern.invokes_readahead() {
            self.grow_window();
        } else if read_pattern == ReadPattern::RandomRead {
            self.shrink_window();
        }

        // 6. Combine what we had in cache and what was fetched to return
        let mut all_ranges = cached_data;
        all_ranges.extend(s3_ranges);
        Ok((
            Some(Self::combine_ranges(all_ranges, range.clone())?),
            hit_memory_pressure,
        ))
    }

    pub fn trigger_speculative_readahead(
        self: Arc<Self>,
        read_bypass_request_context: Arc<ReadBypassRequestContext>,
        range: Range<u64>,
        read_pattern: ReadPattern,
        s3_data_reader: Arc<dyn S3DataReader>,
    ) {
        if read_pattern.invokes_readahead() {
            let window_size = self.window_size.load(Ordering::SeqCst);
            let previous_ra_end = self.last_readahead_position.load(Ordering::SeqCst);
            let current_read_end = range.end;

            // Kernel readahead like trigger: only start new readahead when read crosses into
            // the second half of the ahead window (halfway point)
            let trigger_point = previous_ra_end.saturating_sub(window_size / 2);
            if current_read_end < trigger_point {
                return;
            }

            let readahead_start = previous_ra_end;
            let readahead_end = (previous_ra_end + window_size).min(self.file_size);

            if readahead_start < readahead_end {
                // Update readahead position BEFORE spawning to prevent duplicate readaheads
                self.last_readahead_position
                    .store(readahead_end, Ordering::SeqCst);

                let readahead_locator = awsfile_bypass_data_locator {
                    bucket_name: read_bypass_request_context.s3_bucket.clone().into_bytes(),
                    s3_key: self.s3_key.to_vec(),
                    etag: self.s3_etag.to_vec(),
                    version_id: self.s3_version_id.to_vec(),
                    offset: readahead_start,
                    count: (readahead_end - readahead_start) as u32,
                };

                let readahead_range = readahead_start..readahead_end;
                ctx_debug!(
                    read_bypass_request_context,
                    "Triggering speculative readahead: start ({}) - end ({}), window={}B",
                    readahead_start,
                    readahead_end,
                    window_size
                );
                tokio::spawn(async move {
                    if let Err(e) = self
                        .fetch_and_cache_data_internal(
                            read_bypass_request_context.clone(),
                            &readahead_locator,
                            self.file_size,
                            s3_data_reader,
                            readahead_range,
                            ReadPattern::SpeculativeReadahead,
                        )
                        .await
                    {
                        // Reset position on failure so range can be retried
                        self.last_readahead_position
                            .store(readahead_start, Ordering::SeqCst);
                        ctx_warn!(
                            read_bypass_request_context,
                            "Speculative readahead failed: {}",
                            e
                        );
                    } else {
                        self.grow_window();
                    }
                });
            }
        }
    }

    // Determine if a read of the requested_range is sequential or random based off of the information
    // that we have. A read lock should be taken out on the data_cache to use this method.
    pub fn recognize_read_pattern(
        &self,
        range: Range<u64>,
        data_cache: &RwLockReadGuard<'_, BTreeMap<u64, (u64, Arc<CachedData>)>>,
    ) -> ReadPattern {
        let window_size = self.window_size.load(Ordering::SeqCst);
        let last_pos = self.last_read_position.load(Ordering::SeqCst);

        let pattern = if range.start == 0 {
            ReadPattern::StartOfFile
        } else if last_pos == INVALID_U64
            && range.start < window_size
            && self.file_size > window_size
        {
            // First read within first window of a large file - likely out-of-order sequential
            ReadPattern::FirstWindowRead
        } else if last_pos != INVALID_U64 && last_pos.abs_diff(range.start) <= window_size {
            // Use window_size as tolerance - it grows with confidence in sequential pattern
            ReadPattern::SequentialRead
        } else {
            // Otherwise check if this is a concurrent sequential read via cache state
            self.get_potential_concurrent_read_pattern(range.clone(), window_size, data_cache)
        };

        pattern
    }

    fn get_potential_concurrent_read_pattern(
        &self,
        read_range: Range<u64>,
        tolerance_window: u64,
        data_cache: &RwLockReadGuard<'_, BTreeMap<u64, (u64, Arc<CachedData>)>>,
    ) -> ReadPattern {
        let read_start_offset = read_range.start;
        // Only allow backward seeking within the tolerance window
        let backward_seek_min = read_start_offset.saturating_sub(tolerance_window);

        // Look at cached ranges that could overlap with our tolerance window
        // We need to look at ranges that start before or at our current start position
        for (&_cached_range_start, &(cached_range_end, ref cached_data)) in
            data_cache.range(..=read_start_offset).rev()
        {
            // Exit if we hit a range that ends before our tolerance window
            if cached_range_end < backward_seek_min {
                break;
            }
            let last_cached_read_start_offset = cached_data.get_last_read_end_position();
            // Skip ranges that haven't been read yet
            if last_cached_read_start_offset == INVALID_U64 {
                continue;
            }
            // Out-of-order kernel readahead: a read behind the last-seen position
            // but still within the tolerance window is sequential, not random.
            if last_cached_read_start_offset > read_start_offset {
                if last_cached_read_start_offset <= read_start_offset + tolerance_window {
                    return ReadPattern::SequentialRead;
                }
                return ReadPattern::RandomRead;
            }
            // If we found a previous read within the tolerance window, it's sequential
            if last_cached_read_start_offset >= backward_seek_min
                && last_cached_read_start_offset <= read_start_offset
            {
                return ReadPattern::SequentialRead;
            }
        }
        // No previous read found within tolerance window
        ReadPattern::RandomRead
    }

    async fn acquire_read_lock(
        &self,
    ) -> Result<RwLockReadGuard<'_, BTreeMap<u64, (u64, Arc<CachedData>)>>, ReadAheadCacheError>
    {
        Ok(self.data_cache.read().await)
    }

    async fn acquire_write_lock(
        &self,
    ) -> Result<RwLockWriteGuard<'_, BTreeMap<u64, (u64, Arc<CachedData>)>>, ReadAheadCacheError>
    {
        Ok(self.data_cache.write().await)
    }

    /// Insert a range with an existing write lock guard
    fn insert_range_with_guard(
        &self,
        range: Range<u64>,
        cached_data: Arc<CachedData>,
        data_cache: &mut RwLockWriteGuard<'_, BTreeMap<u64, (u64, Arc<CachedData>)>>,
    ) -> Result<bool, ReadAheadCacheError> {
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
        // If this is a unique range we will add the range to the cache without loaded data
        // to act as a marker until we load the data in
        if !does_requested_range_overlap_in_cache(data_cache, &range) {
            data_cache.insert(range.start, (range.end, cached_data));
            self.lru_insert(range.start);
            return Ok(true);
        }
        Ok(false)
    }

    /// Collect cached ranges that overlap with the request.
    /// Returns all available cached ranges (may be partial - gaps are OK).
    fn collect_cached_ranges<T>(
        &self,
        _read_bypass_request_context: &ReadBypassRequestContext,
        requested_range: Range<u64>,
        data_cache: &T,
    ) -> Result<Vec<(Range<u64>, u64, u64, Arc<CachedData>)>, ReadAheadCacheError>
    where
        T: std::ops::Deref<Target = BTreeMap<u64, (u64, Arc<CachedData>)>>,
    {
        if requested_range.start >= requested_range.end {
            return Err(ReadAheadCacheError {
                message: format!(
                    "Invalid range: start ({}) must be less than end ({})",
                    requested_range.start, requested_range.end
                ),
            });
        }

        let mut ranges_to_fetch: Vec<(Range<u64>, u64, u64, Arc<CachedData>)> = Vec::new();

        for (&cached_range_start, (cached_range_end, cached_data)) in
            data_cache.range(..=requested_range.end)
        {
            if cached_range_start >= requested_range.end {
                break;
            }
            if *cached_range_end <= requested_range.start {
                continue;
            }

            let overlap_start = requested_range.start.max(cached_range_start);
            let overlap_end = requested_range.end.min(*cached_range_end);
            if overlap_start >= overlap_end {
                continue;
            }

            let relative_start = overlap_start - cached_range_start;
            let relative_end = overlap_end - cached_range_start;
            ranges_to_fetch.push((
                relative_start..relative_end,
                cached_range_start,
                *cached_range_end,
                cached_data.clone(),
            ));
        }

        Ok(ranges_to_fetch)
    }

    /// Fetch data from collected CachedData references. May wait for loading entries.
    /// Lock should be released before calling this.
    /// Returns Vec of (absolute_range, bytes) preserving range info for later combining.
    /// When `track_consumption` is true, updates bytes_read / LRU for eviction.
    async fn fetch_from_cached_ranges(
        &self,
        read_bypass_request_context: &ReadBypassRequestContext,
        ranges: Vec<(Range<u64>, u64, u64, Arc<CachedData>)>,
        track_consumption: bool,
    ) -> Result<Vec<(Range<u64>, Bytes)>, ReadAheadCacheError> {
        let mut result_parts: Vec<(Range<u64>, Bytes)> = Vec::new();

        for (relative_range, cached_start, cached_end, cached_data) in ranges {
            match cached_data.get_data_range(relative_range.clone()).await {
                Ok(data) => {
                    if track_consumption {
                        let absolute_end = cached_start + relative_range.end;
                        let _ = cached_data.set_last_read_end_position(absolute_end);

                        // Track cumulative bytes served. Once total bytes read
                        // reaches the range size the kernel page cache backs the
                        // entire range and our copy is cheapest to discard.
                        let read_len = relative_range.end - relative_range.start;
                        cached_data.add_bytes_read(read_len);
                        let range_size = cached_end - cached_start;
                        if cached_data.get_bytes_read() >= range_size {
                            self.lru_demote(cached_start);
                        } else {
                            self.lru_touch(cached_start);
                        }
                    }

                    // Convert to absolute range
                    let absolute_start = cached_start + relative_range.start;
                    let absolute_end = cached_start + relative_range.end;
                    result_parts.push((absolute_start..absolute_end, data));
                }
                Err(err) => {
                    ctx_warn!(
                        read_bypass_request_context,
                        "Error getting data from cached range: {}",
                        err
                    );
                    return Err(err);
                }
            }
        }

        Ok(result_parts)
    }

    /// Combine multiple (Range, Bytes) into a single Bytes for the expected range.
    /// Validates that ranges cover the expected range (may extend beyond).
    fn combine_ranges(
        mut ranges: Vec<(Range<u64>, Bytes)>,
        expected: Range<u64>,
    ) -> Result<Bytes, ReadAheadCacheError> {
        if ranges.is_empty() {
            return Err(ReadAheadCacheError {
                message: format!("No data for range {}..{}", expected.start, expected.end),
            });
        }

        ranges.sort_by_key(|(r, _)| r.start);

        // Validate contiguous coverage of expected range
        let mut pos = expected.start;
        for (range, _) in &ranges {
            // Allow ranges that start before expected (will be trimmed)
            if range.end <= pos {
                continue; // Range entirely before current position
            }
            if range.start > pos {
                return Err(ReadAheadCacheError {
                    message: format!(
                        "Gap in data at offset {}, next range starts at {}",
                        pos, range.start
                    ),
                });
            }
            pos = range.end;
            if pos >= expected.end {
                break; // We have enough
            }
        }
        if pos < expected.end {
            return Err(ReadAheadCacheError {
                message: format!("Data ends at {} but expected {}", pos, expected.end),
            });
        }

        // Extract just the expected range
        let expected_len = (expected.end - expected.start) as usize;
        let mut result = BytesMut::with_capacity(expected_len);

        for (range, bytes) in &ranges {
            if range.end <= expected.start || range.start >= expected.end {
                continue; // No overlap
            }
            let overlap_start = range.start.max(expected.start);
            let overlap_end = range.end.min(expected.end);
            let local_start = (overlap_start - range.start) as usize;
            let local_end = (overlap_end - range.start) as usize;
            result.extend_from_slice(&bytes[local_start..local_end]);
        }

        Ok(result.freeze())
    }

    /// Calculate the range to fetch from S3 based on the read request and readahead strategy
    fn get_range_to_fetch(
        &self,
        requested_range: Range<u64>,
        read_pattern: ReadPattern,
        file_size: u64,
    ) -> Range<u64> {
        if !read_pattern.invokes_readahead() {
            return requested_range;
        }

        // For FirstWindowRead, start from 0 to cover the beginning of the file
        let fetch_start = if read_pattern == ReadPattern::FirstWindowRead {
            0
        } else {
            requested_range.start
        };

        // Fetch from start to start + window_size, capped at file_size
        // This ensures total inline fetch is at most window_size bytes
        // Use max with requested_range.end to ensure we always satisfy the request
        let current_window_size = self.window_size.load(Ordering::Relaxed);
        let fetch_end = file_size.min((fetch_start + current_window_size).max(requested_range.end));
        fetch_start..fetch_end
    }

    /// Calculate which ranges within fetch_range are missing from the cache and need to be fetched
    fn get_missing_ranges(
        &self,
        fetch_range: Range<u64>,
        data_cache: &BTreeMap<u64, (u64, Arc<CachedData>)>,
    ) -> Result<Vec<Range<u64>>, ReadAheadCacheError> {
        let mut missing_ranges = Vec::new();
        let mut current_pos = fetch_range.start;

        if log::log_enabled!(log::Level::Trace) {
            trace!("data_cache has {} entries:", data_cache.len());
            for (start, (end, _)) in data_cache.iter() {
                trace!("  Range: {} - {}", start, end);
            }
        }

        for (&cached_start, &(cached_end, _)) in data_cache.range(..fetch_range.end) {
            if cached_end <= fetch_range.start {
                continue;
            }

            let overlap_start = cached_start.max(fetch_range.start);
            let overlap_end = cached_end.min(fetch_range.end);

            if current_pos < overlap_start {
                missing_ranges.push(current_pos..overlap_start);
            }

            current_pos = current_pos.max(overlap_end);
            if current_pos >= fetch_range.end {
                break;
            }
        }

        if current_pos < fetch_range.end {
            missing_ranges.push(current_pos..fetch_range.end);
        }

        Ok(missing_ranges)
    }

    /// Returns (s3_ranges, hit_memory_pressure)
    /// s3_ranges contains (range, data) pairs for all required S3-fetched data
    async fn fetch_missing_ranges_from_s3(
        &self,
        read_bypass_request_context: Arc<ReadBypassRequestContext>,
        missing_ranges: Vec<Range<u64>>,
        cached_data_objects: Vec<Arc<CachedData>>,
        original_request_range: Range<u64>,
        s3_data_reader: &dyn S3DataReader,
        s3_data_locator: &awsfile_bypass_data_locator,
    ) -> Result<(Vec<(Range<u64>, Bytes)>, bool), ReadAheadCacheError> {
        ctx_debug!(
            read_bypass_request_context,
            "Fetching {} missing ranges from S3",
            missing_ranges.len()
        );
        let mut tasks = Vec::new();

        // Submit read tasks for the missing ranges
        for (missing_range, cached_data) in missing_ranges
            .into_iter()
            .zip(cached_data_objects.into_iter())
        {
            // Track if this range is needed for the original request
            let is_required = missing_range.start < original_request_range.end
                && missing_range.end > original_request_range.start;

            let range_locator = awsfile_bypass_data_locator {
                bucket_name: s3_data_locator.bucket_name.clone(),
                s3_key: s3_data_locator.s3_key.clone(),
                etag: s3_data_locator.etag.clone(),
                version_id: s3_data_locator.version_id.clone(),
                offset: missing_range.start,
                count: (missing_range.end - missing_range.start) as u32,
            };

            let read_task = s3_data_reader
                .spawn_read_task(
                    range_locator,
                    read_bypass_request_context.read_bypass_context.clone(),
                )
                .await;

            tasks.push((missing_range, cached_data, read_task, is_required));
        }

        let mut required_failed = false;
        let mut any_required_cache_failed = false;
        let mut all_required_data: Vec<(Range<u64>, Bytes)> = Vec::new();

        // Gather the result from the S3 reads, we will try and load into cache anything that succeeded
        // Only fail the request if required ranges fail - readahead failures are just warnings
        for (missing_range, cached_data, read_task, is_required) in tasks {
            match read_task.await {
                Ok(Ok(bytes)) => {
                    // Keep all required data in case we need to return directly
                    if is_required {
                        all_required_data.push((missing_range.clone(), bytes.clone()));
                    }
                    if let Err(e) = self
                        .load_s3_data_into_cache_direct(missing_range.clone(), bytes, cached_data)
                        .await
                    {
                        // Memory pressure - use Evicted so waiters can retry
                        self.remove_failed_entry(missing_range.start, CacheEntryState::Evicted)
                            .await;
                        if is_required {
                            ctx_warn!(
                                read_bypass_request_context,
                                "Caching failed ({}), will return data directly",
                                e.message
                            );
                            any_required_cache_failed = true;
                        }
                    }
                }
                Ok(Err(s3_error)) => {
                    // S3 failure - use Failed so file gets denylisted
                    self.remove_failed_entry(missing_range.start, CacheEntryState::Failed)
                        .await;
                    if is_required {
                        ctx_error!(
                            read_bypass_request_context,
                            "Required S3 read failed: {:?}",
                            s3_error
                        );
                        required_failed = true;
                    } else {
                        ctx_warn!(
                            read_bypass_request_context,
                            "Readahead S3 read failed (non-critical): {:?}",
                            s3_error
                        );
                    }
                }
                Err(join_error) => {
                    // Task failure - use Failed so file gets denylisted
                    self.remove_failed_entry(missing_range.start, CacheEntryState::Failed)
                        .await;
                    if is_required {
                        ctx_error!(
                            read_bypass_request_context,
                            "Required S3 task join failed: {:?}",
                            join_error
                        );
                        required_failed = true;
                    } else {
                        ctx_warn!(
                            read_bypass_request_context,
                            "Readahead S3 task join failed (non-critical): {:?}",
                            join_error
                        );
                    }
                }
            }
        }

        if required_failed {
            return Err(ReadAheadCacheError {
                message: "Required S3 read failed".to_string(),
            });
        }

        // Always return the S3 data so caller can combine with cached data
        Ok((all_required_data, any_required_cache_failed))
    }

    async fn remove_failed_entry(&self, offset: u64, state: CacheEntryState) {
        if let Ok(mut cache) = self.acquire_write_lock().await {
            // Set state before removing to wake any waiters
            if let Some((_, cached_data)) = cache.get(&offset) {
                cached_data.set_state(state);
            }
            cache.remove(&offset);
            self.lru_remove(offset);
        }
    }

    /// Load S3 data into the cache using the provided CachedData object directly
    async fn load_s3_data_into_cache_direct(
        &self,
        range: Range<u64>,
        s3_data: Bytes,
        cached_data: Arc<CachedData>,
    ) -> Result<(), ReadAheadCacheError> {
        let chunks = self.prepare_chunks_from_bytes(range, s3_data).await?;
        cached_data.load(chunks).await?;
        Ok(())
    }

    /// Load S3 data into the cache for a specific range
    #[cfg(test)]
    async fn load_s3_data_into_cache(
        &self,
        range: Range<u64>,
        s3_data: Bytes,
    ) -> Result<(), ReadAheadCacheError> {
        let cached_data = {
            let data_cache = self.acquire_read_lock().await?;
            data_cache
                .get(&range.start)
                .map(|(_, cached_data)| cached_data.clone())
        };

        let cached_data = cached_data.ok_or_else(|| ReadAheadCacheError {
            message: format!("Cached range not found for offset {}", range.start),
        })?;

        let chunks = self.prepare_chunks_from_bytes(range, s3_data).await?;
        cached_data.load(chunks).await?;
        Ok(())
    }

    async fn prepare_chunks_from_bytes(
        &self,
        range: Range<u64>,
        s3_data: Bytes,
    ) -> Result<Vec<MemoryChunk>, ReadAheadCacheError> {
        let size = range.end - range.start;

        if size != s3_data.len() as u64 {
            return Err(ReadAheadCacheError {
                message: format!(
                    "Size mismatch: requested range size ({}) != bytes_to_write length ({})",
                    size,
                    s3_data.len()
                ),
            });
        }

        let chunk_size_u64 = memory_pool::CHUNK_SIZE as u64;
        let num_chunks = size.div_ceil(chunk_size_u64) as usize;

        // Check capacity and evict if needed
        if self.memory_pool.would_exceed_capacity(num_chunks) {
            if let Some(cache) = self.cache.upgrade() {
                cache.evict_until_available(num_chunks).await;
            }
        }

        // If still over capacity, fail and let caller handle gracefully
        if self.memory_pool.would_exceed_capacity(num_chunks) {
            return Err(ReadAheadCacheError {
                message: "Memory pool at capacity".to_string(),
            });
        }

        let mut chunks = self.memory_pool.consume(num_chunks);

        // Race condition: another thread may have allocated between our check and consume
        if chunks.len() < num_chunks {
            return Err(ReadAheadCacheError {
                message: "Memory pool at capacity".to_string(),
            });
        }

        // Copy data into chunks
        let mut bytes_written = 0;
        for chunk in chunks.iter_mut() {
            let bytes_remaining = s3_data.len() - bytes_written;
            if bytes_remaining == 0 {
                break;
            }

            let bytes_to_copy = std::cmp::min(bytes_remaining, memory_pool::CHUNK_SIZE);
            let start_idx = bytes_written;
            let end_idx = start_idx + bytes_to_copy;

            chunk[..bytes_to_copy].copy_from_slice(&s3_data[start_idx..end_idx]);
            bytes_written += bytes_to_copy;
        }

        Ok(chunks)
    }

    #[cfg(test)]
    pub async fn clear_cache_entry(
        &self,
        requested_range: Range<u64>,
    ) -> Result<bool, ReadAheadCacheError> {
        let mut data_cache = self.acquire_write_lock().await?;

        if let Some((_, cached_data)) = data_cache.get_mut(&requested_range.start) {
            // Clear the data
            let result = cached_data.clear(&self.memory_pool).await?;

            if result {
                // Remove the entry from the cache
                data_cache.remove(&requested_range.start);
            }

            return Ok(result);
        }

        Ok(false)
    }

    /// Evict a single entry by offset (called by LRU eviction).
    /// Returns true if entry was evicted. Skips entries still loading.
    pub async fn evict_entry(&self, offset: u64) -> bool {
        let cached_data = {
            let Ok(mut cache) = self.data_cache.try_write() else {
                return false;
            };
            if let Some((end_offset, cached_data)) = cache.get(&offset) {
                // Skip loading entries unless they're stuck
                if cached_data.is_loading() && !cached_data.is_stuck_loading() {
                    return false;
                }
                // Skip recently loaded entries unless fully consumed
                let range_size = end_offset - offset;
                let fully_consumed = cached_data.get_bytes_read() >= range_size;
                if !fully_consumed && cached_data.is_recently_loaded(MIN_EVICTION_AGE_MS) {
                    return false;
                }
            }
            cache.remove(&offset).map(|(_, cd)| cd)
        };

        if let Some(cached_data) = cached_data {
            // Don't call lru_remove - caller already popped from LRU
            // Return true because entry was removed from data_cache, even if clear() fails.
            // On timeout, memory is freed when the Bytes holder drops.
            let _ = cached_data.clear(&self.memory_pool).await;
            return true;
        }
        false
    }

    /// Clean up stale entries: stuck loading or loaded but idle for over TTL.
    /// Returns the number of entries cleaned up.
    pub async fn cleanup_stale_entries(&self, ttl_ms: u64) -> usize {
        let to_cleanup: Vec<u64> = {
            let Ok(cache) = self.data_cache.try_read() else {
                return 0;
            };
            cache
                .iter()
                .filter(|(_, (_, cached_data))| {
                    // Evict if stuck loading OR if loaded and older than TTL
                    cached_data.is_stuck_loading()
                        || (!cached_data.is_loading() && !cached_data.is_created_within(ttl_ms))
                })
                .map(|(&offset, _)| offset)
                .collect()
        };

        if to_cleanup.is_empty() {
            return 0;
        }

        let entries_to_clear: Vec<(u64, Arc<CachedData>)> = {
            let Ok(mut cache) = self.data_cache.try_write() else {
                return 0;
            };
            to_cleanup
                .into_iter()
                .filter_map(|offset| {
                    cache
                        .remove(&offset)
                        .map(|(_, cached_data)| (offset, cached_data))
                })
                .collect()
        };

        let mut cleaned = 0;
        for (offset, cached_data) in entries_to_clear {
            if cached_data.clear(&self.memory_pool).await.is_ok() {
                cleaned += 1;
            }
            self.lru_remove(offset);
        }
        cleaned
    }

    /// Returns true if this file state has no cached ranges.
    pub fn is_empty(&self) -> bool {
        self.data_cache
            .try_read()
            .map(|cache| cache.is_empty())
            .unwrap_or(false)
    }

    /// Returns the number of cached ranges.
    #[cfg(test)]
    pub fn get_num_ranges(&self) -> usize {
        self.data_cache
            .try_read()
            .map(|cache| cache.len())
            .unwrap_or(0)
    }

    /// Returns true if a range starting at the given offset exists.
    #[cfg(test)]
    pub fn has_range_at(&self, start_offset: u64) -> bool {
        self.data_cache
            .try_read()
            .map(|cache| cache.contains_key(&start_offset))
            .unwrap_or(false)
    }

    pub fn update_read_position(&self, end_position: u64) {
        // Store the new position and update the timestamp
        self.last_read_position
            .store(end_position, Ordering::SeqCst);
        self.last_read_time
            .store(get_current_time_ms(), Ordering::SeqCst);
    }

    #[cfg(test)]
    pub fn has_valid_read_position(&self) -> bool {
        self.last_read_position.load(Ordering::SeqCst) != INVALID_U64
    }

    #[cfg(test)]
    pub fn get_last_read_position(&self) -> Option<u64> {
        let pos = self.last_read_position.load(Ordering::SeqCst);
        if pos == INVALID_U64 {
            None
        } else {
            Some(pos)
        }
    }

    #[cfg(test)]
    async fn set_cached_data_read_position(
        &self,
        range_start: u64,
        position: u64,
    ) -> Result<(), ReadAheadCacheError> {
        let mut data_cache = self.acquire_write_lock().await?;
        if let Some((_, cached_data)) = data_cache.get_mut(&range_start) {
            cached_data.set_last_read_end_position(position)?;
        }
        Ok(())
    }
}

// Determine if a requested range would overlap with an existing range of cached data
fn does_requested_range_overlap_in_cache(
    cache: &BTreeMap<u64, (u64, Arc<CachedData>)>,
    requested_range: &Range<u64>,
) -> bool {
    // Walk backwards from entries that start at or before requested_range.end
    // If we find an element who's end offset is larger than our start then this represents an overlap
    for (&_start, &(end, _)) in cache.range(..requested_range.end).rev() {
        if end > requested_range.start {
            return true;
        }
        if end <= requested_range.start {
            break;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use super::*;
    use crate::config_parser::ProxyConfig;
    use crate::memory::memory_pool::{MemoryPoolConfig, CHUNK_SIZE};
    use crate::util::read_bypass_context::ReadBypassContext;
    use std::sync::Arc;

    async fn recognize_read_pattern_with_lock(
        state: &FileReadAheadState,
        range: Range<u64>,
    ) -> ReadPattern {
        let data_cache = state.acquire_read_lock().await.unwrap();
        state.recognize_read_pattern(range, &data_cache)
    }

    async fn seek_backward_with_lock(
        state: &FileReadAheadState,
        range: Range<u64>,
        seek_back_window: u64,
    ) -> ReadPattern {
        let data_cache = state.acquire_read_lock().await.unwrap();
        state.get_potential_concurrent_read_pattern(range, seek_back_window, &data_cache)
    }

    fn create_test_memory_pool() -> Arc<MemoryPool> {
        MemoryPool::new(MemoryPoolConfig {
            initial_capacity: 5,
            min_capacity: 5,
            ..Default::default()
        })
    }

    fn create_test_state() -> Arc<FileReadAheadState> {
        let state = Arc::new(FileReadAheadState::new(
            0, // file_lru_id
            Bytes::from_static(b"test-key"),
            Bytes::from_static(b"test-etag"),
            Bytes::from_static(b"test-version-id"),
            1024 * 1024, // 1MB object size
            64 * 1024,   // 64KB window size
            64 * 1024,   // 64KB min window size
            1024 * 1024, // 1MB max window size
            create_test_memory_pool(),
            Arc::new(Mutex::new(LruCache::new(NonZeroUsize::new(100).unwrap()))),
            Weak::new(), // no cache back-reference in tests
        ));
        state.set_self_weak(Arc::downgrade(&state));
        state
    }

    /// Create test state with small file (< window_size) to avoid FirstWindowRead triggering
    fn create_test_state_small_file() -> Arc<FileReadAheadState> {
        let state = Arc::new(FileReadAheadState::new(
            0,
            Bytes::from_static(b"test-key"),
            Bytes::from_static(b"test-etag"),
            Bytes::from_static(b"test-version-id"),
            50 * 1024,   // 50KB object size (smaller than window)
            64 * 1024,   // 64KB window size
            64 * 1024,   // 64KB min window size
            1024 * 1024, // 1MB max window size
            create_test_memory_pool(),
            Arc::new(Mutex::new(LruCache::new(NonZeroUsize::new(100).unwrap()))),
            Weak::new(),
        ));
        state.set_self_weak(Arc::downgrade(&state));
        state
    }

    fn create_test_s3_data_locator(offset: u64, count: u32) -> awsfile_bypass_data_locator {
        awsfile_bypass_data_locator {
            bucket_name: b"test-bucket".to_vec(),
            s3_key: b"test-key".to_vec(),
            etag: b"test-etag".to_vec(),
            version_id: b"test-version-id".to_vec(),
            offset,
            count,
        }
    }

    fn create_test_s3_data_reader() -> Arc<dyn S3DataReader> {
        Arc::new(crate::util::s3_data_reader::S3ReadBypassReader::new(128))
    }

    async fn create_test_read_bypass_context() -> Arc<ReadBypassContext> {
        create_test_read_bypass_context_with_size(100).await
    }

    async fn create_test_read_bypass_context_with_size(size: usize) -> Arc<ReadBypassContext> {
        use aws_sdk_s3::operation::get_object::GetObjectOutput;
        use aws_sdk_s3::primitives::ByteStream;
        use aws_smithy_mocks::{mock, mock_client};
        use std::sync::Arc;

        let get_object_rule = mock!(aws_sdk_s3::Client::get_object)
            .match_requests(|_req| true)
            .then_output(move || {
                let test_data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
                GetObjectOutput::builder()
                    .content_length(test_data.len() as i64)
                    .body(ByteStream::from(test_data))
                    .e_tag("test-etag")
                    .build()
            });

        let mock_client = Arc::new(mock_client!(aws_sdk_s3, [&get_object_rule]));
        let s3_client = crate::aws::s3_client::S3Client::new_with_client(
            "test-bucket",
            "test-prefix",
            mock_client,
        )
        .await;

        let proxy_config = ProxyConfig::default();
        Arc::new(ReadBypassContext::new(
            &proxy_config,
            "test-bucket".to_string(),
            "test-prefix".to_string(),
            s3_client,
            false, // Cache disabled for test
        ))
    }

    #[tokio::test]
    async fn test_new_file_readahead_state() {
        let state = create_test_state();
        assert_eq!(state.s3_key, Bytes::from_static(b"test-key"));
        assert_eq!(state.s3_etag, Bytes::from_static(b"test-etag"));
        assert_eq!(state.file_size, 1024 * 1024);
        assert_eq!(state.window_size.load(Ordering::SeqCst), 64 * 1024);
        assert_eq!(state.last_read_position.load(Ordering::SeqCst), INVALID_U64);
        assert_eq!(state.last_read_time.load(Ordering::SeqCst), 0);
        assert_eq!(state.last_readahead_position.load(Ordering::SeqCst), 0);
        assert!(!state.has_valid_read_position());
        assert_eq!(state.get_last_read_position(), None);
    }

    #[tokio::test]
    async fn test_insert_range() {
        let state = create_test_state();

        // Insert a valid range
        let result = state.insert_range(0..100).await.unwrap();
        assert!(result);

        // Try to insert an invalid range (start >= end)
        let result = state.insert_range(100..100).await;
        assert!(result.is_err());

        // Try to insert an overlapping range
        let result = state.insert_range(50..150).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_load_range() {
        let state = create_test_state();
        let memory_pool = create_test_memory_pool();
        let test_data = "Hello, world!";
        state.insert_range(0..13).await.unwrap();

        let result = state
            .load_range(0..13, &memory_pool, test_data.into())
            .await
            .unwrap();
        assert!(result);

        // Try to load data with mismatched size
        let result = state
            .load_range(0..10, &memory_pool, test_data.into())
            .await;
        assert!(result.is_err());

        // Try to load data for a non-existent range - should fail fast
        let result = state
            .load_range(100..110, &memory_pool, "0123456789".into())
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_clear_cache_entry() {
        let state = create_test_state();
        let test_data = "Hello, world!";
        state.insert_range(0..13).await.unwrap();
        state
            .load_range(0..13, &state.memory_pool, test_data.into())
            .await
            .unwrap();

        let result = state.clear_cache_entry(0..13).await.unwrap();
        assert!(result);
        let result = state.clear_cache_entry(100..110).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_recognize_read_pattern_start_of_file() {
        let state = create_test_state();
        // Reading from start of file should always be sequential
        let pattern = recognize_read_pattern_with_lock(&state, 0..100).await;
        assert_eq!(pattern, ReadPattern::StartOfFile);
    }

    #[tokio::test]
    async fn test_recognize_read_pattern_simple_sequential() {
        let state = create_test_state();
        state.update_read_position(100);
        // Strictly sequential next read
        let pattern = recognize_read_pattern_with_lock(&state, 100..200).await;
        assert_eq!(pattern, ReadPattern::SequentialRead);
    }

    #[tokio::test]
    async fn test_recognize_read_pattern_random_read() {
        let state = create_test_state();

        // Set up a previous read position
        state.update_read_position(100);

        // Read that jumps beyond window_size (64KB in test state) - should be random
        let window_size = state.window_size.load(Ordering::SeqCst);
        let jump_offset = 100 + window_size + 1;
        let pattern =
            recognize_read_pattern_with_lock(&state, jump_offset..jump_offset + 100).await;
        assert_eq!(pattern, ReadPattern::RandomRead);
    }

    #[tokio::test]
    async fn test_recognize_read_pattern_backward_read() {
        let state = create_test_state();

        // Set up a previous read position
        state.update_read_position(100);

        // Small backward read within window_size tolerance is now SequentialRead (bidirectional)
        let pattern = recognize_read_pattern_with_lock(&state, 50..60).await;
        assert_eq!(pattern, ReadPattern::SequentialRead);

        // Large backward read beyond window_size should be RandomRead
        let window_size = state.window_size.load(std::sync::atomic::Ordering::SeqCst);
        state.update_read_position(window_size + 1000);
        // Use offset 10 (not 0) to avoid StartOfFile pattern
        let pattern = recognize_read_pattern_with_lock(&state, 10..20).await;
        assert_eq!(pattern, ReadPattern::RandomRead);
    }

    #[tokio::test]
    async fn test_mid_file_sequential_reads_detected_via_position_update() {
        // Regression test: sequential reads starting beyond window_size must
        // transition from RandomRead to SequentialRead. Before the fix,
        // update_read_position was only called for invokes_readahead()
        // patterns, so last_read_position stayed INVALID and every read
        // was classified as RandomRead.
        let state = create_test_state(); // file=1MB, window=64KB
        let file_size = state.file_size;
        let memory_pool = create_test_memory_pool();
        let window_size = state.window_size.load(Ordering::SeqCst);
        let io_size: u64 = 1024;

        // Pre-populate cache at an offset beyond window_size
        let offset = window_size + io_size;
        let test_data = vec![0xABu8; io_size as usize];
        state.insert_range(offset..offset + io_size).await.unwrap();
        state
            .load_range(
                offset..offset + io_size,
                &memory_pool,
                Bytes::from(test_data),
            )
            .await
            .unwrap();

        // Read from cache via get_data — verify it's RandomRead first (beyond window)
        let pattern = recognize_read_pattern_with_lock(&state, offset..offset + io_size).await;
        assert_eq!(pattern, ReadPattern::RandomRead);

        let s3_data_reader = create_test_s3_data_reader();
        let ctx = create_test_read_bypass_context_with_size(io_size as usize).await;
        let req_ctx = Arc::new(ReadBypassRequestContext::new(ctx, 0));
        let locator = create_test_s3_data_locator(offset, io_size as u32);
        let result = state
            .clone()
            .get_data(req_ctx, &locator, file_size, s3_data_reader, false)
            .await;
        assert!(result.is_ok());

        // Position should be updated even though it was RandomRead
        assert_eq!(
            state.last_read_position.load(Ordering::SeqCst),
            offset + io_size
        );

        // Second read immediately after -> should be SequentialRead (not RandomRead)
        let next_offset = offset + io_size;
        let pattern =
            recognize_read_pattern_with_lock(&state, next_offset..next_offset + io_size).await;
        assert_eq!(pattern, ReadPattern::SequentialRead);
    }

    #[tokio::test]
    async fn test_seek_backward_no_cached_data() {
        let state = create_test_state();
        // No cached data, should be random
        let pattern = seek_backward_with_lock(&state, 100..200, 0).await;
        assert_eq!(pattern, ReadPattern::RandomRead);
    }

    #[tokio::test]
    async fn test_seek_backward_with_cached_data_sequential() {
        let state = create_test_state();
        let memory_pool = create_test_memory_pool();

        // Insert and load some cached data
        state.insert_range(0..100).await.unwrap();
        state
            .load_range(0..100, &memory_pool, "a".repeat(100).into())
            .await
            .unwrap();

        // Simulate that the cached range was read up to position 100
        state.set_cached_data_read_position(0, 100).await.unwrap();

        // Now seek backward from position 100 - should find the previous read
        let pattern = seek_backward_with_lock(&state, 100..200, 0).await;
        assert_eq!(pattern, ReadPattern::SequentialRead);
    }

    #[tokio::test]
    async fn test_seek_backward_with_seek_window() {
        let state = create_test_state();
        let memory_pool = create_test_memory_pool();

        // Insert and load some cached data
        state.insert_range(0..100).await.unwrap();
        state
            .load_range(0..100, &memory_pool, "a".repeat(100).into())
            .await
            .unwrap();

        // Simulate that the cached range was read up to position 90
        state.set_cached_data_read_position(0, 90).await.unwrap();

        // With seek_back_window = 20, reading from 100 should find the read at 90
        let pattern = seek_backward_with_lock(&state, 100..110, 20).await;
        assert_eq!(pattern, ReadPattern::SequentialRead);

        // With seek_back_window = 5, reading from 100 should NOT find the read at 90
        let pattern = seek_backward_with_lock(&state, 100..110, 5).await;
        assert_eq!(pattern, ReadPattern::RandomRead);
    }

    #[tokio::test]
    async fn test_recognize_read_pattern() {
        let state = create_test_state();
        let memory_pool = create_test_memory_pool();

        let pattern = recognize_read_pattern_with_lock(&state, 0..100).await;
        assert_eq!(pattern, ReadPattern::StartOfFile);

        // Update read position and add some cached data
        state.update_read_position(100);
        state.insert_range(0..100).await.unwrap();
        state
            .load_range(0..100, &memory_pool, "a".repeat(100).into())
            .await
            .unwrap();

        // Set the cached data's read position
        state.set_cached_data_read_position(0, 100).await.unwrap();

        // Now test that continuing from position 100 is still sequential
        let pattern = recognize_read_pattern_with_lock(&state, 100..200).await;
        assert_eq!(pattern, ReadPattern::SequentialRead);

        // Test that jumping to a far location falls back to seek_backward logic
        state.update_read_position(50); // Set to a different position
        let pattern = recognize_read_pattern_with_lock(&state, 100..200).await;
        // Should find the cached read at position 100 and determine it's sequential
        assert_eq!(pattern, ReadPattern::SequentialRead);
    }

    #[tokio::test]
    async fn test_out_of_order_concurrent_reads_detected_as_sequential() {
        // Simulates NFS client sending concurrent sequential reads that arrive out of order
        // e.g., reads for offsets 0, 100, 200 sent together but 200 processed before 100
        let state = create_test_state();
        let memory_pool = create_test_memory_pool();

        // Insert and load cached data for range 0..300
        state.insert_range(0..300).await.unwrap();
        state
            .load_range(0..300, &memory_pool, "a".repeat(300).into())
            .await
            .unwrap();

        // Simulate read at offset 0 completing first
        state.set_cached_data_read_position(0, 100).await.unwrap();
        state.update_read_position(100);

        // Simulate read at offset 200 arriving and completing before offset 100
        // This updates last_read_position to 300
        state.set_cached_data_read_position(0, 300).await.unwrap();
        state.update_read_position(300);

        // Now read at offset 100 arrives late - should still be detected as sequential
        // because there's a cached read ending at 100 within the seek back window
        state.set_cached_data_read_position(0, 100).await.unwrap();
        let pattern = recognize_read_pattern_with_lock(&state, 100..200).await;
        assert_eq!(
            pattern,
            ReadPattern::SequentialRead,
            "Late-arriving sequential read should be detected as sequential"
        );
    }

    #[tokio::test]
    async fn test_get_range_to_fetch_sequential_read() {
        let state = create_test_state();
        let file_size = 1024 * 1024;
        let window_size = state.window_size.load(Ordering::SeqCst);

        // Sequential read: fetch_end = start + window_size
        let range = state.get_range_to_fetch(0..1024, ReadPattern::SequentialRead, file_size);
        assert_eq!(range, 0..window_size);

        // StartOfFile pattern should behave the same
        let range = state.get_range_to_fetch(0..1024, ReadPattern::StartOfFile, file_size);
        assert_eq!(range, 0..window_size);
    }

    #[tokio::test]
    async fn test_get_range_to_fetch_random_read() {
        let state = create_test_state();
        let file_size = 1024 * 1024;

        // Random read: no readahead, just return requested range
        let range = state.get_range_to_fetch(100..200, ReadPattern::RandomRead, file_size);
        assert_eq!(range, 100..200);
    }

    #[tokio::test]
    async fn test_get_range_to_fetch_capped_at_file_size() {
        let state = create_test_state();
        let file_size = 1000;
        let _window_size = state.window_size.load(Ordering::SeqCst); // 64KB > file_size

        let range = state.get_range_to_fetch(0..100, ReadPattern::SequentialRead, file_size);
        assert_eq!(range, 0..file_size);
    }

    #[tokio::test]
    async fn test_get_range_to_fetch_large_request() {
        let state = create_test_state();
        let file_size = 1024 * 1024;
        let window_size = state.window_size.load(Ordering::SeqCst);

        // Request larger than window: should still satisfy the full request
        let large_request = 0..(window_size + 1000);
        let range = state.get_range_to_fetch(
            large_request.clone(),
            ReadPattern::SequentialRead,
            file_size,
        );
        assert_eq!(range.start, 0);
        assert!(
            range.end >= large_request.end,
            "Must satisfy the full request"
        );
    }

    #[tokio::test]
    async fn test_get_missing_ranges_no_cached_ranges() {
        let state = create_test_state();
        let data_cache = BTreeMap::new();

        let missing_ranges = state.get_missing_ranges(100..500, &data_cache).unwrap();
        assert_eq!(missing_ranges, vec![100..500]);
    }

    #[tokio::test]
    async fn test_calculate_missing_ranges_full_overlap() {
        let state = create_test_state();
        let mut data_cache = BTreeMap::new();
        data_cache.insert(50, (600, Arc::new(CachedData::new())));

        let missing_ranges = state.get_missing_ranges(100..500, &data_cache).unwrap();
        assert_eq!(missing_ranges, Vec::<Range<u64>>::new());
    }

    #[tokio::test]
    async fn test_calculate_missing_ranges_partial_overlap() {
        let state = create_test_state();
        let mut data_cache = BTreeMap::new();
        data_cache.insert(200, (300, Arc::new(CachedData::new())));

        // Should have two ranges to fetch at the start and end of the range
        let missing_ranges = state.get_missing_ranges(100..500, &data_cache).unwrap();
        assert_eq!(missing_ranges, vec![100..200, 300..500]);
    }

    #[tokio::test]
    async fn test_get_missing_ranges_overlapping_boundaries() {
        let state = create_test_state();
        let mut data_cache = BTreeMap::new();
        data_cache.insert(50, (150, Arc::new(CachedData::new())));
        data_cache.insert(350, (550, Arc::new(CachedData::new())));

        let missing_ranges = state.get_missing_ranges(100..500, &data_cache).unwrap();
        assert_eq!(missing_ranges, vec![150..350]);
    }

    #[tokio::test]
    async fn test_get_missing_ranges_cache_beyond_fetch_range() {
        let state = create_test_state();
        let mut data_cache = BTreeMap::new();
        // Cache that starts after our fetch range
        data_cache.insert(600, (700, Arc::new(CachedData::new())));

        let missing_ranges = state.get_missing_ranges(100..500, &data_cache).unwrap();
        assert_eq!(missing_ranges, vec![100..500]);
    }

    #[tokio::test]
    async fn test_get_missing_ranges_cache_before_fetch_range() {
        let state = create_test_state();
        let mut data_cache = BTreeMap::new();
        // Cache that ends before our fetch range
        data_cache.insert(10, (50, Arc::new(CachedData::new())));

        let missing_ranges = state.get_missing_ranges(100..500, &data_cache).unwrap();
        assert_eq!(missing_ranges, vec![100..500]);
    }

    #[tokio::test]
    async fn test_get_data_cache_hit() {
        let state = create_test_state();
        let memory_pool = create_test_memory_pool();
        let file_size = 1024 * 1024;
        // Pre-populate cache with test data
        let test_data = "Hello, world! This is test data.";
        state.insert_range(0..test_data.len() as u64).await.unwrap();
        state
            .load_range(0..test_data.len() as u64, &memory_pool, test_data.into())
            .await
            .unwrap();

        // Request data that's already in cache
        let s3_data_reader = create_test_s3_data_reader();
        let read_bypass_context = create_test_read_bypass_context().await;
        let read_bypass_request_context = ReadBypassRequestContext::new(read_bypass_context, 0);
        let s3_data_locator = create_test_s3_data_locator(0, 13);
        let result = state
            .clone()
            .get_data(
                Arc::new(read_bypass_request_context),
                &s3_data_locator,
                file_size,
                s3_data_reader,
                false, // suppress_readahead
            )
            .await;

        assert!(result.is_ok());
        let (data, _) = result.unwrap();
        assert!(data.is_some());
        let data_vec = data.unwrap();
        assert_eq!(data_vec, "Hello, world!".as_bytes());
    }

    #[tokio::test]
    async fn test_get_data_cache_miss() {
        // Use small file state to avoid FirstWindowRead triggering readahead with mock reader
        let state = create_test_state_small_file();
        let file_size = state.file_size;

        // Request data that's not in cache
        let s3_data_reader = create_test_s3_data_reader();
        let read_bypass_context = create_test_read_bypass_context().await;
        let read_bypass_request_context = ReadBypassRequestContext::new(read_bypass_context, 0);
        let s3_data_locator = create_test_s3_data_locator(100, 100);
        let result = state
            .clone()
            .get_data(
                Arc::new(read_bypass_request_context),
                &s3_data_locator,
                file_size,
                s3_data_reader,
                false, // suppress_readahead
            )
            .await;

        assert!(result.is_ok(), "Error: {:?}", result.err());
        let (data, _) = result.unwrap();
        assert!(data.is_some());
        let data_vec = data.unwrap();
        assert_eq!(data_vec.len(), 100);
        let expected: Vec<u8> = (0..100).map(|i| (i % 256) as u8).collect();
        assert_eq!(data_vec, expected);
    }

    #[tokio::test]
    async fn test_get_data_file_size_boundary() {
        // Use small file state to avoid FirstWindowRead triggering readahead with mock reader
        let state = create_test_state_small_file();
        let file_size = 200; // Small file

        // Request near end of file
        let s3_data_reader = create_test_s3_data_reader();
        let read_bypass_context = create_test_read_bypass_context_with_size(50).await;
        let read_bypass_request_context = ReadBypassRequestContext::new(read_bypass_context, 0);
        let s3_data_locator = create_test_s3_data_locator(150, 50);
        let result = state
            .clone()
            .get_data(
                Arc::new(read_bypass_request_context),
                &s3_data_locator,
                file_size,
                s3_data_reader,
                false, // suppress_readahead
            )
            .await;

        assert!(result.is_ok());
        let (data, _) = result.unwrap();
        assert!(data.is_some());
        let returned_data = data.unwrap();
        assert_eq!(returned_data.len(), 50);
        let expected: Vec<u8> = (0..50).map(|i| (i % 256) as u8).collect();
        assert_eq!(returned_data, expected);

        // Readahead shouldn't exceed file size
        let last_ra_pos = state.last_readahead_position.load(Ordering::Relaxed);
        assert!(last_ra_pos <= file_size);
    }

    #[tokio::test]
    async fn test_get_data_zero_count_returns_empty() {
        let state = create_test_state();
        let file_size = 1024 * 1024;

        let s3_data_reader = create_test_s3_data_reader();
        let read_bypass_context = create_test_read_bypass_context().await;
        let read_bypass_request_context = ReadBypassRequestContext::new(read_bypass_context, 0);
        let s3_data_locator = create_test_s3_data_locator(100, 0);
        let (data, _) = state
            .clone()
            .get_data(
                Arc::new(read_bypass_request_context),
                &s3_data_locator,
                file_size,
                s3_data_reader,
                false, // suppress_readahead
            )
            .await
            .unwrap();
        let result = data.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_adjacent_ranges_not_overlapping() {
        let mut cache = BTreeMap::new();
        cache.insert(0, (100, Arc::new(CachedData::new())));

        // Request starts exactly where cache ends - should NOT overlap
        assert!(!does_requested_range_overlap_in_cache(&cache, &(100..200)));

        // Request ends exactly where cache starts - should NOT overlap
        cache.clear();
        cache.insert(200, (300, Arc::new(CachedData::new())));
        assert!(!does_requested_range_overlap_in_cache(&cache, &(100..200)));
    }

    #[tokio::test]
    async fn test_get_missing_ranges_cache_starts_at_fetch_end() {
        let state = create_test_state();
        let mut data_cache = BTreeMap::new();
        // Cache starts exactly at fetch_range.end
        data_cache.insert(500, (600, Arc::new(CachedData::new())));

        let missing_ranges = state.get_missing_ranges(100..500, &data_cache).unwrap();
        // Should return entire range - cache at 500 doesn't overlap [100, 500)
        assert_eq!(missing_ranges, vec![100..500]);
    }

    #[tokio::test]
    async fn test_get_missing_ranges_cache_ends_at_fetch_start() {
        let state = create_test_state();
        let mut data_cache = BTreeMap::new();
        // Cache ends exactly at fetch_range.start
        data_cache.insert(0, (100, Arc::new(CachedData::new())));

        let missing_ranges = state.get_missing_ranges(100..500, &data_cache).unwrap();
        // Should return entire range - cache ending at 100 doesn't overlap [100, 500)
        assert_eq!(missing_ranges, vec![100..500]);
    }

    #[tokio::test]
    async fn test_get_data_eof_handling() {
        let state = create_test_state();
        let file_size = 1000;
        let s3_data_reader = create_test_s3_data_reader();
        let read_bypass_context = create_test_read_bypass_context().await;
        let read_bypass_request_context =
            Arc::new(ReadBypassRequestContext::new(read_bypass_context, 0));
        // Read at EOF (offset == file_size) returns empty
        let locator = create_test_s3_data_locator(file_size, 100);
        let (data, _) = state
            .clone()
            .get_data(
                read_bypass_request_context.clone(),
                &locator,
                file_size,
                s3_data_reader.clone(),
                false,
            )
            .await
            .unwrap();
        assert!(data.unwrap().is_empty());

        // Read past EOF (offset > file_size) returns empty
        let locator = create_test_s3_data_locator(file_size + 1, 100);
        let (data, _) = state
            .clone()
            .get_data(
                read_bypass_request_context.clone(),
                &locator,
                file_size,
                s3_data_reader,
                false, // suppress_readahead
            )
            .await
            .unwrap();
        assert!(data.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_get_data_spanning_eof_returns_eof() {
        // Use small file state to avoid FirstWindowRead triggering readahead with mock reader
        let state = create_test_state_small_file();
        let file_size = 150;
        let s3_data_reader = create_test_s3_data_reader();
        let read_bypass_context = create_test_read_bypass_context_with_size(50).await;
        let read_bypass_request_context = ReadBypassRequestContext::new(read_bypass_context, 0);
        // Request 100 bytes at offset 100, but file is only 150 bytes
        // Should return 50 bytes
        let locator = create_test_s3_data_locator(100, 100);
        let (data, _) = state
            .clone()
            .get_data(
                Arc::new(read_bypass_request_context),
                &locator,
                file_size,
                s3_data_reader,
                false, // suppress_readahead
            )
            .await
            .unwrap();
        assert_eq!(data.unwrap().len(), 50);
    }

    // Test helper methods
    impl FileReadAheadState {
        #[cfg(test)]
        pub(crate) async fn insert_range(
            &self,
            range: Range<u64>,
        ) -> Result<bool, ReadAheadCacheError> {
            let cached_data = CachedData::new();
            let mut data_cache = self.acquire_write_lock().await?;
            self.insert_range_with_guard(range, Arc::new(cached_data), &mut data_cache)
        }

        #[cfg(test)]
        pub(crate) async fn load_range(
            &self,
            requested_range: Range<u64>,
            _memory_pool: &Arc<MemoryPool>,
            bytes_to_write: Bytes,
        ) -> Result<bool, ReadAheadCacheError> {
            self.load_s3_data_into_cache(requested_range, bytes_to_write)
                .await?;
            Ok(true)
        }
    }

    use crate::test_utils::CountingS3DataReader;

    #[tokio::test]
    async fn test_speculative_readahead_triggered_on_cache_hit() {
        let state = create_test_state();
        let mock_reader = Arc::new(CountingS3DataReader::new());
        let read_bypass_context = create_test_read_bypass_context().await;
        let read_bypass_request_context =
            Arc::new(ReadBypassRequestContext::new(read_bypass_context, 0));
        // First read - populates cache
        let locator = create_test_s3_data_locator(0, 1024);
        let _ = state
            .clone()
            .get_data(
                read_bypass_request_context.clone(),
                &locator,
                state.file_size,
                mock_reader.clone(),
                false,
            )
            .await;

        let calls_after_first = mock_reader.calls();

        // Second sequential read - should hit cache and trigger speculative readahead
        let locator2 = create_test_s3_data_locator(1024, 1024);
        let _ = state
            .clone()
            .get_data(
                read_bypass_request_context.clone(),
                &locator2,
                state.file_size,
                mock_reader.clone(),
                false,
            )
            .await;

        // Give spawned task time to run
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Should have more calls from speculative readahead
        assert!(mock_reader.calls() > calls_after_first);
    }

    #[tokio::test]
    async fn test_speculative_readahead_not_triggered_on_random_read() {
        let state = create_test_state();
        let mock_reader = Arc::new(CountingS3DataReader::new());
        let read_bypass_context = create_test_read_bypass_context().await;
        let read_bypass_request_context = ReadBypassRequestContext::new(read_bypass_context, 0);
        // Random read far away (beyond window_size) - should NOT trigger speculative readahead
        let window_size = state.window_size.load(Ordering::SeqCst);
        let locator = create_test_s3_data_locator(window_size + 100000, 1024);
        let _ = state
            .clone()
            .get_data(
                Arc::new(read_bypass_request_context),
                &locator,
                state.file_size,
                mock_reader.clone(),
                false,
            )
            .await;

        // Give time for any spawned tasks
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Random read should fetch data but not trigger speculative readahead
        // So we should only see calls for the actual fetch, not extra readahead calls
        let _calls = mock_reader.call_count.load(Ordering::SeqCst);

        // With random read pattern, window shouldn't double
        let window = state.window_size.load(Ordering::SeqCst);
        assert_eq!(window, 64 * 1024, "Window should not grow on random read");
    }

    #[tokio::test]
    async fn test_window_doubles_on_sequential_read() {
        let state = create_test_state();
        let initial_window = state.window_size.load(Ordering::SeqCst);
        let mock_reader = Arc::new(CountingS3DataReader::new());
        let read_bypass_context = create_test_read_bypass_context().await;
        let read_bypass_request_context = ReadBypassRequestContext::new(read_bypass_context, 0);
        // Sequential read from start
        let locator = create_test_s3_data_locator(0, 1024);
        let _ = state
            .clone()
            .get_data(
                Arc::new(read_bypass_request_context),
                &locator,
                state.file_size,
                mock_reader.clone(),
                false,
            )
            .await;

        let window_after = state.window_size.load(Ordering::SeqCst);
        assert_eq!(window_after, initial_window * 2);
    }

    #[tokio::test]
    async fn test_window_halves_on_random_read() {
        // Create state with room to shrink: initial=256KB, min=64KB
        // File must be large enough for the random offset
        let state = Arc::new(FileReadAheadState::new(
            0,
            Bytes::from_static(b"test-key"),
            Bytes::from_static(b"test-etag"),
            Bytes::from_static(b""),
            32 * 1024 * 1024, // 32MB file
            256 * 1024,       // 256KB initial window
            64 * 1024,        // 64KB min window
            1024 * 1024,
            create_test_memory_pool(),
            Arc::new(Mutex::new(LruCache::new(NonZeroUsize::new(100).unwrap()))),
            Weak::new(),
        ));
        state.set_self_weak(Arc::downgrade(&state));

        let mock_reader = Arc::new(CountingS3DataReader::new());
        let read_bypass_context = create_test_read_bypass_context().await;
        let read_bypass_request_context = ReadBypassRequestContext::new(read_bypass_context, 0);

        // Random read far from start (beyond window_size, must be within file size)
        let window_size = state.window_size.load(Ordering::SeqCst);
        let locator = create_test_s3_data_locator(window_size + 100000, 1024);
        let _ = state
            .clone()
            .get_data(
                Arc::new(read_bypass_request_context),
                &locator,
                state.file_size,
                mock_reader.clone(),
                false,
            )
            .await;

        let window = state.window_size.load(Ordering::SeqCst);
        // shrink_window steps down in same order as grow: 256KB -> 128KB
        assert_eq!(window, 128 * 1024, "Window should step down on random read");
    }

    #[tokio::test]
    async fn test_window_halves_floors_at_min() {
        // Create state at min window size
        let state = Arc::new(FileReadAheadState::new(
            0,
            Bytes::from_static(b"test-key"),
            Bytes::from_static(b"test-etag"),
            Bytes::from_static(b""),
            1024 * 1024,
            64 * 1024, // initial = min
            64 * 1024, // min
            1024 * 1024,
            create_test_memory_pool(),
            Arc::new(Mutex::new(LruCache::new(NonZeroUsize::new(100).unwrap()))),
            Weak::new(),
        ));
        state.set_self_weak(Arc::downgrade(&state));

        let mock_reader = Arc::new(CountingS3DataReader::new());
        let read_bypass_context = create_test_read_bypass_context().await;
        let read_bypass_request_context = ReadBypassRequestContext::new(read_bypass_context, 0);

        // Random read (beyond window_size)
        let window_size = state.window_size.load(Ordering::SeqCst);
        let locator = create_test_s3_data_locator(window_size + 100000, 1024);
        let _ = state
            .clone()
            .get_data(
                Arc::new(read_bypass_request_context),
                &locator,
                state.file_size,
                mock_reader.clone(),
                false,
            )
            .await;

        let window = state.window_size.load(Ordering::SeqCst);
        assert_eq!(window, 64 * 1024, "Window should not shrink below min");
    }

    #[test]
    fn test_shrink_window_same_order_as_grow() {
        // Test that shrink_window steps down in the same order as grow_window.
        // With min=8MB and max=48MB, simple halving would give 48->24->12->6.
        // We want 48->32->16->8 to match the grow order.
        let min = 8 * 1024 * 1024;
        let max = 48 * 1024 * 1024;
        let state = Arc::new(FileReadAheadState::new(
            0,
            Bytes::from_static(b"test-key"),
            Bytes::from_static(b"test-etag"),
            Bytes::from_static(b""),
            100 * 1024 * 1024,
            max,
            min,
            max,
            create_test_memory_pool(),
            Arc::new(Mutex::new(LruCache::new(NonZeroUsize::new(100).unwrap()))),
            Weak::new(),
        ));

        state.shrink_window();
        let after_shrink = state.window_size.load(Ordering::SeqCst);
        // Should NOT be 24MB (max/2), should be 32MB (same order as grow)
        assert_ne!(after_shrink, max / 2);
        assert!(after_shrink < max);
        assert!(after_shrink >= min);
    }

    #[test]
    fn test_speculative_readahead_pattern_does_not_invoke_readahead() {
        assert!(!ReadPattern::SpeculativeReadahead.invokes_readahead());
        assert!(!ReadPattern::RandomRead.invokes_readahead());
        assert!(ReadPattern::SequentialRead.invokes_readahead());
        assert!(ReadPattern::StartOfFile.invokes_readahead());
        assert!(ReadPattern::FirstWindowRead.invokes_readahead());
    }

    #[tokio::test]
    async fn test_s3_size_mismatch_fails_request() {
        // Mock that returns wrong-sized data (simulates stale S3 version)
        #[derive(Clone)]
        struct WrongSizeReader {
            actual_size: usize,
        }

        #[async_trait::async_trait]
        impl S3DataReader for WrongSizeReader {
            async fn spawn_read_task(
                &self,
                s3_data_locator: awsfile_bypass_data_locator,
                _read_bypass_context: Arc<ReadBypassContext>,
            ) -> tokio::task::JoinHandle<Result<Bytes, crate::aws::s3_client::S3ClientError>>
            {
                let actual_size = self.actual_size;
                let expected_size = s3_data_locator.count as u64;
                tokio::spawn(async move {
                    // Return wrong size - triggers SizeMismatch error
                    Err(crate::aws::s3_client::S3ClientError::SizeMismatch {
                        expected: expected_size,
                        actual: actual_size as u64,
                    })
                })
            }
        }

        let state = create_test_state();
        let mock_reader = Arc::new(WrongSizeReader { actual_size: 8 });
        let read_bypass_context = create_test_read_bypass_context().await;
        let read_bypass_request_context = ReadBypassRequestContext::new(read_bypass_context, 0);
        let locator = create_test_s3_data_locator(0, 1024); // Request 1024 bytes

        let result = state
            .clone()
            .get_data(
                Arc::new(read_bypass_request_context),
                &locator,
                state.file_size,
                mock_reader,
                false,
            )
            .await;

        // Should fail - size mismatch is a hard error that triggers NFS fallback
        assert!(result.is_err(), "Size mismatch should fail the request");
    }

    #[tokio::test]
    async fn test_readahead_failure_doesnt_fail_request() {
        // Mock that fails all requests
        #[derive(Clone)]
        struct FailAfterNReader {
            call_count: Arc<AtomicU64>,
            fail_after: u64,
        }

        #[async_trait::async_trait]
        impl S3DataReader for FailAfterNReader {
            async fn spawn_read_task(
                &self,
                s3_data_locator: awsfile_bypass_data_locator,
                _read_bypass_context: Arc<ReadBypassContext>,
            ) -> tokio::task::JoinHandle<Result<Bytes, crate::aws::s3_client::S3ClientError>>
            {
                let call_num = self.call_count.fetch_add(1, Ordering::SeqCst);
                let fail_after = self.fail_after;
                let count = s3_data_locator.count as usize;
                let offset = s3_data_locator.offset;
                tokio::spawn(async move {
                    if call_num >= fail_after {
                        Err(crate::aws::s3_client::S3ClientError::InvalidKey)
                    } else {
                        let data: Vec<u8> = (0..count)
                            .map(|i| ((offset as usize + i) % 256) as u8)
                            .collect();
                        Ok(Bytes::from(data))
                    }
                })
            }
        }

        let state = create_test_state();
        // Succeed on first call (required data), fail on subsequent (readahead)
        let mock_reader = Arc::new(FailAfterNReader {
            call_count: Arc::new(AtomicU64::new(0)),
            fail_after: 1,
        });
        let read_bypass_context = create_test_read_bypass_context().await;
        let read_bypass_request_context = ReadBypassRequestContext::new(read_bypass_context, 0);
        let locator = create_test_s3_data_locator(0, 1024);
        let result = state
            .clone()
            .get_data(
                Arc::new(read_bypass_request_context),
                &locator,
                state.file_size,
                mock_reader.clone(),
                false,
            )
            .await;

        // Should succeed despite readahead failure
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_cleanup_stale_entries() {
        let state = create_test_state();

        // Insert a range but don't load it (stays in Loading state)
        state.insert_range(0..100).await.unwrap();

        // Not stale yet (just created, TTL is 60s)
        let cleaned = state.cleanup_stale_entries(60_000).await;
        assert_eq!(cleaned, 0);

        // Verify the entry still exists
        assert!(!state.is_empty());
    }

    #[tokio::test]
    async fn test_cleanup_stale_entries_evicts_old() {
        let state = create_test_state();

        // Insert and load a range
        state.insert_range(0..100).await.unwrap();
        let memory_pool = create_test_memory_pool();
        state
            .load_range(0..100, &memory_pool, bytes::Bytes::from(vec![0u8; 100]))
            .await
            .unwrap();
        assert!(!state.is_empty());

        // TTL of 0 means loaded entries are stale - should evict
        let cleaned = state.cleanup_stale_entries(0).await;
        assert_eq!(cleaned, 1);
        assert!(state.is_empty());
    }

    #[tokio::test]
    async fn test_is_empty() {
        let _memory_pool = create_test_memory_pool();
        let state = create_test_state();

        // Initially empty
        assert!(state.is_empty());

        // Add a range
        state.insert_range(0..100).await.unwrap();
        assert!(!state.is_empty());

        // Clear it
        state.clear_cache_entry(0..100).await.unwrap();
        assert!(state.is_empty());
    }

    #[tokio::test]
    async fn test_evict_entry() {
        let memory_pool = create_test_memory_pool();
        let state = create_test_state();
        state.set_self_weak(Arc::downgrade(&state));

        // Insert and load a range
        state.insert_range(0..100).await.unwrap();
        state
            .load_range(0..100, &memory_pool, Bytes::from(vec![0u8; 100]))
            .await
            .unwrap();

        assert!(!state.is_empty());

        // Evict the entry
        let evicted = state.evict_entry(0).await;
        assert!(evicted);
        assert!(state.is_empty());
    }

    #[tokio::test]
    async fn test_evict_entry_removes_from_cache_even_when_bytes_held() {
        // Create a cache with 2 chunk capacity
        let pool = MemoryPool::new(MemoryPoolConfig {
            initial_capacity: 2,
            min_capacity: 2,
            max_capacity: 2,
            ..Default::default()
        });
        let global_lru = Arc::new(Mutex::new(LruCache::new(NonZeroUsize::new(100).unwrap())));

        let file_size = 10 * 1024 * 1024u64;
        let chunk_size = memory_pool::CHUNK_SIZE as u64;

        let state = Arc::new(FileReadAheadState::new(
            0,
            Bytes::from_static(b"test-key"),
            Bytes::from_static(b"test-etag"),
            Bytes::from_static(b"test-version-id"),
            file_size,
            chunk_size,
            chunk_size,
            chunk_size,
            pool,
            global_lru,
            Weak::new(),
        ));
        state.set_self_weak(Arc::downgrade(&state));

        // Load 2 chunks to fill the pool
        for i in 0..2 {
            let start = i * chunk_size;
            state.insert_range(start..start + chunk_size).await.unwrap();
            state
                .load_range(
                    start..start + chunk_size,
                    &state.memory_pool,
                    Bytes::from(vec![0u8; chunk_size as usize]),
                )
                .await
                .unwrap();
            state.lru_insert(start);
        }

        assert_eq!(
            state.memory_pool.available_chunks(),
            0,
            "Pool should be full"
        );
        assert_eq!(state.get_num_ranges(), 2);

        // Get Bytes from first chunk (holds read guard)
        let cached_data = {
            let cache = state.data_cache.read().await;
            cache.get(&0).map(|(_, cd)| cd.clone()).unwrap()
        };
        let _held_bytes = cached_data.get_data_range(0..100).await.unwrap();

        // Evict first entry - should remove from data_cache even though clear() blocks
        let evicted = state.evict_entry(0).await;

        // Entry should be removed from data_cache
        assert!(evicted, "evict_entry should return true");
        assert_eq!(
            state.get_num_ranges(),
            1,
            "First entry should be removed from cache"
        );
        assert!(!state.has_range_at(0), "Chunk 0 should be gone");
        assert!(state.has_range_at(chunk_size), "Chunk 1 should remain");
    }

    #[tokio::test]
    async fn test_evict_skips_when_locked() {
        let memory_pool = create_test_memory_pool();
        let state = create_test_state();

        state.insert_range(0..100).await.unwrap();
        state
            .load_range(0..100, &memory_pool, Bytes::from(vec![0u8; 100]))
            .await
            .unwrap();

        // Hold write lock - eviction should skip
        let _guard = state.data_cache.write().await;
        let evicted = state.evict_entry(0).await;
        assert!(!evicted);

        // Release lock - eviction should work
        drop(_guard);
        let evicted = state.evict_entry(0).await;
        assert!(evicted);
    }

    #[tokio::test]
    async fn test_prepare_chunks_fails_at_capacity() {
        // Create a pool with very limited capacity
        let pool = MemoryPool::new(MemoryPoolConfig {
            initial_capacity: 1,
            min_capacity: 1,
            max_capacity: 1,
            ..Default::default()
        });

        let state = Arc::new(FileReadAheadState::new(
            0,
            Bytes::from_static(b"test-key"),
            Bytes::from_static(b"test-etag"),
            Bytes::from_static(b"test-version-id"),
            1024 * 1024,
            64 * 1024,
            64 * 1024,
            1024 * 1024,
            pool,
            Arc::new(Mutex::new(LruCache::new(NonZeroUsize::new(100).unwrap()))),
            Weak::new(),
        ));

        // Try to prepare 2 chunks worth of data (exceeds max_capacity of 1)
        let data = Bytes::from(vec![0u8; memory_pool::CHUNK_SIZE * 2]);
        let result = state
            .prepare_chunks_from_bytes(0..(data.len() as u64), data)
            .await;

        match result {
            Err(e) => assert!(e.message.contains("capacity")),
            Ok(_) => panic!("Expected error due to capacity"),
        }
    }

    // These tests verify correct data assembly when:
    // 1. Part of a read request is already cached
    // 2. The missing part is fetched from S3
    // 3. Caching the S3 data may fail due to capacity constraints
    async fn run_partial_cache_test(
        pool_capacity: usize,
        cached_ranges: &[Range<u64>],
        request_range: Range<u64>,
    ) {
        let pool = MemoryPool::new(MemoryPoolConfig {
            initial_capacity: pool_capacity,
            min_capacity: pool_capacity,
            max_capacity: pool_capacity,
            ..Default::default()
        });

        let file_size = 10 * CHUNK_SIZE as u64;
        let state = Arc::new(FileReadAheadState::new(
            0,
            Bytes::from_static(b"test-key"),
            Bytes::from_static(b"test-etag"),
            Bytes::from_static(b""),
            file_size,
            CHUNK_SIZE as u64,
            CHUNK_SIZE as u64,
            CHUNK_SIZE as u64,
            pool.clone(),
            Arc::new(Mutex::new(LruCache::new(NonZeroUsize::new(100).unwrap()))),
            Weak::new(),
        ));
        state.set_self_weak(Arc::downgrade(&state));

        // Pre-populate cache with position-encoded data
        for range in cached_ranges {
            let data: Vec<u8> = (range.start as usize..range.end as usize)
                .map(|i| (i % 256) as u8)
                .collect();
            state.insert_range(range.clone()).await.unwrap();
            state
                .load_range(range.clone(), &pool, Bytes::from(data))
                .await
                .unwrap();
        }

        let request_size = (request_range.end - request_range.start) as u32;
        let mock_reader = Arc::new(CountingS3DataReader::new());
        let read_bypass_context = create_test_read_bypass_context().await;
        let read_bypass_request_context =
            Arc::new(ReadBypassRequestContext::new(read_bypass_context, 0));
        let locator = create_test_s3_data_locator(request_range.start, request_size);

        let result = state
            .clone()
            .get_data(
                read_bypass_request_context,
                &locator,
                file_size,
                mock_reader,
                true, // suppress_readahead
            )
            .await;

        assert!(
            result.is_ok(),
            "get_data should succeed: {:?}",
            result.err()
        );
        let (data, _) = result.unwrap();
        assert!(data.is_some(), "Should return data");
        let bytes = data.unwrap();

        assert_eq!(
            bytes.len(),
            request_size as usize,
            "Returned data length should match requested size"
        );

        // Verify all bytes match position-encoded pattern
        for i in 0..request_size as usize {
            let offset = request_range.start as usize + i;
            assert_eq!(
                bytes[i],
                (offset % 256) as u8,
                "Byte {} (offset {}) should match position pattern",
                i,
                offset
            );
        }
    }

    #[tokio::test]
    async fn test_partial_cache_hit_cached_at_start() {
        // Cached at START
        //
        //   Request: |=======================|
        //   Cached:  |XXXXXXXX|              |
        //   S3:      |        |XXXXXXXXXXXXXX|
        //            0      CHUNK/2        CHUNK
        //
        let half = (CHUNK_SIZE / 2) as u64;
        let chunk = CHUNK_SIZE as u64;
        for capacity in [1, 10] {
            run_partial_cache_test(capacity, &[0..chunk], half..half + chunk).await;
        }
    }

    #[tokio::test]
    async fn test_partial_cache_hit_cached_at_end() {
        // Cached at END
        //
        //   Request: |=======================|
        //   S3:      |XXXXXXXXXXXXXX|        |
        //   Cached:  |              |XXXXXXXX|
        //            0            CHUNK/2   CHUNK
        //
        let half = (CHUNK_SIZE / 2) as u64;
        let chunk = CHUNK_SIZE as u64;
        for capacity in [1, 10] {
            run_partial_cache_test(capacity, &[half..chunk], 0..chunk).await;
        }
    }

    #[tokio::test]
    async fn test_partial_cache_hit_cached_in_middle() {
        // Cached in MIDDLE
        //
        //   Request: |=======================|
        //   S3:      |XXXXXX|        |XXXXXXX|
        //   Cached:  |      |XXXXXXXX|       |
        //            0      Q       3Q     CHUNK  (Q = CHUNK/4)
        //
        let q = (CHUNK_SIZE / 4) as u64;
        let chunk = CHUNK_SIZE as u64;
        for capacity in [1, 10] {
            run_partial_cache_test(capacity, &[q..q * 3], 0..chunk).await;
        }
    }

    #[tokio::test]
    async fn test_partial_cache_hit_multiple_disjoint_ranges() {
        // Multiple disjoint cached ranges
        //
        //   Request: |=======================|
        //   Cached:  |XXXX|    |XXXX|        |
        //   S3:      |    |XXXX|    |XXXXXXXX|
        //            0    Q   2Q   3Q      CHUNK
        //
        let q = (CHUNK_SIZE / 4) as u64;
        let chunk = CHUNK_SIZE as u64;
        for capacity in [2, 10] {
            run_partial_cache_test(capacity, &[0..q, q * 2..q * 3], 0..chunk).await;
        }
    }

    #[tokio::test]
    async fn test_partial_cache_hit_spanning_multiple_cache_entries() {
        // Request spans multiple contiguous cache entries
        //
        //   Cache:   |XXXXXXXX|XXXXXXXX|
        //   Request:     |=================|
        //   S3:          |             |XXX|
        //            0  Q/2  Q       2Q   3Q
        //
        let q = (CHUNK_SIZE / 4) as u64;
        for capacity in [3, 10] {
            run_partial_cache_test(capacity, &[0..q, q..q * 2], q / 2..q * 3).await;
        }
    }

    #[tokio::test]
    async fn test_partial_cache_hit_many_alternating_gaps() {
        // Many alternating cached/uncached (stress test)
        //
        //   Request: |=======================|
        //            |C |S |C |S |C |S |C |S |  (8 segments, C=cached, S=S3)
        //            0  1  2  3  4  5  6  7  CHUNK  (each = CHUNK/8)
        //
        let seg = (CHUNK_SIZE / 8) as u64;
        let chunk = CHUNK_SIZE as u64;
        let cached = &[0..seg, seg * 2..seg * 3, seg * 4..seg * 5, seg * 6..seg * 7];
        for capacity in [4, 10] {
            run_partial_cache_test(capacity, cached, 0..chunk).await;
        }
    }

    #[tokio::test]
    async fn test_read_succeeds_when_cache_at_capacity() {
        // Create a pool with capacity of 1 chunk - requesting 2 chunks will exceed capacity
        let pool = MemoryPool::new(MemoryPoolConfig {
            initial_capacity: 1,
            min_capacity: 1,
            max_capacity: 1,
            ..Default::default()
        });

        let file_size = 10 * 1024 * 1024; // 10MB file
        let state = Arc::new(FileReadAheadState::new(
            0,
            Bytes::from_static(b"test-key"),
            Bytes::from_static(b"test-etag"),
            Bytes::from_static(b"test-version-id"),
            file_size,
            64 * 1024,
            64 * 1024,
            1024 * 1024,
            pool,
            Arc::new(Mutex::new(LruCache::new(NonZeroUsize::new(100).unwrap()))),
            Weak::new(),
        ));

        let mock_reader = Arc::new(CountingS3DataReader::new());
        let read_bypass_context = create_test_read_bypass_context().await;
        let read_bypass_request_context =
            Arc::new(ReadBypassRequestContext::new(read_bypass_context, 0));
        // Request 2 chunks worth of data (exceeds max_capacity of 1)
        let request_size = (memory_pool::CHUNK_SIZE * 2) as u32;
        let locator = create_test_s3_data_locator(0, request_size);

        // Request should succeed even though caching fails
        let result = state
            .clone()
            .get_data(
                read_bypass_request_context,
                &locator,
                file_size,
                mock_reader,
                false, // suppress_readahead
            )
            .await;

        assert!(result.is_ok(), "Read should succeed despite cache failure");
        let (data, _) = result.unwrap();
        assert!(data.is_some(), "Should return data");
        let bytes = data.unwrap();
        assert_eq!(
            bytes.len(),
            request_size as usize,
            "Should return requested amount"
        );

        // Verify nothing was cached
        let cache = state.data_cache.read().await;
        assert!(
            cache.is_empty(),
            "Cache should be empty since caching failed"
        );
    }
}
