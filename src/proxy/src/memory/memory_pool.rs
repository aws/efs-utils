#![allow(unused)]

use log::debug;
use std::mem::{ManuallyDrop, MaybeUninit};
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

const ONE_MB_IN_BYTES: usize = 1024 * 1024;
pub const CHUNK_SIZE: usize = ONE_MB_IN_BYTES;

/// Represents a fixed-size unit of memory allocated on the heap
pub struct MemoryChunk {
    /// Pointer to the raw memory
    ///
    /// [`MaybeUninit`] is used to avoid the cost of initializing the memory,
    /// it is expected for the owner to write data before reading from it.
    ///
    /// [`ManuallyDrop`] is used to allow the memory to be moved to a new chunk
    /// when dropped so that it can be returned to the pool without allocations.
    /// [`MemoryChunk::drop`] guarantees the destructor will be called.
    data: ManuallyDrop<Box<MaybeUninit<[u8; CHUNK_SIZE]>>>,

    /// Pointer to the next free [`MemoryChunk`]
    next: Option<Box<MemoryChunk>>,

    /// Reference to the [`MemoryPool`] which created this chunk
    ///
    /// If this is [`Some`] then the chunk is owned outside the [`MemoryPool`],
    /// if it is [`None`] then the pool owns the chunk.
    pool: Option<Weak<MemoryPool>>,
}

impl MemoryChunk {
    /// Creates a new [`MemoryChunk`] with uninitialized data.
    fn new() -> Self {
        Self {
            data: ManuallyDrop::new(Box::new_uninit()),
            next: None,
            pool: None,
        }
    }
}

impl Drop for MemoryChunk {
    /// Dropping a chunk has different behavior depending on the state of the chunk:
    ///
    /// 1. If the owner obtained the chunk via [`MemoryPool::consume`], dropping will return
    ///    the chunk to the [`MemoryPool`] without deallocating the memory.
    ///
    /// **Example:**
    /// ```
    /// use efs_proxy::memory::memory_pool::{MemoryPool, MemoryPoolConfig};
    ///
    /// let pool = MemoryPool::new(MemoryPoolConfig::default());
    /// {
    ///     let chunk = pool.consume(1).pop().unwrap();
    ///     // chunk is dropped, returns to pool
    /// }
    /// // chunk is available in pool again
    /// ```
    ///
    /// 2. If the current owner is a [`MemoryPool`], or the [`MemoryPool`] which created
    ///    the chunk has already been dropped (unlikely but not impossible),
    ///    dropping will deallocate the memory.
    ///
    /// **Examples:**
    /// ```
    /// use efs_proxy::memory::memory_pool::{MemoryPool, MemoryPoolConfig};
    ///
    /// {
    ///     let pool = MemoryPool::new(MemoryPoolConfig::default());
    ///     // pool is dropped, the chunk it owns gets dropped and deallocates memory
    /// }
    /// {
    ///     let pool = MemoryPool::new(MemoryPoolConfig::default());
    ///     let chunk = pool.consume(1).pop().unwrap();
    ///     drop(pool); // pool is dropped, it doesn't own the chunk and so chunk isn't dropped
    ///     // chunk is dropped, pool is no longer alive and so memory is deallocated
    /// }
    /// ```
    fn drop(&mut self) {
        let pool_weak = match self.pool.take() {
            Some(pool) => pool,
            None => {
                // No pool reference means the pool owns the chunk, the data should deallocate
                unsafe {
                    ManuallyDrop::drop(&mut self.data);
                }
                return;
            }
        };

        let pool = match pool_weak.upgrade() {
            Some(pool) => pool,
            None => {
                // Pool has been dropped, chunk should deallocate
                unsafe {
                    ManuallyDrop::drop(&mut self.data);
                }
                return;
            }
        };

        // Pool exists, return chunk to it
        // Take the data out without dropping or copying
        let data = unsafe { ManuallyDrop::take(&mut self.data) };

        let chunk = MemoryChunk {
            data: ManuallyDrop::new(data),
            next: None,
            pool: None,
        };

        pool.free_chunk(chunk);
    }
}

impl Deref for MemoryChunk {
    type Target = [u8];

    /// Returns a slice to the underlying data.
    ///
    /// # Safety Contract
    ///
    /// The returned slice may reference **uninitialized memory**.
    /// The caller is assumed to have first written data to the chunk.
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.data.as_ptr() }
    }
}

impl DerefMut for MemoryChunk {
    /// Returns a mutable slice to the underlying data.
    ///
    /// # Safety Contract
    ///
    /// The returned slice may reference **uninitialized memory**.
    /// The caller is expected to write data to the chunk before reading.
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.data.as_mut_ptr() }
    }
}

pub struct MemoryPoolConfig {
    /// The initial number of [`MemoryChunk`]s to allocate
    ///
    /// Must be greater than zero, and greater than or equal to [`Self::min_capacity`].
    pub initial_capacity: usize,

    /// The maximum number of [`MemoryChunk`]s that can be allocated
    pub max_capacity: usize,

    /// The minimum number of [`MemoryChunk`]s that must be allocated
    pub min_capacity: usize,

    /// The number of [`MemoryChunk`]s to allocate/deallocate when resizing
    pub resize_batch_size: usize,

    /// The threshold for what is considered high utilization
    ///
    /// If the utilization of a [`MemoryPool`] exceeds this values
    /// it may allocate more [`MemoryChunk`]s.
    pub high_utilization_threshold_percent: usize,

    /// The threshold for what is considered low utilization
    ///
    /// If the utilization of a [`MemoryPool`] falls below this
    /// value it may deallocate [`MemoryChunk`]s.
    pub low_utilization_threshold_percent: usize,

    /// Minimum amount of time that must pass between resize operations that scale down
    /// the pool's capacity.
    ///
    /// The pool will aggressively scale up when resizing.
    /// This delay between scale-down operations prevents "flip-flop"
    /// scale-up/scale-down operations around utilization thresholds.
    pub scale_down_delay: Duration,
}

impl MemoryPoolConfig {
    fn validate(&self) {
        assert!(
            self.initial_capacity > 0,
            "Initial capacity must be greater than 0"
        );
        assert!(
            self.initial_capacity >= self.min_capacity,
            "Initial capacity cannot be less than minimum capacity"
        );
        assert!(
            self.min_capacity <= self.max_capacity,
            "Minimum capacity cannot be greater than maximum capacity"
        )
    }
}

impl Default for MemoryPoolConfig {
    fn default() -> Self {
        Self {
            initial_capacity: 100,
            max_capacity: 1_000,
            min_capacity: 100,
            resize_batch_size: 100,
            high_utilization_threshold_percent: 80,
            low_utilization_threshold_percent: 20,
            scale_down_delay: Duration::from_secs(30),
        }
    }
}

/// A thread-safe pool of reusable [`MemoryChunk`]s.
pub struct MemoryPool {
    /// A linked list of free [`MemoryChunk`]s available for consuming
    free_list: Mutex<Option<Box<MemoryChunk>>>,

    /// A best-estimate of the number of chunks available to be consumed,
    /// i.e. the length of `free_list`.
    available_chunks: AtomicUsize,

    /// The total number of [`MemoryChunk`]s currently allocated
    ///
    /// Note: this includes chunks that have been consumed and so
    /// are not currently owned by the pool.
    capacity: AtomicUsize,

    /// The last time the pool has performed a resize operation
    last_resize_time: Mutex<Instant>,

    /// The configuration for this pool
    config: MemoryPoolConfig,
}

impl MemoryPool {
    /// Creates a new memory pool with `config.initial_capacity` number of pre-allocated [`MemoryChunk`]s.
    pub fn new(config: MemoryPoolConfig) -> Arc<Self> {
        config.validate();

        let capacity = config.initial_capacity;
        let mut free_list: Option<Box<MemoryChunk>> = None;

        // Pre-allocate memory
        for _ in 0..capacity {
            Self::add_chunk_to_free_list(&mut free_list, MemoryChunk::new());
        }

        Arc::new(Self {
            free_list: Mutex::new(free_list),
            available_chunks: AtomicUsize::new(capacity),
            capacity: AtomicUsize::new(capacity),
            last_resize_time: Mutex::new(Instant::now()),
            config,
        })
    }

    /// Returns true if allocating `num_chunks` would exceed max_capacity.
    pub fn would_exceed_capacity(&self, num_chunks: usize) -> bool {
        let available = self.available_chunks.load(Ordering::Relaxed);
        if available >= num_chunks {
            return false; // Can satisfy from pool
        }
        let need_to_allocate = num_chunks - available;
        let current_capacity = self.capacity.load(Ordering::Relaxed);
        current_capacity + need_to_allocate > self.config.max_capacity
    }

    /// Get `num_chunks` [`MemoryChunk`]s from the pool.
    ///
    /// If the pool does not have any available pre-allocated chunks,
    /// new chunks will be allocated on-demand.
    ///
    /// The returned chunks contain uninitialized data,
    /// the caller is responsible for initializing before use.
    pub fn consume(self: &Arc<Self>, num_chunks: usize) -> Vec<MemoryChunk> {
        let mut chunks = Vec::with_capacity(num_chunks);
        let mut num_consumed = 0;

        let mut head = self.free_list.lock().unwrap();

        for _ in 0..num_chunks {
            let mut chunk = if let Some(mut prev_head) = head.take() {
                *head = prev_head.next.take();
                num_consumed += 1;
                *prev_head
            } else {
                // Atomically reserve capacity - only succeeds if under max
                if self
                    .capacity
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |c| {
                        if c < self.config.max_capacity {
                            Some(c + 1)
                        } else {
                            None
                        }
                    })
                    .is_err()
                {
                    debug!("Pool at max capacity, cannot allocate more chunks");
                    break;
                }
                debug!("Pool is empty, allocating new chunk");
                MemoryChunk::new()
            };
            // Set the pool reference so it knows where to return when dropped
            chunk.pool = Some(Arc::downgrade(&self));
            chunks.push(chunk);
        }

        self.available_chunks
            .fetch_sub(num_consumed, Ordering::Relaxed);

        self.resize_if_needed(head);

        chunks
    }

    /// Return `chunks` to the pool.
    pub fn free(&self, chunks: Vec<MemoryChunk>) {
        let n_chunks = chunks.len();
        let mut head = self.free_list.lock().unwrap();

        for chunk in chunks {
            Self::add_chunk_to_free_list(&mut head, chunk);
        }

        self.available_chunks.fetch_add(n_chunks, Ordering::Relaxed);
        self.resize_if_needed(head);
    }

    /// Return a single [`MemoryChunk`] to the pool.
    fn free_chunk(&self, chunk: MemoryChunk) {
        let mut head = self.free_list.lock().unwrap();
        Self::add_chunk_to_free_list(&mut head, chunk);

        self.available_chunks.fetch_add(1, Ordering::Relaxed);
        self.resize_if_needed(head);
    }

    /// Returns the number of [`MemoryChunk`]s available to be consumed.
    ///
    /// This is an approximate value since atomics are used, its eventually
    /// consistent but may be inaccurate if read in parallel with `free_chunk`/`consume`.
    pub fn available_chunks(&self) -> usize {
        self.available_chunks.load(Ordering::Relaxed)
    }

    /// Returns the current total capacity (allocated chunks, both free and in-use).
    pub fn capacity(&self) -> usize {
        self.capacity.load(Ordering::Relaxed)
    }

    /// Returns the maximum capacity the pool can grow to.
    pub fn max_capacity(&self) -> usize {
        self.config.max_capacity
    }

    /// Deallocate `num_chunks` [`MemoryChunk`]s from the pool, freeing their memory.
    fn deallocate(
        &self,
        num_chunks: usize,
        mut free_list_guard: MutexGuard<'_, Option<Box<MemoryChunk>>>,
    ) {
        if num_chunks == 0 {
            return;
        }

        let mut num_deallocated = 0;

        for _ in 0..num_chunks {
            if free_list_guard.is_none() {
                debug!("Pool is empty, no more chunks to deallocate");
                break;
            }

            // Replace head with its next, dropping the old head
            *free_list_guard = free_list_guard.take().unwrap().next.take();
            num_deallocated += 1;
        }

        self.capacity.fetch_sub(num_deallocated, Ordering::Relaxed);
        self.available_chunks
            .fetch_sub(num_deallocated, Ordering::Relaxed);
    }

    /// Allocate `num_chunks` new [`MemoryChunk`]s, adding them to the pool.
    fn allocate(
        &self,
        num_chunks: usize,
        mut free_list_guard: MutexGuard<'_, Option<Box<MemoryChunk>>>,
    ) {
        if num_chunks == 0 {
            return;
        }

        // Create a chain of new chunks
        let mut new_head = Box::new(MemoryChunk::new());
        let mut cur_chunk = &mut new_head;
        for _ in 1..num_chunks {
            cur_chunk.next = Some(Box::new(MemoryChunk::new()));
            cur_chunk = cur_chunk.next.as_mut().unwrap();
        }

        // Link the tail of the new chain to the current head of the free list
        cur_chunk.next = free_list_guard.take();
        *free_list_guard = Some(new_head);

        self.capacity.fetch_add(num_chunks, Ordering::Relaxed);
        self.available_chunks
            .fetch_add(num_chunks, Ordering::Relaxed);
    }

    /// Resize the pool based on current utilization, allocating/deallocating [`MemoryChunk`]s as required
    fn resize_if_needed(&self, free_list_guard: MutexGuard<'_, Option<Box<MemoryChunk>>>) {
        let capacity = self.capacity.load(Ordering::Relaxed);
        let available = self.available_chunks.load(Ordering::Relaxed);

        let num_chunks_in_use = capacity - available;
        let utilization = (num_chunks_in_use * 100) / capacity;

        // If the high utilization threshold is crossed and there is
        // remaining room to adjust capacity, always perform a scale-up
        if utilization > self.config.high_utilization_threshold_percent
            && capacity < self.config.max_capacity
        {
            // Limit resize up to maximum capacity
            let num_to_allocate = self
                .config
                .resize_batch_size
                .min(self.config.max_capacity - capacity);
            self.allocate(num_to_allocate, free_list_guard);

            let mut last_resize_time = self.last_resize_time.lock().unwrap();
            *last_resize_time = Instant::now();
        }
        // If the low utilization threshold is crossed and there is remaining room
        // to adjust capacity, check the time before performing a scale-down
        else if utilization < self.config.low_utilization_threshold_percent
            && capacity > self.config.min_capacity
        {
            let mut last_resize_time = self.last_resize_time.lock().unwrap();

            if last_resize_time.elapsed() >= self.config.scale_down_delay {
                // Limit resize down to minimum capacity
                let num_to_deallocate = self
                    .config
                    .resize_batch_size
                    .min(capacity - self.config.min_capacity);
                self.deallocate(num_to_deallocate, free_list_guard);
                *last_resize_time = Instant::now();
            }
        }
    }

    fn add_chunk_to_free_list(free_list: &mut Option<Box<MemoryChunk>>, mut chunk: MemoryChunk) {
        let current_head = free_list.take();
        chunk.next = current_head;
        chunk.pool = None; // Clear the pool reference so this chunk knows to deallocate if dropped
        free_list.replace(Box::new(chunk));
    }

    /// Attempt to shrink the pool if utilization is low.
    /// Call this periodically when the pool may be idle.
    pub fn try_shrink(&self) {
        let head = self.free_list.lock().unwrap();
        self.resize_if_needed(head);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_new_pool() {
        let pool_config = MemoryPoolConfig {
            initial_capacity: 1,
            min_capacity: 1,
            ..Default::default()
        };
        let _ = MemoryPool::new(pool_config);
    }

    #[test]
    fn test_consume_single_chunk() {
        let pool_config = MemoryPoolConfig {
            initial_capacity: 1,
            min_capacity: 1,
            ..Default::default()
        };
        let pool = MemoryPool::new(pool_config);

        let chunks = pool.consume(1);
        assert_eq!(chunks.len(), 1);
    }

    #[test]
    fn test_consume_multiple_chunks() {
        let pool_config = MemoryPoolConfig {
            initial_capacity: 3,
            min_capacity: 1,
            ..Default::default()
        };
        let pool = MemoryPool::new(pool_config);

        let chunks = pool.consume(3);
        assert_eq!(chunks.len(), 3);
    }

    #[test]
    fn test_consume_all_available_chunks() {
        let capacity = 3;
        let pool_config = MemoryPoolConfig {
            initial_capacity: capacity,
            min_capacity: 1,
            ..Default::default()
        };
        let pool = MemoryPool::new(pool_config);

        let chunks = pool.consume(capacity);
        assert_eq!(chunks.len(), capacity);
    }

    #[test]
    fn test_free_returns_chunks_to_pool() {
        let capacity = 3;
        let pool_config = MemoryPoolConfig {
            initial_capacity: capacity,
            min_capacity: 1,
            resize_batch_size: 0, // disable resizing
            ..Default::default()
        };
        let pool = MemoryPool::new(pool_config);

        let chunks = pool.consume(2);
        assert_eq!(pool.available_chunks(), 1);

        pool.free(chunks);
        assert_eq!(pool.available_chunks(), capacity);
    }

    #[test]
    fn test_consume_and_free_cycle() {
        let capacity = 2;
        let pool_config = MemoryPoolConfig {
            initial_capacity: capacity,
            min_capacity: 1,
            resize_batch_size: 0, // disable resizing
            ..Default::default()
        };
        let pool = MemoryPool::new(pool_config);

        // Consume all chunks
        let chunks1 = pool.consume(1);
        let chunks2 = pool.consume(1);
        assert_eq!(pool.available_chunks(), 0);

        // Free one chunk and consume again
        pool.free(chunks1);
        assert_eq!(pool.available_chunks(), 1);

        let chunks3 = pool.consume(1);
        assert_eq!(pool.available_chunks(), 0);

        // Free all chunks
        pool.free(chunks2);
        pool.free(chunks3);
        assert_eq!(pool.available_chunks(), 2);
    }

    #[test]
    fn test_consume_more_than_available() {
        let capacity = 3;
        let pool_config = MemoryPoolConfig {
            initial_capacity: capacity,
            min_capacity: 1,
            resize_batch_size: 0, // disable resizing
            ..Default::default()
        };
        let pool = MemoryPool::new(pool_config);

        // Consume all chunks
        let chunks = pool.consume(capacity);
        assert_eq!(pool.available_chunks(), 0);

        // We have consumed all pre-allocated chunks, but the pool should
        // still be able to provide new ones allocated per-request
        let extra_chunks = pool.consume(capacity);
        assert_eq!(pool.available_chunks(), 0);

        // Free all chunks
        pool.free(chunks);
        pool.free(extra_chunks);

        // The pool should keep the extra chunks allocated
        assert_eq!(pool.available_chunks(), capacity * 2);
    }

    #[test]
    fn test_thread_safety() {
        let capacity = 10;
        let pool_config = MemoryPoolConfig {
            initial_capacity: capacity,
            min_capacity: capacity,
            max_capacity: capacity,
            ..Default::default()
        };
        let pool = MemoryPool::new(pool_config);
        let n_threads = capacity / 2;
        let barrier = Arc::new(Barrier::new(n_threads));
        let mut handles = Vec::with_capacity(n_threads);

        // Spawn multiple threads that consume and free memory chunks
        for _ in 0..n_threads {
            let local_pool = pool.clone();
            let local_barrier = barrier.clone();

            let handle = thread::spawn(move || {
                // Force concurrency/lock contention
                local_barrier.wait();

                let chunks = local_pool.consume(2);

                // Simulate some work before returning to the pool
                thread::sleep(Duration::from_millis(10));
                local_pool.free(chunks);
            });
            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        // All chunks should be back in the pool
        assert_eq!(pool.available_chunks(), capacity);
    }

    #[test]
    fn test_memory_chunk_read_write() {
        let write_string = "Hello, World!";
        let bytes = write_string.as_bytes();

        let mut chunk = MemoryChunk::new();
        chunk[..bytes.len()].copy_from_slice(bytes);

        let read_string = std::str::from_utf8(&chunk[..bytes.len()]).unwrap();
        assert_eq!(read_string, write_string);
    }

    #[test]
    fn test_available_chunks() {
        let capacity = 5;
        let pool_config = MemoryPoolConfig {
            initial_capacity: capacity,
            min_capacity: capacity,
            max_capacity: capacity,
            ..Default::default()
        };
        let pool = MemoryPool::new(pool_config);
        assert_eq!(
            pool.available_chunks(),
            capacity,
            "New pool should have full capacity available"
        );

        let mut chunks = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            let chunk = pool.consume(1);
            chunks.push(chunk);

            let expected_available = capacity - chunks.len();
            assert_eq!(expected_available, pool.available_chunks());
        }

        for _ in 0..chunks.len() {
            let chunk = chunks.pop().unwrap();
            pool.free(chunk);

            let expected_available = capacity - chunks.len();
            assert_eq!(expected_available, pool.available_chunks());
        }

        assert_eq!(
            pool.available_chunks(),
            capacity,
            "Pool should have full capacity available after freeing all chunks"
        );
    }

    #[test]
    fn test_deallocate_zero() {
        let capacity = 2;
        let pool_config = MemoryPoolConfig {
            initial_capacity: capacity,
            min_capacity: 1,
            resize_batch_size: 0, // disable resizing
            ..Default::default()
        };
        let pool = MemoryPool::new(pool_config);
        assert_eq!(pool.available_chunks(), capacity);

        let free_list_guard = pool.free_list.lock().unwrap();
        pool.deallocate(0, free_list_guard);
        assert_eq!(pool.available_chunks(), capacity);
    }

    #[test]
    fn test_deallocate_multiple() {
        let capacity = 10;
        let pool_config = MemoryPoolConfig {
            initial_capacity: capacity,
            min_capacity: 1,
            ..Default::default()
        };
        let pool = MemoryPool::new(pool_config);
        assert_eq!(pool.available_chunks(), capacity);

        let num_to_deallocate = 5;
        let free_list_guard = pool.free_list.lock().unwrap();
        pool.deallocate(num_to_deallocate, free_list_guard);
        assert_eq!(pool.available_chunks(), capacity - num_to_deallocate);
    }

    #[test]
    fn test_deallocate_all() {
        let capacity = 5;
        let pool_config = MemoryPoolConfig {
            initial_capacity: capacity,
            min_capacity: 1,
            resize_batch_size: 0, // disable resizing
            ..Default::default()
        };
        let pool = MemoryPool::new(pool_config);
        assert_eq!(pool.available_chunks(), capacity);

        let free_list_guard = pool.free_list.lock().unwrap();
        pool.deallocate(capacity, free_list_guard);
        assert_eq!(pool.available_chunks(), 0);
    }

    #[test]
    fn test_allocate_zero() {
        let capacity = 5;
        let pool_config = MemoryPoolConfig {
            initial_capacity: capacity,
            min_capacity: 1,
            resize_batch_size: 0, // disable resizing
            ..Default::default()
        };
        let pool = MemoryPool::new(pool_config);
        assert_eq!(pool.available_chunks(), capacity);

        let free_list_guard = pool.free_list.lock().unwrap();
        pool.allocate(0, free_list_guard);
        assert_eq!(pool.available_chunks(), capacity);
    }

    #[test]
    fn test_allocate_multiple() {
        let capacity = 5;
        let pool_config = MemoryPoolConfig {
            initial_capacity: capacity,
            min_capacity: 1,
            resize_batch_size: 0, // disable resizing
            ..Default::default()
        };
        let pool = MemoryPool::new(pool_config);
        assert_eq!(pool.available_chunks(), capacity);

        let num_to_allocate = 3;
        let free_list_guard = pool.free_list.lock().unwrap();
        pool.allocate(num_to_allocate, free_list_guard);
        assert_eq!(pool.available_chunks(), capacity + num_to_allocate);
    }

    #[test]
    fn test_free_chunk() {
        let capacity = 1;
        let pool_config = MemoryPoolConfig {
            initial_capacity: capacity,
            min_capacity: 1,
            resize_batch_size: 0, // disable resizing
            ..Default::default()
        };
        let pool = MemoryPool::new(pool_config);

        let chunk = pool.consume(1).pop().unwrap();
        assert_eq!(pool.available_chunks(), 0);

        pool.free_chunk(chunk);
        assert_eq!(pool.available_chunks(), 1);
    }

    #[test]
    fn test_drop_chunk_returns_to_pool() {
        let capacity = 1;
        let pool_config = MemoryPoolConfig {
            initial_capacity: capacity,
            min_capacity: 1,
            resize_batch_size: 0, // disable resizing
            ..Default::default()
        };
        let pool = MemoryPool::new(pool_config);
        {
            let _chunk = pool.consume(1).pop().unwrap();
            assert_eq!(pool.available_chunks(), 0);
        }
        assert_eq!(pool.available_chunks(), 1);
    }

    #[test]
    fn test_resize_above_threshold() {
        let initial_capacity = 100;
        let resize_batch_size = 5;
        let pool_config = MemoryPoolConfig {
            initial_capacity,
            resize_batch_size,
            min_capacity: 1,
            high_utilization_threshold_percent: 80,
            low_utilization_threshold_percent: 0, // don't shrink when freeing
            ..Default::default()
        };
        let pool = MemoryPool::new(pool_config);
        assert_eq!(pool.available_chunks(), initial_capacity);

        let mut chunks = Vec::with_capacity(initial_capacity);

        // Consume 80 chunks, reaching the 80% utilization threshold
        chunks.push(pool.consume(80));
        assert_eq!(pool.available_chunks(), initial_capacity - 80);

        // Consume 1 more chunk, exceeding the threshold at 81% utilization
        chunks.push(pool.consume(1));
        let expected_available = initial_capacity - 81 + resize_batch_size;
        assert_eq!(pool.available_chunks(), expected_available);

        for chunk in chunks {
            pool.free(chunk);
        }
        assert!(pool.available_chunks() > initial_capacity);
    }

    #[test]
    fn test_resize_below_threshold() {
        let initial_capacity = 100;
        let resize_batch_size = 5;
        let low_utilization_threshold_percent = 50;
        let pool_config = MemoryPoolConfig {
            initial_capacity,
            resize_batch_size,
            low_utilization_threshold_percent,
            min_capacity: 1,
            scale_down_delay: Duration::from_secs(0), // resize as soon as threshold crossed
            ..Default::default()
        };
        let pool = MemoryPool::new(pool_config);
        assert_eq!(pool.available_chunks(), initial_capacity);

        let mut chunks = Vec::with_capacity(initial_capacity);

        // Consume 50 chunks, reaching the 50% utilization threshold
        chunks.push(pool.consume(50));
        assert_eq!(pool.available_chunks(), initial_capacity - 50);

        // Free a chunk, putting us below the threshold at 49%
        let chunk = chunks[0].pop().unwrap();
        pool.free_chunk(chunk);
        let expected_available = initial_capacity - 49 - resize_batch_size;
        assert_eq!(pool.available_chunks(), expected_available);
    }

    #[test]
    fn test_would_exceed_capacity_with_available() {
        let pool = MemoryPool::new(MemoryPoolConfig {
            initial_capacity: 10,
            min_capacity: 10,
            max_capacity: 10,
            ..Default::default()
        });

        // Can satisfy from available chunks
        assert!(!pool.would_exceed_capacity(5));
        assert!(!pool.would_exceed_capacity(10));

        // Would need to allocate beyond max
        assert!(pool.would_exceed_capacity(11));
    }

    #[test]
    fn test_would_exceed_capacity_after_consumption() {
        let pool = MemoryPool::new(MemoryPoolConfig {
            initial_capacity: 10,
            min_capacity: 10,
            max_capacity: 15,
            ..Default::default()
        });

        // Consume some chunks
        let _chunks = pool.consume(8);
        assert_eq!(pool.available_chunks(), 2);

        // Can satisfy 2 from pool
        assert!(!pool.would_exceed_capacity(2));

        // Need 3 more, capacity is 10, max is 15, so 10+3=13 <= 15
        assert!(!pool.would_exceed_capacity(5));

        // Need 8 more, capacity is 10, max is 15, so 10+6=16 > 15
        assert!(pool.would_exceed_capacity(10));
    }
}
