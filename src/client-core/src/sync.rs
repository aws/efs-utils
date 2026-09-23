//! Concurrency primitives re-exported through the `shuttle-sync` wrapper crate.
//!
//! **Always use `crate::sync` (and `crate::sync::thread`) instead of
//! `std::sync` / `std::thread`.** This module is the single point of control
//! for swapping between std and [Shuttle](https://github.com/awslabs/shuttle)
//! instrumented synchronization primitives: in normal builds everything here
//! delegates to std; with the `shuttle` cargo feature the primitives are
//! replaced by Shuttle's, whose scheduler explores thread interleavings to
//! find concurrency bugs.
//!
//! This is the SHARED sync module for the EFS client crates: downstream
//! crates re-export it (`pub use efs_client_core::sync;`) instead of defining their
//! own, so the shims below are defined exactly once. Downstream `shuttle`
//! features must enable `amzn-efs-client-core/shuttle` so the cfg switches in
//! this module flip together with theirs.
//!
//! Third-party concurrency crates (tokio, tokio-util, dashmap) do not go
//! through this module; they are aliased to their public `shuttle-*` wrapper
//! crates in Cargo.toml, so plain `use tokio::...` imports are already
//! Shuttle-aware.
//!
//! Known gaps (uninstrumented even under the shuttle feature; revisit before
//! relying on Shuttle coverage of code that uses them):
//! - `OnceLock` / `LazyLock`: not provided by shuttle; re-exported from std
//!   below. A racing initialization blocks a real thread, invisible to the
//!   Shuttle scheduler.
//! - `atomic_enum` (`AtomicCacheEntryState` in read_ahead/cached_data.rs):
//!   the macro hard-codes std atomics.
//! - `moka::sync::Cache` (util/fh_denylist.rs): no wrapper exists; its
//!   internal locking is invisible to the scheduler. Usage is encapsulated,
//!   so manual context-switch points can be added if a shuttle test needs to
//!   exercise it.
//! - `rand` (dev-dependency only): real crate; shuttle tests should use
//!   `shuttle::rand` for replayable data non-determinism.

pub use shuttle_sync::sync::*;

// Not modeled by shuttle; std versions work under shuttle but their blocking
// is invisible to the scheduler (see module docs).
pub use std::sync::{LazyLock, OnceLock};

/// Thread primitives that swap to Shuttle's controlled threads when the
/// `shuttle` feature is enabled.
pub mod thread {
    #[cfg(not(feature = "shuttle"))]
    pub use std::thread::*;

    #[cfg(feature = "shuttle")]
    pub use shuttle::thread::*;

    /// Shuttle's thread module does not model `available_parallelism`.
    /// Return a fixed small value: under shuttle, "hardware parallelism"
    /// is meaningless (the scheduler serializes everything) and a small
    /// value keeps sizing-derived thread/slot counts tractable.
    #[cfg(feature = "shuttle")]
    pub fn available_parallelism() -> std::io::Result<std::num::NonZeroUsize> {
        Ok(std::num::NonZeroUsize::new(2).unwrap())
    }
}
