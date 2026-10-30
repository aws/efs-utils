use crate::sync::atomic::{AtomicBool, Ordering};
use crate::sync::LazyLock;
use std::time::Duration;

use tokio::time::Instant;

pub fn create_deadline(duration: Duration) -> Instant {
    Instant::now() + duration
}

static IS_RUNNING_ON_LAMBDA: LazyLock<AtomicBool> =
    LazyLock::new(|| AtomicBool::new(std::env::var("AWS_LAMBDA_FUNCTION_NAME").is_ok()));

pub fn is_running_on_lambda() -> bool {
    IS_RUNNING_ON_LAMBDA.load(Ordering::Relaxed)
}

static IS_RUNNING_ON_ECS: LazyLock<AtomicBool> = LazyLock::new(|| {
    AtomicBool::new(std::env::var("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI").is_ok())
});

pub fn is_running_on_ecs() -> bool {
    IS_RUNNING_ON_ECS.load(Ordering::Relaxed)
}

#[cfg(feature = "read-bypass")]
pub use crate::read_ahead::{
    has_sufficient_memory_for_readahead_cache, MIN_MEMORY_FOR_READAHEAD_GIB,
};

/// Ensures HOME environment variable is set by resolving it from /etc/passwd if missing.
/// The AWS SDK needs HOME to resolve ~/.aws/credentials for profile-based credential loading.
pub fn ensure_home_env_set() {
    if std::env::var("HOME").is_err() {
        let uid = unsafe { libc::getuid() };
        let pw = unsafe { libc::getpwuid(uid) };
        if pw.is_null() {
            log::warn!("HOME not set and getpwuid returned null, unable to resolve home directory");
        } else {
            let dir = unsafe { std::ffi::CStr::from_ptr((*pw).pw_dir) };
            if let Ok(dir_str) = dir.to_str() {
                log::info!("HOME not set, resolved from passwd: {}", dir_str);
                std::env::set_var("HOME", dir_str);
            }
        }
    }
}

#[cfg(test)]
pub fn reset_mock_lambda() {
    IS_RUNNING_ON_LAMBDA.store(
        std::env::var("AWS_LAMBDA_FUNCTION_NAME").is_ok(),
        Ordering::Relaxed,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    #[serial]
    fn test_ensure_home_env_set_when_home_missing() {
        let original_home = std::env::var("HOME").ok();
        std::env::remove_var("HOME");

        ensure_home_env_set();

        let home = std::env::var("HOME");
        assert!(home.is_ok(), "HOME should be set after ensure_home_env_set");
        assert!(!home.unwrap().is_empty(), "HOME should not be empty");

        // Restore
        match original_home {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    #[serial]
    fn test_ensure_home_env_set_preserves_existing_home() {
        let original_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", "/custom/home");

        ensure_home_env_set();

        assert_eq!(std::env::var("HOME").unwrap(), "/custom/home");

        // Restore
        match original_home {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    #[serial]
    fn test_ensure_home_env_set_resolves_to_passwd_entry() {
        let original_home = std::env::var("HOME").ok();
        std::env::remove_var("HOME");

        ensure_home_env_set();

        // Verify it matches what getpwuid returns
        let expected = {
            let uid = unsafe { libc::getuid() };
            let pw = unsafe { libc::getpwuid(uid) };
            assert!(!pw.is_null());
            let dir = unsafe { std::ffi::CStr::from_ptr((*pw).pw_dir) };
            dir.to_str().unwrap().to_string()
        };
        assert_eq!(std::env::var("HOME").unwrap(), expected);

        // Restore
        match original_home {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }
    }
}
