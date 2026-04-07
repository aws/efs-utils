//! # ReadBypassRequestContext
//! Request-scoped context that wraps ReadBypassContext with request-specific metadata
//! for logging and tracing purposes.

use super::read_bypass_context::ReadBypassContext;
use std::ops::Deref;
use std::sync::Arc;
use tokio::task::Id;

pub struct ReadBypassRequestContext {
    pub read_bypass_context: Arc<ReadBypassContext>,
    pub rpc_xid: u32,
    pub thread_name: String,
    pub task_id: Option<Id>,
}

impl ReadBypassRequestContext {
    pub fn new(read_bypass_context: Arc<ReadBypassContext>, rpc_xid: u32) -> Self {
        let thread_name = std::thread::current()
            .name()
            .unwrap_or("unknown")
            .to_string();
        let task_id = tokio::task::try_id();

        Self {
            read_bypass_context,
            rpc_xid,
            thread_name,
            task_id,
        }
    }

    #[cfg(test)]
    pub async fn default() -> Self {
        Self {
            read_bypass_context: Arc::new(ReadBypassContext::default().await),
            rpc_xid: 0,
            thread_name: "test".to_string(),
            task_id: None,
        }
    }

    /// Returns a log prefix containing thread name, task ID, and RPC XID.
    /// Format: [thread_name-task_id-rpc_xid]
    /// This prefix is automatically prepended by ctx_debug!, ctx_info!, ctx_warn!, ctx_error!, and ctx_trace! macros.
    pub fn log_prefix(&self) -> String {
        match self.task_id {
            Some(id) => format!("[{}-{}-{}]", self.thread_name, id, self.rpc_xid),
            None => format!("[{}-?-{}]", self.thread_name, self.rpc_xid),
        }
    }
}

impl Deref for ReadBypassRequestContext {
    type Target = ReadBypassContext;

    fn deref(&self) -> &Self::Target {
        &self.read_bypass_context
    }
}

/// Logs a debug message with request context prefix [thread_name-task_id-rpc_xid].
#[macro_export]
macro_rules! ctx_debug {
    ($ctx:expr, $($arg:tt)*) => {
        log::debug!("{} {}", $ctx.log_prefix(), format!($($arg)*))
    };
}

/// Logs an info message with request context prefix [thread_name-task_id-rpc_xid].
#[macro_export]
macro_rules! ctx_info {
    ($ctx:expr, $($arg:tt)*) => {
        log::info!("{} {}", $ctx.log_prefix(), format!($($arg)*))
    };
}

/// Logs a warning message with request context prefix [thread_name-task_id-rpc_xid].
#[macro_export]
macro_rules! ctx_warn {
    ($ctx:expr, $($arg:tt)*) => {
        log::warn!("{} {}", $ctx.log_prefix(), format!($($arg)*))
    };
}

/// Logs an error message with request context prefix [thread_name-task_id-rpc_xid].
#[macro_export]
macro_rules! ctx_error {
    ($ctx:expr, $($arg:tt)*) => {
        log::error!("{} {}", $ctx.log_prefix(), format!($($arg)*))
    };
}

/// Logs a trace message with request context prefix [thread_name-task_id-rpc_xid].
#[macro_export]
macro_rules! ctx_trace {
    ($ctx:expr, $($arg:tt)*) => {
        log::trace!("{} {}", $ctx.log_prefix(), format!($($arg)*))
    };
}
