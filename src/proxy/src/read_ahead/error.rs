use thiserror::Error as ThisError;

#[derive(Debug, ThisError)]
#[error("ReadAheadCache error: {message}")]
pub struct ReadAheadCacheError {
    pub message: String,
}
