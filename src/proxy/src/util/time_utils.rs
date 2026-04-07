use std::time::Duration;
use tokio::time::Instant;

pub fn create_deadline(duration: Duration) -> Instant {
    Instant::now() + duration
}
