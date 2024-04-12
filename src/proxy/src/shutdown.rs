use log::debug;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ShutdownReason {
    NeedsRestart,
    UnexpectedError,
    Unmount,
    FrameSizeExceeded,
    FrameSizeTooSmall,
}

#[derive(Clone)]
pub struct ShutdownHandle {
    pub cancellation_token: CancellationToken,
    notifier: Sender<ShutdownReason>,
}

impl ShutdownHandle {
    pub fn new(cancellation_token: CancellationToken) -> (Self, Receiver<ShutdownReason>) {
        let (notifier, r) = mpsc::channel(1024);
        let h = Self {
            cancellation_token,
            notifier,
        };
        (h, r)
    }

    pub async fn exit(self, reason: Option<ShutdownReason>) {
        debug!("Exiting: {:?}", reason);
        self.cancellation_token.cancel();
        if let Some(reason) = reason {
            let _ = self.notifier.send(reason).await;
        }
    }
}

#[cfg(test)]
mod test {
    use log::info;
    use std::time::Duration;

    use tokio::sync::mpsc;
    use tokio_util::sync::CancellationToken;

    use super::ShutdownHandle;

    #[tokio::test]
    async fn test() {
        let (t, mut r) = mpsc::channel(1);
        let token = CancellationToken::new();

        let s1 = ShutdownHandle {
            cancellation_token: token.clone(),
            notifier: t.clone(),
        };
        let s2 = ShutdownHandle {
            cancellation_token: token.clone(),
            notifier: t.clone(),
        };

        tokio::spawn(run_task(s1, false));
        tokio::spawn(run_task(s2, true));
        drop(t);

        let _ = r.recv().await;
        info!("Done");
    }

    async fn run_task(shutdown: ShutdownHandle, to_cancel: bool) {
        let f = async {
            if to_cancel {
                shutdown.cancellation_token.clone().cancel()
            } else {
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        };
        tokio::select! {
            _ = shutdown.cancellation_token.cancelled() => {},
            _ = f => {}
        }
        info!("Task exiting");
    }
}
