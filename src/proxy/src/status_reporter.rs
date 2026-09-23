use crate::awsfile_rpc::PartitionId;
use crate::controller::ConnectionSearchState;
use crate::{proxy_identifier::ProxyIdentifier, proxy_task::PerformanceStats};
use anyhow::{Error, Result};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::sync::watch;
use tokio::time::Instant;

#[allow(dead_code)]
pub struct Report {
    pub proxy_id: ProxyIdentifier,
    pub partition_id: Option<PartitionId>,
    pub connection_state: ConnectionSearchState,
    pub num_connections: usize,
    pub last_proxy_update: Option<(Instant, PerformanceStats)>,
    pub scale_up_attempt_count: u64,
    pub restart_count: u64,
}

type Request = ();
type Response = Report;

pub struct StatusReporter {
    pub sender: Sender<Response>,
    pub receiver: Receiver<Request>,
    // Latest incarnation restart count, published by the controller on every
    // restart. Lets a waiter synchronize on a restart without polling.
    restart_tx: watch::Sender<u64>,
}

impl StatusReporter {
    pub async fn await_report_request(&mut self) -> Result<()> {
        self.receiver
            .recv()
            .await
            .ok_or_else(|| Error::msg("Request channel closed"))?;
        Ok(())
    }

    // Note: This should only be called when a message is received by the receiver.
    pub async fn publish_status(&mut self, report: Report) {
        match self.sender.send(report).await {
            Ok(_) => (),
            Err(e) => panic!("StatusReporter could not send report {}", e),
        }
    }

    /// Publish the current incarnation restart count. The watch retains the
    /// latest value, so a waiter observes the restart even if it published
    /// before the waiter started listening.
    pub fn publish_restart(&self, restart_count: u64) {
        // send() fails only once every receiver has been dropped (shutdown is
        // underway); nothing is waiting on the restart signal then, so
        // discarding the result is correct.
        let _ = self.restart_tx.send(restart_count);
    }
}

pub struct StatusRequester {
    _sender: Sender<Request>,
    _receiver: Receiver<Response>,
    restart_rx: watch::Receiver<u64>,
}

impl StatusRequester {
    pub async fn _request_status(&mut self) -> Result<Report> {
        self._sender.send(()).await?;
        self._receiver
            .recv()
            .await
            .ok_or_else(|| Error::msg("Response channel closed"))
    }

    /// Await until the controller's restart count rises above `previous` — i.e.
    /// the incarnation has been torn down and a fresh one is coming up.
    /// Event-driven (the watch retains the latest count), so there is no poll
    /// loop and no lost-wakeup race. Returns the observed restart count.
    pub async fn wait_for_restart_above(&mut self, previous: u64) -> Result<u64> {
        let count = *self
            .restart_rx
            .wait_for(|&c| c > previous)
            .await
            .map_err(|_| Error::msg("Restart watch channel closed"))?;
        Ok(count)
    }
}

pub fn create_status_channel() -> (StatusRequester, StatusReporter) {
    let (call_sender, call_receiver) = mpsc::channel::<Request>(1);
    let (reply_sender, reply_receiver) = mpsc::channel::<Response>(1);
    let (restart_tx, restart_rx) = watch::channel(0u64);

    let status_requester = StatusRequester {
        _sender: call_sender,
        _receiver: reply_receiver,
        restart_rx,
    };

    let status_reporter = StatusReporter {
        sender: reply_sender,
        receiver: call_receiver,
        restart_tx,
    };

    (status_requester, status_reporter)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_basic() -> Result<()> {
        let proxy_id = ProxyIdentifier::new();

        let (mut status_requester, mut status_reporter) = create_status_channel();
        tokio::spawn(async move {
            status_reporter
                .await_report_request()
                .await
                .expect("Request channel closed");
            let report = Report {
                proxy_id,
                partition_id: None,
                connection_state: ConnectionSearchState::Idle,
                num_connections: 1,
                last_proxy_update: None,
                scale_up_attempt_count: 0,
                restart_count: 0,
            };
            status_reporter.publish_status(report).await
        });

        let r = status_requester._request_status().await?;
        assert_eq!(proxy_id, r.proxy_id);
        assert!(r.partition_id.is_none());
        assert_eq!(r.connection_state, ConnectionSearchState::Idle);
        assert!(r.last_proxy_update.is_none());
        assert_eq!(1, r.num_connections);
        Ok(())
    }
}
