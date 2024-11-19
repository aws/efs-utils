use crate::controller::ConnectionSearchState;
use crate::efs_rpc::PartitionId;
use crate::{proxy::PerformanceStats, proxy_identifier::ProxyIdentifier};
use anyhow::{Error, Result};
use tokio::sync::mpsc::{self, Receiver, Sender};
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
}

pub struct StatusRequester {
    _sender: Sender<Request>,
    _receiver: Receiver<Response>,
}

impl StatusRequester {
    pub async fn _request_status(&mut self) -> Result<Report> {
        self._sender.send(()).await?;
        self._receiver
            .recv()
            .await
            .ok_or_else(|| Error::msg("Response channel closed"))
    }
}

pub fn create_status_channel() -> (StatusRequester, StatusReporter) {
    let (call_sender, call_receiver) = mpsc::channel::<Request>(1);
    let (reply_sender, reply_receiver) = mpsc::channel::<Response>(1);

    let status_requester = StatusRequester {
        _sender: call_sender,
        _receiver: reply_receiver,
    };

    let status_reporter = StatusReporter {
        sender: reply_sender,
        receiver: call_receiver,
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
