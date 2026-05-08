use async_trait::async_trait;
use futures_util::SinkExt;
use network::Acknowledgement;
use tokio::sync::mpsc::UnboundedSender;
use types::{beacon::WrapperMsg, SyncMsg};

#[derive(Debug, Clone)]
pub struct Handler {
    consensus_tx: UnboundedSender<WrapperMsg>,
}

impl Handler {
    pub fn new(consensus_tx: UnboundedSender<WrapperMsg>) -> Self {
        Self { consensus_tx }
    }
}

#[async_trait]
impl network::Handler<Acknowledgement, WrapperMsg> for Handler {
    async fn dispatch(
        &self,
        msg: WrapperMsg,
        writer: &mut network::Writer<Acknowledgement>,
    ) {
        // Forward the message to the consensus task. If the consensus
        // task has died (channel receiver dropped), DO NOT panic — that
        // would kill the network task too and turn a single-task crash
        // into a node-wide crash. Just log and drop the inbound message.
        if let Err(e) = self.consensus_tx.send(msg) {
            log::error!(
                "[PPT][NET] consensus channel closed; dropping inbound msg ({})",
                e
            );
            return;
        }

        if let Err(e) = writer.send(Acknowledgement::Pong).await {
            log::warn!("[PPT][NET] failed to send ack to peer: {}", e);
        }
    }
}

#[derive(Debug, Clone)]
pub struct SyncHandler {
    consensus_tx: UnboundedSender<SyncMsg>,
}

impl SyncHandler {
    pub fn new(consensus_tx: UnboundedSender<SyncMsg>) -> Self {
        Self { consensus_tx }
    }
}

#[async_trait]
impl network::Handler<Acknowledgement, SyncMsg> for SyncHandler {
    async fn dispatch(
        &self,
        msg: SyncMsg,
        writer: &mut network::Writer<Acknowledgement>,
    ) {
        // Same graceful-close behaviour as `Handler::dispatch` above.
        if let Err(e) = self.consensus_tx.send(msg) {
            log::error!(
                "[PPT][NET-SYNC] sync channel closed; dropping inbound sync msg ({})",
                e
            );
            return;
        }

        if let Err(e) = writer.send(Acknowledgement::Pong).await {
            log::warn!("[PPT][NET-SYNC] failed to send ack to syncer: {}", e);
        }
    }
}
