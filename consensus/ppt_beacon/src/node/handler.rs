use async_trait::async_trait;
use futures_util::SinkExt;
use network::Acknowledgement;
use tokio::sync::mpsc;
use types::{beacon::WrapperMsg, SyncMsg};

#[derive(Debug, Clone)]
pub struct Handler {
    consensus_tx: mpsc::Sender<WrapperMsg>,
}

impl Handler {
    pub fn new(consensus_tx: mpsc::Sender<WrapperMsg>) -> Self {
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
        // Bounded `mpsc::Sender::send().await` blocks while the
        // consensus task is overloaded. That backpressure flows into
        // the TCP read buffer and slows the peer naturally — much
        // better than the old `unbounded_channel` which would let
        // memory grow without bound while the peer kept sending.
        //
        // If the consensus task is gone (channel closed), drop the
        // inbound msg gracefully — never panic, because that used to
        // cascade-kill the network task and bring the whole node
        // dark.
        if let Err(e) = self.consensus_tx.send(msg).await {
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
    consensus_tx: mpsc::Sender<SyncMsg>,
}

impl SyncHandler {
    pub fn new(consensus_tx: mpsc::Sender<SyncMsg>) -> Self {
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
        // Same graceful-close + backpressure behaviour as
        // `Handler::dispatch` above.
        if let Err(e) = self.consensus_tx.send(msg).await {
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
