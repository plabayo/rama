use serde::Serialize;
use std::sync::Arc;

use parking_lot::Mutex;
use std::time::Duration;

pub(super) mod drops;
pub(super) mod event;
pub(super) mod lifecycle;
pub(super) mod negotiation;
pub(super) mod path;
pub(crate) mod writer;
use event::{Event, Packet, PacketHeader, PacketLost, PacketLostTrigger, PacketType, RawInfo};
use rama_core::telemetry::tracing::warn;
use writer::QlogWriter;

use crate::proto::{
    ConnectionId, Instant,
    connection::{PathData, SentPacket},
    packet::SpaceId,
};

/// Shareable handle to a single qlog output stream
#[derive(Clone)]
pub(crate) struct QlogStream(pub(crate) Arc<Mutex<QlogWriter>>);

impl QlogStream {
    /// Record one event under the connection's group. The group is the destination identifier
    /// the client chose for its first Initial (RFC 9000 §7.2): it is the one identifier both
    /// ends know and neither changes, so every record of a connection carries the same group
    /// even when several connections write into one stream.
    fn emit_event(&self, group: ConnectionId, event: impl Serialize, now: Instant) {
        let result = self.0.lock().emit(&group, event, now);
        if let Err(e) = result {
            warn!("could not emit qlog event: {e}");
        }
    }
}

/// An optional shared qlog stream; no writer means recording is disabled.
#[derive(Clone, Default)]
pub(crate) struct QlogSink {
    stream: Option<QlogStream>,
}

impl QlogSink {
    /// Construct diagnostic data only when a writer is configured.
    pub(crate) fn emit<E: Serialize>(
        &self,
        group: ConnectionId,
        now: Instant,
        event: impl FnOnce() -> E,
    ) {
        if let Some(stream) = &self.stream {
            stream.emit_event(group, event(), now);
        }
    }

    pub(crate) fn is_enabled(&self) -> bool {
        self.stream.is_some()
    }

    pub(super) fn emit_recovery_metrics(
        &self,
        pto_count: u32,
        path: &mut PathData,
        now: Instant,
        group: ConnectionId,
    ) {
        let Some(stream) = self.stream.as_ref() else {
            return;
        };

        let Some(metrics) = path.qlog_recovery_metrics(pto_count) else {
            return;
        };

        stream.emit_event(
            group,
            path::with_path(path.generation(), Event::RecoveryMetricsUpdated(metrics)),
            now,
        );
    }

    pub(super) fn emit_packet_lost(
        &self,
        pn: u64,
        info: &SentPacket,
        loss_delay: Duration,
        space: SpaceId,
        now: Instant,
        group: ConnectionId,
    ) {
        let Some(stream) = self.stream.as_ref() else {
            return;
        };

        let event = PacketLost {
            header: PacketHeader {
                packet_number: pn,
                packet_type: packet_type(space, info.is_0rtt),
            },
            is_mtu_probe_packet: false,
            trigger: match now.saturating_duration_since(info.time_sent) >= loss_delay {
                true => PacketLostTrigger::TimeThreshold,
                false => PacketLostTrigger::ReorderingThreshold,
            },
        };

        stream.emit_event(group, Event::PacketLost(event), now);
    }

    pub(super) fn emit_packet_sent(
        &self,
        pn: u64,
        len: usize,
        space: SpaceId,
        is_0rtt: bool,
        now: Instant,
        group: ConnectionId,
    ) {
        let Some(stream) = self.stream.as_ref() else {
            return;
        };

        let event = Packet {
            header: PacketHeader {
                packet_number: pn,
                packet_type: packet_type(space, is_0rtt),
            },
            raw: Some(RawInfo { length: len }),
        };

        stream.emit_event(group, Event::PacketSent(event), now);
    }

    pub(super) fn emit_packet_received(
        &self,
        pn: u64,
        space: SpaceId,
        is_0rtt: bool,
        now: Instant,
        group: ConnectionId,
    ) {
        let Some(stream) = self.stream.as_ref() else {
            return;
        };

        let event = Packet {
            header: PacketHeader {
                packet_number: pn,
                packet_type: packet_type(space, is_0rtt),
            },
            raw: None,
        };

        stream.emit_event(group, Event::PacketReceived(event), now);
    }
}

impl From<Option<QlogStream>> for QlogSink {
    fn from(stream: Option<QlogStream>) -> Self {
        Self { stream }
    }
}

fn packet_type(space: SpaceId, is_0rtt: bool) -> PacketType {
    match space {
        SpaceId::Initial => PacketType::Initial,
        SpaceId::Handshake => PacketType::Handshake,
        SpaceId::Data if is_0rtt => PacketType::ZeroRtt,
        SpaceId::Data => PacketType::OneRtt,
    }
}

#[cfg(test)]
mod tests;
