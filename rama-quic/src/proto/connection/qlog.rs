// Function bodies in this module are regularly cfg'd out
#![cfg_attr(
    not(feature = "qlog"),
    expect(
        unused_variables,
        reason = "the no-op sink keeps the parameter names of the real one"
    )
)]

#[cfg(feature = "qlog")]
use std::sync::Arc;

#[cfg(feature = "qlog")]
use parking_lot::Mutex;
use std::time::Duration;

#[cfg(feature = "qlog")]
pub(super) mod event;
#[cfg(feature = "qlog")]
pub(crate) mod writer;
#[cfg(feature = "qlog")]
use event::{Event, Packet, PacketHeader, PacketLost, PacketLostTrigger, PacketType, RawInfo};
#[cfg(feature = "qlog")]
use rama_core::telemetry::tracing::warn;
#[cfg(feature = "qlog")]
use writer::QlogWriter;

use crate::proto::{
    ConnectionId, Instant,
    connection::{PathData, SentPacket},
    packet::SpaceId,
};

/// Shareable handle to a single qlog output stream
#[cfg(feature = "qlog")]
#[derive(Clone)]
pub(crate) struct QlogStream(pub(crate) Arc<Mutex<QlogWriter>>);

#[cfg(feature = "qlog")]
impl QlogStream {
    /// Record one event under the connection's group. The group is the destination identifier
    /// the client chose for its first Initial (RFC 9000 §7.2): it is the one identifier both
    /// ends know and neither changes, so every record of a connection carries the same group
    /// even when several connections write into one stream.
    fn emit_event(&self, group: ConnectionId, event: Event, now: Instant) {
        let result = self.0.lock().emit(&group, event, now);
        if let Err(e) = result {
            warn!("could not emit qlog event: {e}");
        }
    }
}

/// A [`QlogStream`] that may be either dynamically disabled or compiled out entirely
#[derive(Clone, Default)]
pub(crate) struct QlogSink {
    #[cfg(feature = "qlog")]
    stream: Option<QlogStream>,
}

#[cfg_attr(
    not(feature = "qlog"),
    expect(
        clippy::unused_self,
        reason = "without the feature the bodies are empty, and the sink holds the stream in the qlog build"
    )
)]
impl QlogSink {
    pub(crate) fn is_enabled(&self) -> bool {
        #[cfg(feature = "qlog")]
        {
            self.stream.is_some()
        }
        #[cfg(not(feature = "qlog"))]
        {
            false
        }
    }

    #[cfg_attr(
        not(feature = "qlog"),
        expect(
            clippy::needless_pass_by_ref_mut,
            reason = "the qlog build takes the metrics through `&mut PathData`; without the feature the body is empty"
        )
    )]
    pub(super) fn emit_recovery_metrics(
        &self,
        pto_count: u32,
        path: &mut PathData,
        now: Instant,
        group: ConnectionId,
    ) {
        #[cfg(feature = "qlog")]
        {
            let Some(stream) = self.stream.as_ref() else {
                return;
            };

            let Some(metrics) = path.qlog_recovery_metrics(pto_count) else {
                return;
            };

            stream.emit_event(group, Event::RecoveryMetricsUpdated(metrics), now);
        }
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
        #[cfg(feature = "qlog")]
        {
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
        #[cfg(feature = "qlog")]
        {
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
    }

    pub(super) fn emit_packet_received(
        &self,
        pn: u64,
        space: SpaceId,
        is_0rtt: bool,
        now: Instant,
        group: ConnectionId,
    ) {
        #[cfg(feature = "qlog")]
        {
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
}

#[cfg(feature = "qlog")]
impl From<Option<QlogStream>> for QlogSink {
    fn from(stream: Option<QlogStream>) -> Self {
        Self { stream }
    }
}

#[cfg(feature = "qlog")]
fn packet_type(space: SpaceId, is_0rtt: bool) -> PacketType {
    match space {
        SpaceId::Initial => PacketType::Initial,
        SpaceId::Handshake => PacketType::Handshake,
        SpaceId::Data if is_0rtt => PacketType::ZeroRtt,
        SpaceId::Data => PacketType::OneRtt,
    }
}

#[cfg(all(test, feature = "qlog"))]
mod tests;
