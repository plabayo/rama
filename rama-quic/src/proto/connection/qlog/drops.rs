//! Connection-scoped packet drops (QUIC events draft 13, section 5.7).

use serde::Serialize;

use super::event::RawInfo;
use crate::proto::{
    Instant,
    connection::Connection,
    packet::{Header, LongType, Packet, PartialDecode, SpaceId},
};

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DropReason {
    Invalid,
    Duplicate,
    DecryptionFailure,
    KeyUnavailable,
    Rejected,
    Unsupported,
}

/// Only authenticated, expanded packet numbers are recorded. An undecodable header is omitted.
#[derive(Clone, Copy)]
pub(crate) struct DropInfo {
    packet_type: Option<&'static str>,
    pub(crate) number: Option<u64>,
    length: Option<usize>,
}

impl DropInfo {
    pub(crate) fn unknown() -> Self {
        Self {
            packet_type: None,
            number: None,
            length: None,
        }
    }

    pub(crate) fn partial(packet: &PartialDecode) -> Self {
        let packet_type = match packet.space() {
            Some(SpaceId::Initial) => Some("initial"),
            Some(SpaceId::Handshake) => Some("handshake"),
            Some(SpaceId::Data) if packet.is_0rtt() => Some("0RTT"),
            Some(SpaceId::Data) => Some("1RTT"),
            None => None,
        };
        Self {
            packet_type,
            number: None,
            length: Some(packet.len()),
        }
    }

    pub(crate) fn packet(packet: &Packet) -> Self {
        let packet_type = match packet.header {
            Header::Initial(_) => "initial",
            Header::Long {
                ty: LongType::Handshake,
                ..
            } => "handshake",
            Header::Long {
                ty: LongType::ZeroRtt,
                ..
            } => "0RTT",
            Header::Short { .. } => "1RTT",
            Header::Retry { .. } => "retry",
            Header::VersionNegotiate { .. } => "version_negotiation",
        };
        Self {
            packet_type: Some(packet_type),
            number: None,
            length: Some(packet.header_data.len() + packet.payload.len()),
        }
    }

    /// Protected packet bodies have already lost their AEAD trailer at this point.
    pub(crate) fn decrypted(packet: &Packet, number: Option<u64>) -> Self {
        let mut info = Self::packet(packet).with_number(number);
        if packet.header.is_protected() {
            info.length = None;
        }
        info
    }

    pub(crate) fn with_number(mut self, number: Option<u64>) -> Self {
        self.number = number;
        self
    }
}

#[derive(Serialize)]
#[serde(tag = "name", content = "data")]
enum Event {
    #[serde(rename = "quic:packet_dropped")]
    PacketDropped(PacketDropped),
}

#[derive(Serialize)]
struct PacketDropped {
    #[serde(skip_serializing_if = "Option::is_none")]
    header: Option<DropHeader>,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw: Option<RawInfo>,
    trigger: DropReason,
}

#[derive(Serialize)]
struct DropHeader {
    packet_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    packet_number: Option<u64>,
}

impl Connection {
    pub(crate) fn qlog_packet_dropped(&self, now: Instant, info: DropInfo, trigger: DropReason) {
        self.config.qlog_sink.emit(self.trace_cid, now, || {
            Event::PacketDropped(PacketDropped {
                header: info.packet_type.map(|packet_type| DropHeader {
                    packet_type,
                    packet_number: info.number,
                }),
                raw: info.length.map(|length| RawInfo { length }),
                trigger,
            })
        });
    }
}
