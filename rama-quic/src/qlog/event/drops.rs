//! Packet drop event data.

use super::packet::RawInfo;
use serde::Serialize;

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
/// Reason a packet was discarded.
pub enum DropReason {
    /// The packet violated QUIC encoding or protocol requirements.
    Invalid,

    /// The packet number was already received.
    Duplicate,

    /// Packet authentication or decryption failed.
    DecryptionFailure,

    /// Required packet-protection keys were unavailable.
    KeyUnavailable,

    /// Connection state or endpoint policy rejected the packet.
    Rejected,

    /// The packet used an unsupported protocol version or feature.
    Unsupported,
}

#[derive(Clone, Copy, Debug, Serialize)]
/// Packet-drop data; undecodable headers and unknown wire lengths are omitted.
pub struct PacketDropped {
    /// Decoded header information, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<DropHeader>,

    /// Encoded packet size, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<RawInfo>,

    /// Reason the packet was discarded.
    pub trigger: DropReason,
}

#[derive(Clone, Copy, Debug, Serialize)]
/// Known packet type and, when authenticated, expanded packet number.
pub struct DropHeader {
    /// Qlog packet type name, including unnumbered packet types.
    pub packet_type: &'static str,

    /// Full packet number, present only when authenticated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packet_number: Option<u64>,
}

/// Tagged packet-drop event.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(tag = "name", content = "data")]
pub enum DropEvent {
    /// A packet was discarded before normal processing completed.
    #[serde(rename = "quic:packet_dropped")]
    PacketDropped(PacketDropped),
}
