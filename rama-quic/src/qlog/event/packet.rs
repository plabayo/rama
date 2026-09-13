//! Packet observations and recovery metrics emitted by Rama.

use serde::Serialize;

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(tag = "name", content = "data")]
/// Packet transmission, reception, loss, and recovery observations.
pub enum PacketEvent {
    /// A packet was transmitted.
    #[serde(rename = "quic:packet_sent")]
    PacketSent(Packet),

    /// A packet was received and authenticated.
    #[serde(rename = "quic:packet_received")]
    PacketReceived(Packet),

    /// Loss detection declared a packet lost.
    #[serde(rename = "quic:packet_lost")]
    PacketLost(PacketLost),

    /// Recovery or congestion-control metrics changed.
    #[serde(rename = "quic:recovery_metrics_updated")]
    RecoveryMetricsUpdated(RecoveryMetricsUpdated),
}

#[derive(Clone, Copy, Debug, Serialize)]
/// Observed packet header and its known wire length.
pub struct Packet {
    /// Packet type and authenticated packet number.
    pub header: PacketHeader,

    /// Encoded packet size, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<RawInfo>,
}

#[derive(Clone, Copy, Debug, Serialize)]
/// Authenticated packet number and encryption level.
pub struct PacketHeader {
    /// QUIC packet type and protection level.
    pub packet_type: PacketType,

    /// Full packet number within its packet-number space.
    pub packet_number: u64,
}

#[derive(Clone, Copy, Debug, Serialize)]
/// Known size of the entire encoded packet, in bytes; contains no packet payload.
pub struct RawInfo {
    /// Entire encoded packet length, in bytes.
    pub length: usize,
}

#[derive(Clone, Copy, Debug, Serialize)]
/// Encryption level of a numbered QUIC packet.
pub enum PacketType {
    /// Initial handshake packet protected with initial secrets.
    #[serde(rename = "initial")]
    Initial,

    /// Handshake packet protected with handshake secrets.
    #[serde(rename = "handshake")]
    Handshake,

    /// Early application data protected with 0-RTT secrets.
    #[serde(rename = "0RTT")]
    ZeroRtt,

    /// Application data protected with 1-RTT secrets.
    #[serde(rename = "1RTT")]
    OneRtt,
}

#[derive(Clone, Copy, Debug, Serialize)]
/// Loss declaration and the detection threshold that triggered it.
pub struct PacketLost {
    /// Packet type and authenticated packet number.
    pub header: PacketHeader,

    /// Whether this packet tested a larger path MTU.
    pub is_mtu_probe_packet: bool,

    /// Loss detection criterion that declared this packet lost.
    pub trigger: PacketLostTrigger,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
/// Loss detection criterion.
pub enum PacketLostTrigger {
    /// The packet exceeded the time-based loss threshold.
    TimeThreshold,

    /// Enough later packets were acknowledged to exceed the reordering threshold.
    ReorderingThreshold,
}

#[derive(Default, Clone, Copy, Debug, Serialize)]
/// Changed recovery metrics. RTT values are milliseconds; window sizes are bytes.
/// Absent values were not updated by this observation.
pub struct RecoveryMetricsUpdated {
    /// Minimum observed round-trip time, in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_rtt: Option<f32>,

    /// Smoothed round-trip time estimate, in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smoothed_rtt: Option<f32>,

    /// Most recent round-trip time sample, in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_rtt: Option<f32>,

    /// Smoothed round-trip time variation, in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_variance: Option<f32>,

    /// Consecutive probe timeouts since acknowledgement progress.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pto_count: Option<u16>,

    /// Current congestion window, in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub congestion_window: Option<u64>,

    /// Unacknowledged congestion-controlled bytes currently in flight.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_in_flight: Option<u64>,

    /// Slow-start threshold, in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssthresh: Option<u64>,

    /// Congestion controller pacing rate, in bits per second.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pacing_rate: Option<u64>,
}
