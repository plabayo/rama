//! QUIC event definitions emitted by Rama (qlog QUIC events draft 13).

use serde::Serialize;

#[derive(Serialize)]
#[serde(tag = "name", content = "data")]
pub(crate) enum Event {
    #[serde(rename = "quic:packet_sent")]
    PacketSent(Packet),
    #[serde(rename = "quic:packet_received")]
    PacketReceived(Packet),
    #[serde(rename = "quic:packet_lost")]
    PacketLost(PacketLost),
    #[serde(rename = "quic:recovery_metrics_updated")]
    RecoveryMetricsUpdated(RecoveryMetricsUpdated),
}

#[derive(Serialize)]
pub(crate) struct Packet {
    pub(crate) header: PacketHeader,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) raw: Option<RawInfo>,
}

#[derive(Serialize)]
pub(crate) struct PacketHeader {
    pub(crate) packet_type: PacketType,
    pub(crate) packet_number: u64,
}

#[derive(Serialize)]
pub(crate) struct RawInfo {
    pub(crate) length: usize,
}

#[derive(Clone, Copy, Serialize)]
pub(crate) enum PacketType {
    #[serde(rename = "initial")]
    Initial,
    #[serde(rename = "handshake")]
    Handshake,
    #[serde(rename = "0RTT")]
    ZeroRtt,
    #[serde(rename = "1RTT")]
    OneRtt,
}

#[derive(Serialize)]
pub(crate) struct PacketLost {
    pub(crate) header: PacketHeader,
    pub(crate) is_mtu_probe_packet: bool,
    pub(crate) trigger: PacketLostTrigger,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PacketLostTrigger {
    TimeThreshold,
    ReorderingThreshold,
}

#[derive(Default, Serialize)]
pub(crate) struct RecoveryMetricsUpdated {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) min_rtt: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) smoothed_rtt: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) latest_rtt: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) rtt_variance: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) pto_count: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) congestion_window: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) bytes_in_flight: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) ssthresh: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) pacing_rate: Option<u64>,
}
