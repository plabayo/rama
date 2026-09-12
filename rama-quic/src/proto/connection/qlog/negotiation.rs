//! Negotiation and traffic-key observations for the QUIC qlog event schema.

use serde::Serialize;

use crate::proto::{
    Instant, connection::Connection, packet::SpaceId, transport_parameters::TransportParameters,
};

#[derive(Serialize)]
#[serde(tag = "name", content = "data")]
enum Event<'a> {
    #[serde(rename = "quic:version_information")]
    VersionInformation(VersionInformation),
    #[serde(rename = "quic:alpn_information")]
    AlpnInformation { chosen_alpn: AlpnIdentifier<'a> },
    #[serde(rename = "quic:parameters_set")]
    ParametersSet(ParametersSet<'a>),
    #[serde(rename = "quic:parameters_restored")]
    ParametersRestored(RestoredParameters),
    #[serde(rename = "quic:key_updated")]
    KeyUpdated(KeyChange),
    #[serde(rename = "quic:key_discarded")]
    KeyDiscarded(KeyChange),
}

#[derive(Serialize)]
struct Hex<'a>(#[serde(with = "rama_utils::bytes::serde_hex")] &'a [u8]);

#[derive(Serialize)]
struct Version(#[serde(with = "rama_utils::bytes::serde_hex")] [u8; 4]);

#[derive(Serialize)]
struct VersionInformation {
    #[serde(skip_serializing_if = "Option::is_none")]
    server_versions: Option<Vec<Version>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_versions: Option<Vec<Version>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chosen_version: Option<Version>,
}

#[derive(Serialize)]
struct AlpnIdentifier<'a> {
    byte_value: Hex<'a>,
}

// These are the remembered parameters that this implementation actually restores.
#[derive(Serialize)]
struct RestoredParameters {
    disable_active_migration: bool,
    max_idle_timeout: u64,
    max_udp_payload_size: u64,
    active_connection_id_limit: u64,
    initial_max_data: u64,
    initial_max_stream_data_bidi_local: u64,
    initial_max_stream_data_bidi_remote: u64,
    initial_max_stream_data_uni: u64,
    initial_max_streams_bidi: u64,
    initial_max_streams_uni: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_datagram_frame_size: Option<u64>,
    grease_quic_bit: bool,
}

impl From<&TransportParameters> for RestoredParameters {
    fn from(params: &TransportParameters) -> Self {
        Self {
            disable_active_migration: params.disable_active_migration,
            max_idle_timeout: params.max_idle_timeout.into_inner(),
            max_udp_payload_size: params.max_udp_payload_size.into_inner(),
            active_connection_id_limit: params.active_connection_id_limit.into_inner(),
            initial_max_data: params.initial_max_data.into_inner(),
            initial_max_stream_data_bidi_local: params
                .initial_max_stream_data_bidi_local
                .into_inner(),
            initial_max_stream_data_bidi_remote: params
                .initial_max_stream_data_bidi_remote
                .into_inner(),
            initial_max_stream_data_uni: params.initial_max_stream_data_uni.into_inner(),
            initial_max_streams_bidi: params.initial_max_streams_bidi.into_inner(),
            initial_max_streams_uni: params.initial_max_streams_uni.into_inner(),
            max_datagram_frame_size: params
                .max_datagram_frame_size
                .map(|value| value.into_inner()),
            grease_quic_bit: params.grease_quic_bit,
        }
    }
}

#[derive(Serialize)]
struct ParametersSet<'a> {
    initiator: &'static str,
    #[serde(flatten)]
    parameters: RestoredParameters,
    ack_delay_exponent: u64,
    max_ack_delay: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    original_destination_connection_id: Option<Hex<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    initial_source_connection_id: Option<Hex<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_source_connection_id: Option<Hex<'a>>,
}

impl<'a> ParametersSet<'a> {
    fn new(initiator: &'static str, params: &'a TransportParameters) -> Self {
        Self {
            initiator,
            parameters: params.into(),
            ack_delay_exponent: params.ack_delay_exponent.into_inner(),
            max_ack_delay: params.max_ack_delay.into_inner(),
            original_destination_connection_id: params
                .original_dst_cid
                .as_ref()
                .map(|cid| Hex(cid)),
            initial_source_connection_id: params.initial_src_cid.as_ref().map(|cid| Hex(cid)),
            retry_source_connection_id: params.retry_src_cid.as_ref().map(|cid| Hex(cid)),
        }
    }
}

#[derive(Serialize)]
struct KeyChange {
    key_type: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_phase: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    trigger: Option<&'static str>,
}

impl Connection {
    pub(in crate::proto::connection) fn qlog_init_negotiation(&self, now: Instant) {
        self.config.qlog_sink.emit(self.trace_cid, now, || {
            let versions = version_list(self.endpoint_config.supported_versions.iter().copied());
            let (client_versions, server_versions) = if self.side.is_client() {
                (versions, None)
            } else {
                (None, versions)
            };
            Event::VersionInformation(VersionInformation {
                client_versions,
                server_versions,
                chosen_version: Some(Version(self.version.to_be_bytes())),
            })
        });
        self.qlog_key_change(now, SpaceId::Initial, false, Some("tls"));
    }

    pub(in crate::proto::connection) fn qlog_version_negotiated(
        &self,
        now: Instant,
        payload: &[u8],
    ) {
        self.config.qlog_sink.emit(self.trace_cid, now, || {
            Event::VersionInformation(VersionInformation {
                client_versions: version_list(
                    self.endpoint_config.supported_versions.iter().copied(),
                ),
                server_versions: version_list(
                    payload
                        .as_chunks::<4>()
                        .0
                        .iter()
                        .map(|bytes| u32::from_be_bytes(*bytes)),
                ),
                // This connection terminates on Version Negotiation, so no version was selected.
                chosen_version: None,
            })
        });
    }

    pub(crate) fn qlog_local_parameters(&self, now: Instant, params: &TransportParameters) {
        self.config.qlog_sink.emit(self.trace_cid, now, || {
            Event::ParametersSet(ParametersSet::new("local", params))
        });
    }

    pub(in crate::proto::connection) fn qlog_remote_parameters(
        &self,
        now: Instant,
        params: &TransportParameters,
    ) {
        self.config.qlog_sink.emit(self.trace_cid, now, || {
            Event::ParametersSet(ParametersSet::new("remote", params))
        });
    }

    pub(in crate::proto::connection) fn qlog_restored_parameters(
        &self,
        now: Instant,
        params: &TransportParameters,
    ) {
        self.config.qlog_sink.emit(self.trace_cid, now, || {
            Event::ParametersRestored(params.into())
        });
    }

    pub(in crate::proto::connection) fn qlog_negotiated_alpn(&self, now: Instant) {
        if !self.config.qlog_sink.is_enabled() {
            return;
        }
        if let Some(summary) = self.crypto.handshake_summary()
            && let Some(protocol) = summary.protocol
        {
            self.config
                .qlog_sink
                .emit(self.trace_cid, now, || Event::AlpnInformation {
                    chosen_alpn: AlpnIdentifier {
                        byte_value: Hex(protocol.as_bytes()),
                    },
                });
        }
    }

    pub(in crate::proto::connection) fn qlog_key_change(
        &self,
        now: Instant,
        space: SpaceId,
        discarded: bool,
        trigger: Option<&'static str>,
    ) {
        let key_types = match space {
            SpaceId::Initial => ["client_initial_secret", "server_initial_secret"],
            SpaceId::Handshake => ["client_handshake_secret", "server_handshake_secret"],
            SpaceId::Data => ["client_1rtt_secret", "server_1rtt_secret"],
        };
        for key_type in key_types {
            self.qlog_key(
                now,
                KeyChange {
                    key_type,
                    key_phase: (space == SpaceId::Data).then_some(self.stats.key_updates),
                    trigger,
                },
                discarded,
            );
        }
    }

    pub(in crate::proto::connection) fn qlog_zero_rtt_key(&self, now: Instant, discarded: bool) {
        // 0-RTT traffic flows only from client to server, even on the server's trace.
        self.qlog_key(
            now,
            KeyChange {
                key_type: "client_0rtt_secret",
                key_phase: None,
                trigger: Some("tls"),
            },
            discarded,
        );
    }

    pub(in crate::proto::connection) fn qlog_discard_retired_keys(&mut self, now: Instant) {
        if self.zero_rtt_crypto.take().is_some() {
            self.qlog_zero_rtt_key(now, true);
        }
        self.qlog_discard_previous_keys(now);
    }

    pub(in crate::proto::connection) fn qlog_discard_previous_keys(&mut self, now: Instant) {
        if self.prev_crypto.take().is_some() {
            for key_type in ["client_1rtt_secret", "server_1rtt_secret"] {
                self.qlog_key(
                    now,
                    KeyChange {
                        key_type,
                        key_phase: Some(self.stats.key_updates.saturating_sub(1)),
                        trigger: None,
                    },
                    true,
                );
            }
        }
    }

    fn qlog_key(&self, now: Instant, change: KeyChange, discarded: bool) {
        self.config.qlog_sink.emit(self.trace_cid, now, || {
            if discarded {
                Event::KeyDiscarded(change)
            } else {
                Event::KeyUpdated(change)
            }
        });
    }
}

fn version_list(versions: impl Iterator<Item = u32>) -> Option<Vec<Version>> {
    let versions: Vec<_> = versions
        .map(|version| Version(version.to_be_bytes()))
        .collect();
    (!versions.is_empty()).then_some(versions)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_version_lists_are_omitted() {
        let event = Event::VersionInformation(VersionInformation {
            client_versions: version_list([1, 0x6b3343cf].into_iter()),
            server_versions: version_list(std::iter::empty()),
            chosen_version: None,
        });
        assert_eq!(
            serde_json::to_value(event).unwrap(),
            serde_json::json!({
                "name": "quic:version_information",
                "data": { "client_versions": ["00000001", "6b3343cf"] }
            })
        );
    }
}
