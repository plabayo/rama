//! Engine glue for QUIC transport parameters.
//!
//! The wire codec, defaults and profile-driven write plan live in
//! [`rama_quic_proto::transport_parameters`]; this module only maps the engine's typed config into
//! an outgoing [`TransportParameters`] and derives engine-local CID limits.

pub(crate) use rama_quic_proto::transport_parameters::*;

use rand::Rng;

use crate::{
    profile::GreaseParameter,
    proto::{
        LOC_CID_COUNT, TIMER_GRANULARITY, VarInt,
        cid_generator::ConnectionIdGenerator,
        cid_queue::CidQueue,
        config::{EndpointConfig, ServerConfig, TransportConfig},
        shared::ConnectionId,
    },
};

/// Build the outgoing transport parameters for a connection from its typed configuration and wire
/// profile.
#[expect(
    clippy::unwrap_used,
    reason = "`TIMER_GRANULARITY` is 1 ms, which fits a varint"
)]
pub(crate) fn new(
    config: &TransportConfig,
    endpoint_config: &EndpointConfig,
    cid_gen: &dyn ConnectionIdGenerator,
    initial_src_cid: ConnectionId,
    server_config: Option<&ServerConfig>,
    rng: &mut impl Rng,
) -> TransportParameters {
    let wire = &config.wire;
    let mut this = TransportParameters {
        initial_src_cid: Some(initial_src_cid),
        initial_max_streams_bidi: config.max_concurrent_bidi_streams,
        initial_max_streams_uni: config.max_concurrent_uni_streams,
        initial_max_data: config.receive_window,
        initial_max_stream_data_bidi_local: config.stream_receive_window,
        initial_max_stream_data_bidi_remote: config
            .stream_receive_window_bidi_remote
            .unwrap_or(config.stream_receive_window),
        initial_max_stream_data_uni: config
            .stream_receive_window_uni
            .unwrap_or(config.stream_receive_window),
        max_udp_payload_size: endpoint_config.max_udp_payload_size,
        max_idle_timeout: config.max_idle_timeout.unwrap_or(VarInt::from_u32(0)),
        max_ack_delay: VarInt::from_u64(config.max_ack_delay.as_millis() as u64)
            .unwrap_or(VarInt::from_u32(25)),
        disable_active_migration: server_config.is_some_and(|c| !c.migration),
        active_connection_id_limit: config.active_connection_id_limit.unwrap_or(
            if cid_gen.cid_len() == 0 {
                2 // i.e. default, i.e. unsent
            } else {
                CidQueue::LEN as u32
            }
            .into(),
        ),
        max_datagram_frame_size: match wire.parameters.max_datagram_frame_size() {
            Some(size) => Some(VarInt::from_u64(size).unwrap_or(VarInt::MAX)),
            None => config
                .datagram_receive_buffer_size
                .map(|x| (x.min(u16::MAX.into()) as u16).into()),
        },
        grease_quic_bit: endpoint_config.grease_quic_bit,
        min_ack_delay: wire.parameters.sends_min_ack_delay().then(|| {
            VarInt::from_u64(u64::try_from(TIMER_GRANULARITY.as_micros()).unwrap()).unwrap()
        }),
        grease_transport_parameter: match wire.parameters.grease() {
            GreaseParameter::Random { value_len } => {
                Some(ReservedTransportParameter::random(rng, *value_len))
            }
            GreaseParameter::Fixed { id, value } => {
                Some(ReservedTransportParameter::fixed(id.0, value))
            }
            // `None`, and any future greasing mode this engine does not know, grease nothing.
            _ => None,
        },
        extra: wire
            .parameters
            .extra()
            .iter()
            .map(|parameter| (parameter.id.0, parameter.value.clone()))
            .collect(),
        write_plan: None,
        ..TransportParameters::default()
    };
    this.write_plan = Some(this.plan(wire.parameters.order(), rng));
    this
}

/// Maximum number of CIDs to issue to this peer.
///
/// Consider both a) the active_connection_id_limit from the other end; and
/// b) LOC_CID_COUNT used locally.
pub(crate) fn issue_cids_limit(params: &TransportParameters) -> u64 {
    params
        .active_connection_id_limit
        .into_inner()
        .min(LOC_CID_COUNT)
}
