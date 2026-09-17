//! Applying a QUIC wire profile to this engine's configuration.
//!
//! The [`QuicProfile`] descriptor and its parts live in [`rama_quic_proto::profile`]; this module
//! turns one into this engine's [`EndpointConfig`], [`ClientConfig`] and [`ServerConfig`], and
//! reads a first flight back through [`capture`].

pub(crate) use rama_quic_proto::profile::*;

pub mod capture;

#[cfg(all(
    test,
    any(
        feature = "boring",
        all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
    )
))]
mod browsers;

#[cfg(all(
    test,
    any(
        feature = "boring",
        all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
    )
))]
mod tests;

use std::sync::Arc;

use crate::proto::{
    ClientConfig, ConfigError, EndpointConfig, ServerConfig, TransportConfig, VarInt,
    cid_generator::{ConnectionIdGenerator as _, RandomConnectionIdGenerator},
    cid_queue::CidQueue,
};

/// The parts of a profile a connection consults as it forms packets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WireProfile {
    pub(crate) parameters: TransportParameterProfile,
    pub(crate) packetization: PacketizationProfile,
}

impl Default for WireProfile {
    fn default() -> Self {
        Self {
            parameters: TransportParameterProfile::standard(),
            packetization: PacketizationProfile::standard(),
        }
    }
}

impl WireProfile {
    fn of(profile: &QuicProfile) -> Self {
        Self {
            parameters: profile.transport_parameters().clone(),
            packetization: profile.packetization().clone(),
        }
    }
}

impl TransportConfig {
    /// A transport configuration advertising this profile's limits and carrying its layout.
    /// Everything else keeps [`TransportConfig::default`]. An `active_connection_id_limit` above
    /// what this engine can store is clamped to that capacity.
    #[must_use]
    pub fn from_quic_profile(profile: &QuicProfile) -> Self {
        let limits = profile.limits();
        let var = |value: u64| VarInt::from_u64(value).unwrap_or(VarInt::MAX);
        let mut config = Self::default()
            .with_max_concurrent_bidi_streams(var(limits.initial_max_streams_bidi))
            .with_max_concurrent_uni_streams(var(limits.initial_max_streams_uni))
            .with_receive_window(var(limits.initial_max_data))
            .with_stream_receive_window(var(limits.initial_max_stream_data_bidi_local))
            .with_stream_receive_window_bidi_remote(var(limits.initial_max_stream_data_bidi_remote))
            .with_stream_receive_window_uni(var(limits.initial_max_stream_data_uni))
            .maybe_with_datagram_receive_buffer_size(limits.datagram_receive_buffer_size)
            .with_wire(WireProfile::of(profile));
        // Initial datagrams cannot exceed the path's current MTU, so a profile that pads them
        // larger raises the starting MTU to match.
        config = config.with_initial_mtu(profile.packetization().initial_datagram_size());
        #[expect(
            clippy::expect_used,
            reason = "`try_with_limits` checked the delay against the parameter's range"
        )]
        config
            .try_set_max_ack_delay(limits.max_ack_delay)
            .expect("a checked max_ack_delay");
        let idle = u64::try_from(limits.max_idle_timeout.as_millis()).unwrap_or(u64::MAX);
        config.maybe_set_max_idle_timeout(if idle == 0 {
            None
        } else {
            Some(var(idle).into())
        });
        let cid_limit = limits
            .active_connection_id_limit
            .map(|limit| var(limit.min(CidQueue::LEN as u64)));
        config.maybe_set_active_connection_id_limit(cid_limit);
        config
    }
}

impl EndpointConfig {
    /// Apply the endpoint-wide parts of a profile: local connection ID length, QUIC bit greasing
    /// and the advertised maximum UDP payload.
    pub fn apply_quic_profile(&mut self, profile: &QuicProfile) -> Result<(), ConfigError> {
        let len = usize::from(profile.connection_ids().local_len());
        self.set_connection_id_generator_factory(Arc::new(move || {
            #[expect(
                clippy::expect_used,
                reason = "`try_with_local_len` bounds the length to what the generator accepts"
            )]
            Box::new(RandomConnectionIdGenerator::new(len).expect("a valid connection ID length"))
        }));
        self.set_grease_quic_bit(profile.greases_quic_bit());
        let payload = u16::try_from(profile.limits().max_udp_payload_size)
            .map_err(|_error| ConfigError::OutOfBounds)?;
        self.max_udp_payload_size(payload)?;
        Ok(())
    }
}

impl ClientConfig {
    /// Apply the client parts of a profile: the version policy, the first destination connection
    /// ID length and a transport configuration with this profile's limits and layout.
    pub fn apply_quic_profile(&mut self, profile: &QuicProfile) -> Result<(), ConfigError> {
        self.set_versions(profile.versions().clone())?;
        let len = usize::from(profile.connection_ids().initial_destination_len());
        self.set_initial_dst_cid_provider(Arc::new(move || {
            #[expect(
                clippy::expect_used,
                reason = "`try_with_initial_destination_len` bounds the length to what the generator accepts"
            )]
            RandomConnectionIdGenerator::new(len)
                .expect("a valid connection ID length")
                .generate_cid()
        }));
        self.set_transport_config(Arc::new(TransportConfig::from_quic_profile(profile)));
        Ok(())
    }
}

impl ServerConfig {
    /// Apply the server parts of a profile: a transport configuration with this profile's limits
    /// and layout.
    pub fn apply_quic_profile(&mut self, profile: &QuicProfile) {
        self.set_transport_config(Arc::new(TransportConfig::from_quic_profile(profile)));
    }
}
