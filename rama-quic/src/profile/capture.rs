//! Engine glue for capturing a QUIC first flight.
//!
//! The crypto-free pipeline and its [`KeyProvider`] seam live in [`rama_quic_proto::capture`]; this
//! module supplies the Initial keys from the engine's TLS backend and offers the convenience entry
//! point the profile tests read a flight through.

pub use rama_quic_proto::capture::*;

use crate::proto::{
    ConnectionId, Side, Version,
    crypto::{HeaderKey, PacketKey, ServerConfig as CryptoServerConfig},
};

/// Bridges a crypto [`ServerConfig`](CryptoServerConfig) to the [`KeyProvider`] seam by deriving
/// Initial keys from the destination connection ID (RFC 9001 §5.2). A passive observer and the
/// destination server derive Initial keys the same way, so this one adapter serves both vantages.
pub struct ProviderKeys<'a>(pub &'a dyn CryptoServerConfig);

impl KeyProvider for ProviderKeys<'_> {
    // The engine's TLS backend hands back erased keys, so the seam carries them boxed.
    type Header = Box<dyn HeaderKey>;
    type Packet = Box<dyn PacketKey>;

    fn initial_keys(
        &self,
        version: Version,
        dcid: &[u8],
        side: Side,
    ) -> Result<InitialKeys<Self::Header, Self::Packet>, CaptureError> {
        let keys = self
            .0
            .initial_keys(version, &ConnectionId::new(dcid))
            .map_err(|_error| CaptureError::Undecryptable)?;
        // The provider gives keys as a server holds them: `remote` opens what the client sent,
        // `local` what the server sent.
        let directional = match side {
            Side::Server => keys.remote.ok_or(CaptureError::Undecryptable)?,
            Side::Client => keys.local,
        };
        Ok(InitialKeys {
            header: directional.header,
            packet: directional.packet,
        })
    }
}

/// Read a client's first flight, deriving the Initial keys from `provider`.
pub fn first_flight(
    datagrams: &[&[u8]],
    provider: &dyn CryptoServerConfig,
) -> Result<FirstFlight, CaptureError> {
    rama_quic_proto::capture::first_flight(datagrams, &ProviderKeys(provider))
}
