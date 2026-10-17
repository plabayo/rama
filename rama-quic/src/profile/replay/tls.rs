//! Prepare a captured QUIC TLS offer for BoringSSL without connection I/O.
//!
//! Wire choices come from the capture. Authentication, credentials and key
//! logging remain caller policy; the transport engine supplies fresh parameters.
//! This module prepares TLS only, not QUIC packet layout or HTTP/3 streams.

use rama_core::error::{BoxError, BoxErrorExt as _};
use rama_net::address::Host;
use rama_tls::{ExtensionId, client::TlsClientConfig};
use rama_tls_boring::client::{
    BoringTlsConnectorConfig,
    profile::wire::{self, TransportShape},
};
use rama_ua::profile::capture::tls::{TlsCapture, TlsCaptureTransport, TlsCapturedExtensionValue};

use crate::{
    ClientConfig,
    tls::{ClientConfigCache, ClientHandshake},
};

/// Prepare the captured TLS offer for the current `peer` and `policy`.
///
/// The first dial consumes the prepared native SSL; address retries own fresh
/// sibling sessions. The engine supplies each connection's transport parameters.
/// The returned configuration belongs to this peer and bypasses ordinary caches.
///
/// Resumed captures require current peer-issued tickets. Full offers suppress
/// older tickets while retaining new ones unless the caller chose Fresh.
/// Fingerprint equality is verified by the wire tests, without parsing the
/// generated ClientHello again in production.
pub(crate) fn prepare(
    cache: &ClientConfigCache,
    policy: &TlsClientConfig,
    peer: Host,
    capture: &TlsCapture,
) -> Result<Option<ClientConfig>, BoxError> {
    if !matches!(capture.transport, TlsCaptureTransport::Quic) {
        return Err(BoxError::from_static_str(
            "QUIC TLS replay requires a QUIC capture",
        ));
    }
    let parameters_len = capture
        .extensions
        .iter()
        .find_map(
            |extension| match (ExtensionId::from(extension.id), &extension.value) {
                (
                    ExtensionId::QUIC_TRANSPORT_PARAMETERS,
                    TlsCapturedExtensionValue::ConnectionLength(length),
                ) => Some(usize::from(*length)),
                _ => None,
            },
        )
        .ok_or_else(|| BoxError::from_static_str("QUIC TLS capture has no parameter shape"))?;
    let current = BoringTlsConnectorConfig::from_extensions(policy.as_extensions());
    let wire =
        wire::compile_for_policy(TransportShape::Quic { parameters_len }, capture, &current)?;
    let handshake = if capture
        .extensions
        .iter()
        .any(|extension| extension.id == u16::from(ExtensionId::PRE_SHARED_KEY))
    {
        ClientHandshake::Resumed
    } else {
        ClientHandshake::Full
    };
    let effective = policy.clone().with_overrides(wire.as_extensions());

    Ok(cache.prepare_client_config(&effective, peer, handshake)?)
}
