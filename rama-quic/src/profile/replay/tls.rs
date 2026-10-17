//! Prepare a captured QUIC TLS offer for BoringSSL without connection I/O.
//!
//! Wire choices come from the capture. Authentication, credentials and key
//! logging remain caller policy; the transport engine supplies fresh parameters.
//! This module prepares TLS only, not QUIC packet layout or HTTP/3 streams.

use rama_core::error::{BoxError, BoxErrorExt as _};
use rama_tls::{ExtensionId, client::TlsClientConfig};
use rama_tls_boring::client::{
    BoringTlsConnectorConfig,
    profile::wire::{self, TransportShape},
};
use rama_ua::profile::capture::tls::{TlsCapture, TlsCaptureTransport, TlsCapturedExtensionValue};

use crate::tls::ClientHandshake;

/// Compile wire options; the native connector owns sessions, identity and I/O.
pub(crate) fn compile(
    policy: &TlsClientConfig,
    capture: &TlsCapture,
) -> Result<TlsClientConfig, BoxError> {
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
    Ok(wire.with_client_handshake(handshake))
}
