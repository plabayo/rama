//! Prepare a captured QUIC TLS offer for BoringSSL without connection I/O.
//!
//! Wire choices come from the capture. Authentication, credentials and key
//! logging remain caller policy; the transport engine supplies fresh parameters.
//! This module prepares TLS only, not QUIC packet layout or HTTP/3 streams.

use rama_core::error::{BoxError, BoxErrorExt as _};
use rama_net::address::Host;
use rama_tls::{
    ExtensionId,
    client::{ClientHelloExtension, TlsClientConfig},
};
use rama_tls_boring::client::{
    BoringTlsConnectorConfig,
    profile::wire::{self, TransportShape},
};
use rama_ua::profile::capture::{
    completeness::ProfileCaptureCompleteness,
    tls::{TlsCapture, TlsCaptureLimits, TlsCaptureTransport, TlsCapturedExtensionValue},
};

use crate::profile::replay::parameters::ParameterExpectation;
use crate::{
    ClientConfig,
    tls::{ClientConfigCache, ClientHandshake},
};

/// Prepare the captured TLS offer for the current `peer` and `policy`.
///
/// The first dial consumes the prepared native SSL; address retries own fresh
/// sibling sessions. Before any handshake output escapes, each session must
/// reproduce the captured TLS shape and contain its own current QUIC parameters.
/// A parameter-size mismatch fails that dial rather than substituting captured
/// identifiers. The returned configuration is bound to this peer and check, so
/// it must bypass configuration caches that do not include those bindings.
///
/// Resumed captures require current peer-issued tickets. A full captured offer
/// suppresses older tickets while retaining new ones unless the caller chose Fresh.
/// Optional parameter expectations validate the generated body from the same
/// selected tuple. First-flight layout and HTTP/3 state need separate compilers.
pub(crate) fn prepare(
    cache: &ClientConfigCache,
    policy: &TlsClientConfig,
    peer: Host,
    capture: TlsCapture,
    expected_parameters: Option<ParameterExpectation>,
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
        wire::compile_for_policy(TransportShape::Quic { parameters_len }, &capture, &current)?;
    let handshake = if capture
        .extensions
        .iter()
        .any(|extension| extension.id == u16::from(ExtensionId::PRE_SHARED_KEY))
    {
        ClientHandshake::Resumed
    } else {
        ClientHandshake::Full
    };
    let expected = capture;
    let effective = policy.clone().with_overrides(wire.as_extensions());

    Ok(cache.prepare_client_config(
        &effective,
        peer,
        handshake,
        Box::new(move |hello, parameters| {
            let installed = hello
                .extensions()
                .iter()
                .find_map(|extension| match extension {
                    ClientHelloExtension::Opaque { id, data }
                        if *id == ExtensionId::QUIC_TRANSPORT_PARAMETERS =>
                    {
                        Some(data.as_slice())
                    }
                    _ => None,
                });
            if installed != Some(parameters) {
                return Err(BoxError::from_static_str(
                    "native QUIC TLS parameters differ from the engine binding",
                ));
            }
            if let Some(expected) = &expected_parameters {
                expected.validate(hello)?;
            }
            let actual = TlsCapture::capture(
                ProfileCaptureCompleteness::Complete,
                TlsCaptureTransport::Quic,
                hello,
                TlsCaptureLimits::default(),
            )?;
            if actual != expected {
                return Err(BoxError::from_static_str(
                    "native QUIC ClientHello differs from the captured TLS shape",
                ));
            }
            Ok(())
        }),
    )?)
}
