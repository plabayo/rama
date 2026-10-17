//! HTTP/3 requirements around the generic QUIC capture compiler.

use rama_core::{
    error::{BoxError, BoxErrorExt as _},
    extensions::ExtensionsRef,
};
use rama_http_types::{Version, conn::TargetHttpVersion};
use rama_net::{ProtocolInputExt, client::ConnectRequest, tls::ApplicationProtocol};
use rama_quic::tls::{
    QuicClientConfigProvider,
    profile::{self, PreparedConfig},
};
use rama_tls::{
    ExtensionId,
    client::{TlsClientConfig, TlsServerName},
};
use rama_ua::profile::{
    capture::tls::{TlsCaptureTransport, TlsCapturedExtensionValue},
    replay::connection::preparation::ConnectionPreparation,
};

pub(super) fn prepare(
    input: &ConnectRequest,
    tls: &TlsClientConfig,
    provider: &dyn QuicClientConfigProvider,
) -> Result<Option<(ConnectionPreparation, PreparedConfig)>, BoxError> {
    ConnectionPreparation::prepare(input, |_, components, _| {
        if input
            .target_protocol()
            .is_none_or(|protocol| !protocol.is_secure())
        {
            return Err(BoxError::from_static_str(
                "captured HTTP/3 requires a secure origin",
            ));
        }
        if input
            .extensions()
            .get_ref::<TargetHttpVersion>()
            .is_some_and(|target| target.0 != Version::HTTP_3)
        {
            return Err(BoxError::from_static_str(
                "captured HTTP/3 requires an HTTP/3 target",
            ));
        }
        if let Some(capture) = &components.tls {
            let offers_h3 = matches!(capture.transport, TlsCaptureTransport::Quic) && capture.extensions.iter().any(|extension| {
                extension.id == u16::from(ExtensionId::APPLICATION_LAYER_PROTOCOL_NEGOTIATION)
                    && matches!(&extension.value, TlsCapturedExtensionValue::Protocols(protocols)
                        if protocols.iter().any(|protocol| protocol.as_ref() == ApplicationProtocol::HTTP_3.as_bytes()))
            });
            if !offers_h3 {
                return Err(BoxError::from_static_str(
                    "captured TLS offer excludes HTTP/3 ALPN",
                ));
            }
        }
        let peer = tls
            .as_extensions()
            .get_ref::<TlsServerName>()
            .map_or_else(|| input.authority.host.clone(), |name| name.0.clone());
        profile::prepare(provider, tls, peer, components)
    })
}

#[cfg(all(test, feature = "boring"))]
mod tests;
