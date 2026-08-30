//! rama TLS-agnostic types and utilities.
//!
//! The TLS-implementation-agnostic vocabulary (protocol versions, cipher suites,
//! ALPN, client/server config, `ClientHello`, fingerprints, keylog, …) shared by
//! the backend crates (`rama-tls-boring` / `rama-tls-rustls`).
//!
//! Learn more about `rama`:
//!
//! - Github: <https://github.com/plabayo/rama>
//! - Book: <https://ramaproxy.org/book/>

#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/plabayo/rama/main/docs/img/rama_logo.svg"
)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(test, allow(clippy::float_cmp))]

use std::borrow::Cow;

use rama_core::extensions::Extension;
use rama_net::{Protocol, tls::ApplicationProtocol};
use rama_utils::collections::smallvec::{SmallVec, smallvec};

mod enums;
pub use enums::{
    CertificateCompressionAlgorithm, CipherSuite, CompressionAlgorithm, ECPointFormat, ExtensionId,
    ProtocolVersion, SignatureScheme, SupportedGroup,
};

pub mod client;
pub mod fingerprint;
pub mod keylog;
pub mod server;

#[cfg(feature = "dial9")]
mod dial9;

/// ALPN protocols to offer.
#[derive(Clone, Debug, Extension)]
#[extension(tags(tls))]
pub struct TlsAlpn(pub SmallVec<[ApplicationProtocol; 2]>);

impl TlsAlpn {
    /// Offer no ALPN protocols.
    #[must_use]
    pub fn empty() -> Self {
        Self(SmallVec::new())
    }

    /// Offer HTTP/2 and HTTP/1.1.
    #[must_use]
    pub fn http_auto() -> Self {
        Self(smallvec![
            ApplicationProtocol::HTTP_2,
            ApplicationProtocol::HTTP_11,
        ])
    }

    /// Offer HTTP/1.1 only.
    #[must_use]
    pub fn http_1() -> Self {
        Self(smallvec![ApplicationProtocol::HTTP_11])
    }

    /// Offer HTTP/2 only.
    #[must_use]
    pub fn http_2() -> Self {
        Self(smallvec![ApplicationProtocol::HTTP_2])
    }
}

/// Return Rama's default ALPN offer for an application protocol.
///
/// HTTP can negotiate HTTP/2 or HTTP/1.1. WebSocket defaults to HTTP/1.1 because
/// HTTP/2 WebSocket support cannot be known until after ALPN negotiation; an
/// explicit target HTTP version can opt into HTTP/2. Protocols without a
/// standardized ALPN in Rama, including ICAPS and custom protocols, return
/// `None`.
#[must_use]
pub fn default_tls_alpn(protocol: &Protocol) -> Option<TlsAlpn> {
    if protocol.is_http() {
        Some(TlsAlpn::http_auto())
    } else if protocol.is_ws() {
        Some(TlsAlpn::http_1())
    } else {
        None
    }
}

/// Keylog intent (e.g. `SSLKEYLOGFILE`) for the connection.
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct TlsKeyLog(pub KeyLogIntent);

/// Supported protocol versions, as a list (backends derive min/max as needed,
/// preserving any GREASE entries in the wire list).
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct TlsSupportedVersions(pub Vec<ProtocolVersion>);

#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
/// Requests TLS from a tunnel connector with an optional server identity.
pub struct TlsTunnel {
    /// Server identity used for certificate verification and, for DNS names, SNI.
    pub server_identity: Option<rama_net::address::Host>,
    /// Application protocol spoken inside the TLS tunnel.
    ///
    /// This is distinct from the final destination protocol. For example, an
    /// ICAPS connection through a TLS-protected HTTP proxy speaks HTTP to the
    /// proxy before the CONNECT tunnel carries ICAP.
    pub application_protocol: Option<Protocol>,
}

/// Whether a tunnel connector should use plaintext or TLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsTunnelMode<'a> {
    /// No tunnel context or fallback identity requested TLS.
    Plain,
    /// TLS was requested, with an optional server certificate identity.
    Tls(Option<&'a rama_net::address::Host>),
}

/// Resolve tunnel activation and server identity consistently across TLS backends.
#[must_use]
pub fn resolve_tls_tunnel<'a>(
    tunnel: Option<&'a TlsTunnel>,
    fallback_server_identity: Option<&'a rama_net::address::Host>,
) -> TlsTunnelMode<'a> {
    match tunnel {
        Some(tunnel) => {
            TlsTunnelMode::Tls(tunnel.server_identity.as_ref().or(fallback_server_identity))
        }
        None => fallback_server_identity.map_or(TlsTunnelMode::Plain, |identity| {
            TlsTunnelMode::Tls(Some(identity))
        }),
    }
}

#[cfg(test)]
mod tunnel_tests {
    use super::*;
    use rama_net::address::Host;

    #[test]
    fn hardcoded_identity_enables_tls_without_context() {
        let identity = Host::from_static("example.com");
        assert_eq!(
            resolve_tls_tunnel(None, Some(&identity)),
            TlsTunnelMode::Tls(Some(&identity))
        );
    }

    #[test]
    fn empty_context_falls_back_to_hardcoded_identity() {
        let tunnel = TlsTunnel {
            server_identity: None,
            application_protocol: None,
        };
        let identity = Host::from_static("example.com");
        assert_eq!(
            resolve_tls_tunnel(Some(&tunnel), Some(&identity)),
            TlsTunnelMode::Tls(Some(&identity))
        );
    }

    #[test]
    fn empty_context_without_fallback_still_requests_tls() {
        let tunnel = TlsTunnel {
            server_identity: None,
            application_protocol: None,
        };
        assert_eq!(
            resolve_tls_tunnel(Some(&tunnel), None),
            TlsTunnelMode::Tls(None)
        );
    }
}

#[cfg(test)]
mod application_protocol_tests {
    use super::*;

    #[test]
    fn derives_only_known_tls_application_protocols() {
        assert_eq!(
            default_tls_alpn(&Protocol::HTTPS).unwrap().0,
            TlsAlpn::http_auto().0,
        );
        assert_eq!(
            default_tls_alpn(&Protocol::WSS).unwrap().0,
            TlsAlpn::http_1().0,
        );
        assert!(default_tls_alpn(&Protocol::ICAPS).is_none());
        assert!(default_tls_alpn(&Protocol::from_static("custom")).is_none());
    }
}

#[derive(Debug, Clone, Default, Extension)]
#[extension(tags(tls))]
/// Metadata that can be added to the [`Extensions`]
/// of a transport layer to signal that the transport is secure.
///
/// [`Extensions`]: rama_core::extensions::Extensions
pub struct SecureTransport {
    client_hello: Option<client::ClientHello>,
}

impl SecureTransport {
    /// Create a [`SecureTransport`] with a [`ClientHello`]
    /// attached to it, containing the client hello info
    /// used to establish this secure transport.
    ///
    /// [`ClientHello`]: crate::client::ClientHello
    #[must_use]
    pub fn with_client_hello(hello: client::ClientHello) -> Self {
        Self {
            client_hello: Some(hello),
        }
    }

    /// Return the [`ClientHello`] used to establish this secure transport,
    /// only available if the tls service stored it.
    ///
    /// [`ClientHello`]: crate::client::ClientHello
    #[must_use]
    pub fn client_hello(&self) -> Option<&client::ClientHello> {
        self.client_hello.as_ref()
    }
}

#[derive(Debug, Clone, Default)]
/// Intent for a (tls) keylogger to be used.
///
/// Applicable to both a client- and server- config. Consumers (the
/// boring / rustls integrations) resolve this into a concrete sink
/// via [`keylog::open_intent_sink`].
pub enum KeyLogIntent {
    #[default]
    /// `SSLKEYLOGFILE` env var: if set, log to that file.
    Environment,
    /// Keylog explicitly disabled.
    Disabled,
    /// Log to the given file path (append).
    File(String),
    /// Use the supplied sink as-is. Lets callers plug in a rotating
    /// sink, a toggle wrapper, an in-memory capture, etc., without
    /// the consumer needing to know which.
    Custom(std::sync::Arc<dyn keylog::KeyLogSink>),
}

impl KeyLogIntent {
    /// `SSLKEYLOGFILE` env value, if set.
    #[must_use]
    pub fn env_file_path() -> Option<String> {
        std::env::var("SSLKEYLOGFILE").ok()
    }

    /// File path for the [`File`] and [`Environment`] variants;
    /// `None` for [`Disabled`] and [`Custom`] (no path to surface).
    ///
    /// [`File`]: Self::File
    /// [`Environment`]: Self::Environment
    /// [`Disabled`]: Self::Disabled
    /// [`Custom`]: Self::Custom
    #[must_use]
    pub fn file_path(&self) -> Option<Cow<'_, str>> {
        match self {
            Self::Disabled | Self::Custom(_) => None,
            Self::Environment => Self::env_file_path().map(Into::into),
            Self::File(keylog_filename) => Some(keylog_filename.into()),
        }
    }
}
