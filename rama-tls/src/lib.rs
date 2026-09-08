//! rama TLS-agnostic types and utilities.
//!
//! The TLS-implementation-agnostic vocabulary (protocol versions, cipher suites,
//! client/server config, `ClientHello`, fingerprints, keylog, …) shared by
//! the backend crates (`rama-tls-boring` / `rama-tls-rustls`).
//! Protocol-neutral ALPN identifiers and offers live in [`rama_net::tls`].
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
use rama_net::Protocol;

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
/// Requests TLS from a tunnel connector with proxy-scoped identity and ALPN.
///
/// Tunnel connectors combine these explicit fields with only their dedicated
/// base configuration. Final-destination TLS request extensions are isolated
/// from the tunnel-side handshake.
pub struct TlsTunnel {
    /// Server identity used for certificate verification and, for DNS names, SNI.
    pub server_identity: Option<rama_net::address::Host>,
    /// Application protocol spoken inside the TLS tunnel.
    ///
    /// This is distinct from the final destination protocol. For example, an
    /// ICAPS connection through a TLS-protected HTTP proxy speaks HTTP to the
    /// proxy before the CONNECT tunnel carries ICAP.
    pub application_protocol: Option<Protocol>,
    /// ALPN protocols to offer for this tunnel-side TLS handshake.
    ///
    /// This is distinct from the final destination's ALPN offer. `None` uses
    /// the tunnel connector's base policy or the tunnel protocol's default;
    /// `Some(TlsAlpn::empty())` explicitly omits ALPN.
    pub alpn: Option<rama_net::tls::TlsAlpn>,
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
    use rama_net::address::Host;

    use super::*;

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
            alpn: None,
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
            alpn: None,
        };
        assert_eq!(
            resolve_tls_tunnel(Some(&tunnel), None),
            TlsTunnelMode::Tls(None)
        );
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

#[cfg(feature = "inspect")]
pub mod inspect;
