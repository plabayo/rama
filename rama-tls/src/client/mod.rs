//! TLS implementation agnostic client types
//!
//! [`ClientHello`] is used in Rama as the implementation agnostic type
//! to convey what client hello was set by the incoming TLS Connection,
//! if the server middleware is configured to store it.
//!
//! By being implementation agnostic we have the advantage to be able to bridge
//! easily between different implementations. Making it possible to run for example
//! a Rustls proxy service but establish connections using BoringSSL.

mod hello;
#[doc(inline)]
pub use hello::{ClientHello, ClientHelloExtension, ECHClientHello};

mod parser;
pub use parser::{
    ClientHelloHandshakePrefix, extract_sni_from_client_hello_handshake,
    extract_sni_from_client_hello_record, parse_client_hello, parse_client_hello_handshake,
    parse_client_hello_handshake_prefix, parse_client_hello_message_prefix,
};

mod config;
mod pool;
#[doc(inline)]
pub use config::{
    ClientAuth, ClientAuthData, ServerTrustRoots, ServerVerifyMode, TlsClientAuth, TlsClientConfig,
    TlsServerCertPin, TlsServerCertPinCheck, TlsServerCertPinSet, TlsServerCertPins,
    TlsServerIdentity, TlsServerName, TlsServerTrust, TlsServerTrustAnchors, TlsServerVerify,
    TlsStoreServerCertChain,
};
pub use pool::{TlsPoolId, TlsPoolIdBuilder};
use rama_crypto::pki_types::CertificateDer;

use super::ProtocolVersion;
use rama_core::extensions::{Extension, Extensions};
use rama_net::address::{Domain, Host};
use rama_net::tls::ApplicationProtocol;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Extension)]
#[extension(tags(tls))]
/// TLS parameters reported by either endpoint and stored in connection extensions.
/// QUIC can expose this while the handshake progresses; optional values may
/// become available later and do not imply handshake completion.
pub struct NegotiatedTlsParameters {
    /// The used [`ProtocolVersion`].
    ///
    /// e.g. [`ProtocolVersion::TLSv1_3`]
    pub protocol_version: ProtocolVersion,
    /// Indicates the agreed upon [`ApplicationProtocol`]
    /// in case the tls implementation can surfice this
    /// AND there is such a protocol negotiated and agreed upon.
    ///
    /// e.g. [`ApplicationProtocol::HTTP_2`]
    pub application_layer_protocol: Option<ApplicationProtocol>,
    /// Certificate chain provided the peer (only stored if config requested this)
    pub peer_certificate_chain: Option<Vec<CertificateDer<'static>>>,
    /// Received SNI on a server, not a verified peer identity. Absent on clients
    /// and when the peer omits SNI (including IP-address connections).
    pub server_name: Option<Domain>,
    /// Whether TLS resumed a session. Absent until the backend has decided,
    /// or if it cannot report resumption.
    pub resumed: Option<bool>,
}

/// Server identity authenticated by the effective TLS verification policy.
///
/// Published only after a successful client handshake. `None` explicitly
/// shadows older connection metadata when verification was disabled; negotiated
/// ALPN or a received certificate alone does not prove server authentication.
#[derive(Debug, Clone, PartialEq, Eq, Extension)]
#[extension(tags(tls))]
pub struct TlsServerAuthentication(pub Option<rama_net::address::Host>);

/// Merge extension lists A and B, with
/// B overwriting any conflict with A, and otherwise push it to the back.
pub fn merge_client_hello_lists(
    a: impl AsRef<[ClientHelloExtension]>,
    b: impl AsRef<[ClientHelloExtension]>,
) -> Vec<ClientHelloExtension> {
    let a = a.as_ref();
    let b = b.as_ref();

    let mut output = Vec::with_capacity(a.len() + b.len());

    output.extend(a.iter().cloned());

    for ext in b.iter().cloned() {
        match output.iter_mut().find(|e| e.id() == ext.id()) {
            Some(old) => {
                *old = ext;
            }
            None => output.push(ext),
        }
    }

    output
}

/// Classify the request overrides understood by a fixed TLS configuration provider.
///
/// Pools must retain the same provider and connector defaults for their lifetime.
/// Custom providers participate through the same interface as built-in providers.
pub trait TlsClientConfigProvider: fmt::Debug + Send + Sync {
    /// Identity of request overrides, before connector defaults are applied.
    ///
    /// `None` means the request does not change the provider's fixed TLS policy,
    /// including server identity and authentication. Callers may then classify
    /// the fixed defaults directly. Opaque overrides must return a non-reusable ID.
    fn pool_id(&self, extensions: &Extensions) -> Option<TlsPoolId>;

    /// Whether the effective configuration establishes the server identity.
    fn authenticates_server(&self, extensions: &Extensions) -> bool;

    /// Whether this effective policy authenticates the requested HTTP origin.
    ///
    /// Connectors call this with their effective configuration when checking
    /// an attempt's peer requirement. Providers with additional identity semantics
    /// can refine it; successful handshake authentication is still reported
    /// separately on the established connection.
    fn authenticates_origin(&self, extensions: &Extensions, origin: &Host) -> bool {
        extensions
            .get_ref::<TlsServerName>()
            .is_none_or(|name| &name.0 == origin)
            && self.authenticates_server(extensions)
    }
}

#[cfg(test)]
mod tests {
    use rama_net::address::Domain;

    use super::*;

    #[test]
    fn test_merge_client_hello_lists_empty() {
        assert!(merge_client_hello_lists(vec![], vec![]).is_empty());
    }

    #[test]
    fn test_merge_client_hello_lists_zero_one() {
        let output = merge_client_hello_lists(&[], [ClientHelloExtension::ServerName(None)]);
        assert_eq!(1, output.len());
        assert!(matches!(output[0], ClientHelloExtension::ServerName(_)))
    }

    #[test]
    fn test_merge_client_hello_lists_one_zero() {
        let output = merge_client_hello_lists(vec![ClientHelloExtension::ServerName(None)], &[]);
        assert_eq!(1, output.len());
        assert!(matches!(output[0], ClientHelloExtension::ServerName(_)))
    }

    #[test]
    fn test_merge_client_hello_lists_one_one() {
        let output = merge_client_hello_lists(
            vec![ClientHelloExtension::ServerName(None)],
            &[ClientHelloExtension::SupportedVersions(vec![])],
        );
        assert_eq!(2, output.len());
        assert!(matches!(output[0], ClientHelloExtension::ServerName(_)));
        assert!(matches!(
            output[1],
            ClientHelloExtension::SupportedVersions(_)
        ));
    }

    #[test]
    fn test_merge_client_hello_lists_two_two_with_one_conflict() {
        let output = merge_client_hello_lists(
            vec![
                ClientHelloExtension::ServerName(None),
                ClientHelloExtension::SupportedVersions(vec![]),
            ],
            &[
                ClientHelloExtension::ServerName(Some(Domain::from_static("example.com"))),
                ClientHelloExtension::ApplicationLayerProtocolNegotiation(vec![]),
            ],
        );
        assert_eq!(3, output.len());
        assert!(matches!(output[0], ClientHelloExtension::ServerName(_)));
        assert!(matches!(
            output[1],
            ClientHelloExtension::SupportedVersions(_)
        ));
        assert!(matches!(
            output[2],
            ClientHelloExtension::ApplicationLayerProtocolNegotiation(_)
        ));
    }
}
