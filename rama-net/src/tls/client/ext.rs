use rama_core::extensions::{Extension, Extensions};

use crate::address::Host;
use crate::tls::{ApplicationProtocol, KeyLogIntent, ProtocolVersion};
use rama_utils::macros::generate_set_and_with;

use super::{ClientAuth, ServerVerifyMode};

/// A backend agnostic builder for the common TLS configs.
///
/// It holds a set of fine grained config extensions (e.g. [`TlsAlpn`], [`TlsServerVerify`])
/// and exposes typed setters for the settings both TLS backends support.
/// Backend crates add setters for their backend-specific pieces via extension
/// traits (`RustlsClientConfigExt`).
#[derive(Debug, Clone, Default)]
pub struct TlsClientConfig(Extensions);

impl TlsClientConfig {
    /// Create an empty config.
    #[must_use]
    pub fn new() -> Self {
        Self(Extensions::new())
    }

    /// Create a default TlsClientConfig that enables:
    /// - ALPN: H2, http1.1
    /// - Keylogger: [`KeyLogIntent::Environment`]
    pub fn default_http() -> Self {
        Self::new()
            .with_alpn_http_auto()
            .with_keylog(KeyLogIntent::Environment)
    }

    /// Transfer this config's pieces onto `extensions` (appending, so they
    /// override existing entries of the same type — newest-wins). Use this to
    /// transfer the tls config to e.g. request extensions
    pub fn write_to(&self, extensions: &Extensions) {
        extensions.extend(&self.0);
    }

    generate_set_and_with! {
        /// Set the ALPN protocols to offer.
        pub fn alpn(mut self, protocols: Vec<ApplicationProtocol>) -> Self {
            self.0.insert(TlsAlpn(protocols));
            self
        }
    }

    generate_set_and_with! {
        /// Offer HTTP/2 and HTTP/1.1 via ALPN.
        pub fn alpn_http_auto(mut self) -> Self {
            self.0.insert(TlsAlpn::http_auto());
            self
        }
    }

    generate_set_and_with! {
        /// Offer HTTP/1.1 only via ALPN.
        pub fn alpn_http_1(mut self) -> Self {
            self.0.insert(TlsAlpn::http_1());
            self
        }
    }

    generate_set_and_with! {
        /// Offer HTTP/2 only via ALPN.
        pub fn alpn_http_2(mut self) -> Self {
            self.0.insert(TlsAlpn::http_2());
            self
        }
    }

    generate_set_and_with! {
        /// Set the client SNI (server name) to send.
        ///
        /// Overrides the SNI the connector would otherwise derive: the transport
        /// authority host, or for a tunnel connector, the [`TlsTunnel`] sni
        ///
        /// [`TlsTunnel`]: crate::tls::TlsTunnel
        pub fn server_name(mut self, server_name: Host) -> Self {
            self.0.insert(TlsServerName(server_name));
            self
        }
    }

    generate_set_and_with! {
        /// Set how the server certificate is verified.
        pub fn server_verify(mut self, mode: ServerVerifyMode) -> Self {
            self.0.insert(TlsServerVerify(mode));
            self
        }
    }

    generate_set_and_with! {
        /// Set the supported protocol versions.
        pub fn supported_versions(mut self, versions: Vec<ProtocolVersion>) -> Self {
            self.0.insert(TlsSupportedVersions(versions));
            self
        }
    }

    generate_set_and_with! {
        /// Set the keylog intent.
        pub fn keylog(mut self, intent: KeyLogIntent) -> Self {
            self.0.insert(TlsKeyLog(intent));
            self
        }
    }

    generate_set_and_with! {
        /// Set the client certificate authentication material (mTLS).
        pub fn client_auth(mut self, client_auth: ClientAuth) -> Self {
            self.0.insert(TlsClientAuth(client_auth));
            self
        }
    }

    generate_set_and_with! {
        /// Set whether the peer certificate chain is captured.
        pub fn store_server_cert_chain(mut self, store: bool) -> Self {
            self.0.insert(TlsStoreServerCertChain(store));
            self
        }
    }

    pub fn as_extensions(&self) -> &Extensions {
        &self.0
    }

    /// Set an any config piece (newest-wins override).
    ///
    /// Should be used by backends in their Ext traits
    #[doc(hidden)]
    pub fn insert<T: Extension>(&self, piece: T) {
        self.0.insert(piece);
    }
}

/// Client SNI (server name) to send, as configured on [`TlsClientConfig`].
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct TlsServerName(pub Host);

/// ALPN protocols to offer.
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct TlsAlpn(pub Vec<ApplicationProtocol>);

impl TlsAlpn {
    /// Offer HTTP/2 and HTTP/1.1.
    #[must_use]
    pub fn http_auto() -> Self {
        Self(vec![
            ApplicationProtocol::HTTP_2,
            ApplicationProtocol::HTTP_11,
        ])
    }

    /// Offer HTTP/1.1 only.
    #[must_use]
    pub fn http_1() -> Self {
        Self(vec![ApplicationProtocol::HTTP_11])
    }

    /// Offer HTTP/2 only.
    #[must_use]
    pub fn http_2() -> Self {
        Self(vec![ApplicationProtocol::HTTP_2])
    }
}

#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
/// How the server certificate is verified.
pub struct TlsServerVerify(pub ServerVerifyMode);

/// Client certificate authentication material (mTLS).
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct TlsClientAuth(pub ClientAuth);

/// Keylog intent (e.g. `SSLKEYLOGFILE`) for the connection.
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct TlsKeyLog(pub KeyLogIntent);

/// Whether to capture the peer certificate chain into `NegotiatedTlsParameters`.
///
/// [`NegotiatedTlsParameters`]: crate::tls::client::NegotiatedTlsParameters
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct TlsStoreServerCertChain(pub bool);

/// Supported protocol versions, as a list (backends derive min/max as needed,
/// preserving any GREASE entries in the wire list).
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct TlsSupportedVersions(pub Vec<ProtocolVersion>);

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::extensions::Extensions;

    #[test]
    fn pieces_layer_newest_wins_per_type() {
        let ext = Extensions::new();
        ext.insert(TlsAlpn::http_1());
        ext.insert(TlsStoreServerCertChain(true));
        // a later layer overrides only ALPN
        ext.insert(TlsAlpn::http_auto());

        assert_eq!(
            ext.get_ref::<TlsAlpn>().map(|a| a.0.clone()),
            Some(vec![
                ApplicationProtocol::HTTP_2,
                ApplicationProtocol::HTTP_11
            ]),
        );
        assert_eq!(
            ext.get_ref::<TlsStoreServerCertChain>().map(|g| g.0),
            Some(true),
        );
        assert!(ext.get_ref::<TlsServerVerify>().is_none());
    }

    #[test]
    fn config_setters_write_to_bag() {
        let config = TlsClientConfig::new()
            .with_alpn_http_auto()
            .with_server_verify(ServerVerifyMode::Disable);

        let bag = Extensions::new();
        config.write_to(&bag);

        assert_eq!(
            bag.get_ref::<TlsAlpn>().map(|a| a.0.clone()),
            Some(vec![
                ApplicationProtocol::HTTP_2,
                ApplicationProtocol::HTTP_11
            ]),
        );
        assert_eq!(
            bag.get_ref::<TlsServerVerify>().map(|v| v.0),
            Some(ServerVerifyMode::Disable),
        );
    }
}
