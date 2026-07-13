use rama_core::{
    error::{BoxError, BoxErrorExt as _},
    extensions::{Extension, Extensions},
};
use rama_crypto::pki_types::{CertificateDer, PrivateKeyDer};
use rama_utils::{collections::smallvec::SmallVec, macros::generate_set_and_with};
use std::sync::Arc;

use crate::{
    ApplicationProtocol, KeyLogIntent, ProtocolVersion, TlsAlpn, TlsKeyLog, TlsSupportedVersions,
};
use rama_net::address::Host;

/// A backend agnostic builder for the common TLS configs.
///
/// It holds a set of fine grained config extensions (e.g. [`TlsAlpn`], [`TlsServerVerify`])
/// and exposes typed setters for the settings both TLS backends support.
/// Backend crates add setters for their backend-specific pieces via extension
/// traits (`RustlsClientConfigExt` or `BoringServerConfigExt`).
#[derive(Debug, Default)]
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
        pub fn alpn(mut self, protocols: SmallVec<[ApplicationProtocol; 2]>) -> Self {
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
        /// [`TlsTunnel`]: crate::TlsTunnel
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
        /// Require the server leaf certificate to match one of the pins.
        ///
        /// With [`ServerVerifyMode::Auto`], normal certificate verification must
        /// also succeed. With [`ServerVerifyMode::Disable`], the pin is the only
        /// certificate check.
        pub fn server_cert_pins(mut self, pins: TlsServerCertPins) -> Self {
            self.0.insert(pins);
            self
        }
    }

    generate_set_and_with! {
        /// Replace the default server trust anchors with `certificates`.
        ///
        /// The certificates are used only with [`ServerVerifyMode::Auto`].
        pub fn server_trust_anchors(
            mut self,
            certificates: impl IntoIterator<Item = CertificateDer<'static>>,
        ) -> Result<Self, BoxError> {
            self.0.insert(TlsServerTrustAnchors::try_new(certificates)?);
            Ok(self)
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

impl Clone for TlsClientConfig {
    fn clone(&self) -> Self {
        let clone = Self::new();
        clone.as_extensions().extend(self.as_extensions());
        clone
    }
}

/// Client SNI (server name) to send, as configured on [`TlsClientConfig`].
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct TlsServerName(pub Host);

#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
/// How the server certificate is verified.
pub struct TlsServerVerify(pub ServerVerifyMode);

/// Exact DER-encoded server leaf certificates accepted by a TLS client.
///
/// The pins apply to every connection using the config. They are not selected
/// from the certificate's DNS names.
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct TlsServerCertPins(Arc<[CertificateDer<'static>]>);

impl TlsServerCertPins {
    /// Create a non-empty set of exact server leaf certificate pins.
    pub fn try_new(
        pins: impl IntoIterator<Item = CertificateDer<'static>>,
    ) -> Result<Self, BoxError> {
        let pins: Vec<_> = pins.into_iter().collect();
        if pins.is_empty() {
            return Err(BoxError::from_static_str(
                "server certificate pin set cannot be empty",
            ));
        }
        Ok(Self(pins.into()))
    }

    /// Return the configured certificate pins.
    pub fn certificates(&self) -> &[CertificateDer<'static>] {
        &self.0
    }

    /// Return whether `certificate` exactly matches one of the pins.
    pub fn matches(&self, certificate: &CertificateDer<'_>) -> bool {
        self.0
            .iter()
            .any(|pin| pin.as_ref() == certificate.as_ref())
    }
}

/// DER-encoded certificates used as the TLS client's server trust anchors.
///
/// These replace the backend's default trust store. They are used by normal
/// certificate verification and can be combined with [`TlsServerCertPins`]. A
/// certificate must be acceptable as a trust anchor; use a pin for an arbitrary
/// CA-issued server leaf.
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct TlsServerTrustAnchors(Arc<[CertificateDer<'static>]>);

impl TlsServerTrustAnchors {
    /// Create a non-empty set of server trust anchors.
    pub fn try_new(
        certificates: impl IntoIterator<Item = CertificateDer<'static>>,
    ) -> Result<Self, BoxError> {
        let certificates: Vec<_> = certificates.into_iter().collect();
        if certificates.is_empty() {
            return Err(BoxError::from_static_str(
                "server trust anchor set cannot be empty",
            ));
        }
        Ok(Self(certificates.into()))
    }

    /// Return the configured trust-anchor certificates.
    pub fn certificates(&self) -> &[CertificateDer<'static>] {
        &self.0
    }
}

/// Client certificate authentication material (mTLS).
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct TlsClientAuth(pub ClientAuth);

/// Whether to capture the peer certificate chain into `NegotiatedTlsParameters`.
///
/// [`NegotiatedTlsParameters`]: crate::client::NegotiatedTlsParameters
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct TlsStoreServerCertChain(pub bool);

#[derive(Debug, Clone)]
/// The kind of client auth to be used.
pub enum ClientAuth {
    /// Request the tls implementation to generate self-signed single data
    SelfSigned,
    /// Single data provided by the configurator
    Single(ClientAuthData),
}

#[derive(Debug)]
/// Raw private key and certificate data to facilitate client authentication.
pub struct ClientAuthData {
    /// private key used by client
    pub private_key: PrivateKeyDer<'static>,
    /// certificate chain as a companion to the private key
    pub cert_chain: Vec<CertificateDer<'static>>,
}

impl Clone for ClientAuthData {
    fn clone(&self) -> Self {
        Self {
            private_key: self.private_key.clone_key(),
            cert_chain: self.cert_chain.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Mode of server verification by a (tls) client
pub enum ServerVerifyMode {
    #[default]
    /// Use the default verification approach as defined
    /// by the implementation of the used (tls) client
    Auto,
    /// Explicitly disable server verification (if possible)
    ///
    /// Configured server certificate pins remain enforced.
    Disable,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::extensions::Extensions;
    use rama_utils::collections::smallvec::smallvec;

    #[test]
    fn pieces_layer_newest_wins_per_type() {
        let ext = Extensions::new();
        ext.insert(TlsAlpn::http_1());
        ext.insert(TlsStoreServerCertChain(true));
        // a later layer overrides only ALPN
        ext.insert(TlsAlpn::http_auto());

        assert_eq!(
            ext.get_ref::<TlsAlpn>().map(|a| a.0.clone()),
            Some(smallvec![
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
        let pins = TlsServerCertPins::try_new([CertificateDer::from(vec![1, 2, 3])]).unwrap();
        let config = TlsClientConfig::new()
            .with_alpn_http_auto()
            .with_server_verify(ServerVerifyMode::Disable)
            .with_server_cert_pins(pins)
            .try_with_server_trust_anchors([CertificateDer::from(vec![4, 5, 6])])
            .unwrap();

        let bag = Extensions::new();
        config.write_to(&bag);

        assert_eq!(
            bag.get_ref::<TlsAlpn>().map(|a| a.0.clone()),
            Some(smallvec![
                ApplicationProtocol::HTTP_2,
                ApplicationProtocol::HTTP_11
            ]),
        );
        assert_eq!(
            bag.get_ref::<TlsServerVerify>().map(|v| v.0),
            Some(ServerVerifyMode::Disable),
        );
        assert!(
            bag.get_ref::<TlsServerCertPins>()
                .unwrap()
                .matches(&CertificateDer::from(vec![1, 2, 3]))
        );
        assert_eq!(
            bag.get_ref::<TlsServerTrustAnchors>()
                .unwrap()
                .certificates(),
            &[CertificateDer::from(vec![4, 5, 6])]
        );
    }

    #[test]
    fn server_cert_pins_must_not_be_empty() {
        TlsServerCertPins::try_new([]).unwrap_err();
    }

    #[test]
    fn server_cert_pins_match_any_configured_certificate() {
        let pins = TlsServerCertPins::try_new([
            CertificateDer::from(vec![1, 2, 3]),
            CertificateDer::from(vec![4, 5, 6]),
        ])
        .unwrap();

        assert!(pins.matches(&CertificateDer::from(vec![1, 2, 3])));
        assert!(pins.matches(&CertificateDer::from(vec![4, 5, 6])));
        assert!(!pins.matches(&CertificateDer::from(vec![7, 8, 9])));
    }

    #[test]
    fn server_trust_anchors_must_not_be_empty() {
        TlsServerTrustAnchors::try_new([]).unwrap_err();
        TlsClientConfig::new()
            .try_with_server_trust_anchors([])
            .unwrap_err();
    }
}
