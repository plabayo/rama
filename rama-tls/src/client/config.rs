use base64::{Engine as _, prelude::BASE64_STANDARD};
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
        /// Require the server leaf certificate to match an applicable pin set.
        ///
        /// With [`ServerVerifyMode::Auto`], normal certificate verification must
        /// also succeed. With [`ServerVerifyMode::Disable`], applicable pins are
        /// the only certificate check.
        pub fn server_cert_pins(mut self, pins: TlsServerCertPins) -> Self {
            self.0.insert(pins);
            self
        }
    }

    generate_set_and_with! {
        /// Replace the default server trust anchors with `certificates`.
        ///
        /// The certificates are used only with [`ServerVerifyMode::Auto`],
        /// and a backend-specific verifier or store takes precedence.
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

/// Server leaf certificate pin sets accepted by a TLS client.
///
/// Pins within a set and applicable sets are alternatives. A set without server
/// names applies globally; otherwise it is considered only when the effective
/// TLS server name matches. Names are configured explicitly rather than inferred
/// from certificate contents.
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct TlsServerCertPins(Arc<Vec<TlsServerCertPinSet>>);

/// A single accepted server leaf pin.
///
/// Serialized as `sha256/<base64 digest>` (the industry-standard key-pin
/// format) or `der/<base64 certificate>`, via [`FromStr`] and [`Display`].
/// [`FromStr`] also accepts a PEM certificate, deriving its key pin.
///
/// [`FromStr`]: std::str::FromStr
/// [`Display`]: std::fmt::Display
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsServerCertPin {
    /// SHA-256 of the leaf's `SubjectPublicKeyInfo`: the industry standard.
    ///
    /// Survives certificate renewal as long as the key pair is unchanged.
    SpkiSha256([u8; 32]),
    /// The exact DER-encoded leaf certificate.
    ///
    /// Stricter than a key pin: any re-issuance breaks it. Prefer
    /// [`TlsServerCertPin::SpkiSha256`] unless you control the certificate
    /// file itself.
    ExactDer(CertificateDer<'static>),
}

/// One alternative group of server leaf pins, optionally scoped to server names.
#[derive(Debug, Clone)]
pub struct TlsServerCertPinSet {
    pins: Vec<TlsServerCertPin>,
    server_names: Vec<Host>,
}

/// Result of checking a server certificate against configured pin sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum TlsServerCertPinCheck {
    /// No pin set applies to the server name.
    NotApplicable,
    /// An applicable pin set contains the server certificate.
    Matched,
    /// Pin sets apply, but none contains the server certificate.
    Mismatched,
}

impl TlsServerCertPin {
    /// Compute the key ([`SpkiSha256`]) pin of `certificate`.
    ///
    /// [`SpkiSha256`]: TlsServerCertPin::SpkiSha256
    pub fn spki_sha256_of(certificate: &CertificateDer<'_>) -> Result<Self, BoxError> {
        Ok(Self::SpkiSha256(rama_crypto::cert::spki_sha256(
            certificate,
        )?))
    }
}

impl From<CertificateDer<'static>> for TlsServerCertPin {
    fn from(certificate: CertificateDer<'static>) -> Self {
        Self::ExactDer(certificate)
    }
}

impl std::str::FromStr for TlsServerCertPin {
    type Err = BoxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use rama_core::error::ErrorContext as _;
        use rama_crypto::pki_types::pem::PemObject as _;

        if let Some(digest) = s.strip_prefix("sha256/") {
            let digest: [u8; 32] = BASE64_STANDARD
                .decode(digest)
                .context("decode base64 spki sha256 server pin digest")?
                .as_slice()
                .try_into()
                .context("spki sha256 server pin digest must be 32 bytes")?;
            Ok(Self::SpkiSha256(digest))
        } else if let Some(der) = s.strip_prefix("der/") {
            Ok(Self::ExactDer(
                BASE64_STANDARD
                    .decode(der)
                    .context("decode base64 der server pin certificate")?
                    .into(),
            ))
        } else if s.contains("-----BEGIN CERTIFICATE-----") {
            let certificate = CertificateDer::from_pem_slice(s.as_bytes())
                .context("parse pem server pin certificate")?;
            Self::spki_sha256_of(&certificate)
        } else {
            Err(BoxError::from_static_str(
                "server pin must use the sha256/<base64> or der/<base64> format, or be a pem certificate",
            ))
        }
    }
}

impl std::fmt::Display for TlsServerCertPin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SpkiSha256(digest) => {
                write!(f, "sha256/{}", BASE64_STANDARD.encode(digest))
            }
            Self::ExactDer(certificate) => {
                write!(f, "der/{}", BASE64_STANDARD.encode(certificate))
            }
        }
    }
}

impl TlsServerCertPinSet {
    /// Create a global pin set containing a single pin.
    pub fn new(pin: impl Into<TlsServerCertPin>) -> Self {
        Self {
            pins: vec![pin.into()],
            server_names: Vec::new(),
        }
    }

    /// Create a global, non-empty pin set of alternative pins.
    pub fn try_new(
        pins: impl IntoIterator<Item: Into<TlsServerCertPin>>,
    ) -> Result<Self, BoxError> {
        let pins: Vec<_> = pins.into_iter().map(Into::into).collect();
        if pins.is_empty() {
            return Err(BoxError::from_static_str("server pin set cannot be empty"));
        }
        Ok(Self {
            pins,
            server_names: Vec::new(),
        })
    }

    generate_set_and_with! {
        /// Add an alternative pin to this set.
        pub fn pin(mut self, pin: impl Into<TlsServerCertPin>) -> Self {
            self.pins.push(pin.into());
            self
        }
    }

    generate_set_and_with! {
        /// Scope this set to `server_name`, added as an alternative to any
        /// previously set server names. Without any the set applies globally.
        pub fn server_name(mut self, server_name: impl Into<Host>) -> Self {
            self.server_names.push(server_name.into());
            self
        }
    }

    fn applies_to(&self, server_name: Option<&Host>) -> bool {
        self.server_names.is_empty()
            || server_name.is_some_and(|name| self.server_names.iter().any(|pin| pin == name))
    }
}

impl From<TlsServerCertPin> for TlsServerCertPinSet {
    fn from(pin: TlsServerCertPin) -> Self {
        Self::new(pin)
    }
}

impl From<CertificateDer<'static>> for TlsServerCertPinSet {
    fn from(certificate: CertificateDer<'static>) -> Self {
        Self::new(certificate)
    }
}

impl TlsServerCertPins {
    /// Create pins holding a single pin set.
    ///
    /// A single pin or certificate converts into a global single-pin set.
    pub fn new(set: impl Into<TlsServerCertPinSet>) -> Self {
        Self(Arc::new(vec![set.into()]))
    }

    generate_set_and_with! {
        /// Add an alternative pin set.
        pub fn pin_set(mut self, set: impl Into<TlsServerCertPinSet>) -> Self {
            Arc::make_mut(&mut self.0).push(set.into());
            self
        }
    }

    /// Check the certificate against pin sets applicable to `server_name`.
    #[doc(hidden)]
    pub fn check(
        &self,
        server_name: Option<&Host>,
        certificate: &CertificateDer<'_>,
    ) -> TlsServerCertPinCheck {
        // leaf spki digest computed at most once, across all sets;
        // an unparsable leaf simply never matches a key pin
        let mut leaf_spki: Option<Option<[u8; 32]>> = None;
        let mut applicable = false;
        for pin_set in self.0.iter() {
            if !pin_set.applies_to(server_name) {
                continue;
            }
            applicable = true;
            for pin in &pin_set.pins {
                let matched = match pin {
                    TlsServerCertPin::ExactDer(pinned) => pinned.as_ref() == certificate.as_ref(),
                    TlsServerCertPin::SpkiSha256(digest) => leaf_spki
                        .get_or_insert_with(|| rama_crypto::cert::spki_sha256(certificate).ok())
                        .is_some_and(|leaf| &leaf == digest),
                };
                if matched {
                    return TlsServerCertPinCheck::Matched;
                }
            }
        }
        if applicable {
            TlsServerCertPinCheck::Mismatched
        } else {
            TlsServerCertPinCheck::NotApplicable
        }
    }

    /// Return whether at least one pin set applies to `server_name`.
    #[doc(hidden)]
    pub fn applies_to(&self, server_name: Option<&Host>) -> bool {
        self.0.iter().any(|pin_set| pin_set.applies_to(server_name))
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
    /// Applicable server certificate pin sets remain enforced. Any other
    /// verification config (trust anchors, backend-specific verifiers or
    /// stores) is ignored.
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
        let pins = TlsServerCertPins::new(CertificateDer::from(vec![1, 2, 3]));
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
        assert_eq!(
            bag.get_ref::<TlsServerCertPins>()
                .unwrap()
                .check(None, &CertificateDer::from(vec![1, 2, 3])),
            TlsServerCertPinCheck::Matched,
        );
        assert_eq!(
            bag.get_ref::<TlsServerTrustAnchors>()
                .unwrap()
                .certificates(),
            &[CertificateDer::from(vec![4, 5, 6])]
        );
    }

    #[test]
    fn server_cert_pin_set_must_not_be_empty() {
        TlsServerCertPinSet::try_new(Vec::<TlsServerCertPin>::new()).unwrap_err();
    }

    #[test]
    fn server_cert_pin_parses_and_displays_standard_formats() {
        let pin: TlsServerCertPin = "sha256/xg6kqyS+uaJikboVvZPxNOYXMD3XPakJAakHSfGau/M="
            .parse()
            .unwrap();
        assert!(matches!(pin, TlsServerCertPin::SpkiSha256(_)));
        assert_eq!(
            pin.to_string(),
            "sha256/xg6kqyS+uaJikboVvZPxNOYXMD3XPakJAakHSfGau/M="
        );

        let pin: TlsServerCertPin = "der/AQID".parse().unwrap();
        assert_eq!(
            pin,
            TlsServerCertPin::ExactDer(CertificateDer::from(vec![1, 2, 3]))
        );
        assert_eq!(pin.to_string(), "der/AQID");

        "sha256/short".parse::<TlsServerCertPin>().unwrap_err();
        "md5/AQID".parse::<TlsServerCertPin>().unwrap_err();
        "sha256/!!!".parse::<TlsServerCertPin>().unwrap_err();
    }

    #[test]
    fn server_cert_pin_parses_pem_certificate_as_key_pin() {
        let body = include_str!("../../test_assets/example_com_crt.b64").trim();
        let body = body
            .as_bytes()
            .chunks(64)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        let pem = format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n");

        let pin: TlsServerCertPin = pem.parse().unwrap();
        assert_eq!(
            pin.to_string(),
            "sha256/xg6kqyS+uaJikboVvZPxNOYXMD3XPakJAakHSfGau/M="
        );

        "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----"
            .parse::<TlsServerCertPin>()
            .unwrap_err();
    }

    #[test]
    fn server_cert_pin_set_matches_any_configured_certificate() {
        let pins = TlsServerCertPins::new(
            TlsServerCertPinSet::try_new([
                CertificateDer::from(vec![1, 2, 3]),
                CertificateDer::from(vec![4, 5, 6]),
            ])
            .unwrap(),
        );

        assert_eq!(
            pins.check(None, &CertificateDer::from(vec![1, 2, 3])),
            TlsServerCertPinCheck::Matched
        );
        assert_eq!(
            pins.check(None, &CertificateDer::from(vec![4, 5, 6])),
            TlsServerCertPinCheck::Matched
        );
        assert_eq!(
            pins.check(None, &CertificateDer::from(vec![7, 8, 9])),
            TlsServerCertPinCheck::Mismatched
        );
    }

    #[test]
    fn spki_pin_matches_certificate_key_and_survives_der_changes() {
        // examples/assets/example.com.crt with its openssl-computed key pin
        let cert = CertificateDer::from(
            BASE64_STANDARD
                .decode(include_str!("../../test_assets/example_com_crt.b64").trim())
                .unwrap(),
        );
        let pin: TlsServerCertPin = "sha256/xg6kqyS+uaJikboVvZPxNOYXMD3XPakJAakHSfGau/M="
            .parse()
            .unwrap();
        assert_eq!(pin, TlsServerCertPin::spki_sha256_of(&cert).unwrap());

        let pins = TlsServerCertPins::new(pin);
        assert_eq!(pins.check(None, &cert), TlsServerCertPinCheck::Matched);
        // an unparsable leaf never matches a key pin
        assert_eq!(
            pins.check(None, &CertificateDer::from(vec![1, 2, 3])),
            TlsServerCertPinCheck::Mismatched
        );
    }

    #[test]
    fn mixed_pin_kinds_are_alternatives_within_one_set() {
        // rotation story: exact pin of the shipped cert OR the next key
        let cert = CertificateDer::from(
            BASE64_STANDARD
                .decode(include_str!("../../test_assets/example_com_crt.b64").trim())
                .unwrap(),
        );
        let pins = TlsServerCertPins::new(
            TlsServerCertPinSet::new(TlsServerCertPin::ExactDer(CertificateDer::from(vec![1])))
                .with_pin(TlsServerCertPin::spki_sha256_of(&cert).unwrap()),
        );

        assert_eq!(
            pins.check(None, &CertificateDer::from(vec![1])),
            TlsServerCertPinCheck::Matched
        );
        assert_eq!(pins.check(None, &cert), TlsServerCertPinCheck::Matched);
        assert_eq!(
            pins.check(None, &CertificateDer::from(vec![2])),
            TlsServerCertPinCheck::Mismatched
        );
    }

    #[test]
    fn scoped_pin_set_does_not_apply_without_a_server_name() {
        let pins = TlsServerCertPins::new(
            TlsServerCertPinSet::new(CertificateDer::from(vec![1]))
                .with_server_name(Host::from_static("api.example.com")),
        );

        assert_eq!(
            pins.check(None, &CertificateDer::from(vec![1])),
            TlsServerCertPinCheck::NotApplicable
        );
        assert!(!pins.applies_to(None));
    }

    #[test]
    fn scoped_pin_set_only_applies_to_its_server_names() {
        let pins = TlsServerCertPins::new(
            TlsServerCertPinSet::new(CertificateDer::from(vec![1]))
                .with_server_name(Host::from_static("api.example.com"))
                .with_server_name(Host::from_static("uploads.example.com")),
        );

        assert_eq!(
            pins.check(
                Some(&Host::from_static("api.example.com")),
                &CertificateDer::from(vec![1]),
            ),
            TlsServerCertPinCheck::Matched
        );
        assert_eq!(
            pins.check(
                Some(&Host::from_static("api.example.com")),
                &CertificateDer::from(vec![2]),
            ),
            TlsServerCertPinCheck::Mismatched
        );
        assert_eq!(
            pins.check(
                Some(&Host::from_static("www.example.com")),
                &CertificateDer::from(vec![1]),
            ),
            TlsServerCertPinCheck::NotApplicable
        );
    }

    #[test]
    fn applicable_pin_sets_are_alternatives() {
        let pins = TlsServerCertPins::new(
            TlsServerCertPinSet::new(CertificateDer::from(vec![1]))
                .with_server_name(Host::from_static("api.example.com")),
        )
        .with_pin_set(
            TlsServerCertPinSet::new(CertificateDer::from(vec![2]))
                .with_server_name(Host::from_static("api.example.com")),
        );
        let server_name = Host::from_static("api.example.com");

        assert_eq!(
            pins.check(Some(&server_name), &CertificateDer::from(vec![1])),
            TlsServerCertPinCheck::Matched
        );
        assert_eq!(
            pins.check(Some(&server_name), &CertificateDer::from(vec![2])),
            TlsServerCertPinCheck::Matched
        );
        assert_eq!(
            pins.check(Some(&server_name), &CertificateDer::from(vec![3])),
            TlsServerCertPinCheck::Mismatched
        );
    }

    #[test]
    fn global_and_scoped_pin_sets_are_alternatives_when_both_apply() {
        let pins = TlsServerCertPins::new(CertificateDer::from(vec![1])).with_pin_set(
            TlsServerCertPinSet::try_new([
                CertificateDer::from(vec![2]),
                CertificateDer::from(vec![3]),
            ])
            .unwrap()
            .with_server_name(Host::from_static("api.example.com")),
        );
        let api = Host::from_static("api.example.com");
        let other = Host::from_static("www.example.com");

        assert_eq!(
            pins.check(Some(&api), &CertificateDer::from(vec![1])),
            TlsServerCertPinCheck::Matched
        );
        assert_eq!(
            pins.check(Some(&api), &CertificateDer::from(vec![3])),
            TlsServerCertPinCheck::Matched
        );
        assert_eq!(
            pins.check(Some(&other), &CertificateDer::from(vec![3])),
            TlsServerCertPinCheck::Mismatched
        );
    }

    #[test]
    fn server_trust_anchors_must_not_be_empty() {
        TlsServerTrustAnchors::try_new([]).unwrap_err();
        TlsClientConfig::new()
            .try_with_server_trust_anchors([])
            .unwrap_err();
    }
}
