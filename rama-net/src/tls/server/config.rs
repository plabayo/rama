use crate::{
    address::Domain,
    tls::{
        ApplicationProtocol, KeyLogIntent, ProtocolVersion, TlsAlpn, TlsKeyLog,
        TlsSupportedVersions, client::ClientHello,
    },
};
use rama_core::{
    error::BoxError,
    extensions::{Extension, Extensions},
};
use rama_crypto::pki_types::{CertificateDer, PrivateKeyDer};
use rama_utils::{collections::smallvec::SmallVec, macros::generate_set_and_with};
use serde::{Deserialize, Serialize};

/// A backend agnostic TLS server config
///
/// It holds a set of fine-grained config pieces (e.g. [`TlsServerAuth`],
/// [`TlsAlpn`]) and exposes typed setters for the settings both TLS backends
/// support. Backend crates add setters for their backend-specific pieces (e.g.
/// dynamic cert issuance + caching, or a native escape hatch) via extension
/// traits (`RustlsServerConfigExt` / `BoringServerConfigExt`).
#[derive(Debug, Default)]
pub struct TlsServerConfig(Extensions);

impl TlsServerConfig {
    /// Create an empty config.
    #[must_use]
    pub fn new() -> Self {
        Self(Extensions::new())
    }

    /// Create a new config using with:
    /// - ALPN: H2, http1.1
    /// - Self signed certificate
    /// - Keylogger: [`KeyLogIntent::Environment`]
    #[must_use]
    pub fn default_http() -> Self {
        Self::new()
            .with_server_auth(ServerAuth::SelfSigned(SelfSignedData::default()))
            .with_alpn_http_auto()
            .with_keylog(KeyLogIntent::Environment)
    }

    /// Create a config that serves a freshly generated self-signed identity and
    /// offers HTTP/2 + HTTP/1.1 via ALPN.
    #[must_use]
    pub fn self_signed_http_auto() -> Self {
        Self::new()
            .with_server_auth(ServerAuth::SelfSigned(SelfSignedData::default()))
            .with_alpn_http_auto()
    }

    /// Transfer this config's pieces onto `extensions` (appending, so they
    /// override existing entries of the same type — newest-wins).
    pub fn write_to(&self, extensions: &Extensions) {
        extensions.extend(&self.0);
    }

    generate_set_and_with! {
        /// Set the server auth (cert/key source): self-signed or provided cert.
        ///
        /// Dynamic / on-the-fly cert issuance (with caching) is backend-specific;
        /// configure it via the backend's server-config extension trait.
        pub fn server_auth(mut self, auth: ServerAuth) -> Self {
            self.0.insert(TlsServerAuth(auth));
            self
        }
    }

    generate_set_and_with! {
        /// Serve a freshly generated self-signed identity.
        pub fn self_signed(mut self, data: SelfSignedData) -> Self {
            self.0.insert(TlsServerAuth(ServerAuth::SelfSigned(data)));
            self
        }
    }

    generate_set_and_with! {
        /// Serve the provided certificate chain + private key.
        pub fn single_cert(mut self, data: ServerAuthData) -> Self {
            self.0.insert(TlsServerAuth(ServerAuth::Single(data)));
            self
        }
    }

    generate_set_and_with! {
        /// Set the ALPN protocols accepted (in preference order).
        pub fn alpn(mut self, protocols: SmallVec<[ApplicationProtocol; 2]>) -> Self {
            self.0.insert(TlsAlpn(protocols));
            self
        }
    }

    generate_set_and_with! {
        /// Accept HTTP/2 and HTTP/1.1 via ALPN.
        pub fn alpn_http_auto(mut self) -> Self {
            self.0.insert(TlsAlpn::http_auto());
            self
        }
    }

    generate_set_and_with! {
        /// Accept HTTP/1.1 only via ALPN.
        pub fn alpn_http_1(mut self) -> Self {
            self.0.insert(TlsAlpn::http_1());
            self
        }
    }

    generate_set_and_with! {
        /// Accept HTTP/2 only via ALPN.
        pub fn alpn_http_2(mut self) -> Self {
            self.0.insert(TlsAlpn::http_2());
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
        /// Set how the client is verified (mTLS).
        pub fn client_verify(mut self, mode: ClientVerifyMode) -> Self {
            self.0.insert(TlsClientVerify(mode));
            self
        }
    }

    generate_set_and_with! {
        /// Set whether the client certificate chain is captured into
        /// `NegotiatedTlsParameters`.
        pub fn store_client_cert_chain(mut self, store: bool) -> Self {
            self.0.insert(TlsStoreClientCertChain(store));
            self
        }
    }

    pub fn as_extensions(&self) -> &Extensions {
        &self.0
    }

    /// Insert any config piece (newest-wins override).
    ///
    /// Should be used by backends in their server-config ext traits.
    #[doc(hidden)]
    pub fn insert<T: Extension>(&self, piece: T) {
        self.0.insert(piece);
    }
}

impl Clone for TlsServerConfig {
    fn clone(&self) -> Self {
        let clone = Self::new();
        clone.as_extensions().extend(self.as_extensions());
        clone
    }
}

#[derive(Debug, Clone)]
/// The kind of server auth to be used.
pub enum ServerAuth {
    /// Request the tls implementation to generate self-signed single data
    SelfSigned(SelfSignedData),
    /// Single data provided by the configurator
    Single(ServerAuthData),
}

impl Default for ServerAuth {
    fn default() -> Self {
        Self::SelfSigned(SelfSignedData::default())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
/// Data that can be used to configure the self-signed single data
pub struct SelfSignedData {
    /// name of the organisation
    pub organisation_name: Option<String>,
    /// common name (CN): server name protected by the SSL certificate
    pub common_name: Option<Domain>,
    /// Subject Alternative Names (SAN) can be defined
    /// to create a cert which allows multiple hostnames or domains to be secured under one certificate.
    pub subject_alternative_names: Option<Vec<String>>,
    /// Key algorithm used for the generated key pair (defaults to EC P-256).
    #[serde(default)]
    pub key_kind: SelfSignedKeyKind,
}

/// Key algorithm to use when generating a self-signed key pair.
///
/// The default is [`SelfSignedKeyKind::EcP256`]: it is universally supported by
/// TLS clients, generates and signs far faster than any RSA variant, and offers
/// stronger security (128-bit) than RSA-2048 with much smaller certificates.
/// Pick [`SelfSignedKeyKind::EcP384`] for a higher security margin (e.g. a
/// long-lived CA) while staying faster than RSA-4096.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum SelfSignedKeyKind {
    /// 2048-bit RSA.
    Rsa2048,
    /// 4096-bit RSA.
    Rsa4096,
    /// ECDSA over NIST P-256 (secp256r1). Default.
    #[default]
    EcP256,
    /// ECDSA over NIST P-384 (secp384r1).
    EcP384,
    /// ECDSA over NIST P-521 (secp521r1).
    EcP521,
    /// Ed25519 (EdDSA).
    Ed25519,
}

#[derive(Debug)]
/// Raw private key and certificate data to facilitate server authentication.
pub struct ServerAuthData {
    /// private key used by server
    pub private_key: PrivateKeyDer<'static>,
    /// certificate chain as a companion to the private key
    pub cert_chain: Vec<CertificateDer<'static>>,

    /// `ocsp` is a DER-encoded OCSP response
    pub ocsp: Option<Vec<u8>>,
}

impl Clone for ServerAuthData {
    fn clone(&self) -> Self {
        Self {
            cert_chain: self.cert_chain.clone(),
            ocsp: self.ocsp.clone(),
            private_key: self.private_key.clone_key(),
        }
    }
}

/// Trait that needs to be implemented by cert issuers to support dynamically
/// issueing (external) certs based on client_hello input.
///
/// The dynamic cert-issuance *config* that consumes this (cert issuer + cache)
/// is backend-specific; see e.g. `rama_tls_boring::server::BoringServerConfigExt`.
pub trait DynamicCertIssuer: Send + Sync + 'static {
    fn issue_cert(
        &self,
        client_hello: ClientHello,
        server_name: Option<Domain>,
    ) -> impl Future<Output = Result<ServerAuthData, BoxError>> + Send + '_;

    /// Can be used to return a normalized domain for purposes
    /// such as caching.
    ///
    /// This is only useful for issuers where
    /// the actual used domain might be modified such
    /// that mutliple different input domains result
    /// in the same output domain. E.g. because of
    /// wildcard domains.
    ///
    /// Mostly useful for optimizations in caching of certs,
    /// but not critical to have, just nice.
    fn norm_cn(&self, _domain: &Domain) -> Option<&Domain> {
        None
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
/// Mode of client verification by a (tls) server
pub enum ClientVerifyMode {
    #[default]
    /// Use the default verification approach as defined
    /// by the implementation of the used (tls) server
    Auto,
    /// Explicitly disable client verification (if possible)
    Disable,
    /// Client certificate chain containing the acceptable client certificates
    ClientAuth(Vec<CertificateDer<'static>>),
}

/// Server auth (cert/key source) to use, as configured on [`TlsServerConfig`].
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct TlsServerAuth(pub ServerAuth);

/// How the client is verified (mTLS).
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct TlsClientVerify(pub ClientVerifyMode);

/// Whether to capture the client certificate chain into
/// `NegotiatedTlsParameters`.
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct TlsStoreClientCertChain(pub bool);
