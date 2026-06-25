use crate::{
    ApplicationProtocol, KeyLogIntent, ProtocolVersion, TlsAlpn, TlsKeyLog, TlsSupportedVersions,
    client::ClientHello,
};
use rama_core::{
    error::BoxError,
    extensions::{Extension, Extensions},
};
use rama_crypto::cert::self_signed_server_auth;
pub use rama_crypto::cert::{SelfSignedData, SelfSignedKeyKind};
use rama_crypto::pki_types::{CertificateDer, PrivateKeyDer};
use rama_net::address::Domain;
use rama_utils::{collections::smallvec::SmallVec, macros::generate_set_and_with};

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
    /// - Self signed certificate (freshly generated)
    /// - Keylogger: [`KeyLogIntent::Environment`]
    pub fn default_http() -> Result<Self, BoxError> {
        Ok(Self::new()
            .try_with_self_signed(SelfSignedData::default())?
            .with_alpn_http_auto()
            .with_keylog(KeyLogIntent::Environment))
    }

    /// Create a config that serves a freshly generated self-signed identity and
    /// offers HTTP/2 + HTTP/1.1 via ALPN.
    pub fn self_signed_http_auto() -> Result<Self, BoxError> {
        Ok(Self::new()
            .try_with_self_signed(SelfSignedData::default())?
            .with_alpn_http_auto())
    }

    /// Transfer this config's pieces onto `extensions` (appending, so they
    /// override existing entries of the same type — newest-wins).
    pub fn write_to(&self, extensions: &Extensions) {
        extensions.extend(&self.0);
    }

    generate_set_and_with! {
        /// Set the server auth: the certificate chain + private key to serve.
        ///
        /// Dynamic / on-the-fly cert issuance (with caching) is backend-specific;
        /// configure it via the backend's server-config extension trait.
        pub fn server_auth(mut self, auth: ServerAuthData) -> Self {
            self.0.insert(TlsServerAuth(auth));
            self
        }
    }

    generate_set_and_with! {
        /// Generate a fresh self-signed identity and serve it.
        pub fn self_signed(mut self, data: SelfSignedData) -> Result<Self, BoxError> {
            self.0
                .insert(TlsServerAuth(ServerAuthData::new_self_signed(data)?));
            Ok(self)
        }
    }

    generate_set_and_with! {
        /// Serve the provided certificate chain + private key.
        pub fn single_cert(mut self, data: ServerAuthData) -> Self {
            self.0.insert(TlsServerAuth(data));
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

impl ServerAuthData {
    /// Create [`ServerAuthData`] from a certificate chain and private key (no OCSP).
    #[must_use]
    pub fn new(
        cert_chain: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
    ) -> Self {
        Self {
            cert_chain,
            private_key,
            ocsp: None,
        }
    }

    pub fn new_self_signed(data: SelfSignedData) -> Result<Self, BoxError> {
        let (cert_chain, private_key) = self_signed_server_auth(data)?;
        Ok(Self {
            cert_chain,
            private_key,
            ocsp: None,
        })
    }
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

/// Server auth (cert chain + key) to use, as configured on [`TlsServerConfig`].
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct TlsServerAuth(pub ServerAuthData);

/// How the client is verified (mTLS).
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct TlsClientVerify(pub ClientVerifyMode);

/// Whether to capture the client certificate chain into
/// `NegotiatedTlsParameters`.
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct TlsStoreClientCertChain(pub bool);
