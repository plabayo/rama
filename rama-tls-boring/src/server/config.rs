use crate::server::ServerCertIssuerData;

use rama_core::extensions::{Extension, FromExtensions};
use rama_net::tls::TlsAlpn;
use rama_tls::server::{TlsClientVerify, TlsServerAuth, TlsServerConfig, TlsStoreClientCertChain};
use rama_tls::{
    CertificateCompressionAlgorithm, CipherSuite, SignatureScheme, SupportedGroup, TlsKeyLog,
    TlsSupportedVersions,
};
use rama_utils::macros::generate_set_and_with;

/// Gather all the TLS extensions supported by boring
#[derive(FromExtensions)]
pub struct BoringTlsAcceptorConfig<'a> {
    pub alpn: Option<&'a TlsAlpn>,
    pub versions: Option<&'a TlsSupportedVersions>,
    pub keylog: Option<&'a TlsKeyLog>,
    pub client_verify: Option<&'a TlsClientVerify>,
    pub store_client_chain: Option<&'a TlsStoreClientCertChain>,
    pub auth: Option<BoringTlsAuth<'a>>,
    pub cipher_suites: Option<&'a BoringServerCipherSuites>,
    pub supported_groups: Option<&'a BoringServerSupportedGroups>,
    pub signature_schemes: Option<&'a BoringServerSignatureSchemes>,
    pub cert_compression: Option<&'a BoringServerCertCompression>,
}

#[derive(FromExtensions)]
/// Auth used by boring acceptor
pub enum BoringTlsAuth<'a> {
    ServerAuth(&'a TlsServerAuth),
    CertIssuer(&'a BoringServerCertIssuer),
}

/// Boring specific tls setters.
pub trait BoringServerConfigExt: Sized {
    generate_set_and_with! {
        /// Issue server certs on the fly (from a CA or a custom [`DynamicCertIssuer`]),
        /// with optional in-memory caching.
        fn cert_issuer(self, data: ServerCertIssuerData) -> Self;
    }
    generate_set_and_with! {
        /// Cipher suites for TLS 1.2 and below, in preference order.
        ///
        /// BoringSSL picks TLS 1.3 cipher suites itself, so those entries are ignored.
        fn cipher_suites(self, suites: Vec<CipherSuite>) -> Self;
    }
    generate_set_and_with! {
        /// Key exchange groups, in preference order.
        fn supported_groups(self, groups: Vec<SupportedGroup>) -> Self;
    }
    generate_set_and_with! {
        /// Signature schemes to sign the handshake with, in preference order.
        fn signature_schemes(self, schemes: Vec<SignatureScheme>) -> Self;
    }
    generate_set_and_with! {
        /// Certificate compression algorithms the server can compress with.
        ///
        /// The first one the client offers is used.
        fn cert_compression(self, algorithms: Vec<CertificateCompressionAlgorithm>) -> Self;
    }
}

impl BoringServerConfigExt for TlsServerConfig {
    generate_set_and_with! {
        fn cert_issuer(mut self, data: ServerCertIssuerData) -> Self {
            self.insert(BoringServerCertIssuer(data));
            self
        }
    }
    generate_set_and_with! {
        fn cipher_suites(mut self, suites: Vec<CipherSuite>) -> Self {
            self.insert(BoringServerCipherSuites(suites));
            self
        }
    }
    generate_set_and_with! {
        fn supported_groups(mut self, groups: Vec<SupportedGroup>) -> Self {
            self.insert(BoringServerSupportedGroups(groups));
            self
        }
    }
    generate_set_and_with! {
        fn signature_schemes(mut self, schemes: Vec<SignatureScheme>) -> Self {
            self.insert(BoringServerSignatureSchemes(schemes));
            self
        }
    }
    generate_set_and_with! {
        fn cert_compression(mut self, algorithms: Vec<CertificateCompressionAlgorithm>) -> Self {
            self.insert(BoringServerCertCompression(algorithms));
            self
        }
    }
}

/// Issue server certs on the fly. See [`BoringServerConfigExt::with_cert_issuer`].
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct BoringServerCertIssuer(pub ServerCertIssuerData);

/// Server cipher suites for TLS 1.2 and below, in preference order.
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct BoringServerCipherSuites(pub Vec<CipherSuite>);

/// Server key exchange groups, in preference order.
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct BoringServerSupportedGroups(pub Vec<SupportedGroup>);

/// Signature schemes the server signs with, in preference order.
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct BoringServerSignatureSchemes(pub Vec<SignatureScheme>);

/// Certificate compression algorithms the server can compress with.
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct BoringServerCertCompression(pub Vec<CertificateCompressionAlgorithm>);
