use itertools::Itertools;
use rama_boring::x509::store::X509Store;
use rama_core::conversion::RamaFrom;
use rama_core::extensions::{Extension, FromExtensions};
use rama_net::tls::client::{
    ClientHello, ClientHelloExtension, TlsAlpn, TlsClientAuth, TlsClientConfig, TlsKeyLog,
    TlsServerName, TlsServerVerify, TlsStoreServerCertChain, TlsSupportedVersions,
};
use rama_net::tls::{
    ApplicationProtocol, CertificateCompressionAlgorithm, CipherSuite, ExtensionId,
    ProtocolVersion, SignatureScheme, SupportedGroup,
};
use rama_utils::macros::generate_set_and_with;
use std::sync::Arc;

use crate::RamaTlsBoringCrateMarker;

/// Gather all the TLS extensions supported by boringssl
#[derive(FromExtensions)]
pub struct BoringTlsConnectorConfig<'a> {
    pub alpn: Option<&'a TlsAlpn>,
    pub versions: Option<&'a TlsSupportedVersions>,
    pub verify: Option<&'a TlsServerVerify>,
    pub keylog: Option<&'a TlsKeyLog>,
    pub server_name: Option<&'a TlsServerName>,
    pub store_chain: Option<&'a TlsStoreServerCertChain>,
    pub client_auth: Option<&'a TlsClientAuth>,
    pub cipher_suites: Option<&'a BoringCipherSuites>,
    pub supported_groups: Option<&'a BoringSupportedGroups>,
    pub signature_schemes: Option<&'a BoringSignatureSchemes>,
    pub grease: Option<&'a BoringGrease>,
    pub alps: Option<&'a BoringAlps>,
    pub extension_order: Option<&'a BoringExtensionOrder>,
    pub cert_compression: Option<&'a BoringCertCompression>,
    pub delegated_credentials: Option<&'a BoringDelegatedCredentials>,
    pub record_size_limit: Option<&'a BoringRecordSizeLimit>,
    pub encrypted_client_hello: Option<&'a BoringEncryptedClientHello>,
    pub ocsp_stapling: Option<&'a BoringOcspStapling>,
    pub signed_cert_timestamps: Option<&'a BoringSignedCertTimestamps>,
    pub verify_cert_store: Option<&'a BoringServerVerifyCertStore>,
    pub min_version: Option<&'a BoringMinVersion>,
    pub max_version: Option<&'a BoringMaxVersion>,
}

/// Boring-specific setters for [`TlsClientConfig`].
pub trait BoringClientConfigExt: Sized {
    /// Create a new config that mimics the provided [`ClientHello`]
    fn new_from_client_hello(hello: &ClientHello) -> Self;

    rama_utils::macros::generate_set_and_with! {
        /// Layer the fingerprint pieces captured in a [`ClientHello`] onto this config.
        fn mimic_client_hello(self, hello: &ClientHello) -> Self;
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the cipher suites to offer, in order.
        fn cipher_suites(self, suites: Vec<CipherSuite>) -> Self;
    }
    rama_utils::macros::generate_set_and_with! {
        /// Set the supported groups (named curves), in order.
        fn supported_groups(self, groups: Vec<SupportedGroup>) -> Self;
    }
    rama_utils::macros::generate_set_and_with! {
        /// Set the signature schemes to advertise, in order.
        fn signature_schemes(self, schemes: Vec<SignatureScheme>) -> Self;
    }
    rama_utils::macros::generate_set_and_with! {
        /// Enable/disable GREASE injection.
        fn grease(self, enabled: bool) -> Self;
    }
    rama_utils::macros::generate_set_and_with! {
        /// Set Application-Layer Protocol Settings (ALPS).
        fn alps(self, protocols: Vec<ApplicationProtocol>, new_codepoint: bool) -> Self;
    }
    rama_utils::macros::generate_set_and_with! {
        /// Set the ClientHello extension ordering.
        fn extension_order(self, order: Vec<ExtensionId>) -> Self;
    }
    rama_utils::macros::generate_set_and_with! {
        /// Set certificate compression algorithms to advertise.
        fn cert_compression(self, algorithms: Vec<CertificateCompressionAlgorithm>) -> Self;
    }
    rama_utils::macros::generate_set_and_with! {
        /// Set delegated credential signature schemes.
        fn delegated_credentials(self, schemes: Vec<SignatureScheme>) -> Self;
    }
    rama_utils::macros::generate_set_and_with! {
        /// Set the `record_size_limit` value.
        fn record_size_limit(self, limit: u16) -> Self;
    }
    rama_utils::macros::generate_set_and_with! {
        /// Enable/disable Encrypted ClientHello (ECH) GREASE.
        fn encrypted_client_hello(self, enabled: bool) -> Self;
    }
    rama_utils::macros::generate_set_and_with! {
        /// Enable/disable OCSP stapling request.
        fn ocsp_stapling(self, enabled: bool) -> Self;
    }
    rama_utils::macros::generate_set_and_with! {
        /// Enable/disable signed certificate timestamps request.
        fn signed_cert_timestamps(self, enabled: bool) -> Self;
    }
    rama_utils::macros::generate_set_and_with! {
        /// Set a custom server-certificate verification store (custom CA roots).
        fn server_verify_cert_store(self, store: Arc<X509Store>) -> Self;
    }
    rama_utils::macros::generate_set_and_with! {
        /// Set the minimum TLS version boring will negotiate.
        fn min_version(self, version: ProtocolVersion) -> Self;
    }
    rama_utils::macros::generate_set_and_with! {
        /// Cap the maximum TLS version boring will negotiate.
        fn max_version(self, version: ProtocolVersion) -> Self;
    }
}

impl BoringClientConfigExt for TlsClientConfig {
    fn new_from_client_hello(hello: &ClientHello) -> Self {
        Self::rama_from(hello)
    }

    generate_set_and_with! {
        fn mimic_client_hello(mut self, hello: &ClientHello) -> Self {
            Self::rama_from(hello).write_to(self.as_extensions());
            self
        }
    }

    generate_set_and_with! {
        fn cipher_suites(mut self, suites: Vec<CipherSuite>) -> Self {
            self.insert(BoringCipherSuites(suites));
            self
        }
    }
    generate_set_and_with! {
        fn supported_groups(mut self, groups: Vec<SupportedGroup>) -> Self {
            self.insert(BoringSupportedGroups(groups));
            self
        }
    }
    generate_set_and_with! {
        fn signature_schemes(mut self, schemes: Vec<SignatureScheme>) -> Self {
            self.insert(BoringSignatureSchemes(schemes));
            self
        }
    }
    generate_set_and_with! {
        fn grease(mut self, enabled: bool) -> Self {
            self.insert(BoringGrease(enabled));
            self
        }
    }
    generate_set_and_with! {
        fn alps(mut self, protocols: Vec<ApplicationProtocol>, new_codepoint: bool) -> Self {
            self.insert(BoringAlps {
                protocols,
                new_codepoint,
            });
            self
        }
    }
    generate_set_and_with! {
        fn extension_order(mut self, order: Vec<ExtensionId>) -> Self {
            self.insert(BoringExtensionOrder(order));
            self
        }
    }
    generate_set_and_with! {
        fn cert_compression(mut self, algorithms: Vec<CertificateCompressionAlgorithm>) -> Self {
            self.insert(BoringCertCompression(algorithms));
            self
        }
    }
    generate_set_and_with! {
        fn delegated_credentials(mut self, schemes: Vec<SignatureScheme>) -> Self {
            self.insert(BoringDelegatedCredentials(schemes));
            self
        }
    }
    generate_set_and_with! {
        fn record_size_limit(mut self, limit: u16) -> Self {
            self.insert(BoringRecordSizeLimit(limit));
            self
        }
    }
    generate_set_and_with! {
        fn encrypted_client_hello(mut self, enabled: bool) -> Self {
            self.insert(BoringEncryptedClientHello(enabled));
            self
        }
    }
    generate_set_and_with! {
        fn ocsp_stapling(mut self, enabled: bool) -> Self {
            self.insert(BoringOcspStapling(enabled));
            self
        }
    }
    generate_set_and_with! {
        fn signed_cert_timestamps(mut self, enabled: bool) -> Self {
            self.insert(BoringSignedCertTimestamps(enabled));
            self
        }
    }
    generate_set_and_with! {
        fn server_verify_cert_store(mut self, store: Arc<X509Store>) -> Self {
            self.insert(BoringServerVerifyCertStore(store));
            self
        }
    }
    generate_set_and_with! {
        fn min_version(mut self, version: ProtocolVersion) -> Self {
            self.insert(BoringMinVersion(version));
            self
        }
    }
    generate_set_and_with! {
        fn max_version(mut self, version: ProtocolVersion) -> Self {
            self.insert(BoringMaxVersion(version));
            self
        }
    }
}

/// Cipher suites to offer, in order (may include GREASE / unknown values).
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct BoringCipherSuites(pub Vec<CipherSuite>);

/// Supported groups (named curves), in order.
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct BoringSupportedGroups(pub Vec<SupportedGroup>);

/// Signature schemes to advertise, in order.
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct BoringSignatureSchemes(pub Vec<SignatureScheme>);

/// Whether GREASE values are injected into the ClientHello.
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct BoringGrease(pub bool);

/// Application-Layer Protocol Settings (ALPS).
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct BoringAlps {
    /// Protocols for which settings are offered.
    pub protocols: Vec<ApplicationProtocol>,
    /// Use the new ALPS codepoint.
    pub new_codepoint: bool,
}

/// ClientHello extension ordering.
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct BoringExtensionOrder(pub Vec<ExtensionId>);

/// Certificate compression algorithms to advertise.
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct BoringCertCompression(pub Vec<CertificateCompressionAlgorithm>);

/// Delegated credential signature schemes.
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct BoringDelegatedCredentials(pub Vec<SignatureScheme>);

/// `record_size_limit` extension value.
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct BoringRecordSizeLimit(pub u16);

/// Whether to GREASE the Encrypted ClientHello (ECH) extension.
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct BoringEncryptedClientHello(pub bool);

/// Whether to request OCSP stapling (`status_request`).
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct BoringOcspStapling(pub bool);

/// Whether to request signed certificate timestamps (SCT).
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct BoringSignedCertTimestamps(pub bool);

/// Minimum TLS version boring negotiates, overriding the min derived from the
/// supported-versions list.
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct BoringMinVersion(pub ProtocolVersion);

/// Maximum TLS version boring negotiates, overriding the max derived from the
/// supported-versions list.
#[derive(Debug, Clone, Extension)]
#[extension(tags(tls))]
pub struct BoringMaxVersion(pub ProtocolVersion);

/// Custom [`X509Store`] used to verify the server certificate (overrides the
/// default OS trust store, unless verification is disabled).
#[derive(Clone, Extension)]
#[extension(tags(tls))]
pub struct BoringServerVerifyCertStore(pub Arc<X509Store>);

impl std::fmt::Debug for BoringServerVerifyCertStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoringServerVerifyCertStore")
            .finish_non_exhaustive()
    }
}

impl RamaFrom<&ClientHello, RamaTlsBoringCrateMarker> for TlsClientConfig {
    fn rama_from(hello: &ClientHello) -> Self {
        let mut config = TlsClientConfig::new();
        let mut grease = false;

        let cipher_suites = hello.cipher_suites();
        if !cipher_suites.is_empty() {
            if cipher_suites.iter().any(|c| c.is_grease()) {
                grease = true;
            }
            config.set_cipher_suites(cipher_suites.to_vec());
        }

        let extensions = hello.extensions();
        let order: Vec<ExtensionId> = extensions.iter().map(|e| e.id()).dedup().collect();
        if !order.is_empty() {
            config.set_extension_order(order);
        }

        for ext in extensions {
            match ext {
                // SNI is resolved per-request from the target host by the
                // connector (with the IP-first / RFC 6066 guard), not baked into
                // the config here.
                ClientHelloExtension::ServerName(_) => {}
                ClientHelloExtension::ApplicationLayerProtocolNegotiation(alpn) => {
                    config.set_alpn(alpn.clone());
                }
                ClientHelloExtension::SupportedGroups(groups) => {
                    if groups.iter().any(|g| g.is_grease()) {
                        grease = true;
                    }
                    config.set_supported_groups(groups.clone());
                }
                ClientHelloExtension::SupportedVersions(versions) => {
                    if versions.iter().any(|v| v.is_grease()) {
                        grease = true;
                    }
                    config.set_supported_versions(versions.clone());
                }
                ClientHelloExtension::SignatureAlgorithms(schemes) => {
                    if schemes.iter().any(|s| s.is_grease()) {
                        grease = true;
                    }
                    config.set_signature_schemes(schemes.clone());
                }
                ClientHelloExtension::CertificateCompression(algorithms) => {
                    config.set_cert_compression(algorithms.clone());
                }
                ClientHelloExtension::DelegatedCredentials(schemes) => {
                    config.set_delegated_credentials(schemes.clone());
                }
                ClientHelloExtension::RecordSizeLimit(limit) => {
                    config.set_record_size_limit(*limit);
                }
                ClientHelloExtension::EncryptedClientHello(_) => {
                    config.set_encrypted_client_hello(true);
                }
                ClientHelloExtension::ApplicationSettings {
                    protocols,
                    new_codepoint,
                } => {
                    config.set_alps(protocols.clone(), *new_codepoint);
                }
                other => match other.id() {
                    ExtensionId::STATUS_REQUEST | ExtensionId::STATUS_REQUEST_V2 => {
                        config.set_ocsp_stapling(true);
                    }
                    ExtensionId::SIGNED_CERTIFICATE_TIMESTAMP => {
                        config.set_signed_cert_timestamps(true);
                    }
                    _ => {}
                },
            }
        }

        if grease {
            config.set_grease(true);
        }

        // Egress version safety (mitm mirror): cap boring's max negotiated version
        // when the mirrored ClientHello isn't a viable TLS 1.3 offer.
        if let Some(max) = egress_max_version_clamp(hello) {
            config.set_max_version(max);
        }

        config
    }
}

/// Compute the egress max-version clamp for a mirrored [`ClientHello`], or
/// `None` when no clamp is needed.
///
/// Two cases require a clamp (otherwise boring would happily offer TLS 1.3 on
/// egress even when the mirrored client wouldn't or couldn't):
/// - the hello has **no `supported_versions` extension** (legacy hello): cap to
///   the legacy `protocol_version`;
/// - the hello advertises TLS 1.3 but isn't viable as 1.3 (no TLS 1.3 cipher
///   suite, or no TLS 1.3-capable signature algorithm): clamp to TLS 1.2 rather
///   than sending an internally inconsistent ClientHello servers reject.
fn egress_max_version_clamp(hello: &ClientHello) -> Option<ProtocolVersion> {
    let Some(versions) = hello.supported_versions() else {
        // No supported_versions extension: the negotiated version lives only in
        // the legacy field, so cap egress to it.
        return Some(hello.protocol_version());
    };

    let advertises_tls13 = versions
        .iter()
        .filter(|v| !v.is_grease())
        .any(|v| *v == ProtocolVersion::TLSv1_3);
    if !advertises_tls13 {
        return None;
    }

    let has_tls13_cipher = hello
        .cipher_suites()
        .iter()
        .filter(|c| !c.is_grease())
        .any(|c| c.is_tls13());
    let has_tls13_sig_alg = hello.ext_signature_algorithms().is_some_and(|schemes| {
        schemes
            .iter()
            .filter(|s| !s.is_grease())
            .any(|s| s.is_tls13_capable())
    });

    (!has_tls13_cipher || !has_tls13_sig_alg).then_some(ProtocolVersion::TLSv1_2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_net::tls::CompressionAlgorithm;

    fn clamp_of(hello: &ClientHello) -> Option<ProtocolVersion> {
        TlsClientConfig::rama_from(hello)
            .as_extensions()
            .get_ref::<BoringMaxVersion>()
            .map(|p| p.0)
    }

    #[test]
    fn clamp_caps_to_legacy_version_when_no_supported_versions_ext() {
        let hello = ClientHello::new(
            ProtocolVersion::TLSv1_2,
            vec![CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
            vec![CompressionAlgorithm::Null],
            vec![],
        );
        assert_eq!(clamp_of(&hello), Some(ProtocolVersion::TLSv1_2));
    }

    #[test]
    fn clamp_to_tls12_when_tls13_advertised_without_tls13_cipher() {
        let hello = ClientHello::new(
            ProtocolVersion::TLSv1_2,
            // no TLS 1.3 cipher suite
            vec![CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256],
            vec![CompressionAlgorithm::Null],
            vec![
                ClientHelloExtension::SupportedVersions(vec![
                    ProtocolVersion::TLSv1_3,
                    ProtocolVersion::TLSv1_2,
                ]),
                ClientHelloExtension::SignatureAlgorithms(vec![SignatureScheme::RSA_PSS_SHA256]),
            ],
        );
        assert_eq!(clamp_of(&hello), Some(ProtocolVersion::TLSv1_2));
    }

    #[test]
    fn clamp_to_tls12_when_tls13_advertised_without_tls13_capable_sig_alg() {
        let hello = ClientHello::new(
            ProtocolVersion::TLSv1_2,
            vec![CipherSuite::TLS13_AES_128_GCM_SHA256],
            vec![CompressionAlgorithm::Null],
            vec![
                ClientHelloExtension::SupportedVersions(vec![ProtocolVersion::TLSv1_3]),
                // PKCS1 is TLS 1.2-only
                ClientHelloExtension::SignatureAlgorithms(vec![SignatureScheme::RSA_PKCS1_SHA256]),
            ],
        );
        assert_eq!(clamp_of(&hello), Some(ProtocolVersion::TLSv1_2));
    }

    #[test]
    fn no_clamp_for_viable_tls13_hello() {
        let hello = ClientHello::new(
            ProtocolVersion::TLSv1_2,
            vec![CipherSuite::TLS13_AES_128_GCM_SHA256],
            vec![CompressionAlgorithm::Null],
            vec![
                ClientHelloExtension::SupportedVersions(vec![
                    ProtocolVersion::TLSv1_3,
                    ProtocolVersion::TLSv1_2,
                ]),
                ClientHelloExtension::SignatureAlgorithms(vec![SignatureScheme::RSA_PSS_SHA256]),
            ],
        );
        assert_eq!(clamp_of(&hello), None);
    }
}
