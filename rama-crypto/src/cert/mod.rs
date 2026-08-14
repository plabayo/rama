//! Certificate generation helpers.
//!
//! Provides a backend pluggable self-signed certificate generator. The actual
//! crypto provider is selected by cargo feature:
//!
//! - `boring`: generate using BoringSSL (via `rama-boring`), for stacks that
//!   already link boringssl and do not want a second crypto provider.
//! - `aws-lc` / `ring`: generate using [`rcgen`].
//!
//! When several providers are enabled, `boring` is preferred. With none
//! enabled, certificate-generation functions return an error.

use crate::pki_types::{CertificateDer, PrivateKeyDer};
use rama_core::error::{BoxError, BoxErrorExt as _};
use rama_net::address::{Domain, Host};
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, time::Duration};

#[cfg(feature = "boring")]
#[cfg_attr(docsrs, doc(cfg(feature = "boring")))]
pub mod boring;

#[cfg(any(feature = "aws-lc", feature = "ring"))]
pub mod rcgen;

/// DNS or IP service identity encoded in a certificate's SAN extension.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CertificateIdentity {
    Dns(Domain),
    Ip(IpAddr),
}

impl CertificateIdentity {
    /// Classify a network host as a certificate identity.
    pub fn try_from_host(host: &Host) -> Result<Self, BoxError> {
        if let Ok(ip) = host.try_as_ip() {
            return Ok(Self::Ip(ip));
        }

        let domain = host.try_as_domain()?;
        Ok(domain
            .as_str()
            .parse()
            .map_or_else(|_| Self::Dns(domain.into_owned()), Self::Ip))
    }
}

impl From<Domain> for CertificateIdentity {
    fn from(domain: Domain) -> Self {
        domain
            .as_str()
            .parse()
            .map_or_else(|_| Self::Dns(domain), Self::Ip)
    }
}

impl From<IpAddr> for CertificateIdentity {
    fn from(ip: IpAddr) -> Self {
        Self::Ip(ip)
    }
}

impl TryFrom<&Host> for CertificateIdentity {
    type Error = BoxError;

    fn try_from(host: &Host) -> Result<Self, Self::Error> {
        Self::try_from_host(host)
    }
}

impl TryFrom<Host> for CertificateIdentity {
    type Error = BoxError;

    fn try_from(host: Host) -> Result<Self, Self::Error> {
        Self::try_from_host(&host)
    }
}

/// X.509 subject metadata. Service identities belong in SANs, not the CN.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateSubject {
    pub organisation_name: Option<String>,
    pub common_name: Option<String>,
}

/// Validity policy relative to certificate generation time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateValidity {
    /// Time between `notBefore` and `notAfter`.
    pub lifetime: Duration,
    /// Amount by which `notBefore` is backdated for clock skew.
    pub not_before_skew: Duration,
}

impl CertificateValidity {
    #[must_use]
    pub const fn new(lifetime: Duration, not_before_skew: Duration) -> Self {
        Self {
            lifetime,
            not_before_skew,
        }
    }
}

impl Default for CertificateValidity {
    fn default() -> Self {
        Self::new(
            Duration::from_secs(90 * 24 * 60 * 60),
            Duration::from_secs(60),
        )
    }
}

/// Key algorithm to use when generating a self-signed key pair.
///
/// The default is [`CertificateKeyKind::EcP256`]: it is universally supported by
/// TLS clients, generates and signs far faster than any RSA variant, and offers
/// stronger security (128-bit) than RSA-2048 with much smaller certificates.
/// Pick [`CertificateKeyKind::EcP384`] for a higher security margin (e.g. a
/// long-lived CA) while staying faster than RSA-4096.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum CertificateKeyKind {
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

/// Configuration for a generated self-signed certificate authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelfSignedCaConfig {
    pub subject: CertificateSubject,
    pub validity: CertificateValidity,
    pub key_kind: CertificateKeyKind,
}

impl Default for SelfSignedCaConfig {
    fn default() -> Self {
        Self {
            subject: CertificateSubject::default(),
            validity: CertificateValidity::new(
                Duration::from_secs(365 * 20 * 24 * 60 * 60),
                Duration::from_secs(60),
            ),
            key_kind: CertificateKeyKind::default(),
        }
    }
}

/// Reusable policy for an end-entity server certificate.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeafCertConfig {
    pub subject: CertificateSubject,
    pub validity: CertificateValidity,
    pub key_kind: CertificateKeyKind,
}

/// One concrete leaf-certificate request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeafCertRequest {
    pub config: LeafCertConfig,
    pub identities: Vec<CertificateIdentity>,
}

impl Default for LeafCertRequest {
    fn default() -> Self {
        Self {
            config: LeafCertConfig::default(),
            identities: vec![CertificateIdentity::Dns(Domain::from_static("localhost"))],
        }
    }
}

impl LeafCertRequest {
    #[must_use]
    pub fn new(identity: impl Into<CertificateIdentity>) -> Self {
        Self {
            config: LeafCertConfig::default(),
            identities: vec![identity.into()],
        }
    }
}

/// Configuration for generating static server-authentication material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GeneratedServerAuthConfig {
    /// One end-entity certificate signed with its own key.
    SelfSignedLeaf(LeafCertRequest),
    /// A generated self-signed CA plus a leaf signed by that CA.
    GeneratedCa {
        ca: SelfSignedCaConfig,
        leaf: LeafCertRequest,
    },
}

impl Default for GeneratedServerAuthConfig {
    fn default() -> Self {
        Self::GeneratedCa {
            ca: SelfSignedCaConfig::default(),
            leaf: LeafCertRequest::default(),
        }
    }
}

impl GeneratedServerAuthConfig {
    #[must_use]
    pub fn generated_ca_for(identity: impl Into<CertificateIdentity>) -> Self {
        Self::GeneratedCa {
            ca: SelfSignedCaConfig::default(),
            leaf: LeafCertRequest::new(identity),
        }
    }
}

/// An issuing CA chain and its private key.
#[derive(Debug)]
pub struct CertificateAuthorityData {
    /// Issuing CA first, followed by any parent certificates.
    certificate_chain: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
}

impl CertificateAuthorityData {
    pub fn try_new(
        certificate_chain: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
    ) -> Result<Self, BoxError> {
        if certificate_chain.is_empty() {
            return Err(BoxError::from_static_str(
                "certificate authority chain cannot be empty",
            ));
        }
        validate_certificate_authority_key(&certificate_chain[0], &private_key)?;
        for (index, certificate) in certificate_chain.iter().enumerate() {
            use rama_core::error::ErrorContext as _;
            let (_, parsed) = x509_parser::parse_x509_certificate(certificate.as_ref())
                .context("parse certificate authority chain")?;
            if index == 0 {
                let is_ca = parsed
                    .basic_constraints()
                    .context("parse CA basic constraints")?
                    .is_some_and(|extension| extension.value.ca);
                if !is_ca {
                    return Err(BoxError::from_static_str(
                        "issuing certificate must have CA basic constraints",
                    ));
                }
                let can_sign = parsed
                    .key_usage()
                    .context("parse CA key usage")?
                    .is_some_and(|extension| extension.value.key_cert_sign());
                if !can_sign {
                    return Err(BoxError::from_static_str(
                        "issuing certificate must permit certificate signing",
                    ));
                }
            }
            if let Some(parent) = certificate_chain.get(index + 1) {
                let (_, parent) = x509_parser::parse_x509_certificate(parent.as_ref())
                    .context("parse parent certificate authority")?;
                if parsed.issuer() != parent.subject() {
                    return Err(BoxError::from_static_str(
                        "certificate authority chain is not ordered issuer-first",
                    ));
                }
            }
        }
        Ok(Self {
            certificate_chain,
            private_key,
        })
    }

    pub fn generate(config: SelfSignedCaConfig) -> Result<Self, BoxError> {
        generate_certificate_authority(config)
    }

    #[must_use]
    pub fn certificate_chain(&self) -> &[CertificateDer<'static>] {
        &self.certificate_chain
    }

    #[must_use]
    pub fn private_key(&self) -> &PrivateKeyDer<'static> {
        &self.private_key
    }

    #[must_use]
    pub fn into_parts(self) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        (self.certificate_chain, self.private_key)
    }

    pub fn issue_leaf(
        &self,
        request: LeafCertRequest,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), BoxError> {
        issue_certificate_authority_leaf(self, request)
    }
}

#[cfg(feature = "boring")]
fn validate_certificate_authority_key(
    certificate: &CertificateDer<'_>,
    private_key: &PrivateKeyDer<'_>,
) -> Result<(), BoxError> {
    boring::validate_certificate_authority_key(certificate, private_key)
}

#[cfg(all(not(feature = "boring"), any(feature = "aws-lc", feature = "ring")))]
fn validate_certificate_authority_key(
    certificate: &CertificateDer<'_>,
    private_key: &PrivateKeyDer<'_>,
) -> Result<(), BoxError> {
    rcgen::validate_certificate_authority_key(certificate, private_key)
}

#[cfg(not(any(feature = "boring", feature = "aws-lc", feature = "ring")))]
fn validate_certificate_authority_key(
    _certificate: &CertificateDer<'_>,
    _private_key: &PrivateKeyDer<'_>,
) -> Result<(), BoxError> {
    Ok(())
}

impl Clone for CertificateAuthorityData {
    fn clone(&self) -> Self {
        Self {
            certificate_chain: self.certificate_chain.clone(),
            private_key: self.private_key.clone_key(),
        }
    }
}

/// Compute the SHA-256 digest of the certificate's `SubjectPublicKeyInfo`.
///
/// This is the industry-standard TLS pin input, usually exchanged in the
/// `sha256/<base64 digest>` format.
pub fn spki_sha256(certificate: &CertificateDer<'_>) -> Result<[u8; 32], BoxError> {
    use rama_core::error::ErrorContext as _;
    use sha2::Digest as _;
    use x509_parser::prelude::FromDer as _;

    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(certificate.as_ref())
        .context("parse x509 certificate for spki digest")?;
    Ok(sha2::Sha256::digest(cert.public_key().raw).into())
}

#[cfg(feature = "boring")]
pub fn generate_server_auth(
    config: GeneratedServerAuthConfig,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), BoxError> {
    boring::generate_server_auth(config)
}

#[cfg(all(not(feature = "boring"), any(feature = "aws-lc", feature = "ring")))]
pub fn generate_server_auth(
    config: GeneratedServerAuthConfig,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), BoxError> {
    rcgen::generate_server_auth(config)
}

#[cfg(not(any(feature = "boring", feature = "aws-lc", feature = "ring")))]
pub fn generate_server_auth(
    _config: GeneratedServerAuthConfig,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), BoxError> {
    use rama_core::error::BoxErrorExt;

    Err(BoxError::from_static_str(
        "enable one of the rama-crypto cert providers (boring, aws-lc, ring) to generate server auth",
    ))
}

#[cfg(feature = "boring")]
pub fn generate_certificate_authority(
    config: SelfSignedCaConfig,
) -> Result<CertificateAuthorityData, BoxError> {
    boring::generate_certificate_authority(config)
}

#[cfg(all(not(feature = "boring"), any(feature = "aws-lc", feature = "ring")))]
pub fn generate_certificate_authority(
    config: SelfSignedCaConfig,
) -> Result<CertificateAuthorityData, BoxError> {
    rcgen::generate_certificate_authority(config)
}

#[cfg(not(any(feature = "boring", feature = "aws-lc", feature = "ring")))]
pub fn generate_certificate_authority(
    _config: SelfSignedCaConfig,
) -> Result<CertificateAuthorityData, BoxError> {
    Err(BoxError::from_static_str(
        "enable one of the rama-crypto cert providers to generate a certificate authority",
    ))
}

#[cfg(feature = "boring")]
pub fn issue_certificate_authority_leaf(
    ca: &CertificateAuthorityData,
    request: LeafCertRequest,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), BoxError> {
    boring::issue_certificate_authority_leaf(ca, request)
}

#[cfg(all(not(feature = "boring"), any(feature = "aws-lc", feature = "ring")))]
pub fn issue_certificate_authority_leaf(
    ca: &CertificateAuthorityData,
    request: LeafCertRequest,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), BoxError> {
    rcgen::issue_certificate_authority_leaf(ca, request)
}

#[cfg(not(any(feature = "boring", feature = "aws-lc", feature = "ring")))]
pub fn issue_certificate_authority_leaf(
    _ca: &CertificateAuthorityData,
    _request: LeafCertRequest,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), BoxError> {
    Err(BoxError::from_static_str(
        "enable one of the rama-crypto cert providers to issue a leaf certificate",
    ))
}

#[cfg(test)]
mod spki_tests {
    use super::*;
    use base64::{Engine as _, prelude::BASE64_STANDARD};

    const EXAMPLE_COM_CRT_B64: &str = "MIIE3DCCAsSgAwIBAgIJAN4TBpLFs4VhMA0GCSqGSIb3DQEBCwUAMBYxFDASBgNVBAMMC2V4YW1wbGUuY29tMB4XDTI0MTIwOTIwMDUxN1oXDTM0MTIwNzIwMDUxN1owFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC14A6yHqrF+5+VPljtBd9vgjTQxBCqQ7Af/7cNlFtZjOKmXz0bOCfZRjaxNNjjveztFH+VhRpH/JyM7Qd7R0FX84IyH4Z9a58jgKW/l/YM1Q4Y50WGpM9Sk5p9Q8xTWIoZPrjvh6zV4PKef87LxxqoO9QXv34d5g7dsQLbSwJ93SeggH0E5e1VvP1DW0kvu1BF6rsmF5eTyK/VNg/el9mGyMbcyhBKTpTyVT2FQYRFuZtHXHRnAocCdv887c/TsYVDffTwv7peVoOotO0twKn0SMdtybiNJyDEdcgw2bFbQu7oV/95cBurpxePzED31E64QI8emTvZ62L/c5QvP0OY3x2CSb5ctd6z7wWTJ8wkl7N8+y7Xgn1aAAfki4rWk5qfWAO3BNZo/TGyiWeoNttJ+NddfwI3+h6phK7X56vRhYSqwSnxWyQYlTJAnFQb7TMEP/k9ov2S9MzLTURLLeNiiXjvkOxi+12HzhlTNgk3X49y9f8PLxkNw37TghunAl4OvA+LdslSayFMmZbx9fm+6ZGkjcsDYnf1Mff+aoCkkUcAFg5DQFDkmvu08mJL2D+9I9OK/Yvn/qXWjhVdWLJ/k5hrQmLIs1KbQtlGvvYeC7kHY3yBK+3wt/Cnx9qwhOPJcufuEChiMcVcseGAZJhUT7gQM22v9jb9QZfhihGMpQIDAQABoy0wKzApBgNVHREEIjAgggtleGFtcGxlLmNvbYILZXhhbXBsZS5jb22HBAoAAAEwDQYJKoZIhvcNAQELBQADggIBAJBG9KcH0FG7xn2u4SA4nlwaP/v2ZWZlOwjVjHEQJF7AGaEZFVofzLoRncVnQs14Xr3SGstIBG/P30LC4zHO4Lhz0M+g/lbXhrDjTJLNX7ZNv2ZJj+6XBysJK2IuZX14YCtxhwFCuPBK1cxPDkP4nZm4u5tozLHPtZEHc4kGVQflurkTVmfhJMi5ndAOevXVgfAHRbHfh6x1kNZWDpybiPeeBvZOjRoxecsD7LA54knsSFCQe6zQRlfBUUD+RDI/ggDi3XnKdDHEkLZCH3/db4CcneyzzVkaNcvpOS6ZT6akDLmR8qAglTrADdsnNVzyWzNbBhXQEFoygY3F2rVQndTLoEFGMx7U2d3Fz8sVN/F2SzBYxtrwgj5rQC8tOhHZPVgQLXu6NRRZHEQgypDtGP0H4SUNcGb1Lw27E43KSIT9CpY8Z3SG34G4bYGfpdMN3wtoXG7BtrdmInNWiT+ygh+iJCSaSsAWtaPRnx/9uGLwUNVjzVxJhxGKBbf1hJ5g1x3zMeL73wrsiY6RBa6tWx9SHbRoq8htbkQAnP0tMOavGiTApFquBYDe2gYbuq5jh4yTbNyuxR4WW6m6Bvj7YhUREXQnTDonUwHzw2P29T95z52aPb5PaZYHgg4S26zRV+/Dc8E3oLkjgCyaDuQO4uUpmtT8ssTolIFNr2QUzD12";

    #[test]
    fn spki_sha256_matches_openssl_pin() {
        let der = BASE64_STANDARD.decode(EXAMPLE_COM_CRT_B64).unwrap();
        let digest = spki_sha256(&CertificateDer::from(der)).unwrap();
        assert_eq!(
            BASE64_STANDARD.encode(digest),
            "xg6kqyS+uaJikboVvZPxNOYXMD3XPakJAakHSfGau/M="
        );
    }

    #[test]
    fn spki_sha256_rejects_invalid_der() {
        spki_sha256(&CertificateDer::from(vec![1, 2, 3])).unwrap_err();
    }
}

#[cfg(all(test, any(feature = "boring", feature = "aws-lc", feature = "ring")))]
mod tests {
    use super::*;
    use x509_parser::prelude::*;

    #[expect(clippy::expect_used)]
    fn parse_certificate<'a>(der: &'a CertificateDer<'_>) -> X509Certificate<'a> {
        X509Certificate::from_der(der.as_ref())
            .expect("parse certificate DER")
            .1
    }

    #[test]
    fn genuine_self_signed_leaf_has_no_ca_certificate() {
        let (chain, _key) = generate_server_auth(GeneratedServerAuthConfig::SelfSignedLeaf(
            LeafCertRequest::new(Domain::from_static("self-signed.rama.test")),
        ))
        .expect("generate self-signed leaf");
        assert_eq!(chain.len(), 1);
        let leaf = parse_certificate(&chain[0]);
        assert_eq!(leaf.subject(), leaf.issuer());
        assert!(
            !leaf
                .basic_constraints()
                .expect("basic constraints")
                .is_some_and(|extension| extension.value.ca)
        );
    }

    #[test]
    fn existing_ca_issues_configured_ip_leaf_in_one_call() {
        let mut ca_validity = SelfSignedCaConfig::default().validity;
        ca_validity.not_before_skew = Duration::from_secs(120);
        let ca = CertificateAuthorityData::generate(SelfSignedCaConfig {
            subject: CertificateSubject {
                organisation_name: Some("Rama Issuer".to_owned()),
                common_name: Some("Rama test CA".to_owned()),
            },
            validity: ca_validity,
            ..Default::default()
        })
        .expect("generate CA");
        let lifetime = Duration::from_secs(365 * 24 * 60 * 60);
        let (chain, _key) = ca
            .issue_leaf(LeafCertRequest {
                config: LeafCertConfig {
                    subject: CertificateSubject {
                        common_name: Some("descriptive leaf label".to_owned()),
                        ..Default::default()
                    },
                    validity: CertificateValidity::new(lifetime, Duration::from_secs(120)),
                    key_kind: CertificateKeyKind::EcP384,
                },
                identities: vec![CertificateIdentity::Ip(
                    std::net::Ipv4Addr::LOCALHOST.into(),
                )],
            })
            .expect("issue leaf");

        assert_eq!(chain.len(), ca.certificate_chain.len() + 1);
        let leaf = parse_certificate(&chain[0]);
        let issuer = parse_certificate(&chain[1]);
        assert_eq!(leaf.issuer(), issuer.subject());
        assert_eq!(
            leaf.validity().not_after.timestamp() - leaf.validity().not_before.timestamp(),
            i64::try_from(lifetime.as_secs()).unwrap()
        );
        assert_eq!(
            leaf.subject()
                .iter_organization()
                .next()
                .and_then(|entry| entry.as_str().ok()),
            Some("Rama Issuer")
        );
        let san = leaf
            .subject_alternative_name()
            .expect("parse SAN")
            .expect("SAN present");
        assert!(san.value.general_names.iter().any(|name| {
            matches!(name, GeneralName::IPAddress(bytes) if *bytes == [127, 0, 0, 1])
        }));
    }

    #[test]
    fn certificate_authority_rejects_mismatched_private_key() {
        let first = CertificateAuthorityData::generate(SelfSignedCaConfig::default())
            .expect("generate first CA");
        let second = CertificateAuthorityData::generate(SelfSignedCaConfig::default())
            .expect("generate second CA");
        CertificateAuthorityData::try_new(first.certificate_chain, second.private_key)
            .expect_err("mismatched key must fail");
    }

    #[test]
    fn generated_leaf_san_covers_dns_names_and_ip_addresses() {
        let leaf = LeafCertRequest {
            config: LeafCertConfig {
                subject: CertificateSubject {
                    common_name: Some("display label, not an identity".to_owned()),
                    ..Default::default()
                },
                ..Default::default()
            },
            identities: vec![
                CertificateIdentity::Dns(Domain::from_static("primary.rama.test")),
                CertificateIdentity::Dns(Domain::from_static("alt-one.rama.test")),
                CertificateIdentity::Dns(Domain::from_static("alt-two.rama.test")),
                CertificateIdentity::Ip(std::net::Ipv4Addr::LOCALHOST.into()),
                CertificateIdentity::Ip(std::net::Ipv4Addr::new(127, 0, 0, 2).into()),
                CertificateIdentity::Ip(std::net::Ipv6Addr::LOCALHOST.into()),
            ],
        };
        let (chain, _key) = generate_server_auth(GeneratedServerAuthConfig::GeneratedCa {
            ca: SelfSignedCaConfig::default(),
            leaf,
        })
        .expect("generate server auth");

        let (_, cert) =
            X509Certificate::from_der(chain[0].as_ref()).expect("parse leaf certificate DER");
        let mut dns = Vec::new();
        let mut ips = Vec::new();
        for ext in cert.extensions() {
            if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
                for gn in &san.general_names {
                    match gn {
                        GeneralName::DNSName(name) => dns.push((*name).to_owned()),
                        GeneralName::IPAddress(ip) => ips.push(ip.to_vec()),
                        _ => {}
                    }
                }
            }
        }

        for expected in [
            "primary.rama.test",
            "alt-one.rama.test",
            "alt-two.rama.test",
        ] {
            assert!(
                dns.iter().any(|n| n == expected),
                "leaf SAN must contain {expected}; got {dns:?}"
            );
        }
        assert!(
            !dns.iter()
                .any(|name| name == "display label, not an identity"),
            "commonName must not be copied into SAN"
        );
        assert!(
            ips.contains(&vec![127, 0, 0, 1]),
            "missing IPv4 SAN: {ips:?}"
        );
        assert!(
            ips.contains(&vec![127, 0, 0, 2]),
            "numeric domain must be an IPv4 SAN: {ips:?}"
        );
        assert!(
            ips.contains(&std::net::Ipv6Addr::LOCALHOST.octets().to_vec()),
            "missing IPv6 SAN: {ips:?}"
        );
    }
}
