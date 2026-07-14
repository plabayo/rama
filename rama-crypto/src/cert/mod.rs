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
//! enabled, [`self_signed_server_auth`] returns an error.

use crate::pki_types::{CertificateDer, PrivateKeyDer};
use rama_core::error::BoxError;
use rama_net::address::Domain;
use serde::{Deserialize, Serialize};

#[cfg(feature = "boring")]
#[cfg_attr(docsrs, doc(cfg(feature = "boring")))]
pub mod boring;

#[cfg(any(feature = "aws-lc", feature = "ring"))]
pub mod rcgen;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
/// Data used to configure the generation of a self-signed certificate.
///
/// How a certificate is created is out of scope for the TLS layer: this lives
/// in `rama-crypto` and produces concrete DER material that the TLS layer then
/// simply stores and serves.
pub struct SelfSignedData {
    /// name of the organisation
    pub organisation_name: Option<String>,
    /// common name (CN): server name protected by the certificate
    pub common_name: Option<Domain>,
    /// Subject Alternative Names (SAN) can be defined
    /// to create a cert which allows multiple hostnames or domains to be secured under one certificate.
    pub subject_alternative_names: Option<Vec<Domain>>,
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

/// Generate a self-signed server certificate (leaf signed by a generated CA).
///
/// Returns the certificate chain (`[leaf, ca]`) and the leaf private key, all
/// DER-encoded. The crypto provider is chosen at compile time by cargo feature
/// (see the [module docs](self)).
#[cfg(feature = "boring")]
pub fn self_signed_server_auth(
    data: SelfSignedData,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), BoxError> {
    boring::self_signed_server_auth(data)
}

/// Generate a self-signed server certificate (leaf signed by a generated CA).
///
/// See the [`boring`]-feature variant for full documentation.
#[cfg(all(not(feature = "boring"), any(feature = "aws-lc", feature = "ring")))]
pub fn self_signed_server_auth(
    data: SelfSignedData,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), BoxError> {
    rcgen::self_signed_server_auth(data)
}

/// Generate a self-signed server certificate.
///
/// No cert-generation provider is enabled; enable one of the `boring`,
/// `aws-lc`, or `ring` features.
#[cfg(not(any(feature = "boring", feature = "aws-lc", feature = "ring")))]
pub fn self_signed_server_auth(
    _data: SelfSignedData,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), BoxError> {
    use rama_core::error::BoxErrorExt;

    Err(BoxError::from_static_str(
        "enable one of the rama-crypto cert providers (boring, aws-lc, ring) to use self_signed_server_auth",
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

    #[test]
    fn self_signed_leaf_san_covers_common_name_and_extra_sans() {
        let data = SelfSignedData {
            common_name: Some(Domain::from_static("primary.rama.test")),
            subject_alternative_names: Some(vec![
                Domain::from_static("alt-one.rama.test"),
                Domain::from_static("alt-two.rama.test"),
            ]),
            ..Default::default()
        };
        let (chain, _key) = self_signed_server_auth(data).expect("generate self-signed");

        let (_, cert) =
            X509Certificate::from_der(chain[0].as_ref()).expect("parse leaf certificate DER");
        let mut dns = Vec::new();
        for ext in cert.extensions() {
            if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
                for gn in &san.general_names {
                    if let GeneralName::DNSName(name) = gn {
                        dns.push((*name).to_owned());
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
    }
}
