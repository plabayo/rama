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
