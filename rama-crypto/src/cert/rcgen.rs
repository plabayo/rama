//! rcgen-backed self-signed certificate generation (feature `aws-lc` / `ring`).

use super::{SelfSignedData, SelfSignedKeyKind};
use crate::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rama_core::error::{BoxError, ErrorContext};
use rama_net::address::Domain;
use time::{Duration, OffsetDateTime};

/// Map a [`SelfSignedKeyKind`] to the rcgen signature algorithm used for both
/// the CA and the leaf key pair.
///
/// EC P-256/P-384 and Ed25519 are honored exactly. Two cases are backend-limited
/// (use the `boring` provider for precise control):
/// - RSA maps to `PKCS_RSA_SHA256`; the exact bit-size is decided by rcgen, and
///   RSA *generation* is only supported by the aws-lc backend (not ring).
/// - P-521 is only available with the aws-lc backend; on ring it falls back to
///   P-384 (ring has no P-521 support).
fn signature_algorithm(kind: SelfSignedKeyKind) -> &'static rcgen::SignatureAlgorithm {
    match kind {
        SelfSignedKeyKind::EcP256 => &rcgen::PKCS_ECDSA_P256_SHA256,
        SelfSignedKeyKind::EcP384 => &rcgen::PKCS_ECDSA_P384_SHA384,
        #[cfg(feature = "aws-lc")]
        SelfSignedKeyKind::EcP521 => &rcgen::PKCS_ECDSA_P521_SHA512,
        #[cfg(not(feature = "aws-lc"))]
        SelfSignedKeyKind::EcP521 => &rcgen::PKCS_ECDSA_P384_SHA384,
        SelfSignedKeyKind::Ed25519 => &rcgen::PKCS_ED25519,
        SelfSignedKeyKind::Rsa2048 | SelfSignedKeyKind::Rsa4096 => &rcgen::PKCS_RSA_SHA256,
    }
}

pub fn self_signed_server_auth(
    data: SelfSignedData,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), BoxError> {
    let alg = signature_algorithm(data.key_kind);
    let now = OffsetDateTime::now_utc();
    let org = data
        .organisation_name
        .clone()
        .unwrap_or_else(|| "Anonymous".to_owned());
    let common_name = data
        .common_name
        .clone()
        .unwrap_or_else(|| Domain::from_static("localhost"));

    // CA cert: self-signed issuer, 20 year validity (matches the boring provider).
    let ca_key_pair =
        rcgen::KeyPair::generate_for(alg).context("self-signed: generate ca key pair")?;
    let mut ca_params =
        rcgen::CertificateParams::new(Vec::new()).context("self-signed: create ca params")?;
    ca_params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, org.clone());
    if data.common_name.is_some() {
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, common_name.as_str());
    }
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    ca_params.not_before = now;
    ca_params.not_after = now + Duration::days(365 * 20);
    let ca_cert = ca_params
        .self_signed(&ca_key_pair)
        .context("self-signed: create ca cert")?;

    // Leaf cert: valid for the common name plus any extra SANs, 90 day validity.
    let mut sans: Vec<String> = vec![common_name.as_str().to_owned()];
    for extra_san in data.subject_alternative_names.into_iter().flatten() {
        if extra_san != common_name {
            sans.push(extra_san.as_str().to_owned());
        }
    }
    let server_key_pair =
        rcgen::KeyPair::generate_for(alg).context("self-signed: create server key pair")?;
    let mut server_ee_params =
        rcgen::CertificateParams::new(sans).context("self-signed: create server EE params")?;
    server_ee_params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, org);
    server_ee_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name.as_str());
    server_ee_params.is_ca = rcgen::IsCa::NoCa;
    server_ee_params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::ContentCommitment,
        rcgen::KeyUsagePurpose::KeyEncipherment,
    ];
    server_ee_params.not_before = now;
    server_ee_params.not_after = now + Duration::days(90);
    let server_cert = server_ee_params
        .signed_by(
            &server_key_pair,
            &rcgen::Issuer::new(ca_params, ca_key_pair),
        )
        .context("self-signed: sign server cert")?;

    let server_ca_cert_der: CertificateDer = ca_cert.into();
    let server_cert_der: CertificateDer = server_cert.into();
    let server_key_der = PrivatePkcs8KeyDer::from(server_key_pair.serialize_der());

    Ok((
        vec![server_cert_der, server_ca_cert_der],
        PrivatePkcs8KeyDer::from(server_key_der.secret_pkcs8_der().to_owned()).into(),
    ))
}
