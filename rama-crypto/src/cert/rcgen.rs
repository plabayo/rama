//! rcgen-backed certificate generation (feature `aws-lc` / `ring`).

use super::{
    CertificateAuthorityData, CertificateIdentity, CertificateKeyKind, CertificateSubject,
    CertificateValidity, GeneratedServerAuthConfig, LeafCertRequest, SelfSignedCaConfig,
};
use crate::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rama_core::error::{BoxError, BoxErrorExt as _, ErrorContext};
use rcgen::PublicKeyData as _;
use time::{Duration, OffsetDateTime};

pub(super) fn validate_certificate_authority_key(
    certificate: &CertificateDer<'_>,
    private_key: &PrivateKeyDer<'_>,
) -> Result<(), BoxError> {
    let key = rcgen::KeyPair::try_from(private_key).context("parse CA private key")?;
    let (_, certificate) = x509_parser::parse_x509_certificate(certificate.as_ref())
        .context("parse CA certificate")?;
    if key.subject_public_key_info() != certificate.public_key().raw {
        return Err(BoxError::from_static_str(
            "certificate authority private key does not match its certificate",
        ));
    }
    Ok(())
}

#[cfg(not(feature = "boring"))]
pub(super) fn validate_certificate_authority_chain(
    certificate_chain: &[CertificateDer<'_>],
) -> Result<(), BoxError> {
    for pair in certificate_chain.windows(2) {
        let (_, child) = x509_parser::parse_x509_certificate(pair[0].as_ref())
            .context("parse child CA certificate")?;
        let (_, parent) = x509_parser::parse_x509_certificate(pair[1].as_ref())
            .context("parse parent CA certificate")?;
        child
            .verify_signature(Some(parent.public_key()))
            .context("verify child CA certificate signature")?;
    }
    Ok(())
}

fn signature_algorithm(
    kind: CertificateKeyKind,
) -> Result<&'static rcgen::SignatureAlgorithm, BoxError> {
    match kind {
        CertificateKeyKind::EcP256 => Ok(&rcgen::PKCS_ECDSA_P256_SHA256),
        CertificateKeyKind::EcP384 => Ok(&rcgen::PKCS_ECDSA_P384_SHA384),
        #[cfg(feature = "aws-lc")]
        CertificateKeyKind::EcP521 => Ok(&rcgen::PKCS_ECDSA_P521_SHA512),
        #[cfg(not(feature = "aws-lc"))]
        CertificateKeyKind::EcP521 => Err(BoxError::from_static_str(
            "EC P-521 key generation requires the aws-lc certificate provider",
        )),
        CertificateKeyKind::Ed25519 => Ok(&rcgen::PKCS_ED25519),
        CertificateKeyKind::Rsa2048 | CertificateKeyKind::Rsa4096 => Ok(&rcgen::PKCS_RSA_SHA256),
    }
}

fn generate_key(kind: CertificateKeyKind) -> Result<rcgen::KeyPair, BoxError> {
    #[cfg(feature = "aws-lc")]
    match kind {
        CertificateKeyKind::Rsa2048 => {
            return rcgen::KeyPair::generate_rsa_for(
                &rcgen::PKCS_RSA_SHA256,
                rcgen::RsaKeySize::_2048,
            )
            .context("generate RSA-2048 key pair");
        }
        CertificateKeyKind::Rsa4096 => {
            return rcgen::KeyPair::generate_rsa_for(
                &rcgen::PKCS_RSA_SHA256,
                rcgen::RsaKeySize::_4096,
            )
            .context("generate RSA-4096 key pair");
        }
        _ => {}
    }
    #[cfg(not(feature = "aws-lc"))]
    if matches!(
        kind,
        CertificateKeyKind::Rsa2048 | CertificateKeyKind::Rsa4096
    ) {
        return Err(BoxError::from_static_str(
            "RSA key generation requires the aws-lc or boring certificate provider",
        ));
    }
    rcgen::KeyPair::generate_for(signature_algorithm(kind)?)
        .context("generate certificate key pair")
}

fn duration(value: std::time::Duration, name: &'static str) -> Result<Duration, BoxError> {
    let seconds =
        i64::try_from(value.as_secs()).context("certificate duration exceeds i64 seconds")?;
    if seconds == 0 && value.subsec_nanos() == 0 {
        return Err(BoxError::from_static_str(name));
    }
    Ok(Duration::seconds(seconds) + Duration::nanoseconds(i64::from(value.subsec_nanos())))
}

fn validity_bounds(
    validity: CertificateValidity,
) -> Result<(OffsetDateTime, OffsetDateTime), BoxError> {
    let now = OffsetDateTime::now_utc();
    let skew =
        duration(validity.not_before_skew, "invalid zero clock skew").unwrap_or(Duration::ZERO);
    let lifetime = duration(validity.lifetime, "certificate lifetime must be non-zero")?;
    let not_before = now - skew;
    Ok((not_before, not_before + lifetime))
}

fn apply_subject(params: &mut rcgen::CertificateParams, subject: &CertificateSubject) {
    if let Some(value) = subject.organisation_name.as_ref() {
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, value.clone());
    }
    if let Some(value) = subject.common_name.as_ref() {
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, value.clone());
    }
}

fn leaf_params(request: &LeafCertRequest) -> Result<rcgen::CertificateParams, BoxError> {
    if request.identities.is_empty() {
        return Err(BoxError::from_static_str(
            "server leaf certificate requires at least one DNS or IP identity",
        ));
    }

    let mut params = rcgen::CertificateParams::new(Vec::new())
        .context("certificate leaf: create certificate parameters")?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    for identity in &request.identities {
        let san = match identity {
            CertificateIdentity::Dns(domain) => rcgen::SanType::DnsName(
                domain
                    .as_str()
                    .try_into()
                    .context("certificate leaf: encode DNS SAN")?,
            ),
            CertificateIdentity::Ip(ip) => rcgen::SanType::IpAddress(*ip),
        };
        if !params.subject_alt_names.contains(&san) {
            params.subject_alt_names.push(san);
        }
    }
    apply_subject(&mut params, &request.config.subject);
    params.is_ca = rcgen::IsCa::NoCa;
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    if matches!(
        request.config.key_kind,
        CertificateKeyKind::Rsa2048 | CertificateKeyKind::Rsa4096
    ) {
        params
            .key_usages
            .push(rcgen::KeyUsagePurpose::KeyEncipherment);
    }
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let (not_before, not_after) = validity_bounds(request.config.validity)?;
    params.not_before = not_before;
    params.not_after = not_after;
    Ok(params)
}

fn ca_params(config: &SelfSignedCaConfig) -> Result<rcgen::CertificateParams, BoxError> {
    let mut params = rcgen::CertificateParams::new(Vec::new())
        .context("certificate authority: create certificate parameters")?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    apply_subject(&mut params, &config.subject);
    if config.subject.organisation_name.is_none() && config.subject.common_name.is_none() {
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "Anonymous");
    }
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let (not_before, not_after) = validity_bounds(config.validity)?;
    params.not_before = not_before;
    params.not_after = not_after;
    Ok(params)
}

fn inherit_ca_organisation(ca: &CertificateDer<'_>, request: &mut LeafCertRequest) {
    if request.config.subject.organisation_name.is_some() {
        return;
    }
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(ca.as_ref()) else {
        return;
    };
    request.config.subject.organisation_name = cert
        .subject()
        .iter_organization()
        .find_map(|entry| entry.as_str().ok().map(ToOwned::to_owned));
}

fn constrain_validity_to_ca(
    ca: &CertificateDer<'_>,
    params: &mut rcgen::CertificateParams,
) -> Result<(), BoxError> {
    let (_, cert) = x509_parser::parse_x509_certificate(ca.as_ref())
        .context("certificate authority: parse validity")?;
    let ca_not_before = OffsetDateTime::from_unix_timestamp(cert.validity().not_before.timestamp())
        .context("certificate authority: parse notBefore")?;
    let ca_not_after = OffsetDateTime::from_unix_timestamp(cert.validity().not_after.timestamp())
        .context("certificate authority: parse notAfter")?;
    params.not_before = params.not_before.max(ca_not_before);
    params.not_after = params.not_after.min(ca_not_after);
    if params.not_before >= params.not_after {
        return Err(BoxError::from_static_str(
            "certificate authority validity cannot contain requested leaf validity",
        ));
    }
    Ok(())
}

pub fn generate_server_auth(
    config: GeneratedServerAuthConfig,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), BoxError> {
    match config {
        GeneratedServerAuthConfig::SelfSignedLeaf(mut request) => {
            if request.config.subject.organisation_name.is_none()
                && request.config.subject.common_name.is_none()
            {
                request.config.subject.organisation_name = Some("Anonymous".to_owned());
            }
            let key = generate_key(request.config.key_kind)
                .context("self-signed leaf: generate key pair")?;
            let cert = leaf_params(&request)?
                .self_signed(&key)
                .context("self-signed leaf: generate certificate")?;
            Ok((
                vec![cert.into()],
                PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            ))
        }
        GeneratedServerAuthConfig::GeneratedCa { ca, leaf } => {
            let ca = generate_certificate_authority(ca)?;
            issue_certificate_authority_leaf(&ca, leaf)
        }
    }
}

#[expect(clippy::needless_pass_by_value)]
pub fn generate_certificate_authority(
    config: SelfSignedCaConfig,
) -> Result<CertificateAuthorityData, BoxError> {
    let key = generate_key(config.key_kind).context("certificate authority: generate key pair")?;
    let cert = ca_params(&config)?
        .self_signed(&key)
        .context("certificate authority: generate self-signed certificate")?;
    CertificateAuthorityData::try_new(
        vec![cert.into()],
        PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
    )
}

pub fn issue_certificate_authority_leaf(
    ca: &CertificateAuthorityData,
    mut request: LeafCertRequest,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), BoxError> {
    let issuer_cert = ca
        .certificate_chain
        .first()
        .ok_or_else(|| BoxError::from_static_str("certificate authority chain cannot be empty"))?;
    inherit_ca_organisation(issuer_cert, &mut request);
    validate_certificate_authority_key(issuer_cert, &ca.private_key)?;

    let issuer_key = rcgen::KeyPair::try_from(&ca.private_key)
        .context("certificate authority: parse issuer private key")?;
    let issuer = rcgen::Issuer::from_ca_cert_der(issuer_cert, issuer_key)
        .context("certificate authority: parse issuer certificate")?;
    let leaf_key =
        generate_key(request.config.key_kind).context("certificate leaf: generate key pair")?;
    let mut params = leaf_params(&request)?;
    constrain_validity_to_ca(issuer_cert, &mut params)?;
    let leaf = params
        .signed_by(&leaf_key, &issuer)
        .context("certificate leaf: sign with certificate authority")?;

    let mut chain = Vec::with_capacity(ca.certificate_chain.len() + 1);
    chain.push(leaf.into());
    chain.extend(ca.certificate_chain.iter().cloned());
    Ok((
        chain,
        PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_preserves_subsecond_precision() {
        assert_eq!(
            duration(std::time::Duration::from_millis(1_500), "invalid").unwrap(),
            Duration::milliseconds(1_500)
        );
        assert_eq!(
            duration(std::time::Duration::from_nanos(1), "invalid").unwrap(),
            Duration::nanoseconds(1)
        );
    }

    #[test]
    fn validity_bounds_backdate_the_start() {
        let before = OffsetDateTime::now_utc();
        let (not_before, not_after) = validity_bounds(CertificateValidity::new(
            std::time::Duration::from_millis(1_500),
            std::time::Duration::from_secs(2),
        ))
        .unwrap();
        let after = OffsetDateTime::now_utc();

        assert_eq!(not_after - not_before, Duration::milliseconds(1_500));
        assert!(not_before >= before - Duration::seconds(2));
        assert!(not_before <= after - Duration::seconds(2));
    }
}
