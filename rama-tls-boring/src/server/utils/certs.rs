use crate::core::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    dsa::Dsa,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{Id, PKey, Private},
    rand::rand_bytes,
    rsa::Rsa,
    x509::{
        X509, X509NameBuilder, X509Ref,
        extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier},
    },
};
use rama_boring::x509::extension::{AuthorityKeyIdentifier, SubjectAlternativeName};
use rama_core::error::{BoxError, ErrorContext};
use rama_core::telemetry::tracing;
use rama_net::{address::Domain, tls::server::SelfSignedData};

/// Generate a server cert for the [`SelfSignedData`] using the given CA Cert + Key.
///
/// In most cases you probably want more refined configuration and controls,
/// so in general we recommend to not use this utility outside of experimental or testing purposes.
pub fn self_signed_server_auth_gen_cert(
    data: &SelfSignedData,
    ca_cert: &X509,
    ca_privkey: &PKey<Private>,
) -> Result<(X509, PKey<Private>), BoxError> {
    let rsa = Rsa::generate(4096).context("generate 4096 RSA key")?;
    let privkey = PKey::from_rsa(rsa).context("create private key from 4096 RSA key")?;

    let common_name = data
        .common_name
        .clone()
        .unwrap_or(Domain::from_static("localhost"));

    let mut x509_name = X509NameBuilder::new().context("create x509 name builder")?;
    x509_name
        .append_entry_by_nid(
            Nid::ORGANIZATIONNAME,
            data.organisation_name.as_deref().unwrap_or("Anonymous"),
        )
        .context("append organisation name to x509 name builder")?;
    for subject_alt_name in data.subject_alternative_names.iter().flatten() {
        x509_name
            .append_entry_by_nid(Nid::SUBJECT_ALT_NAME, subject_alt_name.as_ref())
            .context("append subject alt name to x509 name builder")?;
    }
    x509_name
        .append_entry_by_nid(Nid::COMMONNAME, common_name.as_str())
        .context("append common name to x509 name builder")?;
    let x509_name = x509_name.build();

    let mut cert_builder = X509::builder().context("create x509 (cert) builder")?;
    cert_builder
        .set_version(2)
        .context("x509 cert builder: set version = 2")?;
    let serial_number = {
        let mut serial = BigNum::new().context("x509 cert builder: create big num (serial")?;
        serial
            .rand(159, MsbOption::MAYBE_ZERO, false)
            .context("x509 cert builder: randomise serial number (big num)")?;
        serial
            .to_asn1_integer()
            .context("x509 cert builder: convert serial to ASN1 integer")?
    };
    cert_builder
        .set_serial_number(&serial_number)
        .context("x509 cert builder: set serial number")?;
    cert_builder
        .set_issuer_name(ca_cert.subject_name())
        .context("x509 cert builder: set issuer name")?;
    cert_builder
        .set_pubkey(&privkey)
        .context("x509 cert builder: set pub key")?;
    cert_builder
        .set_subject_name(&x509_name)
        .context("x509 cert builder: set subject name")?;
    cert_builder
        .set_pubkey(&privkey)
        .context("x509 cert builder: set public key using private key (ref)")?;
    let not_before =
        Asn1Time::days_from_now(0).context("x509 cert builder: create ASN1Time for today")?;
    cert_builder
        .set_not_before(&not_before)
        .context("x509 cert builder: set not before to today")?;
    let not_after = Asn1Time::days_from_now(90)
        .context("x509 cert builder: create ASN1Time for 90 days in future")?;
    cert_builder
        .set_not_after(&not_after)
        .context("x509 cert builder: set not after to 90 days in future")?;

    cert_builder
        .append_extension(
            BasicConstraints::new()
                .build()
                .context("x509 cert builder: build basic constraints")?
                .as_ref(),
        )
        .context("x509 cert builder: add basic constraints as x509 extension")?;
    cert_builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .non_repudiation()
                .digital_signature()
                .key_encipherment()
                .build()
                .context("x509 cert builder: create key usage")?
                .as_ref(),
        )
        .context("x509 cert builder: add key usage x509 extension")?;

    let mut subject_alt_name = SubjectAlternativeName::new();
    subject_alt_name.dns(common_name.as_str());
    let subject_alt_name = subject_alt_name
        .build(&cert_builder.x509v3_context(Some(ca_cert), None))
        .context("x509 cert builder: build subject alt name")?;

    cert_builder
        .append_extension(subject_alt_name.as_ref())
        .context("x509 cert builder: add subject alt name")?;

    let subject_key_identifier = SubjectKeyIdentifier::new()
        .build(&cert_builder.x509v3_context(Some(ca_cert), None))
        .context("x509 cert builder: build subject key id")?;
    cert_builder
        .append_extension(subject_key_identifier.as_ref())
        .context("x509 cert builder: add subject key id x509 extension")?;

    let auth_key_identifier = AuthorityKeyIdentifier::new()
        .keyid(false)
        .issuer(false)
        .build(&cert_builder.x509v3_context(Some(ca_cert), None))
        .context("x509 cert builder: build auth key id")?;
    cert_builder
        .append_extension(auth_key_identifier.as_ref())
        .context("x509 cert builder: set auth key id extension")?;

    cert_builder
        .sign(ca_privkey, MessageDigest::sha256())
        .context("x509 cert builder: sign cert")?;

    let cert = cert_builder.build();

    Ok((cert, privkey))
}

/// Generate a mirrored server certificate based on a source certificate.
///
/// The generated certificate mirrors identity data from `source_cert` (subject and SAN, when
/// present), but is signed by the provided `ca_cert` + `ca_privkey`.
pub fn self_signed_server_auth_mirror_cert(
    source_cert: &X509Ref,
    ca_cert: &X509,
    ca_privkey: &PKey<Private>,
) -> Result<(X509, PKey<Private>), BoxError> {
    let source_pubkey = source_cert
        .public_key()
        .context("x509 cert builder: read source public key")?;
    let privkey = match source_pubkey.id() {
        Id::RSA | Id::RSAPSS => {
            let bits = source_pubkey.bits().max(2048);
            let rsa =
                Rsa::generate(bits).with_context(|| format!("generate {bits}-bit RSA key"))?;
            PKey::from_rsa(rsa)
                .with_context(|| format!("create private key from {bits}-bit RSA key"))?
        }
        Id::EC => {
            let source_ec_key = source_pubkey
                .ec_key()
                .context("x509 cert builder: read source EC key")?;
            let source_curve = source_ec_key
                .group()
                .curve_name()
                .context("x509 cert builder: source EC key has unnamed curve")?;
            let group = EcGroup::from_curve_name(source_curve)
                .context("x509 cert builder: create mirrored EC group")?;
            let ec_key =
                EcKey::generate(&group).context("x509 cert builder: generate mirrored EC key")?;
            PKey::from_ec_key(ec_key)
                .context("x509 cert builder: create private key from EC key")?
        }
        Id::DSA => {
            let bits = source_pubkey.bits().max(2048);
            let dsa =
                Dsa::generate(bits).with_context(|| format!("generate {bits}-bit DSA key"))?;
            PKey::from_dsa(dsa)
                .with_context(|| format!("create private key from {bits}-bit DSA key"))?
        }
        Id::ED25519 => {
            let mut key = [0_u8; 32];
            rand_bytes(&mut key).context("generate Ed25519 private key bytes")?;
            PKey::from_ed25519_private_key(&key)
                .context("create private key from Ed25519 key bytes")?
        }
        Id::X25519 => {
            let mut key = [0_u8; 32];
            rand_bytes(&mut key).context("generate X25519 private key bytes")?;
            PKey::from_x25519_private_key(&key)
                .context("create private key from X25519 key bytes")?
        }
        other => {
            tracing::debug!(
                key_type = ?other,
                "source certificate key type not mirror-supported yet; falling back to RSA-2048"
            );
            let rsa = Rsa::generate(2048).context("generate fallback 2048 RSA key")?;
            PKey::from_rsa(rsa).context("create private key from fallback 2048 RSA key")?
        }
    };

    let mut cert_builder = X509::builder().context("create x509 (cert) builder")?;
    cert_builder
        .set_version(2)
        .context("x509 cert builder: set version = 2")?;
    let serial_number = {
        let mut serial = BigNum::new().context("x509 cert builder: create big num (serial")?;
        serial
            .rand(159, MsbOption::MAYBE_ZERO, false)
            .context("x509 cert builder: randomise serial number (big num)")?;
        serial
            .to_asn1_integer()
            .context("x509 cert builder: convert serial to ASN1 integer")?
    };
    cert_builder
        .set_serial_number(&serial_number)
        .context("x509 cert builder: set serial number")?;
    cert_builder
        .set_issuer_name(ca_cert.subject_name())
        .context("x509 cert builder: set issuer name from CA")?;
    cert_builder
        .set_subject_name(source_cert.subject_name())
        .context("x509 cert builder: set mirrored subject name")?;
    cert_builder
        .set_pubkey(&privkey)
        .context("x509 cert builder: set public key using generated private key (ref)")?;

    cert_builder
        .set_not_before(source_cert.not_before())
        .context("x509 cert builder: mirror source not-before")?;
    cert_builder
        .set_not_after(source_cert.not_after())
        .context("x509 cert builder: mirror source not-after")?;

    for source_ext in source_cert.extensions() {
        let ext_nid = source_ext.object().nid();
        if ext_nid == Nid::SUBJECT_KEY_IDENTIFIER || ext_nid == Nid::AUTHORITY_KEY_IDENTIFIER {
            tracing::trace!(
                ?ext_nid,
                "skip source key identifier extension (will regenerate)"
            );
            continue;
        }

        cert_builder
            .append_extension_der_payload(
                source_ext.object(),
                source_ext.critical(),
                source_ext.data().as_slice(),
            )
            .context("x509 cert builder: append mirrored source extension")?;
    }

    let subject_key_identifier = SubjectKeyIdentifier::new()
        .build(&cert_builder.x509v3_context(Some(ca_cert), None))
        .context("x509 cert builder: build mirrored subject key identifier")?;
    cert_builder
        .append_extension(subject_key_identifier.as_ref())
        .context("x509 cert builder: append mirrored subject key identifier")?;

    let auth_key_identifier = AuthorityKeyIdentifier::new()
        .keyid(false)
        .issuer(false)
        .build(&cert_builder.x509v3_context(Some(ca_cert), None))
        .context("x509 cert builder: build mirrored authority key identifier")?;
    cert_builder
        .append_extension(auth_key_identifier.as_ref())
        .context("x509 cert builder: append mirrored authority key identifier")?;

    cert_builder
        .sign(ca_privkey, MessageDigest::sha256())
        .context("x509 cert builder: sign mirrored cert")?;

    Ok((cert_builder.build(), privkey))
}

/// Generate a self-signed server CA from the given [`SelfSignedData`].
///
/// This should not be used in production but mostly for experimental / testing purposes.
pub fn self_signed_server_auth_gen_ca(
    data: &SelfSignedData,
) -> Result<(X509, PKey<Private>), BoxError> {
    let rsa = Rsa::generate(4096).context("generate 4096 RSA key")?;
    let privkey = PKey::from_rsa(rsa).context("create private key from 4096 RSA key")?;

    let mut x509_name = X509NameBuilder::new().context("create x509 name builder")?;
    x509_name
        .append_entry_by_nid(
            Nid::ORGANIZATIONNAME,
            data.organisation_name.as_deref().unwrap_or("Anonymous"),
        )
        .context("append organisation name to x509 name builder")?;
    for subject_alt_name in data.subject_alternative_names.iter().flatten() {
        x509_name
            .append_entry_by_nid(Nid::SUBJECT_ALT_NAME, subject_alt_name.as_ref())
            .context("append subject alt name to x509 name builder")?;
    }

    if let Some(cn) = data.common_name.as_ref() {
        x509_name
            .append_entry_by_nid(Nid::COMMONNAME, cn.as_str())
            .context("append common name to x509 name builder")?;
    }

    let x509_name = x509_name.build();

    let mut ca_cert_builder = X509::builder().context("create x509 (cert) builder")?;
    ca_cert_builder
        .set_version(2)
        .context("x509 cert builder: set version = 2")?;
    let serial_number = {
        let mut serial = BigNum::new().context("x509 cert builder: create big num (serial")?;
        serial
            .rand(159, MsbOption::MAYBE_ZERO, false)
            .context("x509 cert builder: randomise serial number (big num)")?;
        serial
            .to_asn1_integer()
            .context("x509 cert builder: convert serial to ASN1 integer")?
    };
    ca_cert_builder
        .set_serial_number(&serial_number)
        .context("x509 cert builder: set serial number")?;
    ca_cert_builder
        .set_subject_name(&x509_name)
        .context("x509 cert builder: set subject name")?;
    ca_cert_builder
        .set_issuer_name(&x509_name)
        .context("x509 cert builder: set issuer (self-signed")?;
    ca_cert_builder
        .set_pubkey(&privkey)
        .context("x509 cert builder: set public key using private key (ref)")?;
    let not_before =
        Asn1Time::days_from_now(0).context("x509 cert builder: create ASN1Time for today")?;
    ca_cert_builder
        .set_not_before(&not_before)
        .context("x509 cert builder: set not before to today")?;
    let not_after = Asn1Time::days_from_now(365 * 20)
        .context("x509 cert builder: create ASN1Time for 20 years in future")?;
    ca_cert_builder
        .set_not_after(&not_after)
        .context("x509 cert builder: set not after to 20 years in future")?;

    ca_cert_builder
        .append_extension(
            BasicConstraints::new()
                .critical()
                .ca()
                .build()
                .context("x509 cert builder: build basic constraints")?
                .as_ref(),
        )
        .context("x509 cert builder: add basic constraints as x509 extension")?;
    ca_cert_builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .context("x509 cert builder: create key usage")?
                .as_ref(),
        )
        .context("x509 cert builder: add key usage x509 extension")?;

    let subject_key_identifier = SubjectKeyIdentifier::new()
        .build(&ca_cert_builder.x509v3_context(None, None))
        .context("x509 cert builder: build subject key id")?;
    ca_cert_builder
        .append_extension(subject_key_identifier.as_ref())
        .context("x509 cert builder: add subject key id x509 extension")?;

    ca_cert_builder
        .sign(&privkey, MessageDigest::sha256())
        .context("x509 cert builder: sign cert")?;

    let cert = ca_cert_builder.build();

    Ok((cert, privkey))
}

#[cfg(test)]
#[path = "./certs_tests.rs"]
mod certs_tests;
