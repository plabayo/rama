use crate::core::{
    asn1::{Asn1Object, Asn1ObjectRef, Asn1Time},
    bn::{BigNum, MsbOption},
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{Id, PKey, PKeyRef, Private},
    rand::rand_bytes,
    rsa::Rsa,
    x509::{
        X509, X509Extension, X509NameBuilder, X509Ref,
        extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier},
    },
};
use rama_boring::x509::extension::{AuthorityKeyIdentifier, SubjectAlternativeName};
use rama_core::error::{BoxError, ErrorContext};
use rama_core::telemetry::tracing;
use rama_net::{
    address::Domain,
    tls::server::{SelfSignedData, SelfSignedKeyKind},
};

/// Build an `AuthorityKeyIdentifier` extension whose `keyIdentifier` is derived from
/// the CA's public key per RFC 5280 §4.2.1.2 method (1): SHA-1 of the SubjectPublicKey
/// BIT STRING contents. Used as a fallback when the CA certificate carries no SKI extension.
fn aki_from_ca_pubkey_keyid(ca_cert: &X509Ref) -> Result<X509Extension, BoxError> {
    let digest = ca_cert
        .pubkey_digest(MessageDigest::sha1())
        .context("compute SHA-1 of CA SubjectPublicKey BIT STRING")?;
    let keyid: &[u8] = &digest[..];
    debug_assert_eq!(keyid.len(), 20, "SHA-1 digest must be 20 bytes");

    // AuthorityKeyIdentifier ::= SEQUENCE { [0] IMPLICIT OCTET STRING keyIdentifier }
    let mut payload = Vec::with_capacity(4 + keyid.len());
    payload.push(0x30); // SEQUENCE
    payload.push((2 + keyid.len()) as u8);
    payload.push(0x80); // [0] IMPLICIT OCTET STRING
    payload.push(keyid.len() as u8);
    payload.extend_from_slice(keyid);

    // 2.5.29.35 = id-ce-authorityKeyIdentifier
    let aki_oid =
        Asn1Object::from_str("2.5.29.35").context("construct AuthorityKeyIdentifier OID object")?;
    X509Extension::from_der_payload(aki_oid.as_ref(), false, &payload)
        .context("build AuthorityKeyIdentifier extension from raw DER payload")
}

/// Message digest to use when signing a certificate with `key`.
///
/// - EdDSA (Ed25519 / Ed448) is a "pure" signature scheme: `X509_sign` must be
///   invoked with a NULL digest because the algorithm signs the message
///   directly instead of a prehash. Passing a real digest makes BoringSSL's
///   `EVP_DigestSignInit` fail.
/// - ECDSA pairs the digest to the curve strength (P-384 → SHA-384,
///   P-521 → SHA-512), per common practice / CA-Browser-Forum guidance; an
///   unnamed (explicit-parameter) curve falls back to SHA-256.
/// - Everything else (RSA, RSA-PSS, DSA) signs over SHA-256, as before.
fn signing_digest_for(key: &PKeyRef<Private>) -> MessageDigest {
    match key.id() {
        Id::ED25519 | Id::ED448 => {
            // SAFETY: a null `EVP_MD` is precisely what `X509_sign` expects for
            // EdDSA keys; BoringSSL reads it as "no prehash".
            unsafe { MessageDigest::from_ptr(std::ptr::null()) }
        }
        Id::EC => match key.ec_key().ok().and_then(|ec| ec.group().curve_name()) {
            Some(Nid::SECP521R1) => MessageDigest::sha512(),
            Some(Nid::SECP384R1) => MessageDigest::sha384(),
            _ => MessageDigest::sha256(),
        },
        _ => MessageDigest::sha256(),
    }
}

/// Generate a fresh private key of the requested [`SelfSignedKeyKind`].
fn generate_self_signed_key(kind: SelfSignedKeyKind) -> Result<PKey<Private>, BoxError> {
    fn ec(curve: Nid) -> Result<PKey<Private>, BoxError> {
        let group =
            EcGroup::from_curve_name(curve).context("create EC group for self-signed key")?;
        let ec_key = EcKey::generate(&group).context("generate EC key for self-signed key")?;
        PKey::from_ec_key(ec_key).context("create private key from generated EC key")
    }

    match kind {
        SelfSignedKeyKind::Rsa2048 => {
            let rsa = Rsa::generate(2048).context("generate 2048-bit RSA key")?;
            PKey::from_rsa(rsa).context("create private key from 2048-bit RSA key")
        }
        SelfSignedKeyKind::Rsa4096 => {
            let rsa = Rsa::generate(4096).context("generate 4096-bit RSA key")?;
            PKey::from_rsa(rsa).context("create private key from 4096-bit RSA key")
        }
        SelfSignedKeyKind::EcP256 => ec(Nid::X9_62_PRIME256V1),
        SelfSignedKeyKind::EcP384 => ec(Nid::SECP384R1),
        SelfSignedKeyKind::EcP521 => ec(Nid::SECP521R1),
        SelfSignedKeyKind::Ed25519 => {
            let mut seed = [0_u8; 32];
            rand_bytes(&mut seed).context("generate Ed25519 private key bytes")?;
            PKey::from_ed25519_private_key(&seed)
                .context("create private key from Ed25519 key bytes")
        }
    }
}

/// OID of the RFC 7633 TLS Feature extension (OCSP "must-staple").
const OID_TLS_FEATURE: &str = "1.3.6.1.5.5.7.1.24";
/// OID of the RFC 6962 embedded Signed Certificate Timestamp (SCT) list.
const OID_SCT_LIST: &str = "1.3.6.1.4.1.11129.2.4.2";

/// Canonical OID renderings of the extensions we strip by OID rather than by
/// [`Nid`] (rama-boring exposes no stable constant for these). Resolving them
/// once keeps the per-extension membership check cheap.
fn mirror_strip_oid_texts() -> Vec<String> {
    [OID_TLS_FEATURE, OID_SCT_LIST]
        .into_iter()
        .filter_map(|oid| Asn1Object::from_str(oid).ok().map(|obj| obj.to_string()))
        .collect()
}

/// Returns `true` when a source-certificate extension must NOT be mirrored onto
/// a leaf that we re-sign with our own MITM CA.
///
/// Two classes are stripped (see [`self_signed_server_auth_mirror_cert`]):
///
/// 1. Revocation / authority-info pointers bound to the *real* issuer — CRL
///    Distribution Points, Authority Information Access (OCSP responder +
///    caIssuers) and Freshest CRL (delta CRL). A leaf re-signed by our CA can
///    never be covered by those responders, so a client that follows them
///    (notably Windows schannel via `lsass.exe`) hits an issuer mismatch and
///    aborts the handshake with `CRYPT_E_REVOCATION_OFFLINE`. Both are OPTIONAL
///    and non-critical (RFC 5280 §4.2): with no pointer present, conformant
///    clients simply skip the revocation check, which is the correct behaviour
///    for a locally-trusted MITM CA.
///
/// 2. Assertions we cannot honour after re-signing — the RFC 7633 TLS Feature
///    extension ("must-staple") would force the client to *require* a stapled
///    OCSP response we never produce (handshake abort), and RFC 6962 embedded
///    SCTs are signed over the original `TBSCertificate` and become invalid the
///    instant we re-sign. These have no stable `Nid` constant, so they are
///    matched by canonical OID text, which is robust whether or not BoringSSL
///    knows the OID by name.
fn should_strip_mirrored_extension(
    ext_nid: Nid,
    ext_obj: &Asn1ObjectRef,
    strip_oid_texts: &[String],
) -> bool {
    if ext_nid == Nid::CRL_DISTRIBUTION_POINTS
        || ext_nid == Nid::INFO_ACCESS
        || ext_nid == Nid::FRESHEST_CRL
    {
        return true;
    }

    let ext_text = ext_obj.to_string();
    strip_oid_texts.contains(&ext_text)
}

/// Generate a server cert for the [`SelfSignedData`] using the given CA Cert + Key.
///
/// In most cases you probably want more refined configuration and controls,
/// so in general we recommend to not use this utility outside of experimental or testing purposes.
pub fn self_signed_server_auth_gen_cert(
    data: &SelfSignedData,
    ca_cert: &X509,
    ca_privkey: &PKey<Private>,
) -> Result<(X509, PKey<Private>), BoxError> {
    let privkey = generate_self_signed_key(data.key_kind)?;

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

    if ca_cert.subject_key_id().is_some() {
        let auth_key_identifier = AuthorityKeyIdentifier::new()
            .keyid(false)
            .issuer(false)
            .build(&cert_builder.x509v3_context(Some(ca_cert), None))
            .context("x509 cert builder: build auth key id")?;
        cert_builder
            .append_extension(auth_key_identifier.as_ref())
            .context("x509 cert builder: set auth key id extension")?;
    } else {
        let auth_key_identifier = aki_from_ca_pubkey_keyid(ca_cert)?;
        cert_builder
            .append_extension(auth_key_identifier.as_ref())
            .context("x509 cert builder: set derived auth key id extension")?;
    }

    cert_builder
        .sign(ca_privkey, signing_digest_for(ca_privkey))
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
    self_signed_server_auth_mirror_cert_with_extensions(source_cert, ca_cert, ca_privkey, &[])
}

/// Like [`self_signed_server_auth_mirror_cert`], additionally appending
/// `extra_extensions` (e.g. proxy-hosted CRL/OCSP revocation pointers) to the
/// re-signed leaf before signing.
pub fn self_signed_server_auth_mirror_cert_with_extensions(
    source_cert: &X509Ref,
    ca_cert: &X509,
    ca_privkey: &PKey<Private>,
    extra_extensions: &[X509Extension],
) -> Result<(X509, PKey<Private>), BoxError> {
    let source_pubkey = source_cert
        .public_key()
        .context("x509 cert builder: read source public key")?;
    let privkey = match source_pubkey.id() {
        // RSA-PSS leaves are mirrored as plain RSA (`rsaEncryption`) keys: the
        // leaf still works for the TLS handshake, but its SPKI algorithm OID is
        // not preserved, as rama-boring exposes no safe `id-RSASSA-PSS` key
        // constructor. This is a fidelity-only gap, not a functional one.
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
            // Generate on the source key's own group rather than going through
            // `curve_name()`, so explicit-parameter curves are mirrored too
            // instead of hard-failing the whole interception.
            let ec_key = EcKey::generate(source_ec_key.group())
                .context("x509 cert builder: generate mirrored EC key")?;
            PKey::from_ec_key(ec_key)
                .context("x509 cert builder: create private key from EC key")?
        }
        Id::ED25519 => {
            let mut key = [0_u8; 32];
            rand_bytes(&mut key).context("generate Ed25519 private key bytes")?;
            PKey::from_ed25519_private_key(&key)
                .context("create private key from Ed25519 key bytes")?
        }
        // Everything else — DSA, X25519/X448, Ed448, or anything exotic — cannot
        // serve as a TLS server-auth leaf key (key-agreement-only, disabled in
        // modern TLS, or not constructible here). Mirroring such a key would
        // yield a leaf the MITM server can never complete a handshake with, so
        // fall back to a universally functional RSA-2048 key instead.
        other => {
            tracing::debug!(
                key_type = ?other,
                "source cert key type cannot serve as a TLS leaf key; using RSA-2048 for the mirrored leaf"
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

    // Clamp the mirrored validity into the issuing CA's window so the leaf is
    // fully nested. A freshly-generated MITM CA starts later than the origin
    // (issued in the past), and a leaf that predates — or outlives — its issuer
    // is rejected by strict validators (CERT_E_VALIDITYPERIODNESTING), even
    // though Schannel tolerates it.
    let not_before = if source_cert.not_before() < ca_cert.not_before() {
        ca_cert.not_before()
    } else {
        source_cert.not_before()
    };
    let not_after = if source_cert.not_after() > ca_cert.not_after() {
        ca_cert.not_after()
    } else {
        source_cert.not_after()
    };
    cert_builder
        .set_not_before(not_before)
        .context("x509 cert builder: set mirrored not-before (clamped to CA)")?;
    cert_builder
        .set_not_after(not_after)
        .context("x509 cert builder: set mirrored not-after (clamped to CA)")?;

    let source_had_ski = source_cert.subject_key_id().is_some();
    let source_had_aki = source_cert.authority_key_id().is_some();

    let strip_oid_texts = mirror_strip_oid_texts();

    for source_ext in source_cert.extensions() {
        let ext_nid = source_ext.object().nid();
        if ext_nid == Nid::SUBJECT_KEY_IDENTIFIER || ext_nid == Nid::AUTHORITY_KEY_IDENTIFIER {
            tracing::trace!(
                ?ext_nid,
                "skip source key identifier extension (will regenerate if applicable)"
            );
            continue;
        }

        if should_strip_mirrored_extension(ext_nid, source_ext.object(), &strip_oid_texts) {
            tracing::trace!(
                ?ext_nid,
                "skip source extension invalid for a re-signed MITM leaf \
                 (issuer-bound revocation/authority pointer, or assertion we cannot honour)"
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

    if source_had_ski {
        let subject_key_identifier = SubjectKeyIdentifier::new()
            .build(&cert_builder.x509v3_context(Some(ca_cert), None))
            .context("x509 cert builder: build mirrored subject key identifier")?;
        cert_builder
            .append_extension(subject_key_identifier.as_ref())
            .context("x509 cert builder: append mirrored subject key identifier")?;
    }

    if source_had_aki {
        if ca_cert.subject_key_id().is_some() {
            let auth_key_identifier = AuthorityKeyIdentifier::new()
                .keyid(false)
                .issuer(false)
                .build(&cert_builder.x509v3_context(Some(ca_cert), None))
                .context("x509 cert builder: build mirrored authority key identifier")?;
            cert_builder
                .append_extension(auth_key_identifier.as_ref())
                .context("x509 cert builder: append mirrored authority key identifier")?;
        } else {
            let auth_key_identifier = aki_from_ca_pubkey_keyid(ca_cert)?;
            cert_builder
                .append_extension(auth_key_identifier.as_ref())
                .context("x509 cert builder: append derived mirrored authority key identifier")?;
        }
    }

    for ext in extra_extensions {
        cert_builder
            .append_extension(ext.as_ref())
            .context("x509 cert builder: append extra revocation extension")?;
    }

    cert_builder
        .sign(ca_privkey, signing_digest_for(ca_privkey))
        .context("x509 cert builder: sign mirrored cert")?;

    Ok((cert_builder.build(), privkey))
}

/// Generate a self-signed server CA from the given [`SelfSignedData`].
///
/// This should not be used in production but mostly for experimental / testing purposes.
pub fn self_signed_server_auth_gen_ca(
    data: &SelfSignedData,
) -> Result<(X509, PKey<Private>), BoxError> {
    let privkey = generate_self_signed_key(data.key_kind)?;

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
        .sign(&privkey, signing_digest_for(&privkey))
        .context("x509 cert builder: sign cert")?;

    let cert = ca_cert_builder.build();

    Ok((cert, privkey))
}

#[cfg(test)]
#[path = "./certs_tests.rs"]
mod certs_tests;
