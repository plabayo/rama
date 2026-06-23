//! Boring glue for signing a MITM CA CRL.
//!
//! The generic `CertificateList` assembly lives in [`rama_crypto::crl`]; this
//! module extracts the issuer name + authority key identifier from the CA
//! `X509` and signs the `tbsCertList` with the CA key.

use std::time::SystemTime;

use rama_boring::{
    hash::MessageDigest,
    pkey::{Id, PKeyRef, Private},
    sign::Signer,
    x509::X509Ref,
};
use rama_core::error::{BoxError, ErrorContext};
use rama_crypto::crl::{CrlParams, CrlSignatureAlgorithm, RevokedEntry, build_crl};

/// Build a DER `CertificateList` for the MITM CA (`ca_cert` + `ca_key`).
///
/// The CRL covers every leaf the CA issues; `revoked` is empty for the common
/// `good` case. The `authorityKeyIdentifier` comes from the CA's SKI (falling
/// back to a SHA-1 digest of its public key).
pub fn build_mitm_ca_crl(
    ca_cert: &X509Ref,
    ca_key: &PKeyRef<Private>,
    this_update: SystemTime,
    next_update: SystemTime,
    crl_number: u64,
    revoked: &[RevokedEntry<'_>],
) -> Result<Vec<u8>, BoxError> {
    let issuer_name_der = ca_cert
        .subject_name()
        .to_der()
        .context("crl: issuer subject name to DER")?;

    let authority_key_id = match ca_cert.subject_key_id() {
        Some(skid) => skid.as_slice().to_vec(),
        None => ca_cert
            .pubkey_digest(MessageDigest::sha1())
            .context("crl: hash CA key")?
            .as_ref()
            .to_vec(),
    };

    let alg = match ca_key.id() {
        Id::EC => CrlSignatureAlgorithm::EcdsaSha256,
        Id::RSA => CrlSignatureAlgorithm::RsaSha256,
        other => return Err(format!("crl: unsupported CA key type: {other:?}").into()),
    };

    let params = CrlParams {
        issuer_name_der: &issuer_name_der,
        authority_key_id: &authority_key_id,
        this_update,
        next_update,
        crl_number,
        revoked,
    };

    build_crl(&params, alg, |tbs| {
        let mut signer = Signer::new(MessageDigest::sha256(), ca_key).context("crl: new signer")?;
        signer
            .sign_oneshot_to_vec(tbs)
            .context("crl: sign tbsCertList")
    })
}
