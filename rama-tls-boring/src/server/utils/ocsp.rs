//! Boring glue for OCSP "good" stapling of MITM leaf certificates.
//!
//! The generic OCSP response assembly lives in [`rama_crypto::ocsp`]; this
//! module only adapts boring types: it extracts the CertID inputs from the
//! issuer/leaf `X509` (issuer Name DER + SHA-1 hashes + leaf serial) and signs
//! the `tbsResponseData` with the boring CA key. The DER it returns is fed to
//! `SslRef::set_ocsp_status` during the handshake.
//!
//! Why: a revocation-strict client (notably cargo / schannel on Windows with
//! `http.check-revoke=true`) hard-fails with `CRYPT_E_NO_REVOCATION_CHECK` when
//! a re-signed MITM leaf carries no revocation information. Because we are the
//! issuer, an issuer-signed `good` status the client already trusts resolves it
//! inline, without an external responder.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rama_boring::{
    asn1::Asn1Time,
    hash::{MessageDigest, hash},
    pkey::{Id, PKeyRef, Private},
    sign::Signer,
    x509::X509Ref,
};
use rama_core::error::{BoxError, ErrorContext};
use rama_crypto::ocsp::{OcspCertId, OcspSignatureAlgorithm, build_ocsp_response};

#[doc(inline)]
pub use rama_crypto::ocsp::OcspCertStatus as MitmLeafOcspStatus;

/// Backdate `producedAt`/`thisUpdate` to tolerate client clock skew.
const CLOCK_SKEW_BACKDATE: Duration = Duration::from_hours(1);
/// Floor on the derived validity, for the degenerate case of a leaf `notAfter`
/// at/before `producedAt` (shouldn't happen post egress handshake).
const MIN_VALIDITY: Duration = Duration::from_hours(1);

/// Build a DER-encoded OCSP response for `leaf`, signed by the MITM CA
/// (`issuer` + `issuer_key`), ready for `SslRef::set_ocsp_status`.
///
/// CertID uses SHA-1 (the algorithm clients compute for CertID matching) and
/// the response is signed directly by the issuer CA, so no delegated
/// OCSP-signing certificate is needed.
pub fn build_mitm_leaf_ocsp_response(
    leaf: &X509Ref,
    issuer: &X509Ref,
    issuer_key: &PKeyRef<Private>,
    status: MitmLeafOcspStatus,
) -> Result<Vec<u8>, BoxError> {
    // CertID inputs, all from boring.
    let issuer_name_der = issuer
        .subject_name()
        .to_der()
        .context("ocsp: issuer subject name to DER")?;
    let issuer_name_sha1 =
        hash(MessageDigest::sha1(), &issuer_name_der).context("ocsp: hash issuer name")?;
    let issuer_key_sha1 = issuer
        .pubkey_digest(MessageDigest::sha1())
        .context("ocsp: hash issuer key")?;
    let serial = leaf
        .serial_number()
        .to_bn()
        .context("ocsp: leaf serial to bn")?
        .to_vec();

    let cert = OcspCertId {
        issuer_name_der: &issuer_name_der,
        issuer_name_sha1: issuer_name_sha1.as_ref(),
        issuer_key_sha1: issuer_key_sha1.as_ref(),
        serial: &serial,
    };

    let produced_at = SystemTime::now()
        .checked_sub(CLOCK_SKEW_BACKDATE)
        .unwrap_or_else(SystemTime::now);

    // nextUpdate = the leaf's own notAfter, so the staple never goes stale
    // before the cert it attests (independent of the issuer cache TTL).
    let validity = validity_until_not_after(leaf, produced_at)?;

    build_ocsp_response(&cert, status, produced_at, validity, |tbs| {
        sign_tbs(issuer_key, tbs)
    })
}

/// Window from `produced_at` to the leaf's `notAfter`, so the OCSP `nextUpdate`
/// lands on the cert's own expiry. Clamped to [`MIN_VALIDITY`] for the
/// degenerate near-/post-expiry case.
fn validity_until_not_after(leaf: &X509Ref, produced_at: SystemTime) -> Result<Duration, BoxError> {
    let produced_unix = produced_at
        .duration_since(UNIX_EPOCH)
        .context("ocsp: producedAt before unix epoch")?
        .as_secs();
    // `from_unix` takes a `time_t` (i32 on 32-bit platforms, i64 elsewhere);
    // infer the width via `try_into` so this builds on every target.
    let produced_unix = produced_unix
        .try_into()
        .context("ocsp: producedAt out of range for ASN1 time")?;
    let produced_asn1 =
        Asn1Time::from_unix(produced_unix).context("ocsp: producedAt to ASN1 time")?;
    let diff = produced_asn1
        .diff(leaf.not_after())
        .context("ocsp: diff producedAt..notAfter")?;
    let secs = i64::from(diff.days) * 86_400 + i64::from(diff.secs);
    Ok(if secs <= MIN_VALIDITY.as_secs() as i64 {
        MIN_VALIDITY
    } else {
        Duration::from_secs(secs as u64)
    })
}

/// Sign `tbs` with the CA key; SHA-256 based, algorithm chosen by key type.
fn sign_tbs(
    issuer_key: &PKeyRef<Private>,
    tbs: &[u8],
) -> Result<(OcspSignatureAlgorithm, Vec<u8>), BoxError> {
    let alg = match issuer_key.id() {
        Id::EC => OcspSignatureAlgorithm::EcdsaSha256,
        Id::RSA => OcspSignatureAlgorithm::RsaSha256,
        other => {
            return Err(format!("ocsp: unsupported CA key type for stapling: {other:?}").into());
        }
    };
    let mut signer =
        Signer::new(MessageDigest::sha256(), issuer_key).context("ocsp: new signer")?;
    let signature = signer
        .sign_oneshot_to_vec(tbs)
        .context("ocsp: sign tbsResponseData")?;
    Ok((alg, signature))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::utils::{self_signed_server_auth_gen_ca, self_signed_server_auth_gen_cert};
    use rama_boring::sign::Verifier;
    use rama_crypto::ocsp::OcspCertStatus;
    use rama_net::{address::Domain, tls::server::SelfSignedData};

    fn sample(common_name: &'static str) -> SelfSignedData {
        SelfSignedData {
            common_name: Some(Domain::from_static(common_name)),
            organisation_name: Some("Rama OCSP Test".to_owned()),
            ..Default::default()
        }
    }

    /// End-to-end through the boring glue: build a `good` response for a real
    /// CA+leaf and prove the CA's signature over the `tbsResponseData`
    /// verifies. The tbs + signature are captured via the sign closure (we
    /// drive `build_ocsp_response` directly so we don't need an OCSP parser to
    /// re-extract them).
    #[test]
    fn ocsp_tbs_signature_verifies_against_ca() {
        let (ca_cert, ca_key) =
            self_signed_server_auth_gen_ca(&sample("rama-mitm-test-ca.example")).expect("gen CA");
        let (leaf, _leaf_key) =
            self_signed_server_auth_gen_cert(&sample("example.com"), &ca_cert, &ca_key)
                .expect("gen leaf");

        let issuer_name_der = ca_cert.subject_name().to_der().expect("issuer name der");
        let issuer_name_sha1 =
            hash(MessageDigest::sha1(), &issuer_name_der).expect("hash issuer name");
        let issuer_key_sha1 = ca_cert
            .pubkey_digest(MessageDigest::sha1())
            .expect("hash issuer key");
        let serial = leaf.serial_number().to_bn().expect("serial bn").to_vec();
        assert_eq!(issuer_key_sha1.as_ref().len(), 20, "SHA-1 issuerKeyHash");

        let cert = OcspCertId {
            issuer_name_der: &issuer_name_der,
            issuer_name_sha1: issuer_name_sha1.as_ref(),
            issuer_key_sha1: issuer_key_sha1.as_ref(),
            serial: &serial,
        };

        let mut captured_tbs: Vec<u8> = Vec::new();
        let mut captured_sig: Vec<u8> = Vec::new();
        let der = build_ocsp_response(
            &cert,
            OcspCertStatus::Good,
            SystemTime::now(),
            Duration::from_hours(24 * 7),
            |tbs| {
                captured_tbs = tbs.to_vec();
                let (alg, sig) = sign_tbs(&ca_key, tbs)?;
                captured_sig = sig.clone();
                Ok((alg, sig))
            },
        )
        .expect("build ocsp response");

        assert!(!der.is_empty(), "produced a non-empty OCSP response");

        let ca_pub = ca_cert.public_key().expect("ca public key");
        let mut verifier = Verifier::new(MessageDigest::sha256(), &ca_pub).expect("verifier");
        verifier.update(&captured_tbs).expect("verifier update");
        assert!(
            verifier.verify(&captured_sig).expect("verify"),
            "the CA signature over tbsResponseData must verify against the CA key"
        );
    }
}
