//! Generic OCSP response builder (TLS-backend agnostic).
//!
//! Builds and DER-encodes an OCSP response asserting a single certificate's
//! status, signed by its issuer. Hashing and signing are supplied *by the
//! caller* (the TLS backend), so this module pulls in no crypto backend — it is
//! pure ASN.1 assembly on the `yasna` DER writer already in the dependency tree.
//!
//! BoringSSL (and others) can *staple* a pre-built OCSP response on the server
//! side but cannot *build* one — there is no responder/builder API. This is
//! that builder, kept generic so every TLS backend (`rama-tls-boring`,
//! `rama-tls-rustls`, …) can share it; only the cert/key/hash/sign glue lives
//! in the backend crate.
//!
//! Primary use: a MITM proxy stapling an issuer-signed `good` status onto a
//! re-signed leaf, so revocation-strict clients (e.g. cargo / schannel on
//! Windows) accept it inline without an external responder.

use std::time::{Duration, SystemTime};

use rama_core::error::{BoxError, ErrorContext};
use yasna::{
    Tag,
    models::{GeneralizedTime, ObjectIdentifier},
};

fn oid_sha1() -> ObjectIdentifier {
    ObjectIdentifier::from_slice(&[1, 3, 14, 3, 2, 26])
}
fn oid_ecdsa_sha256() -> ObjectIdentifier {
    ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 4, 3, 2])
}
fn oid_rsa_sha256() -> ObjectIdentifier {
    ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 1, 11])
}
fn oid_ocsp_basic() -> ObjectIdentifier {
    ObjectIdentifier::from_slice(&[1, 3, 6, 1, 5, 5, 7, 48, 1, 1])
}

/// Status to assert for the certificate. Only `Good` today; `Revoked` is the
/// seam for a future mode that mirrors an upstream's real revocation status.
#[derive(Debug, Clone, Copy)]
pub enum OcspCertStatus {
    /// The certificate is valid.
    Good,
}

/// Signature algorithm the caller used to sign the `tbsResponseData`.
#[derive(Debug, Clone, Copy)]
pub enum OcspSignatureAlgorithm {
    /// `ecdsa-with-SHA256` (1.2.840.10045.4.3.2) — parameters absent.
    EcdsaSha256,
    /// `sha256WithRSAEncryption` (1.2.840.113549.1.1.11) — NULL parameters.
    RsaSha256,
}

/// Identifies the certificate whose status is attested (RFC 6960 `CertID`).
///
/// All fields are caller-computed so this crate needs no hash backend; the
/// `*_sha1` hashes use the SHA-1 CertID algorithm clients expect.
#[derive(Debug, Clone, Copy)]
pub struct OcspCertId<'a> {
    /// DER of the issuer's subject `Name` (the full `SEQUENCE` TLV), used for
    /// the `responderID` byName field.
    pub issuer_name_der: &'a [u8],
    /// SHA-1 over the issuer `Name` (the `issuerNameHash`).
    pub issuer_name_sha1: &'a [u8],
    /// SHA-1 over the issuer's `subjectPublicKey` BIT STRING value
    /// (the `issuerKeyHash`).
    pub issuer_key_sha1: &'a [u8],
    /// The leaf's serial number as a big-endian unsigned magnitude.
    pub serial: &'a [u8],
}

/// Build a DER-encoded `OCSPResponse` attesting `cert`'s `status`.
///
/// `sign_tbs` signs the `tbsResponseData` DER with the issuer key and reports
/// which algorithm it used. `produced_at` sets `producedAt`/`thisUpdate`;
/// `nextUpdate` = `produced_at + validity`.
///
/// The public surface takes only `std` time types — `time::OffsetDateTime` is
/// an internal detail of the DER `GeneralizedTime` encoding.
pub fn build_ocsp_response(
    cert: &OcspCertId<'_>,
    status: OcspCertStatus,
    produced_at: SystemTime,
    validity: Duration,
    sign_tbs: impl FnOnce(&[u8]) -> Result<(OcspSignatureAlgorithm, Vec<u8>), BoxError>,
) -> Result<Vec<u8>, BoxError> {
    let OcspCertStatus::Good = status;

    // producedAt and thisUpdate are the same instant — encode it once.
    let produced = generalized_time(produced_at)?;
    let next_at = produced_at
        .checked_add(validity)
        .ok_or_else(|| BoxError::from("ocsp: nextUpdate overflow"))?;
    let next_update = generalized_time(next_at)?;

    // tbsResponseData (ResponseData) — exactly the bytes that get signed.
    // Borrow `cert`'s slices straight into the writer; no intermediate copies.
    let tbs_der = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            // version [0] DEFAULT v1 — omitted.
            // responderID ::= byName [1] EXPLICIT Name
            w.next()
                .write_tagged(Tag::context(1), |w| w.write_der(cert.issuer_name_der));
            // producedAt
            w.next().write_generalized_time(&produced);
            // responses ::= SEQUENCE OF SingleResponse (one entry)
            w.next().write_sequence(|w| {
                w.next().write_sequence(|w| {
                    // certID
                    w.next().write_sequence(|w| {
                        // hashAlgorithm = sha1, NULL params
                        w.next().write_sequence(|w| {
                            w.next().write_oid(&oid_sha1());
                            w.next().write_null();
                        });
                        w.next().write_bytes(cert.issuer_name_sha1);
                        w.next().write_bytes(cert.issuer_key_sha1);
                        w.next().write_bigint_bytes(cert.serial, true);
                    });
                    // certStatus ::= good [0] IMPLICIT NULL
                    w.next()
                        .write_tagged_implicit(Tag::context(0), |w| w.write_null());
                    // thisUpdate (same instant as producedAt)
                    w.next().write_generalized_time(&produced);
                    // nextUpdate [0] EXPLICIT GeneralizedTime
                    w.next()
                        .write_tagged(Tag::context(0), |w| w.write_generalized_time(&next_update));
                });
            });
        });
    });

    let (alg, signature) = sign_tbs(&tbs_der)?;

    // BasicOCSPResponse
    let basic_der = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_der(&tbs_der);
            // signatureAlgorithm
            w.next().write_sequence(|w| match alg {
                OcspSignatureAlgorithm::EcdsaSha256 => {
                    w.next().write_oid(&oid_ecdsa_sha256());
                }
                OcspSignatureAlgorithm::RsaSha256 => {
                    w.next().write_oid(&oid_rsa_sha256());
                    w.next().write_null();
                }
            });
            // signature BIT STRING (0 unused bits)
            w.next().write_bitvec_bytes(&signature, signature.len() * 8);
        });
    });

    // OCSPResponse
    let resp_der = yasna::construct_der(|w| {
        w.write_sequence(|w| {
            // responseStatus = successful (0)
            w.next().write_enum(0);
            // responseBytes [0] EXPLICIT ResponseBytes
            w.next().write_tagged(Tag::context(0), |w| {
                w.write_sequence(|w| {
                    w.next().write_oid(&oid_ocsp_basic());
                    w.next().write_bytes(&basic_der);
                });
            });
        });
    });

    Ok(resp_der)
}

/// Convert a `SystemTime` to a DER `GeneralizedTime`. `time::OffsetDateTime` is
/// used only here (internal); it never appears in the public API.
fn generalized_time(t: SystemTime) -> Result<GeneralizedTime, BoxError> {
    let secs = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .context("ocsp: timestamp before unix epoch")?
        .as_secs();
    let odt = time::OffsetDateTime::from_unix_timestamp(secs as i64)
        .map_err(|e| BoxError::from(format!("ocsp: invalid timestamp: {e}")))?;
    Ok(GeneralizedTime::from_datetime(odt))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The builder emits a well-formed `OCSPResponse`: `successful` status,
    /// `id-pkix-ocsp-basic` responseBytes wrapping a 3-element
    /// BasicOCSPResponse, and it feeds the caller a non-empty `tbsResponseData`
    /// to sign. Parsed back with yasna (no extra deps).
    #[test]
    fn builds_wellformed_ocsp_response() {
        let cert = OcspCertId {
            issuer_name_der: &yasna::construct_der(|w| {
                // a minimal Name: SEQUENCE {} (empty RDNSequence) — enough for shape.
                w.write_sequence(|_| {});
            }),
            issuer_name_sha1: &[0xAA; 20],
            issuer_key_sha1: &[0xBB; 20],
            serial: &[0x12, 0x34, 0x56],
        };

        let mut signed_tbs: Vec<u8> = Vec::new();
        let der = build_ocsp_response(
            &cert,
            OcspCertStatus::Good,
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000),
            Duration::from_hours(24 * 7),
            |tbs| {
                signed_tbs = tbs.to_vec();
                Ok((
                    OcspSignatureAlgorithm::EcdsaSha256,
                    vec![0xDE, 0xAD, 0xBE, 0xEF],
                ))
            },
        )
        .expect("build ocsp response");

        assert!(
            !signed_tbs.is_empty(),
            "tbsResponseData was handed to the signer"
        );

        // Parse the outer OCSPResponse: SEQUENCE { ENUMERATED, [0] { OID, OCTET STRING } }.
        let basic_der = yasna::parse_der(&der, |r| {
            r.read_sequence(|r| {
                let status = r.next().read_enum()?;
                assert_eq!(status, 0, "responseStatus successful");
                r.next().read_tagged(Tag::context(0), |r| {
                    r.read_sequence(|r| {
                        let oid = r.next().read_oid()?;
                        assert_eq!(oid, oid_ocsp_basic(), "responseType id-pkix-ocsp-basic");
                        r.next().read_bytes()
                    })
                })
            })
        })
        .expect("parse OCSPResponse");

        // Inner BasicOCSPResponse: SEQUENCE { tbs, sigAlg, signature }.
        yasna::parse_der(&basic_der, |r| {
            r.read_sequence(|r| {
                // tbsResponseData round-trips byte-for-byte with what we signed.
                let tbs = r.next().read_der()?;
                assert_eq!(tbs, signed_tbs, "embedded tbs == signed tbs");
                // signatureAlgorithm
                r.next().read_sequence(|r| {
                    let oid = r.next().read_oid()?;
                    assert_eq!(oid, oid_ecdsa_sha256());
                    Ok(())
                })?;
                // signature BIT STRING
                let (sig, _bits) = r.next().read_bitvec_bytes()?;
                assert_eq!(sig, vec![0xDE, 0xAD, 0xBE, 0xEF]);
                Ok(())
            })
        })
        .expect("parse BasicOCSPResponse");
    }
}
