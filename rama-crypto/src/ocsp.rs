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
fn oid_ocsp_nonce() -> ObjectIdentifier {
    ObjectIdentifier::from_slice(&[1, 3, 6, 1, 5, 5, 7, 48, 1, 2])
}
fn oid_ad_ocsp() -> ObjectIdentifier {
    ObjectIdentifier::from_slice(&[1, 3, 6, 1, 5, 5, 7, 48, 1])
}

/// DER of an `AuthorityInfoAccessSyntax` extension value with a single
/// `id-ad-ocsp` responder URI, for embedding as the `1.3.6.1.5.5.7.1.1`
/// extension on a re-signed leaf.
#[must_use]
pub fn authority_info_access_ocsp_der(uri: &str) -> Vec<u8> {
    yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_sequence(|w| {
                w.next().write_oid(&oid_ad_ocsp());
                // accessLocation: uniformResourceIdentifier [6] IA5String
                w.next().write_tagged_implicit(Tag::context(6), |w| {
                    w.write_bytes(uri.as_bytes());
                });
            });
        });
    })
}

/// DER of the `sha1` CertID `hashAlgorithm` (`AlgorithmIdentifier { sha1, NULL }`),
/// for callers building a `CertID` without an inbound request to echo (e.g. a
/// stapled `good` response).
#[must_use]
pub fn sha1_hash_algorithm_der() -> Vec<u8> {
    yasna::construct_der(|w| {
        w.write_sequence(|w| {
            w.next().write_oid(&oid_sha1());
            w.next().write_null();
        });
    })
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
/// All fields are caller-computed so this crate needs no hash backend. When
/// answering a request, set `hash_algorithm_der` to the request's verbatim
/// `hashAlgorithm` and the hashes to the request's values, so the response
/// `CertID` matches byte-for-byte; for a stapled response use
/// [`sha1_hash_algorithm_der`] with SHA-1 hashes.
#[derive(Debug, Clone, Copy)]
pub struct OcspCertId<'a> {
    /// DER of the issuer's subject `Name` (the full `SEQUENCE` TLV), used for
    /// the `responderID` byName field.
    pub issuer_name_der: &'a [u8],
    /// The `hashAlgorithm` `AlgorithmIdentifier` as full DER.
    pub hash_algorithm_der: &'a [u8],
    /// Hash over the issuer `Name` (the `issuerNameHash`).
    pub issuer_name_hash: &'a [u8],
    /// Hash over the issuer's `subjectPublicKey` BIT STRING value
    /// (the `issuerKeyHash`).
    pub issuer_key_hash: &'a [u8],
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
/// `nonce`, when set, is echoed verbatim as the `id-pkix-ocsp-nonce`
/// `responseExtensions` value (the bytes a request's matching `extnValue`
/// carried); pass the value [`parse_ocsp_request`] returned.
pub fn build_ocsp_response(
    cert: &OcspCertId<'_>,
    status: OcspCertStatus,
    produced_at: SystemTime,
    validity: Duration,
    nonce: Option<&[u8]>,
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
                        w.next().write_der(cert.hash_algorithm_der);
                        w.next().write_bytes(cert.issuer_name_hash);
                        w.next().write_bytes(cert.issuer_key_hash);
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
            // responseExtensions [1] EXPLICIT Extensions — nonce echo only.
            if let Some(nonce) = nonce {
                w.next().write_tagged(Tag::context(1), |w| {
                    w.write_sequence(|w| {
                        w.next().write_sequence(|w| {
                            w.next().write_oid(&oid_ocsp_nonce());
                            w.next().write_bytes(nonce);
                        });
                    });
                });
            }
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

/// A single `CertID` extracted from an OCSP request.
#[derive(Debug, Clone)]
pub struct OcspRequestCertId {
    /// The `hashAlgorithm` `AlgorithmIdentifier` as full DER, to echo verbatim
    /// so the response `CertID` matches the request.
    pub hash_algorithm_der: Vec<u8>,
    /// `issuerNameHash` value.
    pub issuer_name_hash: Vec<u8>,
    /// `issuerKeyHash` value.
    pub issuer_key_hash: Vec<u8>,
    /// `serialNumber` as a big-endian unsigned magnitude.
    pub serial: Vec<u8>,
}

/// A parsed OCSP request: the requested `CertID`s and the optional nonce.
#[derive(Debug, Clone, Default)]
pub struct OcspRequestInfo {
    /// One entry per `Request` in the `requestList`.
    pub certs: Vec<OcspRequestCertId>,
    /// `id-pkix-ocsp-nonce` `extnValue` contents, for verbatim echo via
    /// [`build_ocsp_response`].
    pub nonce: Option<Vec<u8>>,
}

/// Parse a DER `OCSPRequest` (RFC 6960 §4.1.1).
///
/// Returns each requested `CertID` and the optional nonce. `version`,
/// `requestorName`, the optional signature and per-request extensions are
/// accepted but ignored.
pub fn parse_ocsp_request(der: &[u8]) -> Result<OcspRequestInfo, BoxError> {
    yasna::parse_der(der, |r| {
        r.read_sequence(|r| {
            let info = r.next().read_sequence(|r| {
                // version [0] EXPLICIT DEFAULT v1
                r.read_optional(|r| r.read_tagged(Tag::context(0), |r| r.read_i64()))?;
                // requestorName [1] EXPLICIT GeneralName
                r.read_optional(|r| r.read_tagged(Tag::context(1), |r| r.read_der()))?;
                // requestList ::= SEQUENCE OF Request
                let mut certs = Vec::new();
                r.next().read_sequence_of(|r| {
                    r.read_sequence(|r| {
                        let cert = r.next().read_sequence(|r| {
                            let hash_algorithm_der = r.next().read_der()?;
                            let issuer_name_hash = r.next().read_bytes()?;
                            let issuer_key_hash = r.next().read_bytes()?;
                            let (serial, _positive) = r.next().read_bigint_bytes()?;
                            Ok(OcspRequestCertId {
                                hash_algorithm_der,
                                issuer_name_hash,
                                issuer_key_hash,
                                serial,
                            })
                        })?;
                        // singleRequestExtensions [0] EXPLICIT
                        r.read_optional(|r| r.read_tagged(Tag::context(0), |r| r.read_der()))?;
                        certs.push(cert);
                        Ok(())
                    })
                })?;
                // requestExtensions [2] EXPLICIT Extensions
                let nonce = r
                    .read_optional(|r| {
                        r.read_tagged(Tag::context(2), |r| {
                            let mut nonce = None;
                            r.read_sequence_of(|r| {
                                r.read_sequence(|r| {
                                    let oid = r.next().read_oid()?;
                                    r.read_optional(|r| r.read_bool())?;
                                    let value = r.next().read_bytes()?;
                                    if oid == oid_ocsp_nonce() {
                                        nonce = Some(value);
                                    }
                                    Ok(())
                                })
                            })?;
                            Ok(nonce)
                        })
                    })?
                    .flatten();
                Ok(OcspRequestInfo { certs, nonce })
            })?;
            // optionalSignature [0] EXPLICIT
            r.read_optional(|r| r.read_tagged(Tag::context(0), |r| r.read_der()))?;
            Ok(info)
        })
    })
    .map_err(|e| BoxError::from(format!("ocsp: parse request: {e}")))
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
            hash_algorithm_der: &sha1_hash_algorithm_der(),
            issuer_name_hash: &[0xAA; 20],
            issuer_key_hash: &[0xBB; 20],
            serial: &[0x12, 0x34, 0x56],
        };

        let mut signed_tbs: Vec<u8> = Vec::new();
        let der = build_ocsp_response(
            &cert,
            OcspCertStatus::Good,
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000),
            Duration::from_hours(24 * 7),
            None,
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

    /// Build a minimal `OCSPRequest` with one SHA-1 `CertID`, optionally a
    /// version field and an `id-pkix-ocsp-nonce` extension.
    fn build_request(version: bool, nonce: Option<&[u8]>) -> Vec<u8> {
        let algid = sha1_hash_algorithm_der();
        yasna::construct_der(|w| {
            w.write_sequence(|w| {
                w.next().write_sequence(|w| {
                    if version {
                        w.next().write_tagged(Tag::context(0), |w| w.write_i64(0));
                    }
                    w.next().write_sequence(|w| {
                        w.next().write_sequence(|w| {
                            w.next().write_sequence(|w| {
                                w.next().write_der(&algid);
                                w.next().write_bytes(&[0xAA; 20]);
                                w.next().write_bytes(&[0xBB; 20]);
                                w.next().write_bigint_bytes(&[0x12, 0x34, 0x56], true);
                            });
                        });
                    });
                    if let Some(nonce) = nonce {
                        w.next().write_tagged(Tag::context(2), |w| {
                            w.write_sequence(|w| {
                                w.next().write_sequence(|w| {
                                    w.next().write_oid(&oid_ocsp_nonce());
                                    w.next().write_bytes(nonce);
                                });
                            });
                        });
                    }
                });
            });
        })
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn parses_minimal_request() {
        let info = parse_ocsp_request(&build_request(false, None)).expect("parse");
        assert_eq!(info.certs.len(), 1);
        let c = &info.certs[0];
        assert_eq!(c.hash_algorithm_der, sha1_hash_algorithm_der());
        assert_eq!(c.issuer_name_hash, vec![0xAA; 20]);
        assert_eq!(c.issuer_key_hash, vec![0xBB; 20]);
        assert_eq!(c.serial, vec![0x12, 0x34, 0x56]);
        assert!(info.nonce.is_none());
    }

    #[test]
    fn parses_request_with_version_and_nonce() {
        let nonce_value = yasna::construct_der(|w| w.write_bytes(&[1, 2, 3, 4, 5, 6, 7, 8]));
        let info = parse_ocsp_request(&build_request(true, Some(&nonce_value))).expect("parse");
        assert_eq!(info.certs.len(), 1);
        assert_eq!(info.nonce.as_deref(), Some(nonce_value.as_slice()));
    }

    /// A response built from a parsed request echoes the request's `CertID`
    /// (hashes + serial) and nonce verbatim.
    #[test]
    fn response_echoes_request_certid_and_nonce() {
        let nonce_value = yasna::construct_der(|w| w.write_bytes(&[9, 9, 9, 9]));
        let info = parse_ocsp_request(&build_request(true, Some(&nonce_value))).expect("parse");
        let c = &info.certs[0];
        let issuer = yasna::construct_der(|w| w.write_sequence(|_| {}));
        let cert = OcspCertId {
            issuer_name_der: &issuer,
            hash_algorithm_der: &c.hash_algorithm_der,
            issuer_name_hash: &c.issuer_name_hash,
            issuer_key_hash: &c.issuer_key_hash,
            serial: &c.serial,
        };
        let der = build_ocsp_response(
            &cert,
            OcspCertStatus::Good,
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000),
            Duration::from_hours(24),
            info.nonce.as_deref(),
            |_| Ok((OcspSignatureAlgorithm::EcdsaSha256, vec![0x00])),
        )
        .expect("build ocsp response");

        assert!(contains(&der, &[0xAA; 20]), "issuerNameHash echoed");
        assert!(contains(&der, &[0xBB; 20]), "issuerKeyHash echoed");
        assert!(contains(&der, &[0x12, 0x34, 0x56]), "serial echoed");
        assert!(contains(&der, &nonce_value), "nonce echoed");
    }

    #[test]
    fn aia_ocsp_carries_the_responder_uri() {
        let uri = "http://127.0.0.1:9999/ocsp/abc";
        let der = authority_info_access_ocsp_der(uri);
        let oid = yasna::parse_der(&der, |r| {
            r.read_sequence(|r| {
                r.next().read_sequence(|r| {
                    let oid = r.next().read_oid()?;
                    let _loc = r.next().read_der()?;
                    Ok(oid)
                })
            })
        })
        .expect("AIA structure");
        assert_eq!(oid, oid_ad_ocsp());
        assert!(contains(&der, uri.as_bytes()), "responder URI present");
    }
}
