use std::{fmt, sync::Arc};

use rama_boring::{
    pkey::{PKey, Private},
    x509::X509,
};
use rama_core::{error::BoxError, telemetry::tracing};
use rama_net::tls::server::SelfSignedData;
use rama_utils::collections::non_empty_vec;

use crate::server::utils::{MitmLeafOcspStatus, self_signed_server_auth_gen_ca};

use super::{BoringMitmCertIssuer, MitmIssuedCert};

#[derive(Clone)]
/// A [`BoringMitmCertIssuer`] which mirrors the original reference
/// using its internal (in-memory) CA crt/key pair to sign.
pub struct InMemoryBoringMitmCertIssuer {
    ca_crt: X509,
    ca_key: PKey<Private>,
}

impl fmt::Debug for InMemoryBoringMitmCertIssuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InMemoryBoringMitmCertIssuer")
            .field("ca_crt", &self.ca_crt)
            .field("ca_key", &"PKey<Private>")
            .finish()
    }
}

impl InMemoryBoringMitmCertIssuer {
    #[inline(always)]
    /// Create a new [`InMemoryBoringMitmCertIssuer`].
    #[must_use]
    pub fn new(ca_crt: X509, ca_key: PKey<Private>) -> Self {
        Self { ca_crt, ca_key }
    }

    #[inline(always)]
    /// Create a new [`InMemoryBoringMitmCertIssuer`] with self-signed CA using the given data.
    pub fn try_new_self_signed(data: &SelfSignedData) -> Result<Self, BoxError> {
        let (ca_cert, ca_privkey) = self_signed_server_auth_gen_ca(data)?;
        Ok(Self::new(ca_cert, ca_privkey))
    }
}

impl BoringMitmCertIssuer for InMemoryBoringMitmCertIssuer {
    type Error = BoxError;

    #[inline(always)]
    async fn issue_mitm_x509_cert(&self, original: X509) -> Result<MitmIssuedCert, Self::Error> {
        let (crt, key) = crate::server::utils::self_signed_server_auth_mirror_cert(
            &original,
            &self.ca_crt,
            &self.ca_key,
        )?;

        // OCSP staple: only when the upstream advertised OCSP (so we restore
        // parity with what a direct client could have checked) — and signed by
        // the MITM CA that just issued the leaf, i.e. the leaf's direct issuer,
        // which is what a client validates against (works for a root *or*
        // intermediate MITM CA). Best-effort: a failure must not block issuance.
        let ocsp_staple = if upstream_advertised_ocsp(&original) {
            match crate::server::utils::build_mitm_leaf_ocsp_response(
                &crt,
                &self.ca_crt,
                &self.ca_key,
                MitmLeafOcspStatus::Good,
            ) {
                Ok(der) => Some(Arc::from(der.into_boxed_slice())),
                Err(err) => {
                    tracing::debug!("mitm: OCSP staple generation skipped (build failed): {err}");
                    None
                }
            }
        } else {
            None
        };

        Ok(MitmIssuedCert {
            crt_chain: non_empty_vec![crt, self.ca_crt.clone()],
            key,
            ocsp_staple,
        })
    }
}

/// Whether the upstream certificate advertises an OCSP responder (AIA). We only
/// staple when it did, mirroring the origin's revocation posture rather than
/// fabricating status the origin never offered.
fn upstream_advertised_ocsp(original: &X509) -> bool {
    original
        .ocsp_responders()
        .map(|responders| !responders.is_empty())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_boring::{
        asn1::{Asn1Object, Asn1Time},
        bn::{BigNum, MsbOption},
        hash::{MessageDigest, hash},
        rsa::Rsa,
        sign::Verifier,
        ssl::{SslAcceptor, SslConnector, SslMethod, SslVerifyMode},
        x509::{X509, X509Builder, X509Extension, X509NameBuilder},
    };
    use rama_net::{
        address::Domain,
        tls::server::{SelfSignedData, SelfSignedKeyKind},
    };
    use tokio::io::duplex;
    use x509_cert::der::{Decode, Encode};
    use x509_ocsp::{BasicOcspResponse, CertStatus, OcspResponse, OcspResponseStatus};

    /// DER of `AuthorityInfoAccessSyntax` with a single `id-ad-ocsp`
    /// AccessDescription pointing at `uri` (short-form lengths; uri < 128 bytes).
    fn aia_ocsp_payload(uri: &[u8]) -> Vec<u8> {
        // accessLocation ::= GeneralName [6] IA5String (URI)
        let mut loc = vec![0x86, uri.len() as u8];
        loc.extend_from_slice(uri);
        // accessMethod ::= id-ad-ocsp OID (1.3.6.1.5.5.7.48.1)
        let oid = [0x06u8, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01];
        // AccessDescription ::= SEQUENCE { accessMethod, accessLocation }
        let mut ad = oid.to_vec();
        ad.extend_from_slice(&loc);
        let mut ad_seq = vec![0x30, ad.len() as u8];
        ad_seq.extend_from_slice(&ad);
        // AuthorityInfoAccessSyntax ::= SEQUENCE OF AccessDescription
        let mut aia = vec![0x30, ad_seq.len() as u8];
        aia.extend_from_slice(&ad_seq);
        aia
    }

    fn mitm_ca(key_kind: SelfSignedKeyKind) -> InMemoryBoringMitmCertIssuer {
        InMemoryBoringMitmCertIssuer::try_new_self_signed(&SelfSignedData {
            common_name: Some(Domain::from_static("rama-mitm-ca.example")),
            organisation_name: Some("Rama".to_owned()),
            key_kind,
            ..Default::default()
        })
        .expect("self-signed MITM CA")
    }

    /// Validate a stapled OCSP response the way a strict client does: parse it
    /// with a vetted parser (x509-ocsp), check it is `successful` + `good` for
    /// the right CertID (issuer name/key hashes + leaf serial), and verify the
    /// signature against the issuing CA's key. Parsing with x509-ocsp +
    /// re-encoding the tbs (which must still verify) also proves our yasna DER
    /// is canonical — what a strict client's parser expects.
    fn validate_staple(staple: &[u8], ca_cert: &X509, leaf: &X509) {
        let resp = OcspResponse::from_der(staple).expect("parse OcspResponse");
        assert_eq!(resp.response_status, OcspResponseStatus::Successful);
        let bytes = resp.response_bytes.expect("response bytes present");
        let basic = BasicOcspResponse::from_der(bytes.response.as_bytes())
            .expect("parse BasicOcspResponse");

        assert_eq!(
            basic.tbs_response_data.responses.len(),
            1,
            "one SingleResponse"
        );
        let single = &basic.tbs_response_data.responses[0];
        assert!(
            matches!(single.cert_status, CertStatus::Good(_)),
            "certStatus good"
        );
        assert!(single.next_update.is_some(), "nextUpdate present");

        // CertID == this leaf under this CA (independent boring computations).
        let name_der = ca_cert.subject_name().to_der().unwrap();
        let name_hash = hash(MessageDigest::sha1(), &name_der).unwrap();
        let key_hash = ca_cert.pubkey_digest(MessageDigest::sha1()).unwrap();
        assert_eq!(
            single.cert_id.issuer_name_hash.as_bytes(),
            name_hash.as_ref(),
            "issuerNameHash"
        );
        assert_eq!(
            single.cert_id.issuer_key_hash.as_bytes(),
            key_hash.as_ref(),
            "issuerKeyHash"
        );
        let got = BigNum::from_slice(single.cert_id.serial_number.as_bytes()).unwrap();
        let want = leaf.serial_number().to_bn().unwrap();
        assert_eq!(got, want, "CertID serial == leaf serial");

        // Signature over tbsResponseData verifies against the CA key.
        let tbs = basic.tbs_response_data.to_der().unwrap();
        let ca_pub = ca_cert.public_key().unwrap();
        let mut verifier = Verifier::new(MessageDigest::sha256(), &ca_pub).unwrap();
        verifier.update(&tbs).unwrap();
        assert!(
            verifier.verify(basic.signature.raw_bytes()).unwrap(),
            "OCSP signature must verify against the issuing CA key"
        );
    }

    /// Build a self-signed "upstream" certificate, optionally advertising an
    /// OCSP responder via Authority Information Access — the signal the staple
    /// gate keys off.
    fn upstream_cert(with_ocsp: bool) -> X509 {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "upstream.example").unwrap();
        let name = name.build();

        let mut b = X509Builder::new().unwrap();
        b.set_version(2).unwrap();
        let serial = {
            let mut bn = BigNum::new().unwrap();
            bn.rand(159, MsbOption::MAYBE_ZERO, false).unwrap();
            bn.to_asn1_integer().unwrap()
        };
        b.set_serial_number(&serial).unwrap();
        b.set_subject_name(&name).unwrap();
        b.set_issuer_name(&name).unwrap();
        b.set_pubkey(&key).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        b.set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        if with_ocsp {
            // authorityInfoAccess (1.3.6.1.5.5.7.1.1) advertising an OCSP responder.
            let aia_oid = Asn1Object::from_str("1.3.6.1.5.5.7.1.1").unwrap();
            let ext = X509Extension::from_der_payload(
                aia_oid.as_ref(),
                false,
                &aia_ocsp_payload(b"http://ocsp.test.example"),
            )
            .unwrap();
            b.append_extension(&ext).unwrap();
        }
        b.sign(&key, MessageDigest::sha256()).unwrap();
        b.build()
    }

    /// Full mirror + issue flow, end to end, across CA key kinds and the
    /// upstream-OCSP gate. For every case that should staple, the produced
    /// response is parsed and validated the way a strict client would (status,
    /// CertID, CA signature) — so we know it'll be trusted.
    #[tokio::test]
    async fn e2e_mirror_ocsp_staple_matrix() {
        // (CA key kind, upstream advertises OCSP, expect a valid staple)
        let scenarios = [
            (SelfSignedKeyKind::EcP256, true, true),
            (SelfSignedKeyKind::EcP384, true, true),
            (SelfSignedKeyKind::Rsa2048, true, true),
            // gate: upstream advertised no OCSP → no staple
            (SelfSignedKeyKind::EcP256, false, false),
            // unsupported OCSP signing key → graceful skip (no staple), issuance still ok
            (SelfSignedKeyKind::Ed25519, true, false),
        ];

        for (key_kind, upstream_ocsp, expect_staple) in scenarios {
            let issuer = mitm_ca(key_kind);
            let issued = issuer
                .issue_mitm_x509_cert(upstream_cert(upstream_ocsp))
                .await
                .unwrap_or_else(|err| panic!("issue failed for {key_kind:?}: {err}"));

            let mut chain = issued.crt_chain.iter();
            let leaf = chain.next().expect("leaf cert");
            let ca = chain.next().expect("issuing CA in chain");

            match (expect_staple, issued.ocsp_staple.as_deref()) {
                (true, Some(staple)) => {
                    assert!(!staple.is_empty(), "{key_kind:?}: empty staple");
                    validate_staple(staple, ca, leaf);
                }
                (false, None) => {}
                (true, None) => {
                    panic!(
                        "{key_kind:?} (upstream_ocsp={upstream_ocsp}): expected a staple, got none"
                    )
                }
                (false, Some(_)) => {
                    panic!(
                        "{key_kind:?} (upstream_ocsp={upstream_ocsp}): expected no staple, got one"
                    )
                }
            }
        }
    }

    /// Real in-memory TLS handshake: a boring client that requested OCSP
    /// stapling connects to a server acceptor configured like the mirror flow
    /// (minted leaf chain + `set_status_callback` → `set_ocsp_status`). Proves
    /// the staple is actually emitted on the wire and the client receives it,
    /// then validates the received bytes the way a strict client would.
    ///
    /// (No pure-Rust client *enforces* OCSP — boring soft-fails — so this proves
    /// delivery + validity; strict acceptance is the Windows curl/cargo gate.)
    #[tokio::test]
    async fn e2e_handshake_delivers_valid_staple() {
        let issuer = mitm_ca(SelfSignedKeyKind::EcP256);
        let issued = issuer
            .issue_mitm_x509_cert(upstream_cert(true))
            .await
            .expect("issue with upstream OCSP");
        let staple = issued.ocsp_staple.clone().expect("staple present");

        // Server acceptor, configured like the mirror flow.
        let mut acc = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).unwrap();
        for (i, crt) in issued.crt_chain.iter().enumerate() {
            if i == 0 {
                acc.set_certificate(crt).unwrap();
            } else {
                acc.add_extra_chain_cert(crt.clone()).unwrap();
            }
        }
        acc.set_private_key(&issued.key).unwrap();
        {
            let staple = staple.clone();
            acc.set_status_callback(move |ssl| ssl.set_ocsp_status(&staple).map(|()| true))
                .unwrap();
        }
        let acceptor = acc.build();

        // Client requesting OCSP stapling (verify disabled — self-signed test CA).
        let mut conn = SslConnector::builder(SslMethod::tls_client()).unwrap();
        conn.set_verify(SslVerifyMode::NONE);
        conn.enable_ocsp_stapling();
        let mut cfg = conn.build().configure().unwrap();
        cfg.set_verify_hostname(false);

        let (client_io, server_io) = duplex(1 << 20);
        let server = tokio::spawn(async move {
            rama_boring_tokio::accept(&acceptor, server_io)
                .await
                .map_err(|e| e.to_string())
        });

        let client_stream = rama_boring_tokio::connect(cfg, Some("example.com"), client_io)
            .await
            .expect("client TLS handshake");

        // The client received the server's stapled OCSP on the wire.
        let received = client_stream
            .ssl()
            .ocsp_status()
            .map(|s| s.to_vec())
            .expect("client received a stapled OCSP response");
        assert_eq!(
            received.as_slice(),
            staple.as_ref(),
            "received == server staple"
        );

        server.await.unwrap().expect("server handshake");

        // …and it passes strict-client validation.
        let mut chain = issued.crt_chain.iter();
        let leaf = chain.next().unwrap();
        let ca = chain.next().unwrap();
        validate_staple(&received, ca, leaf);
    }
}
