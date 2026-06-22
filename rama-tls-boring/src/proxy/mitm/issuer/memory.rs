use std::{fmt, sync::Arc};

use rama_boring::{
    nid::Nid,
    pkey::{PKey, Private},
    x509::X509,
};
use rama_core::{error::BoxError, telemetry::tracing};
use rama_net::tls::server::SelfSignedData;
use rama_utils::collections::non_empty_vec;

use crate::proxy::mitm::revocation::{BoringMitmRevocation, MitmRevocationCtx};
use crate::server::utils::{MitmLeafOcspStatus, self_signed_server_auth_gen_ca};

use super::{BoringMitmCertIssuer, MitmIssuedCert};

#[derive(Clone)]
/// A [`BoringMitmCertIssuer`] which mirrors the original reference
/// using its internal (in-memory) CA crt/key pair to sign.
pub struct InMemoryBoringMitmCertIssuer {
    ca_crt: X509,
    ca_key: PKey<Private>,
    revocation: Option<Arc<dyn BoringMitmRevocation>>,
}

impl fmt::Debug for InMemoryBoringMitmCertIssuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InMemoryBoringMitmCertIssuer")
            .field("ca_crt", &self.ca_crt)
            .field("ca_key", &"PKey<Private>")
            .field("revocation", &self.revocation.is_some())
            .finish()
    }
}

impl InMemoryBoringMitmCertIssuer {
    #[inline(always)]
    /// Create a new [`InMemoryBoringMitmCertIssuer`].
    #[must_use]
    pub fn new(ca_crt: X509, ca_key: PKey<Private>) -> Self {
        Self {
            ca_crt,
            ca_key,
            revocation: None,
        }
    }

    #[inline(always)]
    /// Create a new [`InMemoryBoringMitmCertIssuer`] with self-signed CA using the given data.
    pub fn try_new_self_signed(data: &SelfSignedData) -> Result<Self, BoxError> {
        let (ca_cert, ca_privkey) = self_signed_server_auth_gen_ca(data)?;
        Ok(Self::new(ca_cert, ca_privkey))
    }

    rama_utils::macros::generate_set_and_with! {
        /// Attach a [`BoringMitmRevocation`] responder. Its CA must be the same
        /// one this issuer signs with, so the stamped pointers resolve. Issued
        /// leaves then carry the responder's revocation extensions.
        pub fn revocation(mut self, revocation: Option<Arc<dyn BoringMitmRevocation>>) -> Self {
            self.revocation = revocation;
            self
        }
    }
}

impl BoringMitmCertIssuer for InMemoryBoringMitmCertIssuer {
    type Error = BoxError;

    #[inline(always)]
    async fn issue_mitm_x509_cert(&self, original: X509) -> Result<MitmIssuedCert, Self::Error> {
        let extra_extensions = match &self.revocation {
            Some(revocation) => revocation.leaf_extensions(&MitmRevocationCtx {
                original: &original,
                issuer_ca: &self.ca_crt,
            })?,
            None => Vec::new(),
        };

        let (crt, key) = crate::server::utils::self_signed_server_auth_mirror_cert_with_extensions(
            &original,
            &self.ca_crt,
            &self.ca_key,
            &extra_extensions,
        )?;

        // Staple a `good` only when the upstream advertised revocation info (the
        // mirror strips it, so a strict client would otherwise have nothing to
        // check). Signed by the issuing CA — root or intermediate, though an
        // intermediate's own hop isn't covered. Best-effort: never block issuance.
        let ocsp_staple = if upstream_advertised_revocation(&original) {
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

/// Whether the upstream cert advertised any revocation source (OCSP responder,
/// CRL distribution point, or freshest CRL) — the pointers the mirror strips.
/// We staple only then, mirroring the origin's posture rather than fabricating.
fn upstream_advertised_revocation(original: &X509) -> bool {
    if original
        .ocsp_responders()
        .map(|responders| !responders.is_empty())
        .unwrap_or(false)
    {
        return true;
    }
    original.extensions().any(|ext| {
        let nid = ext.object().nid();
        nid == Nid::CRL_DISTRIBUTION_POINTS || nid == Nid::FRESHEST_CRL
    })
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

        // nextUpdate must track the leaf's notAfter, else a long-lived cache
        // serves an expired staple for a still-valid leaf (the original bug).
        let next_update_unix = single
            .next_update
            .as_ref()
            .expect("nextUpdate present")
            .0
            .to_unix_duration()
            .as_secs() as i64;
        let not_after_diff = Asn1Time::from_unix(0)
            .unwrap()
            .diff(leaf.not_after())
            .unwrap();
        let not_after_unix =
            i64::from(not_after_diff.days) * 86_400 + i64::from(not_after_diff.secs);
        assert!(
            (next_update_unix - not_after_unix).abs() <= 1,
            "nextUpdate ({next_update_unix}) must track leaf notAfter ({not_after_unix})"
        );

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

    /// Which revocation source an upstream test certificate advertises.
    #[derive(Clone, Copy, Debug)]
    enum Revocation {
        /// No revocation pointers at all (a private-CA leaf looks like this).
        None,
        /// An OCSP responder via Authority Information Access.
        Ocsp,
        /// A CRL Distribution Point and no OCSP — e.g. every current Let's
        /// Encrypt leaf, which dropped OCSP in 2025.
        Crl,
    }

    /// DER of `CRLDistributionPoints` with a single DistributionPoint whose
    /// fullName is `uri` (short-form lengths; uri < 120 bytes). Only the
    /// extension's OID (→ NID) drives the staple gate, but a well-formed payload
    /// keeps the test cert realistic.
    fn crldp_payload(uri: &[u8]) -> Vec<u8> {
        // GeneralName ::= uniformResourceIdentifier [6] IA5String
        let mut gn = vec![0x86, uri.len() as u8];
        gn.extend_from_slice(uri);
        // fullName [0] IMPLICIT GeneralNames (SEQUENCE OF GeneralName)
        let mut full_name = vec![0xA0, gn.len() as u8];
        full_name.extend_from_slice(&gn);
        // distributionPoint [0] EXPLICIT DistributionPointName
        let mut dpn = vec![0xA0, full_name.len() as u8];
        dpn.extend_from_slice(&full_name);
        // DistributionPoint ::= SEQUENCE { distributionPoint ... }
        let mut dp = vec![0x30, dpn.len() as u8];
        dp.extend_from_slice(&dpn);
        // CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
        let mut crldp = vec![0x30, dp.len() as u8];
        crldp.extend_from_slice(&dp);
        crldp
    }

    /// A self-signed "upstream" identity (key + cert) advertising `revocation`.
    fn upstream_identity(revocation: Revocation) -> (PKey<Private>, X509) {
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
        match revocation {
            Revocation::None => {}
            Revocation::Ocsp => {
                // authorityInfoAccess (1.3.6.1.5.5.7.1.1) advertising an OCSP responder.
                let oid = Asn1Object::from_str("1.3.6.1.5.5.7.1.1").unwrap();
                let ext = X509Extension::from_der_payload(
                    oid.as_ref(),
                    false,
                    &aia_ocsp_payload(b"http://ocsp.test.example"),
                )
                .unwrap();
                b.append_extension(&ext).unwrap();
            }
            Revocation::Crl => {
                // cRLDistributionPoints (2.5.29.31).
                let oid = Asn1Object::from_str("2.5.29.31").unwrap();
                let ext = X509Extension::from_der_payload(
                    oid.as_ref(),
                    false,
                    &crldp_payload(b"http://crl.test.example/a.crl"),
                )
                .unwrap();
                b.append_extension(&ext).unwrap();
            }
        }
        b.sign(&key, MessageDigest::sha256()).unwrap();
        (key, b.build())
    }

    /// A self-signed "upstream" certificate advertising `revocation`.
    fn upstream_cert(revocation: Revocation) -> X509 {
        upstream_identity(revocation).1
    }

    /// Full mirror + issue flow, end to end, across CA key kinds and the
    /// upstream-OCSP gate. For every case that should staple, the produced
    /// response is parsed and validated the way a strict client would (status,
    /// CertID, CA signature) — so we know it'll be trusted.
    #[tokio::test]
    async fn e2e_mirror_ocsp_staple_matrix() {
        // (CA key kind, revocation the upstream advertises, expect a valid staple)
        let scenarios = [
            (SelfSignedKeyKind::EcP256, Revocation::Ocsp, true),
            (SelfSignedKeyKind::EcP384, Revocation::Ocsp, true),
            (SelfSignedKeyKind::Rsa2048, Revocation::Ocsp, true),
            // CRL-only upstream (no OCSP) must staple too — the mirror strips the
            // CRLDP, so a revocation-strict client needs the staple in its place.
            (SelfSignedKeyKind::EcP256, Revocation::Crl, true),
            // gate: upstream advertised no revocation source → no staple
            (SelfSignedKeyKind::EcP256, Revocation::None, false),
            // unsupported OCSP signing key → graceful skip (no staple), issuance still ok
            (SelfSignedKeyKind::Ed25519, Revocation::Ocsp, false),
        ];

        for (key_kind, revocation, expect_staple) in scenarios {
            let issuer = mitm_ca(key_kind);
            let issued = issuer
                .issue_mitm_x509_cert(upstream_cert(revocation))
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
                    panic!("{key_kind:?} ({revocation:?}): expected a staple, got none")
                }
                (false, Some(_)) => {
                    panic!("{key_kind:?} ({revocation:?}): expected no staple, got one")
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
            .issue_mitm_x509_cert(upstream_cert(Revocation::Ocsp))
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

    /// Drive the real [`TlsMitmRelay::handshake`] end to end: live upstream
    /// (OCSP-advertising cert) → relay → OCSP-requesting client. Unlike
    /// `e2e_handshake_delivers_valid_staple`, this exercises the actual
    /// `set_status_callback` wiring, so a regression there fails the suite.
    /// ([`ServiceInput`] wraps the duplex ends for the `ExtensionsRef` bound.)
    #[tokio::test]
    async fn e2e_relay_handshake_staples_mirrored_leaf() {
        use crate::client::TlsConnectorData;
        use crate::proxy::mitm::TlsMitmRelay;
        use rama_core::{ServiceInput, io::BridgeIo};
        use rama_net::tls::client::{ServerVerifyMode, TlsClientConfig};

        // Upstream TLS server presenting a cert that advertises OCSP.
        let (upstream_key, upstream_x509) = upstream_identity(Revocation::Ocsp);
        let mut up = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).unwrap();
        up.set_certificate(&upstream_x509).unwrap();
        up.set_private_key(&upstream_key).unwrap();
        let up_acceptor = up.build();

        // MITM relay with an in-memory self-signed CA (kept here for validation).
        let (ca_crt, ca_key) = self_signed_server_auth_gen_ca(&SelfSignedData {
            common_name: Some(Domain::from_static("rama-mitm-relay-ca.example")),
            organisation_name: Some("Rama".to_owned()),
            ..Default::default()
        })
        .expect("self-signed MITM CA");
        let relay = TlsMitmRelay::new_in_memory(ca_crt.clone(), ca_key);

        let (client_io, relay_ingress) = duplex(1 << 20);
        let (relay_egress, upstream_io) = duplex(1 << 20);

        // Upstream accepts the relay's egress handshake (stream held until teardown).
        let upstream = tokio::spawn(async move {
            rama_boring_tokio::accept(&up_acceptor, upstream_io)
                .await
                .map_err(|e| e.to_string())
        });

        // Egress connector: verification disabled (self-signed test upstream),
        // exactly as the relay service configures it.
        let egress_cd = TlsConnectorData::try_from(
            &TlsClientConfig::new().with_server_verify(ServerVerifyMode::Disable),
        )
        .expect("egress connector data");

        // Relay drives both handshakes: egress connect → mirror → ingress accept.
        let relay_task = tokio::spawn(async move {
            relay
                .handshake(
                    BridgeIo(
                        ServiceInput::new(relay_ingress),
                        ServiceInput::new(relay_egress),
                    ),
                    Some(egress_cd),
                )
                .await
                .map_err(|e| e.to_string())
        });

        // Ingress client requests OCSP stapling.
        let mut conn = SslConnector::builder(SslMethod::tls_client()).unwrap();
        conn.set_verify(SslVerifyMode::NONE);
        conn.enable_ocsp_stapling();
        let mut cfg = conn.build().configure().unwrap();
        cfg.set_verify_hostname(false);
        let client_stream = rama_boring_tokio::connect(cfg, Some("upstream.example"), client_io)
            .await
            .expect("client TLS handshake through relay");

        // The client received a staple — produced by the real relay wiring.
        let received = client_stream
            .ssl()
            .ocsp_status()
            .map(|s| s.to_vec())
            .expect("relay stapled an OCSP response on the wire");
        assert!(!received.is_empty(), "non-empty staple via relay");

        // Validate it against the MITM CA and the leaf the relay actually minted
        // (the client's peer cert is that mirrored leaf).
        let leaf = client_stream
            .ssl()
            .peer_certificate()
            .expect("client received the mirrored leaf");
        validate_staple(&received, &ca_crt, &leaf);

        relay_task.await.unwrap().expect("relay handshake ok");
        upstream.await.unwrap().expect("upstream server ok");
    }
}
