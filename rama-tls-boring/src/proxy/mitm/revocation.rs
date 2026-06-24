//! Pluggable revocation for re-signed MITM leaves.
//!
//! Stamps revocation pointers (CRL distribution point / AIA OCSP) onto the
//! re-signed leaf, mirroring whichever source the upstream advertised, and
//! serves the matching CA-signed artifact — so revocation-strict clients
//! (notably libcurl + schannel, which resolves revocation from the cert's own
//! pointers and ignores stapled OCSP) accept the leaf. Opt-in: an issuer with
//! no responder configured strips as before and stamps nothing.

use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime},
};

use parking_lot::Mutex;
use rama_boring::{
    asn1::Asn1Object,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    x509::{X509, X509Extension, X509Ref},
};
use rama_core::{
    bytes::Bytes,
    error::{BoxError, ErrorContext},
};
use rama_crypto::{
    crl::{RevokedEntry, crl_distribution_point_der},
    ocsp::{OcspCertStatus, authority_info_access_ocsp_der},
};
use rama_net::uri::Uri;

use crate::server::utils::{answer_ocsp_request, build_mitm_ca_crl};

/// Backdate a CRL `thisUpdate` to tolerate client clock skew.
const CLOCK_SKEW_BACKDATE: Duration = Duration::from_hours(1);

/// The MITM signing identity shared between the cert issuer and the revocation
/// responder. Sharing one instance keeps the leaf's issuer and the CRL/OCSP
/// signer in agreement — the client derives its `CertID` and CRL issuer match
/// from this CA. An immutable handle meant to be wrapped in `Arc` and shared,
/// not cloned per use.
#[derive(Clone)]
pub struct MitmCa {
    /// CA certificate.
    pub cert: X509,
    /// CA private key.
    pub key: PKey<Private>,
}

impl fmt::Debug for MitmCa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MitmCa")
            .field("cert", &self.cert)
            .field("key", &"PKey<Private>")
            .finish()
    }
}

impl MitmCa {
    /// Create a new [`MitmCa`].
    #[must_use]
    pub fn new(cert: X509, key: PKey<Private>) -> Self {
        Self { cert, key }
    }

    /// Stable id derived from the CA's subject key identifier (hex), used in the
    /// served URL path so several CAs don't collide.
    #[must_use]
    pub fn id(&self) -> CaId {
        let bytes = match self.cert.subject_key_id() {
            Some(skid) => skid.as_slice().to_vec(),
            None => self
                .cert
                .pubkey_digest(MessageDigest::sha1())
                .map(|d| d.as_ref().to_vec())
                .unwrap_or_default(),
        };
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut hex = String::with_capacity(bytes.len() * 2);
        for &b in &bytes {
            hex.push(HEX[(b >> 4) as usize] as char);
            hex.push(HEX[(b & 0x0f) as usize] as char);
        }
        CaId(hex)
    }
}

/// A stable, URL-safe identifier for a [`MitmCa`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CaId(String);

impl CaId {
    /// The identifier as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CaId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A revoked certificate, as reported by a [`RevocationLedger`].
#[derive(Debug, Clone)]
pub struct RevokedCert {
    /// Revoked serial as a big-endian unsigned magnitude.
    pub serial: Vec<u8>,
    /// When the certificate was revoked.
    pub revocation_date: SystemTime,
}

/// Source of revoked serials for a CA. The default responder uses no ledger
/// (nothing revoked); implement this to actually revoke issued leaves.
pub trait RevocationLedger: Send + Sync + 'static {
    /// Currently-revoked certificates for `ca_id`.
    fn revoked(&self, ca_id: &CaId) -> Vec<RevokedCert>;
}

/// Context passed to [`BoringMitmRevocation::leaf_extensions`].
pub struct MitmRevocationCtx<'a> {
    /// The upstream (origin) certificate being mirrored.
    pub original: &'a X509Ref,
    /// The CA that signs the re-signed leaf (and the CRL/OCSP).
    pub issuer_ca: &'a X509Ref,
}

/// A revocation fetch routed in from the HTTP edge.
pub enum RevocationFetch<'a> {
    /// CRL requested for `ca_id`.
    Crl {
        /// CA whose CRL is requested.
        ca_id: &'a CaId,
    },
    /// OCSP request for `ca_id`.
    Ocsp {
        /// CA the request targets.
        ca_id: &'a CaId,
        /// The DER `OCSPRequest` body.
        der_request: &'a [u8],
    },
}

/// MIME type of a [`RevocationArtifact`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RevocationContentType {
    /// `application/pkix-crl`.
    Crl,
    /// `application/ocsp-response`.
    Ocsp,
}

impl RevocationContentType {
    /// The artifact's HTTP `Content-Type`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Crl => "application/pkix-crl",
            Self::Ocsp => "application/ocsp-response",
        }
    }
}

/// A revocation artifact (DER) to return over HTTP.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RevocationArtifact {
    /// Content type to set on the response.
    pub content_type: RevocationContentType,
    /// DER body.
    pub body: Bytes,
}

/// Revocation behaviour for a MITM issuer: which pointers to stamp on the
/// re-signed leaf, and how to serve the artifacts they reference.
pub trait BoringMitmRevocation: Send + Sync + 'static {
    /// Extensions to add to the re-signed leaf (empty adds none).
    fn leaf_extensions(&self, ctx: &MitmRevocationCtx<'_>) -> Result<Vec<X509Extension>, BoxError>;

    /// Produce the artifact for a fetch routed in from the HTTP edge.
    fn serve(&self, fetch: RevocationFetch<'_>) -> Result<RevocationArtifact, BoxError>;
}

/// Default [`BoringMitmRevocation`]: serves a CA-signed CRL and/or OCSP for one
/// CA over plain HTTP, stamping whichever pointer the upstream advertised.
pub struct ProxyHostedRevocation {
    ca: Arc<MitmCa>,
    ca_id: CaId,
    crl_url: Arc<str>,
    ocsp_url: Arc<str>,
    validity: Duration,
    serves_crl: bool,
    serves_ocsp: bool,
    ledger: Option<Arc<dyn RevocationLedger>>,
    /// Monotonic `cRLNumber`, bumped only on a real CRL (re)build.
    crl_seq: AtomicU64,
    /// Last built CRL, reused until its `nextUpdate` (no-ledger case only).
    cached_crl: Mutex<Option<CachedCrl>>,
}

struct CachedCrl {
    body: Bytes,
    next_update: SystemTime,
}

impl fmt::Debug for ProxyHostedRevocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyHostedRevocation")
            .field("ca_id", &self.ca_id)
            .field("crl_url", &self.crl_url)
            .field("ocsp_url", &self.ocsp_url)
            .field("validity", &self.validity)
            .field("serves_crl", &self.serves_crl)
            .field("serves_ocsp", &self.serves_ocsp)
            .field("ledger", &self.ledger.is_some())
            .finish()
    }
}

impl ProxyHostedRevocation {
    /// Create a responder for `ca`, serving at `base_url` (plain HTTP, e.g.
    /// `http://127.0.0.1:9999`), with the given CRL/OCSP `validity` window. Both
    /// CRL and OCSP are served; nothing is revoked.
    #[must_use]
    pub fn new(ca: Arc<MitmCa>, base_url: Uri, validity: Duration) -> Self {
        Self {
            ca_id: ca.id(),
            crl_url: base_url
                .clone()
                .with_additional_path_segment("crl")
                .to_string()
                .into(),
            ocsp_url: base_url
                .with_additional_path_segment("ocsp")
                .to_string()
                .into(),
            ca,
            validity,
            serves_crl: true,
            serves_ocsp: true,
            ledger: None,
            crl_seq: AtomicU64::new(1),
            cached_crl: Mutex::new(None),
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Enable or disable serving (and stamping) CRLs.
        pub fn crl(mut self, enabled: bool) -> Self {
            self.serves_crl = enabled;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Enable or disable serving (and stamping) OCSP.
        pub fn ocsp(mut self, enabled: bool) -> Self {
            self.serves_ocsp = enabled;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// A [`RevocationLedger`] supplying revoked serials (none if unset).
        pub fn ledger(mut self, ledger: Option<Arc<dyn RevocationLedger>>) -> Self {
            self.ledger = ledger;
            self
        }
    }

    /// The shared CA.
    #[must_use]
    pub fn ca(&self) -> &Arc<MitmCa> {
        &self.ca
    }

    /// The CA identifier, computed once at construction.
    #[must_use]
    pub fn ca_id(&self) -> &CaId {
        &self.ca_id
    }

    /// Reject a fetch whose `ca_id` is not the one this responder serves.
    fn check_ca(&self, ca_id: &CaId) -> Result<(), BoxError> {
        if *ca_id == self.ca_id {
            Ok(())
        } else {
            Err(format!("revocation: request for unknown ca id {ca_id}").into())
        }
    }

    /// Currently-revoked serials from the ledger (empty without one).
    fn revoked(&self) -> Vec<RevokedCert> {
        self.ledger
            .as_ref()
            .map(|l| l.revoked(&self.ca_id))
            .unwrap_or_default()
    }

    /// The signed CRL, reused from cache while still within its validity window.
    /// Skips the cache when a ledger is set, since its revoked set can change.
    fn crl_body(&self) -> Result<Bytes, BoxError> {
        let now = SystemTime::now();
        if self.ledger.is_none() {
            let cache = self.cached_crl.lock();
            if let Some(cached) = cache.as_ref()
                && now < cached.next_update
            {
                return Ok(cached.body.clone());
            }
        }

        let this_update = now.checked_sub(CLOCK_SKEW_BACKDATE).unwrap_or(now);
        let next_update = now
            .checked_add(self.validity)
            .ok_or_else(|| BoxError::from("crl: nextUpdate overflow"))?;
        let crl_number = self.crl_seq.fetch_add(1, Ordering::Relaxed);
        let revoked = self.revoked();
        let entries: Vec<RevokedEntry<'_>> = revoked
            .iter()
            .map(|r| RevokedEntry {
                serial: &r.serial,
                revocation_date: r.revocation_date,
            })
            .collect();
        let der = build_mitm_ca_crl(
            &self.ca.cert,
            &self.ca.key,
            this_update,
            next_update,
            crl_number,
            &entries,
        )?;
        let body = Bytes::from(der);
        if self.ledger.is_none() {
            *self.cached_crl.lock() = Some(CachedCrl {
                body: body.clone(),
                next_update,
            });
        }
        Ok(body)
    }
}

impl BoringMitmRevocation for ProxyHostedRevocation {
    fn leaf_extensions(&self, ctx: &MitmRevocationCtx<'_>) -> Result<Vec<X509Extension>, BoxError> {
        let mut exts = Vec::new();
        if self.serves_crl && upstream_has_crl(ctx.original) {
            exts.push(crl_distribution_point_extension(&self.crl_url)?);
        }
        if self.serves_ocsp && upstream_has_ocsp(ctx.original) {
            exts.push(aia_ocsp_extension(&self.ocsp_url)?);
        }
        Ok(exts)
    }

    fn serve(&self, fetch: RevocationFetch<'_>) -> Result<RevocationArtifact, BoxError> {
        match fetch {
            RevocationFetch::Crl { ca_id } => {
                self.check_ca(ca_id)?;
                Ok(RevocationArtifact {
                    content_type: RevocationContentType::Crl,
                    body: self.crl_body()?,
                })
            }
            RevocationFetch::Ocsp { ca_id, der_request } => {
                self.check_ca(ca_id)?;
                let revoked = self.revoked();
                let der = answer_ocsp_request(
                    &self.ca.cert,
                    &self.ca.key,
                    der_request,
                    self.validity,
                    |serial| match revoked.iter().find(|r| r.serial.as_slice() == serial) {
                        Some(r) => OcspCertStatus::Revoked {
                            revocation_time: r.revocation_date,
                        },
                        None => OcspCertStatus::Good,
                    },
                )?;
                Ok(RevocationArtifact {
                    content_type: RevocationContentType::Ocsp,
                    body: Bytes::from(der),
                })
            }
        }
    }
}

fn upstream_has_ocsp(cert: &X509Ref) -> bool {
    cert.ocsp_responders()
        .map(|r| !r.is_empty())
        .unwrap_or(false)
}

fn upstream_has_crl(cert: &X509Ref) -> bool {
    cert.extensions().any(|ext| {
        let nid = ext.object().nid();
        nid == Nid::CRL_DISTRIBUTION_POINTS || nid == Nid::FRESHEST_CRL
    })
}

/// Build a non-critical `CRL Distribution Points` extension with a single
/// `fullName` URI pointing at `url`.
pub fn crl_distribution_point_extension(url: &str) -> Result<X509Extension, BoxError> {
    let oid = Asn1Object::from_str("2.5.29.31").context("crl dp oid")?;
    X509Extension::from_der_payload(oid.as_ref(), false, &crl_distribution_point_der(url))
        .context("build CRL distribution point extension")
}

/// Build a non-critical `Authority Information Access` extension with a single
/// `id-ad-ocsp` responder URI pointing at `url`.
pub fn aia_ocsp_extension(url: &str) -> Result<X509Extension, BoxError> {
    let oid = Asn1Object::from_str("1.3.6.1.5.5.7.1.1").context("aia oid")?;
    X509Extension::from_der_payload(oid.as_ref(), false, &authority_info_access_ocsp_der(url))
        .context("build AIA OCSP extension")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_boring::{
        asn1::Asn1Time,
        bn::{BigNum, MsbOption},
        rsa::Rsa,
        x509::{X509Builder, X509NameBuilder},
    };
    use rama_net::address::Domain;
    use rama_tls::server::SelfSignedData;

    use rama_crypto::cert::boring::{
        self_signed_server_auth_gen_ca, self_signed_server_auth_mirror_cert_with_extensions,
    };

    fn base_uri() -> Uri {
        Uri::from_static("http://127.0.0.1:9999")
    }

    fn ca() -> (X509, PKey<Private>) {
        self_signed_server_auth_gen_ca(&SelfSignedData {
            common_name: Some(Domain::from_static("rama-mitm-revoc-test-ca.example")),
            organisation_name: Some("Rama Revocation Test".to_owned()),
            ..Default::default()
        })
        .expect("gen CA")
    }

    /// A self-signed "upstream" advertising the chosen revocation pointers.
    fn upstream(crldp: bool, ocsp: bool) -> X509 {
        let key = PKey::from_rsa(Rsa::generate(2048).expect("rsa")).expect("pkey");
        let mut name = X509NameBuilder::new().expect("name");
        name.append_entry_by_text("CN", "upstream.test")
            .expect("cn");
        let name = name.build();

        let mut b = X509Builder::new().expect("builder");
        b.set_version(2).expect("version");
        let serial = {
            let mut bn = BigNum::new().expect("bn");
            bn.rand(159, MsbOption::MAYBE_ZERO, false).expect("rand");
            bn.to_asn1_integer().expect("serial")
        };
        b.set_serial_number(&serial).expect("set serial");
        b.set_subject_name(&name).expect("subject");
        b.set_issuer_name(&name).expect("issuer");
        b.set_pubkey(&key).expect("pubkey");
        b.set_not_before(&Asn1Time::days_from_now(0).expect("nb"))
            .expect("set nb");
        b.set_not_after(&Asn1Time::days_from_now(365).expect("na"))
            .expect("set na");
        if crldp {
            b.append_extension(
                &crl_distribution_point_extension("http://crl.upstream.test/a.crl").expect("crldp"),
            )
            .expect("append crldp");
        }
        if ocsp {
            b.append_extension(&aia_ocsp_extension("http://ocsp.upstream.test").expect("aia"))
                .expect("append aia");
        }
        b.sign(&key, MessageDigest::sha256()).expect("sign");
        b.build()
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn ca_id_is_stable_and_nonempty() {
        let (cert, key) = ca();
        let a = MitmCa::new(cert.clone(), key.clone()).id();
        let b = MitmCa::new(cert, key).id();
        assert_eq!(a, b);
        assert!(!a.as_str().is_empty());
    }

    /// Stamps our pointers for whatever the upstream advertised, replacing the
    /// upstream's (stripped) pointers — and stamps nothing for a bare upstream.
    #[test]
    fn stamps_pointers_mirroring_upstream() {
        let (ca_crt, ca_key) = ca();
        let mitm = Arc::new(MitmCa::new(ca_crt.clone(), ca_key.clone()));
        let rev = ProxyHostedRevocation::new(mitm, base_uri(), Duration::from_hours(24));

        let up = upstream(true, true);
        let exts = rev
            .leaf_extensions(&MitmRevocationCtx {
                original: &up,
                issuer_ca: &ca_crt,
            })
            .expect("leaf extensions");
        assert_eq!(exts.len(), 2, "one CDP + one AIA");

        let (leaf, _key) =
            self_signed_server_auth_mirror_cert_with_extensions(&up, &ca_crt, &ca_key, &exts)
                .expect("mirror leaf");
        let der = leaf.to_der().expect("leaf der");

        assert!(
            contains(&der, base_uri().as_str().as_bytes()),
            "our endpoint stamped"
        );
        assert!(
            !contains(&der, b"crl.upstream.test"),
            "upstream CRL pointer stripped"
        );
        assert!(
            !contains(&der, b"ocsp.upstream.test"),
            "upstream OCSP pointer stripped"
        );

        let bare = upstream(false, false);
        assert!(
            rev.leaf_extensions(&MitmRevocationCtx {
                original: &bare,
                issuer_ca: &ca_crt,
            })
            .expect("leaf extensions")
            .is_empty(),
            "no pointers when upstream advertised none"
        );
    }

    #[test]
    fn serves_a_crl_signed_for_the_ca() {
        let (ca_crt, ca_key) = ca();
        let mitm = Arc::new(MitmCa::new(ca_crt.clone(), ca_key));
        let rev = ProxyHostedRevocation::new(mitm.clone(), base_uri(), Duration::from_hours(24));

        let art = rev
            .serve(RevocationFetch::Crl { ca_id: &mitm.id() })
            .expect("serve crl");
        assert_eq!(art.content_type, RevocationContentType::Crl);
        let issuer_der = ca_crt.subject_name().to_der().expect("issuer der");
        assert!(
            contains(&art.body, &issuer_der),
            "CRL carries the CA issuer name"
        );
    }

    /// A ledger-revoked serial appears in the served CRL; absent without a ledger.
    #[test]
    fn ledger_revoked_serial_listed_in_crl() {
        struct Ledger(Vec<u8>);
        impl RevocationLedger for Ledger {
            fn revoked(&self, _ca_id: &CaId) -> Vec<RevokedCert> {
                vec![RevokedCert {
                    serial: self.0.clone(),
                    revocation_date: SystemTime::now(),
                }]
            }
        }

        let (ca_crt, ca_key) = ca();
        let mitm = Arc::new(MitmCa::new(ca_crt, ca_key));
        let serial = vec![0xAB_u8; 19];

        let plain = ProxyHostedRevocation::new(mitm.clone(), base_uri(), Duration::from_hours(24));
        let plain_crl = plain
            .serve(RevocationFetch::Crl { ca_id: &mitm.id() })
            .expect("serve crl")
            .body;
        assert!(
            !contains(&plain_crl, &serial),
            "no ledger: serial must be absent"
        );

        let revoking =
            ProxyHostedRevocation::new(mitm.clone(), base_uri(), Duration::from_hours(24))
                .with_ledger(Arc::new(Ledger(serial.clone())));
        let crl = revoking
            .serve(RevocationFetch::Crl { ca_id: &mitm.id() })
            .expect("serve crl")
            .body;
        assert!(contains(&crl, &serial), "revoked serial listed in CRL");
    }

    /// A fetch for a CA id this responder does not serve is rejected.
    #[test]
    fn rejects_unknown_ca_id() {
        let (ca_crt, ca_key) = ca();
        let mitm = Arc::new(MitmCa::new(ca_crt, ca_key));
        let rev = ProxyHostedRevocation::new(mitm, base_uri(), Duration::from_hours(24));
        let (other_crt, other_key) = self_signed_server_auth_gen_ca(&SelfSignedData {
            common_name: Some(Domain::from_static("other-ca.example")),
            ..Default::default()
        })
        .expect("gen other CA");
        let other_id = MitmCa::new(other_crt, other_key).id();
        assert!(
            rev.serve(RevocationFetch::Crl { ca_id: &other_id })
                .is_err(),
            "unknown ca id must be rejected"
        );
    }
}
