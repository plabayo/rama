use rama_boring::sha;
use rama_crypto::pki_types::CertificateDer;
use rama_tls::client::ClientAuthData;
use rama_utils::macros::generate_set_and_with;
use std::{collections::HashMap, fmt};
use zeroize::Zeroize;

/// Guest-certificate to upstream-key registry for a [`TlsMitmRelay`](super::TlsMitmRelay).
///
/// A guest presenting a certificate chains it against [`trust`](Self::with_trust_anchors)
/// during the ingress accept. The relay then matches the presented leaf against
/// [`identities`](Self::with_identity) and runs the single upstream leg with
/// that key. Authorization is the upstream's verdict: if the upstream rejects
/// the matched key the guest fails and nothing bridges (fail closed).
///
/// Matching hashes only the presented leaf DER bytes (SHA-256) and looks the
/// digest up in the registry. A client certificate covers whatever it covers;
/// the relay never scopes guest certificates to the requested host. Registry
/// membership plus the upstream verdict decide.
///
/// The joined handshake exists because of ordering: the guest key is known
/// only after the ingress accept, so the relay parks the upstream handshake
/// once the server flight is processed (to learn the upstream certificate for
/// minting), accepts the guest, then resumes the same upstream leg presenting
/// the matched key. Effective upstream identity precedence: flow
/// [`TlsMitmEgressClientAuth`](super::TlsMitmEgressClientAuth) extension wins
/// over a storage match, which wins over the relay default. A flow extension
/// wins without installing anything (explicit caller intent); if the upstream
/// never requested a certificate the installed key goes unused and the
/// handshake completes normally.
///
/// Guests whose leaf is trusted but absent from the registry are always
/// rejected (ingress-direction error, nothing bridges). Trust itself is always
/// enforced while storage is configured: missing or untrusted guest
/// certificates fail the ingress accept.
#[derive(Clone)]
pub struct TlsMitmIngressClientAuth {
    trust: Vec<CertificateDer<'static>>,
    identities: HashMap<[u8; 32], ClientAuthData>,
}

impl fmt::Debug for TlsMitmIngressClientAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Elide all key material: only report how many anchors/identities
        // are registered, never lengths or bytes that could leak secrets.
        f.debug_struct("TlsMitmIngressClientAuth")
            .field("trust_anchors", &self.trust.len())
            .field("identities", &self.identities.len())
            .finish()
    }
}

impl Drop for TlsMitmIngressClientAuth {
    fn drop(&mut self) {
        for identity in self.identities.values_mut() {
            identity.private_key.zeroize();
        }
    }
}

impl Default for TlsMitmIngressClientAuth {
    fn default() -> Self {
        Self {
            trust: Vec::new(),
            identities: HashMap::new(),
        }
    }
}

/// SHA-256 over the guest leaf DER bytes.
///
/// Used identically at insert (over each registry entry's first chain
/// certificate) and at match (over the presented leaf DER), so the digest is
/// stable across DER parse/serialize round-trips of valid certificates.
fn fingerprint_leaf(der: &[u8]) -> [u8; 32] {
    sha::sha256(der)
}

impl TlsMitmIngressClientAuth {
    /// Create an empty registry. Guests are rejected until trust anchors and
    /// identities are registered.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    generate_set_and_with! {
        /// Replace the trust anchors guests must chain to.
        ///
        /// Each DER certificate becomes a trusted ingress client CA. Minted
        /// acceptors fail handshakes without a chain to this trust. Empty
        /// trust rejects every guest.
        pub fn trust_anchors(mut self, certificates: impl IntoIterator<Item = CertificateDer<'static>>) -> Self {
            self.trust = certificates.into_iter().collect();
            self
        }
    }

    generate_set_and_with! {
        /// Add certificates to the guest trust anchors.
        pub fn extra_trust_anchors(mut self, certificates: impl IntoIterator<Item = CertificateDer<'static>>) -> Self {
            self.trust.extend(certificates);
            self
        }
    }

    generate_set_and_with! {
        /// Register one guest leaf with the upstream key to present for it.
        ///
        /// The leaf is `identity.cert_chain[0]`; the whole pair is presented
        /// upstream on a match. Entries with an empty chain never match and
        /// are skipped.
        pub fn identity(mut self, identity: ClientAuthData) -> Self {
            if let Some(leaf) = identity.cert_chain.first() {
                self.identities
                    .insert(fingerprint_leaf(leaf.as_ref()), identity);
            }
            self
        }
    }

    generate_set_and_with! {
        /// Register more guest leaves with their upstream keys.
        ///
        /// Same as [`identity`](Self::with_identity) per entry.
        pub fn identities(mut self, identities: impl IntoIterator<Item = ClientAuthData>) -> Self {
            for identity in identities {
                if let Some(leaf) = identity.cert_chain.first() {
                    self.identities
                        .insert(fingerprint_leaf(leaf.as_ref()), identity);
                }
            }
            self
        }
    }

    /// Borrow the guest trust anchors.
    #[must_use]
    pub(super) fn trust_anchors(&self) -> &[CertificateDer<'static>] {
        &self.trust
    }

    /// Match a presented leaf DER against the registry.
    ///
    /// Hashes the input with [`fingerprint_leaf`] and returns the registered
    /// pair, if any.
    pub(super) fn match_leaf(&self, leaf_der: &[u8]) -> Option<&ClientAuthData> {
        self.identities.get(&fingerprint_leaf(leaf_der))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::client_identity;
    use rama_boring::x509::X509;

    #[test]
    fn defaults_match_nothing() {
        let auth = TlsMitmIngressClientAuth::new();
        assert!(auth.match_leaf(&[1, 2, 3]).is_none());
    }

    #[test]
    fn match_leaf_hits_first_chain_cert_only() {
        let (root, first) = client_identity();
        let (_, second) = client_identity();
        let auth = TlsMitmIngressClientAuth::new()
            .with_trust_anchors([root])
            .with_identities([first.clone(), second.clone()]);

        let first_leaf = first.cert_chain[0].as_ref().to_vec();
        let second_leaf = second.cert_chain[0].as_ref().to_vec();
        assert_eq!(
            auth.match_leaf(&first_leaf)
                .expect("first leaf matches")
                .cert_chain[0]
                .as_ref(),
            first_leaf.as_slice()
        );
        assert_eq!(
            auth.match_leaf(&second_leaf)
                .expect("second leaf matches")
                .cert_chain[0]
                .as_ref(),
            second_leaf.as_slice()
        );
        assert!(auth.match_leaf(&[9, 9, 9]).is_none());
        // Chain intermediates never match on their own.
        if first.cert_chain.len() > 1 {
            let intermediate = first.cert_chain[1].as_ref().to_vec();
            if intermediate != first_leaf && intermediate != second_leaf {
                assert!(auth.match_leaf(&intermediate).is_none());
            }
        }
    }

    #[test]
    fn fingerprint_stable_across_der_parse() {
        let (_, identity) = client_identity();
        let leaf_der = identity.cert_chain[0].as_ref().to_vec();
        let parsed = X509::from_der(&leaf_der).expect("parse leaf");
        let reserialized = parsed.to_der().expect("reserialize leaf");
        assert_eq!(fingerprint_leaf(&leaf_der), fingerprint_leaf(&reserialized));

        let auth = TlsMitmIngressClientAuth::new().with_identity(identity);
        assert!(auth.match_leaf(&reserialized).is_some());
    }

    #[test]
    fn empty_chain_entries_never_match() {
        let (_, mut identity) = client_identity();
        identity.cert_chain.clear();
        let auth = TlsMitmIngressClientAuth::new().with_identity(identity);
        assert!(auth.match_leaf(&[]).is_none());
        assert_eq!(
            format!("{auth:?}"),
            "TlsMitmIngressClientAuth { trust_anchors: 0, identities: 0 }"
        );
    }

    #[test]
    fn debug_elides_key_bytes() {
        let (root, identity) = client_identity();
        let key_bytes = identity.private_key.secret_der().to_vec();
        let auth = TlsMitmIngressClientAuth::new()
            .with_trust_anchors([root])
            .with_identity(identity);
        let debug = format!("{auth:?}");
        assert!(debug.contains("trust_anchors"));
        assert!(debug.contains("identities"));
        assert!(!debug.contains("private_key"));
        // Raw key material must not leak even if it renders as text.
        if let Ok(key_text) = std::str::from_utf8(&key_bytes) {
            if key_text.len() > 8 {
                assert!(!debug.contains(key_text));
            }
        }
    }

    #[test]
    fn builders_replace_and_extend() {
        let (root_a, id_a) = client_identity();
        let (root_b, id_b) = client_identity();
        let auth = TlsMitmIngressClientAuth::new()
            .with_trust_anchors([root_a.clone()])
            .with_extra_trust_anchors([root_b.clone()]);
        assert_eq!(auth.trust.len(), 2);

        let auth = auth.with_trust_anchors([root_a.clone()]);
        assert_eq!(auth.trust, [root_a]);

        let leaf_a = id_a.cert_chain[0].as_ref().to_vec();
        let leaf_b = id_b.cert_chain[0].as_ref().to_vec();
        let auth = auth.with_identity(id_a).with_identities([id_b]);
        assert!(auth.match_leaf(&leaf_a).is_some());
        assert!(auth.match_leaf(&leaf_b).is_some());
    }

    // Drop zeroization is intentionally not asserted: observing it would
    // require reading freed memory (unsafe) after the registry drops. The
    // `Drop` impl calls `Zeroize` on every stored private key; behavior of
    // `Zeroize` itself is covered by its own crate tests.
}
