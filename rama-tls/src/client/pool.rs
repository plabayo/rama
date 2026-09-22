use std::hash::{Hash, Hasher};

use rama_core::extensions::Extension;
use sha2::{Digest as _, Sha256};

/// Compact identity of request-level TLS configuration overrides.
///
/// Provider configuration views return `None` when no overrides are present.
/// Explicit default values remain distinct from absence: they may replace a
/// different connector default. Common settings have the same identity across
/// providers; native settings use a separate namespace.
///
/// Opaque credentials, verifiers, hooks and custom key-log sinks cannot be
/// compared by value. Their identity is non-reusable, and a pool must honor
/// [`Self::is_reusable`] before both lookup and return. Equality itself remains
/// reflexive, including for non-reusable identities.
///
/// This identifies overrides within a pool with fixed connector defaults. It
/// does not compare different connectors or encode the destination. The hash
/// encoding is local to the build, not a stable serialization or TLS fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Extension)]
#[extension(tags(tls))]
pub struct TlsPoolId {
    digest: [u8; 32],
    reusable: bool,
}

impl TlsPoolId {
    /// Identify settings that are completely comparable by value.
    ///
    /// Provider integrations must include every effective override, preserve
    /// absence versus explicit values, and namespace their native fields.
    /// Custom connectors may use this to identify their own comparable policy.
    /// Never use object addresses as a substitute for opaque policy semantics.
    #[must_use]
    pub fn from_hash(settings: &impl Hash) -> Self {
        Self {
            digest: policy_digest(b"rama.tls.overrides.v1", settings),
            reusable: true,
        }
    }

    /// Require a fresh connection that is discarded after use.
    #[must_use]
    pub const fn non_reusable() -> Self {
        Self {
            digest: [0; 32],
            reusable: false,
        }
    }

    /// Whether this identity may participate in connection reuse.
    #[must_use]
    pub const fn is_reusable(&self) -> bool {
        self.reusable
    }
}

pub(crate) fn policy_digest(domain: &[u8], settings: &impl Hash) -> [u8; 32] {
    let mut state = PolicyHasher(Sha256::new());
    state.write(domain);
    settings.hash(&mut state);
    state.0.finalize().into()
}

// Frame every Hash write, in addition to the field/presence framing supplied by
// tuple, Option and collection Hash implementations. No 64-bit projection is
// used for identity equality.
struct PolicyHasher(Sha256);

impl Hasher for PolicyHasher {
    fn finish(&self) -> u64 {
        let digest = self.0.clone().finalize();
        let mut prefix = [0; 8];
        prefix.copy_from_slice(&digest[..8]);
        u64::from_be_bytes(prefix)
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.update((bytes.len() as u64).to_be_bytes());
        self.0.update(bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{
        TlsServerCertPin, TlsServerCertPinSet, TlsServerCertPins, TlsServerTrustAnchors,
    };
    use rama_utils::octets::kib;

    #[test]
    fn compact_identity_preserves_presence_and_reflexive_equality() {
        assert!(std::mem::size_of::<TlsPoolId>() <= 40);
        assert_ne!(
            TlsPoolId::from_hash(&None::<bool>),
            TlsPoolId::from_hash(&Some(false))
        );
        let opaque = TlsPoolId::non_reusable();
        assert_eq!(opaque, opaque);
        assert!(!opaque.is_reusable());
        let known = TlsPoolId::from_hash(&(Some(false), "name.example"));
        assert_eq!(known, TlsPoolId::from_hash(&(Some(false), "name.example")));
        assert!(known.is_reusable());
        assert_ne!(known, opaque);
    }

    #[test]
    fn hash_writes_and_domains_are_unambiguous() {
        let mut one = PolicyHasher(Sha256::new());
        one.write(b"ab");
        one.write(b"c");
        let mut two = PolicyHasher(Sha256::new());
        two.write(b"a");
        two.write(b"bc");
        assert_ne!(one.0.finalize(), two.0.finalize());
        assert_ne!(policy_digest(b"one", &42), policy_digest(b"two", &42));
        assert_ne!(
            TlsPoolId::from_hash(&("ab", "c")),
            TlsPoolId::from_hash(&("a", "bc"))
        );
    }

    #[test]
    fn cached_certificate_hashes_are_bounded_and_updated_after_mutation() {
        struct ByteCounter(usize);

        impl Hasher for ByteCounter {
            fn finish(&self) -> u64 {
                0
            }

            fn write(&mut self, bytes: &[u8]) {
                self.0 += bytes.len();
            }
        }

        let large = vec![7; kib(64)];
        let pins = TlsServerCertPins::new(TlsServerCertPin::ExactDer(large.clone().into()));
        let anchors = TlsServerTrustAnchors::try_new([large.clone().into()]).unwrap();
        let mut counter = ByteCounter(0);
        pins.hash(&mut counter);
        anchors.hash(&mut counter);
        assert!(
            counter.0 <= 80,
            "certificate bytes were rehashed: {}",
            counter.0
        );
        assert_eq!(
            pins,
            TlsServerCertPins::new(TlsServerCertPin::ExactDer(large.clone().into()))
        );
        assert_eq!(
            anchors,
            TlsServerTrustAnchors::try_new([large.into()]).unwrap()
        );

        let original_id = TlsPoolId::from_hash(&pins);
        let changed = pins
            .clone()
            .with_pin_set(TlsServerCertPin::SpkiSha256([8; 32]));
        assert_eq!(original_id, TlsPoolId::from_hash(&pins));
        assert_ne!(original_id, TlsPoolId::from_hash(&changed));
        assert_eq!(
            TlsPoolId::from_hash(&changed),
            TlsPoolId::from_hash(&pins.with_pin_set(TlsServerCertPin::SpkiSha256([8; 32])))
        );

        let scoped = |name: &str| {
            TlsServerCertPins::new(
                TlsServerCertPinSet::new(TlsServerCertPin::SpkiSha256([1; 32]))
                    .with_server_name(name.parse::<rama_net::address::Host>().unwrap()),
            )
        };
        let lower = scoped("example.test");
        let upper = scoped("EXAMPLE.TEST");
        assert_eq!(lower, upper);
        assert_eq!(TlsPoolId::from_hash(&lower), TlsPoolId::from_hash(&upper));
    }
}
