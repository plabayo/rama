use std::{
    fmt,
    hash::{Hash, Hasher},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use rama_crypto::pki_types::CertificateDer;

use super::controller::NativeTrustScope;

/// Immutable trust material selected for a particular handshake.
#[derive(Clone)]
pub(in crate::client) struct NativeTrustSnapshot(Arc<SnapshotData>);

struct SnapshotData {
    generation: u64,
    scope: NativeTrustScope,
    anchors: Vec<CertificateDer<'static>>,
}

impl NativeTrustSnapshot {
    pub(super) fn new(scope: NativeTrustScope, anchors: Vec<CertificateDer<'static>>) -> Self {
        static GENERATION: AtomicU64 = AtomicU64::new(1);
        Self(Arc::new(SnapshotData {
            generation: GENERATION.fetch_add(1, Ordering::Relaxed),
            scope,
            anchors,
        }))
    }

    pub(super) fn matches_anchors(&self, anchors: &[CertificateDer<'static>]) -> bool {
        self.0.anchors == anchors
    }

    pub(in crate::client) fn native_roots(&self) -> Option<&[CertificateDer<'static>]> {
        matches!(self.0.scope, NativeTrustScope::Full).then_some(&self.0.anchors)
    }

    pub(in crate::client) fn platform_extra_roots(&self) -> Option<&[CertificateDer<'static>]> {
        matches!(self.0.scope, NativeTrustScope::PlatformExtras).then_some(&self.0.anchors)
    }
}

impl fmt::Debug for NativeTrustSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeTrustSnapshot")
            .field("generation", &self.0.generation)
            .field("scope", &self.0.scope)
            .field("anchor_count", &self.0.anchors.len())
            .finish()
    }
}

impl PartialEq for NativeTrustSnapshot {
    fn eq(&self, other: &Self) -> bool {
        self.0.generation == other.0.generation
    }
}

impl Eq for NativeTrustSnapshot {}

impl Hash for NativeTrustSnapshot {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.generation.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::{NativeTrustScope, NativeTrustSnapshot};

    #[test]
    fn pinned_scope_and_identity_are_preserved_even_for_empty_roots() {
        let full = NativeTrustSnapshot::new(NativeTrustScope::Full, vec![]);
        let extras = NativeTrustSnapshot::new(NativeTrustScope::PlatformExtras, vec![]);
        assert_eq!(full, full.clone());
        assert_ne!(full, extras);
        assert_eq!(full.native_roots(), Some([].as_slice()));
        assert_eq!(full.platform_extra_roots(), None);
        assert_eq!(extras.native_roots(), None);
        assert_eq!(extras.platform_extra_roots(), Some([].as_slice()));
    }
}
