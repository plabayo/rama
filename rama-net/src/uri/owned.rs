//! Owned-form internals for a parsed [`Uri`](super::Uri).
//!
//! `OwnedUriRef` holds decomposed, individually mutable components. Reached
//! by upgrading from [`LazyUriRef`](super::lazy::LazyUriRef) on first
//! mutation via the (pub(crate)) `to_mut` machinery in `mod.rs`.
//!
//! Skeleton — the upgrade conversion and mutation API land in M5.

use rama_core::bytes::BytesMut;

use crate::Protocol;
use crate::address::Authority;

use super::{Fragment, Query};

/// Decomposed, individually mutable URI reference.
#[derive(Debug, Clone, Default)]
pub(crate) struct OwnedUriRef {
    pub(crate) scheme: Option<Protocol>,
    pub(crate) authority: Option<Authority>,
    /// Path bytes. Always present (§3.3); empty `BytesMut` = empty path.
    /// `/` is part of the path itself, not an outer delimiter — hence no `Option`.
    pub(crate) path: BytesMut,
    /// `None` = no `?` on wire; `Some(empty)` = `?` with empty content.
    /// Distinct URIs per §3.4 (SigV4 / cache keys / proxy fidelity).
    pub(crate) query: Option<Query>,
    /// Same `None` vs `Some(empty)` distinction as `query`, per §3.5.
    pub(crate) fragment: Option<Fragment>,
}
