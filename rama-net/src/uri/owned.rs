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
#[expect(
    dead_code,
    reason = "M2 skeleton: fields consumed by M5 (mutation API)"
)]
pub(crate) struct OwnedUriRef {
    pub(crate) scheme: Option<Protocol>,
    pub(crate) authority: Option<Authority>,
    /// Path bytes. Empty `BytesMut` means an empty path.
    pub(crate) path: BytesMut,
    pub(crate) query: Option<Query>,
    pub(crate) fragment: Option<Fragment>,
}
