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
    /// Path bytes. Always present per RFC 3986 §3.3 — an empty `BytesMut`
    /// models the empty path (`path-empty` production). No `Option`
    /// because there's no wire signal that distinguishes "no path" from
    /// "empty path".
    pub(crate) path: BytesMut,
    /// `None` = no `?` delimiter on the wire; `Some(empty)` = `?` with no
    /// content. The two are distinct URIs per RFC 3986 §3.4 and must
    /// round-trip differently.
    pub(crate) query: Option<Query>,
    /// `None` vs `Some(empty)` distinction analogous to `query`, per
    /// RFC 3986 §3.5.
    pub(crate) fragment: Option<Fragment>,
}
