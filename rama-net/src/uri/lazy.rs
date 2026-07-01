//! Lazy-form internals for a parsed [`Uri`](super::Uri).
//!
//! `LazyUriRef` is the cheap-to-clone "parsed once, never mutated" form. It
//! holds the original bytes plus pre-parsed offsets and scalars. Borrowed
//! reads project into the bytes; first mutation triggers an upgrade to
//! [`OwnedUriRef`](super::owned::OwnedUriRef).
//!
//! Skeleton — fields are in place so M3 (parser) and M4 (accessors) can
//! consume them. Methods land in those milestones.

use crate::Protocol;
use crate::address::Host;

use rama_core::bytes::Bytes;

/// Parsed-once URI reference. Reads are zero-copy slices into `bytes`;
/// mutation upgrades to [`OwnedUriRef`](super::owned::OwnedUriRef).
#[derive(Debug, Clone)]
pub(crate) struct LazyUriRef {
    /// The original input buffer. All component ranges below index into this.
    pub(crate) bytes: Bytes,

    /// Pre-parsed scheme (cheap to keep — `Protocol` is small and is read on
    /// almost every URI operation).
    pub(crate) scheme: Option<Protocol>,

    /// Optional authority. When present, carries pre-parsed host (incl. IP
    /// values), pre-parsed port, plus the userinfo byte range (parsed lazily
    /// on demand).
    pub(crate) authority: Option<LazyAuthority>,

    /// Path range. Always present (§3.3); empty range = empty path.
    /// `/` is part of the path itself, not an outer delimiter — hence no `Option`.
    pub(crate) path: (u16, u16),

    /// Query range (no leading `?`). `None` = no `?` on wire;
    /// `Some(empty)` = `?` with empty content. Distinct URIs per §3.4
    /// (load-bearing for SigV4, cache keys, proxy fidelity).
    pub(crate) query: Option<(u16, u16)>,

    /// Fragment range (no leading `#`). Same `None` vs `Some(empty)`
    /// distinction as `query`, per §3.5.
    pub(crate) fragment: Option<(u16, u16)>,
}

/// Parsed-once authority for [`LazyUriRef`].
#[derive(Debug, Clone)]
pub(crate) struct LazyAuthority {
    /// Byte range of userinfo (sans `@`) within the parent buffer, if any.
    pub(crate) userinfo_range: Option<(u16, u16)>,

    /// Pre-parsed host. Domain variants reference a zero-copy slice of the
    /// parent `Bytes`; IP variants carry the address value directly.
    pub(crate) host: Host,

    /// Parsed port marker. `Unset` = no `:` after host; `Empty` = `:`
    /// with no digits; `Set(n)` = explicit port.
    pub(crate) port: crate::address::OptPort,
}
