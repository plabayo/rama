//! Lazy-form internals for a parsed [`Uri`](super::Uri).
//!
//! `LazyUriRef` is the cheap-to-clone "parsed once, never mutated" form. It
//! holds the original bytes plus pre-parsed offsets and scalars. Borrowed
//! reads project into the bytes; first mutation triggers an upgrade to
//! [`OwnedUriRef`](super::owned::OwnedUriRef).

use crate::Protocol;
use crate::address::Host;

use rama_core::bytes::{ByteStr, Bytes};

/// Parsed-once URI reference. Reads are zero-copy slices into `bytes`;
/// mutation upgrades to [`OwnedUriRef`](super::owned::OwnedUriRef).
#[derive(Debug, Clone)]
pub(crate) struct LazyUriRef {
    /// The original input buffer. All component ranges below index into this.
    pub(crate) bytes: ByteStr,

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
    /// `Some(empty)` = `?` with empty content. These are distinct URIs per
    /// RFC 3986 §3.4, and request signatures (SigV4), cache keys and proxy
    /// forwarding depend on keeping them apart.
    pub(crate) query: Option<(u16, u16)>,

    /// Fragment range (no leading `#`). Same `None` vs `Some(empty)`
    /// distinction as `query`, per §3.5.
    pub(crate) fragment: Option<(u16, u16)>,
}

impl LazyUriRef {
    /// The whole source buffer as `str`.
    pub(crate) fn as_str(&self) -> &str {
        &self.bytes
    }

    /// The whole source buffer as bytes.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.bytes.as_bytes()
    }

    /// `[start, end)` of the source buffer as `str`.
    ///
    /// # Panics
    ///
    /// If the range is out of bounds or not on `char` boundaries.
    pub(crate) fn str_range(&self, (start, end): (u16, u16)) -> &str {
        &self.as_str()[usize::from(start)..usize::from(end)]
    }
}

/// A [`ByteStr`] sharing `owner`'s allocation for `sub`.
///
/// # Panics
///
/// If `sub` does not lie within `owner` (see [`Bytes::slice_ref`]).
pub(crate) fn byte_str_slice(owner: &Bytes, sub: &str) -> ByteStr {
    let bytes = owner.slice_ref(sub.as_bytes());
    // SAFETY: `ByteStr::from_utf8_unchecked` requires valid UTF-8.
    // `Bytes::slice_ref` returns the bytes of the given subset, so `bytes`
    // equals `sub`, a `str`.
    unsafe { ByteStr::from_utf8_unchecked(bytes) }
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
