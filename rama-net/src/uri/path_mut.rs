//! RAII guard for incremental path mutation.
//!
//! Created by [`Uri::path_mut`](super::Uri::path_mut). Amortises the
//! Lazy → Owned promotion across multiple operations and supports
//! the common `push_segment` / `pop_segment` pattern.

use rama_core::bytes::BytesMut;

use super::component_input::IntoUriComponent;
use super::encode;
use super::owned::OwnedUriRef;

/// Mutable view of a [`Uri`](super::Uri)'s path component.
///
/// Holds the Owned representation of the URI for the guard's lifetime.
/// Each method modifies the path in place. Drop releases the borrow —
/// no special finalization required.
pub struct PathMut<'a> {
    owned: &'a mut OwnedUriRef,
}

impl<'a> PathMut<'a> {
    #[inline]
    pub(crate) fn new(owned: &'a mut OwnedUriRef) -> Self {
        Self { owned }
    }

    /// Append a `/`-delimited segment, percent-encoding any bytes that
    /// aren't legal in a URI path segment per RFC 3986.
    ///
    /// Encodes: ASCII controls, space, `"`, `#`, `%`, `/`, `<`, `>`,
    /// `?`, `[`, `\`, `]`, `^`, `` ` ``, `{`, `|`, `}`, and every
    /// non-ASCII byte. Passes through: ALPHA, DIGIT, `-._~`,
    /// `!$&'()*+,;=`, `:`, `@`. The `%` itself is encoded to `%25` —
    /// pass already-decoded values, not pre-encoded ones.
    ///
    /// If the current path doesn't already end with `/`, one is
    /// inserted before the segment. Empty path + `push_segment("x")`
    /// yields `/x`. `/foo` + `push_segment("bar")` yields `/foo/bar`.
    /// `/foo/` + `push_segment("bar")` yields `/foo/bar` (no double
    /// slash).
    #[expect(
        clippy::needless_pass_by_value,
        reason = "by-value matches IntoUriComponent's signature on sibling setters; this impl only borrows because percent_encode can't consume its input"
    )]
    pub fn push_segment(&mut self, segment: impl IntoUriComponent) -> &mut Self {
        let bytes = segment.as_uri_component_bytes();
        if !self.owned.path.ends_with(b"/") {
            self.owned.path.extend_from_slice(b"/");
        }
        encode::extend_encoded_segment(&mut self.owned.path, bytes);
        self
    }

    /// Remove and return the last path segment.
    ///
    /// `/foo/bar` → `Some("bar")`, path becomes `/foo`. `/foo/` →
    /// `Some("")`, path becomes `/foo`. `/foo` → `Some("foo")`, path
    /// becomes empty. Empty path → `None`. Opaque paths (no `/`) → the
    /// whole path is returned.
    ///
    /// The returned bytes are the raw on-wire form (still
    /// percent-encoded). Use [`PathSegment::as_decoded_str`](super::PathSegment::as_decoded_str)
    /// on the corresponding [`PathRef::segments`](super::PathRef::segments)
    /// item before mutation if you need the decoded value.
    pub fn pop_segment(&mut self) -> Option<BytesMut> {
        if self.owned.path.is_empty() {
            return None;
        }
        match memchr::memrchr(b'/', &self.owned.path) {
            Some(i) => {
                let mut removed = self.owned.path.split_off(i);
                let _slash = removed.split_to(1);
                Some(removed)
            }
            None => Some(std::mem::take(&mut self.owned.path)),
        }
    }

    /// Clear the path entirely.
    pub fn clear(&mut self) -> &mut Self {
        self.owned.path.clear();
        self
    }
}

impl std::fmt::Debug for PathMut<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Safety: parser invariant — path bytes are valid UTF-8.
        let path = unsafe { std::str::from_utf8_unchecked(&self.owned.path) };
        f.debug_struct("PathMut").field("path", &path).finish()
    }
}
