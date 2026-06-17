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
        encode::extend_encoded_segment(&mut self.owned.path, &bytes);
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

    /// Append multiple `/`-delimited segments at once.
    ///
    /// Splits the input on `/` and pushes each piece via
    /// [`push_segment`](Self::push_segment), so every piece is
    /// percent-encoded under the path-segment policy (a literal `/`
    /// inside the input is the separator, not encoded). The normal
    /// slash-insertion rule applies, so `"a/b"` and `"/a/b"` both append
    /// `/a/b`, internal `//` collapses to a single separator, and a
    /// trailing `/` yields a trailing empty segment.
    ///
    /// `"/api"` + `push_segments("v2/users")` → `/api/v2/users`.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "by-value matches IntoUriComponent's signature on sibling setters; this impl only borrows because percent_encode can't consume its input"
    )]
    pub fn push_segments(&mut self, segments: impl IntoUriComponent) -> &mut Self {
        let bytes = segments.as_uri_component_bytes();
        for piece in bytes.split(|&b| b == b'/') {
            self.push_segment(piece);
        }
        self
    }

    /// Remove up to `n` trailing segments, returning the number actually
    /// removed (fewer than `n` if the path runs out first).
    ///
    /// Equivalent to calling [`pop_segment`](Self::pop_segment) `n`
    /// times, stopping early at an empty path.
    pub fn pop_segments(&mut self, n: usize) -> usize {
        let mut removed = 0;
        while removed < n && self.pop_segment().is_some() {
            removed += 1;
        }
        removed
    }

    /// Strip a leading prefix from the path, re-rooting the remainder
    /// with a single leading `/`. Matching is **case-sensitive** (RFC
    /// 3986 paths are case-sensitive); see
    /// [`strip_prefix_ignore_ascii_case`](Self::strip_prefix_ignore_ascii_case)
    /// for the case-insensitive variant.
    ///
    /// The comparison is on the raw (percent-encoded) bytes. The path's
    /// leading `/` and any leading/trailing `/` on `prefix` are ignored,
    /// and the match may land mid-segment: `/foo/bar` with prefix `foo`
    /// (or `/foo/`) becomes `/bar`, and prefix `foo/b` becomes `/ar`.
    ///
    /// Returns `true` when the prefix matched and was removed; on no
    /// match the path is left unchanged and `false` is returned.
    pub fn strip_prefix(&mut self, prefix: impl IntoUriComponent) -> bool {
        self.strip_prefix_inner(prefix, false)
    }

    /// Like [`strip_prefix`](Self::strip_prefix) but compares the prefix
    /// case-insensitively for ASCII bytes (`A-Z` ≡ `a-z`), e.g.
    /// `/FOO/bar` with prefix `foo` becomes `/bar`. Non-ASCII bytes
    /// still compare exactly.
    ///
    /// Returns `true` when the prefix matched and was removed.
    pub fn strip_prefix_ignore_ascii_case(&mut self, prefix: impl IntoUriComponent) -> bool {
        self.strip_prefix_inner(prefix, true)
    }

    #[expect(
        clippy::needless_pass_by_value,
        reason = "by-value matches IntoUriComponent's signature on sibling setters; this impl only borrows the input"
    )]
    fn strip_prefix_inner(
        &mut self,
        prefix: impl IntoUriComponent,
        ignore_ascii_case: bool,
    ) -> bool {
        let prefix_bytes = prefix.as_uri_component_bytes();
        let prefix = trim_ascii_slashes(&prefix_bytes);
        let new = {
            let path: &[u8] = &self.owned.path;
            let body = path.strip_prefix(b"/").unwrap_or(path);
            let matches = if ignore_ascii_case {
                body.len() >= prefix.len() && body[..prefix.len()].eq_ignore_ascii_case(prefix)
            } else {
                body.starts_with(prefix)
            };
            if !matches {
                return false;
            }
            let mut rest = &body[prefix.len()..];
            while let Some(stripped) = rest.strip_prefix(b"/") {
                rest = stripped;
            }
            let mut new = BytesMut::with_capacity(rest.len() + 1);
            new.extend_from_slice(b"/");
            new.extend_from_slice(rest);
            new
        };
        self.owned.path = new;
        true
    }
}

/// Trim all leading and trailing `/` bytes from a slice.
fn trim_ascii_slashes(mut bytes: &[u8]) -> &[u8] {
    while let Some(rest) = bytes.strip_prefix(b"/") {
        bytes = rest;
    }
    while let Some(rest) = bytes.strip_suffix(b"/") {
        bytes = rest;
    }
    bytes
}

impl std::fmt::Debug for PathMut<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Safety: parser invariant — path bytes are valid UTF-8.
        let path = unsafe { std::str::from_utf8_unchecked(&self.owned.path) };
        f.debug_struct("PathMut").field("path", &path).finish()
    }
}
