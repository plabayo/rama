//! RAII guard for incremental path mutation.
//!
//! Created by [`Uri::path_mut`](super::Uri::path_mut). Amortises the
//! Lazy → Owned promotion across multiple operations and supports
//! the common `push_segment` / `pop_segment` pattern.

use rama_core::bytes::BytesMut;

use super::component_input::IntoUriComponent;
use super::encode;
use super::owned::OwnedUriRef;
use super::path::{
    PathMatchOptions, match_prefix_in_body, match_suffix_in_body, segment_range_bounds,
    trim_ascii_slashes,
};

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
        if !self.owned.path.ends_with(b"/") {
            self.owned.path.extend_from_slice(b"/");
        }
        encode::extend_encoded_segment(&mut self.owned.path, segment);
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

    /// Ensure the path ends with exactly one trailing `/`: appended when
    /// missing, left alone when already present. An empty path becomes `/`.
    pub fn ensure_trailing_slash(&mut self) -> &mut Self {
        if !self.owned.path.ends_with(b"/") {
            self.owned.path.extend_from_slice(b"/");
        }
        self
    }

    /// Normalize the path by removing trailing `/` characters while keeping a
    /// single leading `/`. Leading duplicate slashes are collapsed as part of
    /// the same operation. Returns `true` when the path changed.
    pub fn trim_trailing_slash(&mut self) -> bool {
        let path = &self.owned.path;
        if !path.ends_with(b"/") && !path.starts_with(b"//") {
            return false;
        }

        let body = trim_ascii_slashes(path);
        let mut new = BytesMut::with_capacity(body.len() + 1);
        new.extend_from_slice(b"/");
        new.extend_from_slice(body);
        self.owned.path = new;
        true
    }

    /// Normalize the path by ensuring one trailing `/` and collapsing duplicate
    /// trailing slashes. Returns `true` when the path changed.
    pub fn append_trailing_slash(&mut self) -> bool {
        let path = &self.owned.path;
        if path.ends_with(b"/") && !path.ends_with(b"//") {
            return false;
        }

        let body = trim_ascii_slashes(path);
        let mut new = BytesMut::with_capacity(body.len() + 2);
        new.extend_from_slice(b"/");
        new.extend_from_slice(body);
        if !body.is_empty() {
            new.extend_from_slice(b"/");
        }
        self.owned.path = new;
        true
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

    /// Strip a leading `prefix` from the path, re-rooting the remainder with
    /// a single leading `/`. Matching uses the default [`PathMatchOptions`]
    /// (segment-boundary, percent-decoded, case-sensitive); see
    /// [`strip_prefix_with_opts`](Self::strip_prefix_with_opts) to allow
    /// partial / raw / case-insensitive matching.
    ///
    /// Returns `true` when the prefix matched and was removed; otherwise the
    /// path is left unchanged and `false` is returned.
    pub fn strip_prefix(&mut self, prefix: impl IntoUriComponent) -> bool {
        self.strip_prefix_with_opts(prefix, PathMatchOptions::default())
    }

    /// Strip the first `count` path segments, re-rooting the remainder with a
    /// single leading `/`.
    ///
    /// Returns `false` when the path has fewer than `count` segments. A
    /// `count` of `0` only re-roots the current path.
    pub fn strip_prefix_segments(&mut self, count: usize) -> bool {
        let new = {
            let path: &[u8] = &self.owned.path;
            let rest = if count == 0 {
                path
            } else {
                let Some((_, end)) = segment_range_bounds(path, 0, count) else {
                    return false;
                };
                &path[end..]
            };
            let rest = trim_ascii_slashes(rest);
            let mut new = BytesMut::with_capacity(rest.len() + 1);
            new.extend_from_slice(b"/");
            new.extend_from_slice(rest);
            new
        };
        self.owned.path = new;
        true
    }

    /// [`strip_prefix`](Self::strip_prefix) with explicit [`PathMatchOptions`].
    #[expect(
        clippy::needless_pass_by_value,
        reason = "by-value matches IntoUriComponent's signature on sibling setters; this impl only borrows the input"
    )]
    pub fn strip_prefix_with_opts(
        &mut self,
        prefix: impl IntoUriComponent,
        opts: PathMatchOptions,
    ) -> bool {
        let prefix = prefix.as_uri_component_bytes();
        let new = {
            let path: &[u8] = &self.owned.path;
            let body = path.strip_prefix(b"/").unwrap_or(path);
            let Some(offset) = match_prefix_in_body(body, &prefix, opts) else {
                return false;
            };
            let mut rest = &body[offset..];
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

    /// Strip a trailing `suffix` from the path, keeping a single leading `/`.
    /// Matching uses the default [`PathMatchOptions`]; see
    /// [`strip_suffix_with_opts`](Self::strip_suffix_with_opts) for the rest.
    ///
    /// Returns `true` when the suffix matched and was removed.
    pub fn strip_suffix(&mut self, suffix: impl IntoUriComponent) -> bool {
        self.strip_suffix_with_opts(suffix, PathMatchOptions::default())
    }

    /// [`strip_suffix`](Self::strip_suffix) with explicit [`PathMatchOptions`].
    #[expect(
        clippy::needless_pass_by_value,
        reason = "by-value matches IntoUriComponent's signature on sibling setters; this impl only borrows the input"
    )]
    pub fn strip_suffix_with_opts(
        &mut self,
        suffix: impl IntoUriComponent,
        opts: PathMatchOptions,
    ) -> bool {
        let suffix = suffix.as_uri_component_bytes();
        let new = {
            let path: &[u8] = &self.owned.path;
            let body = path.strip_prefix(b"/").unwrap_or(path);
            let Some(keep) = match_suffix_in_body(body, &suffix, opts) else {
                return false;
            };
            let kept = &body[..keep];
            let mut new = BytesMut::with_capacity(kept.len() + 1);
            new.extend_from_slice(b"/");
            new.extend_from_slice(kept);
            new
        };
        self.owned.path = new;
        true
    }
}

impl std::fmt::Debug for PathMut<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Safety: parser invariant — path bytes are valid UTF-8.
        let path = unsafe { std::str::from_utf8_unchecked(&self.owned.path) };
        f.debug_struct("PathMut").field("path", &path).finish()
    }
}
