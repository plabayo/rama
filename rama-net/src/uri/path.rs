//! Borrowed view of a [`Uri`](super::Uri)'s path component.
//!
//! The owned storage for the path lives directly inside `OwnedUriRef` as a
//! `BytesMut` — there is no separate `Path` owned type. The borrowed view
//! is just a `&[u8]` plus iteration helpers.

use std::borrow::Cow;

use percent_encoding::percent_decode;

/// Borrowed view of a URI path.
///
/// The bytes are the raw on-the-wire form (percent-encoded). Iterate
/// segments via [`PathRef::segments`] — each segment can be inspected
/// raw or percent-decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathRef<'a> {
    pub(crate) bytes: &'a [u8],
}

impl<'a> PathRef<'a> {
    /// Construct a [`PathRef`] from a byte slice. `pub(crate)` — only
    /// the parser / accessors should produce one; external code goes
    /// through [`Uri::path`](super::Uri::path).
    #[must_use]
    #[inline]
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Returns the raw on-the-wire path bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the raw path as a `&str` (no percent-decoding). The path is
    /// guaranteed UTF-8 by the parser (`graceful` accepts UTF-8 bytes;
    /// `strict` only accepts ASCII).
    ///
    /// **No `as_decoded_str` for the whole path** — percent-decoding
    /// across segment boundaries (e.g. `%2F` → `/`) is a path-traversal
    /// vector. Iterate [`segments`](Self::segments) and call
    /// [`PathSegment::as_decoded_str`] on each instead.
    #[must_use]
    pub fn as_raw_str(&self) -> &'a str {
        // Safety: parser ensures the bytes are valid UTF-8.
        unsafe { std::str::from_utf8_unchecked(self.bytes) }
    }

    /// Iterator over path segments — the parts between `/` separators.
    ///
    /// Behaviour matches `url::Url::path_segments` for predictability:
    /// - empty path → empty iterator
    /// - path starts with `/` → the leading `/` is a delimiter, not a
    ///   segment, and is stripped before splitting
    /// - trailing `/` → yields an empty segment at the end (preserves
    ///   the distinction between `/foo` and `/foo/`)
    /// - opaque paths (no leading `/`, e.g. `urn:isbn:0` → path
    ///   `isbn:0`) split from the start
    ///
    /// Each [`PathSegment`] is the raw bytes; call [`PathSegment::as_decoded_str`]
    /// for the percent-decoded form.
    ///
    /// Examples:
    /// ```text
    /// ""          -> []
    /// "/"         -> [""]
    /// "/foo"      -> ["foo"]
    /// "/foo/"     -> ["foo", ""]
    /// "/foo/bar"  -> ["foo", "bar"]
    /// "/a//b"     -> ["a", "", "b"]
    /// "foo/bar"   -> ["foo", "bar"]
    /// ```
    #[must_use]
    pub fn segments(&self) -> PathSegments<'a> {
        if self.bytes.is_empty() {
            return PathSegments::empty();
        }
        // Strip the leading `/` if present — it's the separator before
        // the first segment, not part of it. After stripping, an
        // empty remainder still yields one empty segment (the `/` case).
        let (remaining, _had_leading_slash) = match self.bytes.split_first() {
            Some((&b'/', rest)) => (rest, true),
            _ => (self.bytes, false),
        };
        PathSegments {
            remaining,
            exhausted: false,
        }
    }
}

/// One segment in a URI path — the bytes between two `/` separators
/// (or between a `/` and the end of the path).
///
/// Raw bytes by default; call [`PathSegment::as_decoded_str`] for the
/// percent-decoded view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathSegment<'a> {
    raw: &'a [u8],
}

impl<'a> PathSegment<'a> {
    /// `pub(crate)` constructor — only [`PathSegments`] produces these.
    #[must_use]
    #[inline]
    pub(crate) const fn new(raw: &'a [u8]) -> Self {
        Self { raw }
    }

    /// Raw on-the-wire bytes (no percent-decoding).
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.raw
    }

    /// Raw bytes as `&str` (parser-validated UTF-8, no percent-decoding).
    ///
    /// Useful when the caller does its own decoding policy (e.g.
    /// routing where `%2F` must not be treated as `/`).
    #[must_use]
    pub fn as_raw_str(&self) -> &'a str {
        // Safety: parser invariant.
        unsafe { std::str::from_utf8_unchecked(self.raw) }
    }

    /// Percent-decoded segment.
    ///
    /// `Cow::Borrowed` when the segment contains no `%`; `Cow::Owned`
    /// when decoding actually changed bytes. UTF-8 errors in the
    /// decoded result fall back to the Unicode replacement character
    /// (matches what curl and browsers do).
    #[must_use]
    pub fn as_decoded_str(&self) -> Cow<'a, str> {
        percent_decode(self.raw).decode_utf8_lossy()
    }

    /// `true` if this segment is empty (`""`). Useful for detecting
    /// trailing slashes and double-slashes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }
}

/// Iterator over the segments of a URI path. Created by
/// [`PathRef::segments`].
#[derive(Debug, Clone)]
pub struct PathSegments<'a> {
    /// Bytes that haven't been yielded yet, excluding any `/` that
    /// triggered the previous yield.
    remaining: &'a [u8],
    /// `true` after the final segment has been yielded.
    exhausted: bool,
}

impl<'a> PathSegments<'a> {
    /// An iterator that yields nothing. Used for the empty-path case.
    fn empty() -> Self {
        Self {
            remaining: &[],
            exhausted: true,
        }
    }
}

impl<'a> Iterator for PathSegments<'a> {
    type Item = PathSegment<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.exhausted {
            return None;
        }
        if let Some(i) = memchr::memchr(b'/', self.remaining) {
            let seg = &self.remaining[..i];
            self.remaining = &self.remaining[i + 1..];
            Some(PathSegment::new(seg))
        } else {
            // Final segment — yield then exhaust.
            let seg = self.remaining;
            self.remaining = &[];
            self.exhausted = true;
            Some(PathSegment::new(seg))
        }
    }
}

impl std::iter::FusedIterator for PathSegments<'_> {}
