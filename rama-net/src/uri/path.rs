//! Borrowed view of a [`Uri`](super::Uri)'s path component. Mutate
//! incrementally via the [`PathMut`](super::PathMut) RAII guard.

use std::borrow::Cow;

use percent_encoding::percent_decode;

use super::component_input::IntoUriComponent;

/// Borrowed view of a URI path.
///
/// The bytes are the raw on-the-wire form (percent-encoded). Iterate
/// segments via [`PathRef::segments`] — each segment can be inspected
/// raw or percent-decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PathRef<'a> {
    pub(crate) bytes: &'a [u8],
}

impl<'a> PathRef<'a> {
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
    /// Matches `url::Url::path_segments`: an empty path yields no
    /// segments, a leading `/` is the delimiter (not a segment), and a
    /// trailing `/` yields a final empty segment (so `/foo` and `/foo/`
    /// stay distinct). Opaque paths (no leading `/`, e.g. the path of
    /// `data:text/plain`) split from the first byte.
    ///
    /// ```text
    /// "/"        -> [""]
    /// "/foo/"    -> ["foo", ""]
    /// "/a//b"    -> ["a", "", "b"]
    /// ```
    #[must_use]
    pub fn segments(&self) -> PathSegments<'a> {
        if self.bytes.is_empty() {
            return PathSegments::empty();
        }
        // Leading `/` is the delimiter before the first segment, not part
        // of it. After stripping, an empty remainder still yields one
        // empty segment — the `/` case.
        let remaining = self.bytes.strip_prefix(b"/").unwrap_or(self.bytes);
        PathSegments {
            remaining,
            exhausted: false,
        }
    }

    /// `true` when the path begins with `prefix` — matched at `/` segment
    /// boundaries, comparing percent-decoded segment values. Shortcut for
    /// [`has_prefix_with_opts`](Self::has_prefix_with_opts) with the default
    /// [`PathMatchOptions`].
    #[must_use]
    pub fn has_prefix(&self, prefix: impl IntoUriComponent) -> bool {
        self.has_prefix_with_opts(prefix, PathMatchOptions::default())
    }

    /// `true` when the path begins with `prefix` under `opts`.
    #[must_use]
    #[expect(
        clippy::needless_pass_by_value,
        reason = "by-value matches IntoUriComponent's signature on sibling setters; this impl only borrows the input"
    )]
    pub fn has_prefix_with_opts(
        &self,
        prefix: impl IntoUriComponent,
        opts: PathMatchOptions,
    ) -> bool {
        let prefix = prefix.as_uri_component_bytes();
        match_prefix_in_body(strip_leading_slash(self.bytes), &prefix, opts).is_some()
    }

    /// `true` when the path ends with `suffix` — matched at `/` segment
    /// boundaries, comparing percent-decoded segment values. Shortcut for
    /// [`has_suffix_with_opts`](Self::has_suffix_with_opts) with the default
    /// [`PathMatchOptions`].
    #[must_use]
    pub fn has_suffix(&self, suffix: impl IntoUriComponent) -> bool {
        self.has_suffix_with_opts(suffix, PathMatchOptions::default())
    }

    /// `true` when the path ends with `suffix` under `opts`.
    #[must_use]
    #[expect(
        clippy::needless_pass_by_value,
        reason = "by-value matches IntoUriComponent's signature on sibling setters; this impl only borrows the input"
    )]
    pub fn has_suffix_with_opts(
        &self,
        suffix: impl IntoUriComponent,
        opts: PathMatchOptions,
    ) -> bool {
        let suffix = suffix.as_uri_component_bytes();
        match_suffix_in_body(strip_leading_slash(self.bytes), &suffix, opts).is_some()
    }
}

impl std::fmt::Display for PathRef<'_> {
    /// Renders the raw on-wire path bytes (pct-encoding preserved).
    #[inline(always)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_raw_str())
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

/// Options controlling path prefix/suffix matching and stripping
/// ([`PathRef::has_prefix_with_opts`], [`super::PathMut::strip_prefix_with_opts`], …).
///
/// The default ([`Default`]) is **segment-boundary**, **percent-decoded**
/// (normalized), **case-sensitive** matching — the safe, least-surprising
/// behaviour. Each field opts out of one of those.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathMatchOptions {
    /// Match the boundary segment as a raw byte substring instead of at a
    /// `/` segment boundary (`false` by default). Partial matching is always
    /// byte-level, so [`percent_decode`](Self::percent_decode) has no effect
    /// when this is set.
    pub partial: bool,
    /// Compare ASCII case-insensitively (`false` by default).
    pub ignore_ascii_case: bool,
    /// Compare percent-**decoded** segment values rather than the raw
    /// (percent-encoded) bytes (`true` by default — comparison is normalized).
    pub percent_decode: bool,
}

impl Default for PathMatchOptions {
    fn default() -> Self {
        Self {
            partial: false,
            ignore_ascii_case: false,
            percent_decode: true,
        }
    }
}

/// Drop a single leading `/`, yielding the path "body" used by the matchers.
#[inline]
fn strip_leading_slash(path: &[u8]) -> &[u8] {
    path.strip_prefix(b"/").unwrap_or(path)
}

/// Trim every leading and trailing `/` from a slice (pattern normalization).
fn trim_ascii_slashes(mut bytes: &[u8]) -> &[u8] {
    while let Some(rest) = bytes.strip_prefix(b"/") {
        bytes = rest;
    }
    while let Some(rest) = bytes.strip_suffix(b"/") {
        bytes = rest;
    }
    bytes
}

/// Compare a single path segment against a pattern segment under `opts`.
fn segment_eq(seg: &[u8], pat: &[u8], opts: PathMatchOptions) -> bool {
    if opts.percent_decode {
        // Compare decoded BYTES, not a lossy-UTF-8 rendering: lossy decoding
        // collapses every distinct invalid-UTF-8 byte to U+FFFD, which would
        // make unrelated segments (e.g. `%ff` vs `%fe`) compare equal.
        let seg: std::borrow::Cow<'_, [u8]> = percent_decode(seg).into();
        let pat: std::borrow::Cow<'_, [u8]> = percent_decode(pat).into();
        if opts.ignore_ascii_case {
            seg.eq_ignore_ascii_case(&pat)
        } else {
            seg == pat
        }
    } else if opts.ignore_ascii_case {
        seg.eq_ignore_ascii_case(pat)
    } else {
        seg == pat
    }
}

/// Match `pattern_raw` as a prefix of `body` (a path without its leading `/`).
///
/// Returns the byte offset in `body` just past the matched prefix (so
/// `body[offset..]` is the remainder, starting with `/` or empty), or `None`.
pub(super) fn match_prefix_in_body(
    body: &[u8],
    pattern_raw: &[u8],
    opts: PathMatchOptions,
) -> Option<usize> {
    let pat = trim_ascii_slashes(pattern_raw);
    if pat.is_empty() {
        return Some(0);
    }

    if opts.partial {
        let matches = if opts.ignore_ascii_case {
            body.len() >= pat.len() && body[..pat.len()].eq_ignore_ascii_case(pat)
        } else {
            body.starts_with(pat)
        };
        return matches.then_some(pat.len());
    }

    let mut bi = 0;
    let mut pi = 0;
    loop {
        let bend = body[bi..]
            .iter()
            .position(|&c| c == b'/')
            .map_or(body.len(), |p| bi + p);
        let pend = pat[pi..]
            .iter()
            .position(|&c| c == b'/')
            .map_or(pat.len(), |p| pi + p);
        if !segment_eq(&body[bi..bend], &pat[pi..pend], opts) {
            return None;
        }
        if pend == pat.len() {
            return Some(bend);
        }
        // pattern has another segment; body must too.
        if bend >= body.len() {
            return None;
        }
        bi = bend + 1;
        pi = pend + 1;
    }
}

/// Match `pattern_raw` as a suffix of `body` (a path without its leading `/`).
///
/// Returns the byte offset in `body` up to which content is **kept**
/// (`body[..offset]`, with the separator before the suffix removed), or `None`.
pub(super) fn match_suffix_in_body(
    body: &[u8],
    pattern_raw: &[u8],
    opts: PathMatchOptions,
) -> Option<usize> {
    let pat = trim_ascii_slashes(pattern_raw);
    if pat.is_empty() {
        return Some(body.len());
    }

    if opts.partial {
        let matches = if opts.ignore_ascii_case {
            body.len() >= pat.len() && body[body.len() - pat.len()..].eq_ignore_ascii_case(pat)
        } else {
            body.ends_with(pat)
        };
        return matches.then(|| body.len() - pat.len());
    }

    let mut be = body.len();
    let mut pe = pat.len();
    loop {
        let bstart = body[..be]
            .iter()
            .rposition(|&c| c == b'/')
            .map_or(0, |p| p + 1);
        let pstart = pat[..pe]
            .iter()
            .rposition(|&c| c == b'/')
            .map_or(0, |p| p + 1);
        if !segment_eq(&body[bstart..be], &pat[pstart..pe], opts) {
            return None;
        }
        if pstart == 0 {
            // Drop the `/` before the matched suffix (if any).
            return Some(bstart.saturating_sub(1));
        }
        // pattern has another leading segment; body must too.
        if bstart == 0 {
            return None;
        }
        be = bstart - 1;
        pe = pstart - 1;
    }
}

#[cfg(test)]
mod segment_eq_fix_tests {
    use super::*;

    #[test]
    fn distinct_invalid_utf8_segments_do_not_coalesce() {
        let opts = PathMatchOptions::default(); // percent_decode = true
        // `%ff` and `%fe` decode to distinct invalid-UTF-8 bytes; lossy decoding
        // would map both to U+FFFD and (wrongly) match them.
        assert!(!segment_eq(b"%ff", b"%fe", opts));
        // valid + %-hex-case-insensitive decoding still matches.
        assert!(segment_eq(b"%2f", b"%2F", opts));
        assert!(segment_eq(b"abc", b"abc", opts));
    }
}
