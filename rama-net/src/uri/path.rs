//! Borrowed view of a [`Uri`](super::Uri)'s path component. Mutate
//! incrementally via the [`PathMut`](super::PathMut) RAII guard.

use std::{
    borrow::Cow,
    fmt::{self, Debug},
    hash::Hash,
};

use itertools::Itertools;
use percent_encoding::percent_decode;
use rama_core::bytes::BytesMut;

use crate::uri::{
    PathCaptures, PathPattern,
    encode::{encoded_path, encoded_segment, extend_encoded_path},
};

use super::component_input::IntoUriComponent;

/// Borrowed view of a URI path.
///
/// The backing bytes preserve the parsed path representation. Use
/// [`as_encoded_str`](Self::as_encoded_str) or
/// [`as_decoded_str`](Self::as_decoded_str) to explicitly choose the
/// presentation you need. Iterate segments via [`PathRef::segments`].
#[derive(Debug, Default, Clone, Copy)]
pub struct PathRef<'a> {
    pub(crate) bytes: &'a [u8],
}

impl<'a> PathRef<'a> {
    #[must_use]
    #[inline]
    pub(crate) const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Borrow a raw string as a [`PathRef`] — no allocation,
    /// no `unsafe`. Note that it can mean that invalid characters are not yet pct-encoded,
    /// this is fine as for comparison/hashing purposes it is handled fine.
    #[must_use]
    #[inline]
    pub fn from_raw_str(path: &'a str) -> Self {
        Self::new(path.as_bytes())
    }

    /// Percent-encoded path.
    #[must_use]
    #[inline(always)]
    pub fn as_encoded_str(self) -> Cow<'a, str> {
        encoded_path(self.bytes)
    }

    pub(super) fn write_encoded_to(self, buf: &mut BytesMut) {
        extend_encoded_path(buf, self.bytes);
    }

    /// `true` when the path contains no bytes.
    #[must_use]
    #[inline(always)]
    pub fn is_empty(self) -> bool {
        self.bytes.is_empty()
    }

    /// Percent-decoded path.
    #[must_use]
    pub fn as_decoded_str(self) -> Cow<'a, str> {
        percent_decode(self.bytes).decode_utf8_lossy()
    }

    /// Path view with every leading and trailing `/` removed.
    #[must_use]
    #[inline]
    pub fn trimmed_slashes(self) -> Self {
        Self::new(trim_ascii_slashes(self.bytes))
    }

    /// Borrow a window of `count` consecutive path segments starting at
    /// `start`.
    ///
    /// When the window begins after an earlier segment, the returned view
    /// includes the `/` delimiter immediately before the first selected
    /// segment, making it directly usable with rooted [`PathPattern`]s.
    /// Returns `None` when the requested window is empty or extends beyond the
    /// available segments.
    #[must_use]
    pub fn segment_range(self, start: usize, count: usize) -> Option<Self> {
        let (start, end) = segment_range_bounds(self.bytes, start, count)?;
        Some(Self::new(&self.bytes[start..end]))
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
    pub fn segments(self) -> PathSegments<'a> {
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
    pub fn has_prefix(self, prefix: impl IntoUriComponent) -> bool {
        self.has_prefix_with_opts(prefix, PathMatchOptions::default())
    }

    /// `true` when the path begins with `prefix` under `opts`.
    #[must_use]
    #[expect(
        clippy::needless_pass_by_value,
        reason = "by-value matches IntoUriComponent's signature on sibling setters; this impl only borrows the input"
    )]
    pub fn has_prefix_with_opts(
        self,
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
    pub fn has_suffix(self, suffix: impl IntoUriComponent) -> bool {
        self.has_suffix_with_opts(suffix, PathMatchOptions::default())
    }

    /// `true` when the path ends with `suffix` under `opts`.
    #[must_use]
    #[expect(
        clippy::needless_pass_by_value,
        reason = "by-value matches IntoUriComponent's signature on sibling setters; this impl only borrows the input"
    )]
    pub fn has_suffix_with_opts(
        self,
        suffix: impl IntoUriComponent,
        opts: PathMatchOptions,
    ) -> bool {
        let suffix = suffix.as_uri_component_bytes();
        match_suffix_in_body(strip_leading_slash(self.bytes), &suffix, opts).is_some()
    }

    /// The `n`-th path segment (0-based), or `None` when the path has fewer
    /// segments. See [`segments`](Self::segments) for the splitting rules.
    #[must_use]
    pub fn nth_segment(self, n: usize) -> Option<PathSegment<'a>> {
        self.segments().nth(n)
    }

    /// The first path segment, or `None` for an empty path.
    #[must_use]
    pub fn first_segment(self) -> Option<PathSegment<'a>> {
        self.segments().next()
    }

    /// The last path segment, or `None` for an empty path. A trailing `/`
    /// yields a final empty segment, so `/foo/`'s last segment is `""`.
    #[must_use]
    pub fn last_segment(self) -> Option<PathSegment<'a>> {
        self.segments().last()
    }

    /// Number of path segments. `O(n)` in the path length.
    #[must_use]
    pub fn segment_count(self) -> usize {
        self.segments().len()
    }

    /// `true` when `needle`'s segment(s) appear as a consecutive run of whole
    /// path segments — matched at `/` boundaries with percent-decoded values
    /// (default [`PathMatchOptions`]). E.g. `contains_segments("@v")` is true
    /// for `/golang.org/x/mod/@v/list`, and false for `/x/@version/y`.
    #[must_use]
    pub fn contains_segments(self, needle: impl IntoUriComponent) -> bool {
        self.contains_segments_with_opts(needle, PathMatchOptions::default())
    }

    /// `true` when `needle`'s segment(s) appear as a consecutive run of whole
    /// path segments under `opts`.
    #[must_use]
    #[expect(
        clippy::needless_pass_by_value,
        reason = "by-value matches IntoUriComponent's signature on sibling matchers; this impl only borrows the input"
    )]
    pub fn contains_segments_with_opts(
        self,
        needle: impl IntoUriComponent,
        opts: PathMatchOptions,
    ) -> bool {
        let needle = needle.as_uri_component_bytes();
        if trim_ascii_slashes(&needle).is_empty() {
            return true;
        }
        // Try the needle as a segment-prefix at each segment-aligned start
        // of the path body (offset 0, and every byte just past a `/`).
        let body = strip_leading_slash(self.bytes);
        let mut start = 0;
        loop {
            if match_prefix_in_body(&body[start..], &needle, opts).is_some() {
                return true;
            }
            match memchr::memchr(b'/', &body[start..]) {
                Some(i) => start += i + 1,
                None => return false,
            }
        }
    }

    /// `true` when `path` matches given [`PathPattern`].
    ///
    /// Shortcut for [`PathPattern::is_match`].
    #[must_use]
    #[inline(always)]
    pub fn is_pattern_match(self, pattern: &PathPattern) -> bool {
        pattern.is_match(self)
    }

    /// Match using the given [`PathPattern`]
    /// and return captured values, or `None` when `path` doesn't
    /// match. May allocate a small `Vec` for the bindings.
    ///
    /// Shortcut for [`PathPattern::captures`].
    #[must_use]
    #[inline(always)]
    pub fn pattern_captures(self, pattern: &PathPattern) -> Option<PathCaptures<'_, 'a>> {
        pattern.captures(self)
    }

    /// True if the path ref starts with as slash '/'.
    #[must_use]
    #[inline(always)]
    fn has_leading_slash(self) -> bool {
        self.bytes.first().copied() == Some(b'/')
    }
}

impl<'a> From<&'a str> for PathRef<'a> {
    /// Borrow a raw on-the-wire path string as a [`PathRef`]. See
    /// [`PathRef::from_raw_str`].
    #[inline]
    fn from(path: &'a str) -> Self {
        Self::from_raw_str(path)
    }
}

impl PartialEq for PathRef<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.segments()
            .zip_longest(other.segments())
            .all(|segment_pair| {
                let (segment_a, segment_b) = segment_pair.left_and_right();
                segment_a == segment_b
            })
    }
}

impl Eq for PathRef<'_> {}

impl Ord for PathRef<'_> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        for segment_pair in self.segments().zip_longest(other.segments()) {
            match segment_pair.left_and_right() {
                (None, None) => (),
                (None, Some(_)) => return std::cmp::Ordering::Less,
                (Some(_), None) => return std::cmp::Ordering::Greater,
                (Some(segment_a), Some(segment_b)) => {
                    let ordering = segment_a.cmp(&segment_b);
                    if ordering != std::cmp::Ordering::Equal {
                        return ordering;
                    }
                }
            }
        }
        std::cmp::Ordering::Equal
    }
}

impl PartialOrd for PathRef<'_> {
    #[inline(always)]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq<str> for PathRef<'_> {
    #[inline(always)]
    fn eq(&self, other: &str) -> bool {
        self.eq(&PathRef::from_raw_str(other))
    }
}

impl PartialEq<&str> for PathRef<'_> {
    #[inline(always)]
    fn eq(&self, other: &&str) -> bool {
        self.eq(&PathRef::from_raw_str(other))
    }
}

impl<'a> PartialEq<PathRef<'a>> for str {
    #[inline(always)]
    fn eq(&self, other: &PathRef<'a>) -> bool {
        PathRef::from_raw_str(self).eq(other)
    }
}

impl<'a> PartialEq<PathRef<'a>> for &str {
    #[inline(always)]
    fn eq(&self, other: &PathRef<'a>) -> bool {
        PathRef::from_raw_str(self).eq(other)
    }
}

impl Hash for PathRef<'_> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let mut separator = "";
        for segment in self.segments() {
            separator.hash(state);
            separator = "/";
            segment.hash(state);
        }
    }
}

impl std::fmt::Display for PathRef<'_> {
    /// Renders the raw on-wire path bytes (pct-encoding preserved).
    #[inline(always)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut separator = if self.has_leading_slash() { "/" } else { "" };
        for segment in self.segments() {
            write!(f, "{separator}{segment}")?;
            separator = "/";
        }
        Ok(())
    }
}

/// One segment in a URI path — the bytes between two `/` separators
/// (or between a `/` and the end of the path).
///
/// Use [`PathSegment::as_encoded_str`] or [`PathSegment::as_decoded_str`] to
/// explicitly choose a presentation.
#[derive(Debug, Clone, Copy)]
pub struct PathSegment<'a> {
    raw: &'a [u8],
}

impl PartialEq for PathSegment<'_> {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        self.as_encoded_str() == other.as_encoded_str()
    }
}

impl Eq for PathSegment<'_> {}

impl PartialEq<str> for PathSegment<'_> {
    #[inline(always)]
    fn eq(&self, other: &str) -> bool {
        self.eq(&PathSegment::new(other.as_bytes()))
    }
}

impl PartialEq<&str> for PathSegment<'_> {
    #[inline(always)]
    fn eq(&self, other: &&str) -> bool {
        self.eq(&PathSegment::new(other.as_bytes()))
    }
}

impl<'a> PartialEq<PathSegment<'a>> for str {
    #[inline(always)]
    fn eq(&self, other: &PathSegment<'a>) -> bool {
        PathSegment::new(self.as_bytes()).eq(other)
    }
}

impl<'a> PartialEq<PathSegment<'a>> for &str {
    #[inline(always)]
    fn eq(&self, other: &PathSegment<'a>) -> bool {
        PathSegment::new(self.as_bytes()).eq(other)
    }
}

impl PartialOrd for PathSegment<'_> {
    #[inline(always)]
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PathSegment<'_> {
    #[inline(always)]
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_encoded_str()
            .as_ref()
            .cmp(other.as_encoded_str().as_ref())
    }
}

impl Hash for PathSegment<'_> {
    #[inline(always)]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_encoded_str().hash(state);
    }
}

impl fmt::Display for PathSegment<'_> {
    #[inline(always)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_encoded_str())
    }
}

impl<'a> PathSegment<'a> {
    #[must_use]
    #[inline]
    pub(crate) const fn new(raw: &'a [u8]) -> Self {
        Self { raw }
    }

    /// Percent-encoded segment.
    ///
    /// `Cow::Borrowed` when the segment does not have to be encoded.
    #[must_use]
    #[inline(always)]
    pub fn as_encoded_str(self) -> Cow<'a, str> {
        encoded_segment(self.raw)
    }

    /// Percent-decoded segment.
    ///
    /// `Cow::Borrowed` when the segment contains no `%`; `Cow::Owned`
    /// when decoding actually changed bytes. UTF-8 errors in the
    /// decoded result fall back to the Unicode replacement character
    /// (matches what curl and browsers do).
    #[must_use]
    pub fn as_decoded_str(self) -> Cow<'a, str> {
        percent_decode(self.raw).decode_utf8_lossy()
    }

    /// `true` if this segment is empty (`""`). Useful for detecting
    /// trailing slashes and double-slashes.
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.raw.is_empty()
    }

    /// `true` when this segment equals `other`, comparing percent-decoded
    /// values (default [`PathMatchOptions`]). The typed alternative to
    /// `seg.as_decoded_str() == other` that also handles `%`-case and the
    /// invalid-UTF-8 pitfalls correctly.
    #[must_use]
    pub fn matches(self, other: impl IntoUriComponent) -> bool {
        self.matches_with_opts(other, PathMatchOptions::default())
    }

    /// `true` when this segment equals `other` under `opts` (the `partial`
    /// flag is irrelevant within a single segment and is ignored here).
    #[must_use]
    #[expect(
        clippy::needless_pass_by_value,
        reason = "by-value matches IntoUriComponent's signature on sibling matchers; this impl only borrows the input"
    )]
    pub fn matches_with_opts(self, other: impl IntoUriComponent, opts: PathMatchOptions) -> bool {
        segment_eq(self.raw, &other.as_uri_component_bytes(), opts)
    }

    /// `true` when the (percent-decoded) segment value begins with `prefix`.
    /// Byte-level *within* this one segment — for e.g. file-name prefixes.
    #[must_use]
    pub fn has_prefix(self, prefix: impl IntoUriComponent) -> bool {
        self.has_prefix_with_opts(prefix, PathMatchOptions::default())
    }

    /// `true` when the (percent-decoded) segment value begins with `prefix`
    /// under `opts` (`partial` ignored — always byte-level within the segment).
    #[must_use]
    #[expect(
        clippy::needless_pass_by_value,
        reason = "by-value matches IntoUriComponent's signature on sibling matchers; this impl only borrows the input"
    )]
    pub fn has_prefix_with_opts(
        self,
        prefix: impl IntoUriComponent,
        opts: PathMatchOptions,
    ) -> bool {
        let pat = prefix.as_uri_component_bytes();
        let seg = maybe_decode(self.raw, opts.percent_decode);
        let pat = maybe_decode(&pat, opts.percent_decode);
        byte_starts_with(&seg, &pat, opts.ignore_ascii_case)
    }

    /// `true` when the (percent-decoded) segment value ends with `suffix`.
    /// Byte-level *within* this one segment — e.g. a file extension:
    /// `seg.has_suffix(".tgz")`.
    #[must_use]
    pub fn has_suffix(self, suffix: impl IntoUriComponent) -> bool {
        self.has_suffix_with_opts(suffix, PathMatchOptions::default())
    }

    /// `true` when the (percent-decoded) segment value ends with `suffix`
    /// under `opts` (`partial` ignored — always byte-level within the segment).
    #[must_use]
    #[expect(
        clippy::needless_pass_by_value,
        reason = "by-value matches IntoUriComponent's signature on sibling matchers; this impl only borrows the input"
    )]
    pub fn has_suffix_with_opts(
        self,
        suffix: impl IntoUriComponent,
        opts: PathMatchOptions,
    ) -> bool {
        let pat = suffix.as_uri_component_bytes();
        let seg = maybe_decode(self.raw, opts.percent_decode);
        let pat = maybe_decode(&pat, opts.percent_decode);
        byte_ends_with(&seg, &pat, opts.ignore_ascii_case)
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

    fn size_hint(&self) -> (usize, Option<usize>) {
        // Each unyielded `/` precedes another segment, plus the final tail
        // segment — exact, so this is also an `ExactSizeIterator`.
        let n = if self.exhausted {
            0
        } else {
            self.remaining.iter().filter(|&&b| b == b'/').count() + 1
        };
        (n, Some(n))
    }
}

impl std::iter::FusedIterator for PathSegments<'_> {}

impl ExactSizeIterator for PathSegments<'_> {}

/// Options controlling path prefix/suffix matching and stripping
/// ([`PathRef::has_prefix_with_opts`], [`super::PathMut::strip_prefix_with_opts`], …).
///
/// The default ([`Default`]) is **segment-boundary**, **percent-decoded**
/// (normalized), **case-sensitive** matching — the safe, least-surprising
/// behaviour. Each field opts out of one of those.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
pub(super) fn strip_leading_slash(path: &[u8]) -> &[u8] {
    path.strip_prefix(b"/").unwrap_or(path)
}

/// Trim every leading and trailing `/` from a slice (pattern normalization).
pub(super) fn trim_ascii_slashes(mut bytes: &[u8]) -> &[u8] {
    while let Some(rest) = bytes.strip_prefix(b"/") {
        bytes = rest;
    }
    while let Some(rest) = bytes.strip_suffix(b"/") {
        bytes = rest;
    }
    bytes
}

pub(super) fn segment_range_bounds(
    path: &[u8],
    start: usize,
    count: usize,
) -> Option<(usize, usize)> {
    if path.is_empty() || count == 0 {
        return None;
    }

    let has_leading_slash = path.first().copied() == Some(b'/');
    let body_offset = usize::from(has_leading_slash);
    let body = &path[body_offset..];

    let first = segment_body_bounds(body, start)?;
    let last = segment_body_bounds(body, start.checked_add(count - 1)?)?;

    let abs_start = if has_leading_slash {
        if start == 0 {
            0
        } else {
            body_offset + first.0 - 1
        }
    } else if start == 0 {
        0
    } else {
        first.0 - 1
    };

    let abs_end = if has_leading_slash && body.is_empty() && start == 0 {
        1
    } else {
        body_offset + last.1
    };

    Some((abs_start, abs_end))
}

fn segment_body_bounds(body: &[u8], target: usize) -> Option<(usize, usize)> {
    let mut index = 0;
    let mut start = 0;
    loop {
        let end = body[start..]
            .iter()
            .position(|&b| b == b'/')
            .map_or(body.len(), |pos| start + pos);
        if index == target {
            return Some((start, end));
        }
        if end == body.len() {
            return None;
        }
        start = end + 1;
        index += 1;
    }
}

#[inline]
pub(super) fn maybe_decode(bytes: &[u8], decode: bool) -> Cow<'_, [u8]> {
    if decode {
        percent_decode(bytes).into()
    } else {
        Cow::Borrowed(bytes)
    }
}

#[inline]
pub(super) fn byte_starts_with(hay: &[u8], needle: &[u8], ignore_case: bool) -> bool {
    if ignore_case {
        hay.len() >= needle.len() && hay[..needle.len()].eq_ignore_ascii_case(needle)
    } else {
        hay.starts_with(needle)
    }
}

#[inline]
pub(super) fn byte_ends_with(hay: &[u8], needle: &[u8], ignore_case: bool) -> bool {
    if ignore_case {
        hay.len() >= needle.len() && hay[hay.len() - needle.len()..].eq_ignore_ascii_case(needle)
    } else {
        hay.ends_with(needle)
    }
}

/// Compare a single path segment against a pattern segment under `opts`.
pub(super) fn segment_eq(seg: &[u8], pat: &[u8], opts: PathMatchOptions) -> bool {
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

#[cfg(test)]
mod partial_ignore_case_boundary_tests {
    use super::*;

    // Pin the length-guard + slice arithmetic in the `partial && ignore_ascii_case`
    // branch of the prefix/suffix matchers — these were the only mutation-surviving
    // paths and they govern (case-insensitive) routing prefix/suffix matches.
    const OPTS: PathMatchOptions = PathMatchOptions {
        partial: true,
        ignore_ascii_case: true,
        percent_decode: true,
    };

    #[test]
    fn prefix_partial_ignore_case_length_and_match() {
        // Long-enough body + case-insensitive match must succeed (guards `>=`).
        assert_eq!(match_prefix_in_body(b"abc", b"AB", OPTS), Some(2));
        // Long-enough body but mismatched bytes must NOT match (guards the `&&`,
        // which an `||` mutant would short-circuit to a false positive).
        assert_eq!(match_prefix_in_body(b"abc", b"xy", OPTS), None);
        // Body shorter than the pattern must not match (and must not panic).
        assert_eq!(match_prefix_in_body(b"a", b"AB", OPTS), None);
    }

    #[test]
    fn suffix_partial_ignore_case_length_and_offset() {
        // Body longer than the pattern: the kept-offset is `body.len() - pat.len()`,
        // distinguishing `-` from `+` (panic) and `/` (wrong slice) mutants.
        assert_eq!(match_suffix_in_body(b"abcde", b"DE", OPTS), Some(3));
        // Mismatched suffix of sufficient length must NOT match (guards `&&`).
        assert_eq!(match_suffix_in_body(b"abc", b"xy", OPTS), None);
        // Body shorter than the pattern must not match (and must not panic).
        assert_eq!(match_suffix_in_body(b"a", b"DE", OPTS), None);
    }
}
