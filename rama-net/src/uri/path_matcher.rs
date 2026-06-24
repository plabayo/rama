//! Infallible path-pattern matching.
//!
//! [`PathPattern`] compiles a small glob/capture syntax and matches it against
//! a [`PathRef`](super::PathRef) segment-by-segment, decode-aware and (by
//! default) case-sensitive. Compilation never fails: anything that isn't a
//! recognized meta token is treated as a literal. See [`PathPattern`] for the
//! full syntax.

use std::borrow::Cow;

use rama_utils::collections::smallvec::SmallVec;

use crate::byte_sets::is_pattern_name_byte;

use super::component_input::IntoUriComponent;
use super::path::{PathMatchOptions, PathRef, byte_starts_with, maybe_decode, strip_leading_slash};

/// A compiled path pattern.
///
/// Construct via [`PathPattern::new`] / [`new_with_opts`](Self::new_with_opts)
/// and test paths with [`is_match`](Self::is_match) / [`captures`](Self::captures).
///
/// # Syntax
///
/// A pattern is split on `/` into segments. Within a segment:
///
/// - **literal** text must equal the (decoded) path segment value;
/// - `:name` captures a whole segment under `name`;
/// - `:name*` captures a wildcard run within a segment, allowing literal
///   prefix/suffix around it (`:pkg*.json` captures the part before `.json`).
///   `:name` and `:name*` are equivalent when there is no surrounding literal;
/// - `*` is an anonymous wildcard run (0+ chars), not captured;
/// - `?` makes the immediately preceding element optional (zero-or-one):
///   `a?` is an optional `a`, a trailing `/?` is an optional trailing slash;
/// - `**`, as a *whole* segment, is an anonymous catch-all matching one or
///   more path segments, available '/'-joined and decoded via
///   [`PathCaptures::glob`]. It may appear in the middle of a pattern;
/// - `:name**`, as a *whole* segment, is the **named** catch-all: same 1+
///   segment match as `**`, but the run is recorded under `name` (read back,
///   '/'-joined and decoded, via [`PathCaptures::get`]). So a single `*`
///   stays within a segment; a doubled `**` spans segments.
///
/// Trailing slash is explicit: `/a` matches only `/a`, `/a/` matches only
/// `/a/`, and `/a/?` matches both.
///
/// ```
/// use rama_net::uri::{PathPattern, PathRef};
///
/// let pat = PathPattern::new("/p2/:vendor/:pkg*.json");
/// let caps = pat.captures(PathRef::from_raw_str("/p2/acme/widget.json")).unwrap();
/// assert_eq!(caps.get("vendor"), Some("acme"));
/// assert_eq!(caps.get("pkg"), Some("widget"));
/// assert!(pat.captures(PathRef::from_raw_str("/p2/acme/widget.txt")).is_none());
///
/// let assets = PathPattern::new("/assets/**");
/// assert!(assets.is_match(PathRef::from_raw_str("/assets/css/app.css")));
/// assert!(!assets.is_match(PathRef::from_raw_str("/assets")));
///
/// // `:name**` is the named catch-all (read back via `get`).
/// let files = PathPattern::new("/files/:rest**");
/// let caps = files.captures(PathRef::from_raw_str("/files/a/b/c.txt")).unwrap();
/// assert_eq!(caps.get("rest"), Some("a/b/c.txt"));
/// ```
#[derive(Debug, Clone)]
pub struct PathPattern {
    segments: Vec<PatternSegment>,
    /// Capture names are appended here at compile time; [`Element`] capture
    /// kinds index into it. Owning the names here is what lets
    /// [`PathCaptures`] borrow them for `'a`.
    name_bytes: Vec<u8>,
    trailing: TrailingSlash,
    opts: PathMatchOptions,
    /// `true` when no segment binds a name and there is no catch-all — the
    /// alloc-free [`is_match`](PathPattern::is_match) fast path applies.
    capture_free: bool,
}

/// Policy for a path's trailing slash, derived from the pattern's own
/// trailing form (explicit, never inferred).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrailingSlash {
    /// Pattern has no trailing `/`: the path must not either.
    Forbidden,
    /// Pattern ends in `/`: the path must too.
    Required,
    /// Pattern ends in `/?`: both forms accepted.
    Optional,
}

impl TrailingSlash {
    /// Does this policy accept a path that does (`true`) / doesn't (`false`)
    /// carry a trailing slash?
    fn accepts(self, path_has_slash: bool) -> bool {
        match self {
            Self::Forbidden => !path_has_slash,
            Self::Required => path_has_slash,
            Self::Optional => true,
        }
    }
}

/// One `/`-delimited unit of a compiled pattern.
#[derive(Debug, Clone)]
enum PatternSegment {
    /// `**` — matches one or more whole path segments (anonymous; read back
    /// via [`PathCaptures::glob`]).
    CatchAll,
    /// `:name**` — like [`CatchAll`](Self::CatchAll) but records the matched,
    /// '/'-joined run under `name` (read back via [`PathCaptures::get`]).
    NamedCatchAll { name_start: usize, name_len: usize },
    /// A sequence of within-segment elements matched against a single path
    /// segment via greedy backtracking. Inline-sized for the common one- or
    /// two-element segment (a bare literal, capture, or `:name*.ext` pair).
    Normal {
        elems: SmallVec<[Element; 2]>,
        /// Count of *ambiguity sources* in `elems`: wildcard runs
        /// (`Star`/`Capture`) plus `optional` elements. Each is a backtrack
        /// point; with two or more of them the greedy recursion can revisit
        /// the same `(element, hay)` state exponentially, so we memoize
        /// failures. With at most one source the recursion is linear, so we
        /// skip the memo (and its allocation) entirely. Precomputed here so
        /// the hot path doesn't rescan the element list per match.
        ambiguity: usize,
    },
}

/// A within-segment matching element.
#[derive(Debug, Clone)]
struct Element {
    kind: ElementKind,
    /// `?` suffix: the element may match zero occurrences.
    optional: bool,
}

#[derive(Debug, Clone)]
enum ElementKind {
    /// Literal bytes, compared against the decoded path-segment bytes. Boxed:
    /// fixed after compilation, so the `Vec` capacity word is dead weight.
    Literal(Box<[u8]>),
    /// Anonymous wildcard run (0+ chars within the segment).
    Star,
    /// Named wildcard run that records what it matched. The name is the
    /// `name_bytes[start..start+len]` slice of the owning [`PathPattern`].
    Capture { name_start: usize, name_len: usize },
}

impl PathPattern {
    /// Compile a path pattern. Infallible: anything not a recognized meta
    /// token is a literal.
    ///
    /// ```
    /// use rama_net::uri::{PathPattern, PathRef};
    ///
    /// let pat = PathPattern::new("/backend-api/codex/responses");
    /// assert!(pat.is_match(PathRef::from_raw_str("/backend-api/codex/responses")));
    /// assert!(!pat.is_match(PathRef::from_raw_str("/backend-api/codex")));
    /// ```
    #[must_use]
    pub fn new(pattern: impl IntoUriComponent) -> Self {
        Self::new_with_opts(pattern, PathMatchOptions::default())
    }

    /// [`new`](Self::new) with explicit [`PathMatchOptions`]. The matcher
    /// honors `ignore_ascii_case` and `percent_decode`; `partial` is
    /// irrelevant and ignored.
    ///
    /// ```
    /// use rama_net::uri::{PathMatchOptions, PathPattern, PathRef};
    ///
    /// let opts = PathMatchOptions {
    ///     ignore_ascii_case: true,
    ///     ..Default::default()
    /// };
    /// let pat = PathPattern::new_with_opts("/api/v2", opts);
    /// assert!(pat.is_match(PathRef::from_raw_str("/API/v2")));
    /// ```
    #[must_use]
    #[expect(
        clippy::needless_pass_by_value,
        reason = "by-value matches IntoUriComponent's signature on sibling APIs; this impl only borrows the input"
    )]
    pub fn new_with_opts(pattern: impl IntoUriComponent, opts: PathMatchOptions) -> Self {
        let raw = pattern.as_uri_component_bytes();
        Self::compile(&raw, opts)
    }

    fn compile(raw: &[u8], opts: PathMatchOptions) -> Self {
        // Trailing-slash policy is read off the raw pattern *before* the
        // leading slash is stripped, so the bare-root `/` (which becomes empty
        // after stripping) still registers as a required trailing slash.
        let (raw, trailing) = if let Some(rest) = raw.strip_suffix(b"/?") {
            (rest, TrailingSlash::Optional)
        } else if let Some(rest) = raw.strip_suffix(b"/") {
            (rest, TrailingSlash::Required)
        } else {
            (raw, TrailingSlash::Forbidden)
        };
        let body = strip_leading_slash(raw);

        let mut name_bytes: Vec<u8> = Vec::new();
        let mut segments = Vec::new();
        let mut capture_free = true;

        // Split on `/`. An empty `body` (root pattern `/`) yields no
        // segments, which together with `TrailingSlash::Required` matches
        // exactly `/`.
        if !body.is_empty() {
            for seg in body.split(|&b| b == b'/') {
                if seg == b"**" {
                    capture_free = false;
                    segments.push(PatternSegment::CatchAll);
                    continue;
                }
                if let Some(name) = parse_named_catchall(seg) {
                    capture_free = false;
                    // `:**` (empty name) is just the anonymous catch-all.
                    if name.is_empty() {
                        segments.push(PatternSegment::CatchAll);
                    } else {
                        let name_start = name_bytes.len();
                        name_bytes.extend_from_slice(name);
                        segments.push(PatternSegment::NamedCatchAll {
                            name_start,
                            name_len: name.len(),
                        });
                    }
                    continue;
                }
                let elements = parse_segment(seg, &mut name_bytes, &mut capture_free);
                let ambiguity = elements
                    .iter()
                    .filter(|e| {
                        e.optional
                            || matches!(e.kind, ElementKind::Star | ElementKind::Capture { .. })
                    })
                    .count();
                segments.push(PatternSegment::Normal {
                    elems: elements,
                    ambiguity,
                });
            }
        }

        Self {
            segments,
            name_bytes,
            trailing,
            opts,
            capture_free,
        }
    }

    /// `true` when `path` matches. Allocation-free when the pattern has no
    /// captures and no catch-all.
    ///
    /// ```
    /// use rama_net::uri::{PathPattern, PathRef};
    ///
    /// let pat = PathPattern::new("/files/*.txt");
    /// assert!(pat.is_match(PathRef::from_raw_str("/files/readme.txt")));
    /// assert!(!pat.is_match(PathRef::from_raw_str("/files/readme.md")));
    /// ```
    #[must_use]
    pub fn is_match(&self, path: PathRef<'_>) -> bool {
        if self.capture_free {
            self.is_match_fast(path)
        } else {
            self.captures(path).is_some()
        }
    }

    /// Allocation-free match for capture-free patterns. A capture-free
    /// pattern has no `**`, so every pattern segment matches exactly one path
    /// segment positionally — no backtracking across segments, no `Vec`, no
    /// captured-value strings.
    fn is_match_fast(&self, path: PathRef<'_>) -> bool {
        // Walk the path segments with one-segment lookahead so the trailing-`/`
        // marker can be classified without materializing the list.
        let mut path_iter = path.segments().peekable();
        let mut pat_iter = self.segments.iter();
        let mut content_count = 0usize;
        let mut ignore = Sink::Ignore;

        let trailing = loop {
            let Some(seg) = path_iter.next() else {
                // No (more) segments: no trailing slash.
                break false;
            };
            let is_last = path_iter.peek().is_none();
            // The root path `/` is a lone empty segment: it carries the root
            // slash but no content. A final empty segment after real content is
            // the trailing-`/` marker. Either way it is not matched as content.
            if seg.is_empty() && is_last && (content_count >= 1 || self.segments.is_empty()) {
                break true;
            }
            match pat_iter.next() {
                Some(PatternSegment::Normal { elems, ambiguity }) => {
                    if !match_segment(elems, *ambiguity, seg.as_bytes(), self.opts, &mut ignore) {
                        return false;
                    }
                }
                // Either the pattern ran out of segments (path has a real one
                // left) or a catch-all snuck in — impossible for a capture-free
                // pattern, but a defensive miss either way.
                None | Some(PatternSegment::CatchAll | PatternSegment::NamedCatchAll { .. }) => {
                    return false;
                }
            }
            content_count += 1;
        };

        // All path content consumed: the pattern must be exhausted and the
        // observed trailing slash must satisfy the policy.
        pat_iter.next().is_none() && self.trailing.accepts(trailing)
    }

    /// Match and return captured values, or `None` when `path` doesn't
    /// match. May allocate a small `Vec` for the bindings.
    ///
    /// ```
    /// use rama_net::uri::{PathPattern, PathRef};
    ///
    /// let pat = PathPattern::new("/simple/:name/?");
    /// let caps = pat.captures(PathRef::from_raw_str("/simple/requests")).unwrap();
    /// assert_eq!(caps.get("name"), Some("requests"));
    /// ```
    #[must_use]
    pub fn captures<'p>(&self, path: PathRef<'p>) -> Option<PathCaptures<'_, 'p>> {
        // Inline the segment list: most paths have a handful of segments, so
        // this keeps the capturing path off the allocator in the common case.
        let segs: SmallVec<[&'p [u8]; 8]> = path.segments().map(|s| s.as_bytes()).collect();
        let segs = self.check_trailing(&segs)?;
        let mut bindings: Vec<Binding<'p>> = Vec::new();
        let mut sink = Sink::Record(&mut bindings);
        let mut seq_memo = SeqMemo::new(&self.segments, segs.len());
        if match_sequence(&self.segments, segs, self.opts, &mut sink, &mut seq_memo) {
            Some(PathCaptures {
                name_bytes: &self.name_bytes,
                bindings,
            })
        } else {
            None
        }
    }

    /// Validate the trailing-slash policy and return the content segments
    /// (with any trailing-`/` empty marker removed), or `None` if the policy
    /// rejects the path.
    ///
    /// `PathRef::segments()` yields a trailing empty segment for a trailing
    /// `/` (so `/a/` -> ["a", ""]); we consume that here rather than letting
    /// it leak into element matching. The bare root `/` is a lone empty
    /// segment that carries the root slash but no content.
    fn check_trailing<'s, 'p>(&self, segs: &'s [&'p [u8]]) -> Option<&'s [&'p [u8]]> {
        // Root `/` (lone empty segment) carries the slash but no content; a
        // final empty segment after real content is the trailing-`/` marker.
        let last_empty = segs.last().is_some_and(|s| s.is_empty());
        let is_root = segs.len() == 1 && last_empty && self.segments.is_empty();
        let (content, has_slash) = if is_root {
            (&segs[..0], true)
        } else if last_empty && segs.len() >= 2 {
            (&segs[..segs.len() - 1], true)
        } else {
            (segs, false)
        };
        self.trailing.accepts(has_slash).then_some(content)
    }
}

/// A recorded capture: name slice into the pattern's `name_bytes`
/// (`name_len == 0` for the anonymous glob), plus the matched, decoded value.
#[derive(Debug, Clone)]
struct Binding<'p> {
    name_start: usize,
    name_len: usize,
    value: Cow<'p, str>,
    /// `true` for the `**` catch-all's joined value.
    is_glob: bool,
}

/// Where matched capture values go. The `is_match` fast path discards them
/// without allocating; `captures` records them.
enum Sink<'b, 'p> {
    Ignore,
    Record(&'b mut Vec<Binding<'p>>),
}

impl<'p> Sink<'_, 'p> {
    /// Insert a binding at index `idx`, preserving left-to-right order when a
    /// run records itself after its tail already pushed bindings.
    fn insert_at(&mut self, idx: usize, b: Binding<'p>) {
        if let Sink::Record(v) = self {
            v.insert(idx, b);
        }
    }
    fn len(&self) -> usize {
        match self {
            Sink::Ignore => 0,
            Sink::Record(v) => v.len(),
        }
    }
    fn truncate(&mut self, n: usize) {
        if let Sink::Record(v) = self {
            v.truncate(n);
        }
    }
}

/// Captured values from a successful [`PathPattern::captures`] match.
///
/// Capture names borrow from the compiled pattern (`'a`). Values are always
/// percent-decoded (per the pattern's options); the `'p` value lifetime ties
/// them to the matched path so a future zero-copy fast path can borrow,
/// though today every value is owned.
///
/// ```
/// use rama_net::uri::{PathPattern, PathRef};
///
/// let pat = PathPattern::new("/p2/**/:file*.txt");
/// let caps = pat.captures(PathRef::from_raw_str("/p2/a/b/c.txt")).unwrap();
/// assert_eq!(caps.glob(), Some("a/b"));
/// assert_eq!(caps.get("file"), Some("c"));
/// ```
#[derive(Debug, Clone)]
pub struct PathCaptures<'a, 'p> {
    name_bytes: &'a [u8],
    bindings: Vec<Binding<'p>>,
}

impl<'a, 'p> PathCaptures<'a, 'p> {
    fn name_of(&self, b: &Binding<'p>) -> &'a str {
        let raw = &self.name_bytes[b.name_start..b.name_start + b.name_len];
        // Safety: capture names are pattern bytes copied verbatim; the
        // accepted name bytes are all ASCII (see `is_name_byte`).
        unsafe { std::str::from_utf8_unchecked(raw) }
    }

    /// The decoded value captured under `name`, or `None` if `name` was not
    /// bound. The `**` catch-all is reachable via [`glob`](Self::glob), not
    /// here.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.bindings
            .iter()
            .find(|b| !b.is_glob && b.name_len != 0 && self.name_of(b) == name)
            .map(|b| b.value.as_ref())
    }

    /// Iterator over `(name, decoded value)` for every named (non-glob)
    /// capture, in match order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.bindings
            .iter()
            .filter(|b| !b.is_glob && b.name_len != 0)
            .map(|b| (self.name_of(b), b.value.as_ref()))
    }

    /// The `**` catch-all value, '/'-joined and decoded, or `None` when the
    /// pattern has no catch-all (or it didn't match).
    #[must_use]
    pub fn glob(&self) -> Option<&str> {
        self.bindings
            .iter()
            .find(|b| b.is_glob)
            .map(|b| b.value.as_ref())
    }

    /// `true` when there are no captures and no catch-all value.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }
}

// ----------------------------------------------------------------------
// Compilation helpers
// ----------------------------------------------------------------------

/// If `seg` is a whole-segment named catch-all (`:name**`), return its name
/// bytes (possibly empty for `:**`). Returns `None` for anything else — including
/// within-segment `:name*` runs (single `*`) and names with non-identifier bytes,
/// which fall through to [`parse_segment`].
fn parse_named_catchall(seg: &[u8]) -> Option<&[u8]> {
    let name = seg.strip_prefix(b":")?.strip_suffix(b"**")?;
    name.iter()
        .all(|&b| is_pattern_name_byte(b))
        .then_some(name)
}

/// Parse one (non catch-all) pattern segment into a sequence of elements.
///
/// `name_bytes` accumulates capture-name bytes; element name indices point
/// into it. `capture_free` is cleared whenever a named capture is seen.
fn parse_segment(
    seg: &[u8],
    name_bytes: &mut Vec<u8>,
    capture_free: &mut bool,
) -> SmallVec<[Element; 2]> {
    let mut elements: SmallVec<[Element; 2]> = SmallVec::new();
    let mut literal: Vec<u8> = Vec::new();
    let mut i = 0;

    // Flush any pending literal run into an element.
    macro_rules! flush_literal {
        () => {
            if !literal.is_empty() {
                elements.push(Element {
                    kind: ElementKind::Literal(std::mem::take(&mut literal).into_boxed_slice()),
                    optional: false,
                });
            }
        };
    }

    while i < seg.len() {
        match seg[i] {
            b'*' => {
                flush_literal!();
                elements.push(Element {
                    kind: ElementKind::Star,
                    optional: false,
                });
                i += 1;
            }
            b':' => {
                flush_literal!();
                // Capture name: identifier bytes until a meta char.
                let start = i + 1;
                let mut end = start;
                while end < seg.len() && is_pattern_name_byte(seg[end]) {
                    end += 1;
                }
                let name = &seg[start..end];
                let name_start = name_bytes.len();
                name_bytes.extend_from_slice(name);
                *capture_free = false;
                elements.push(Element {
                    kind: ElementKind::Capture {
                        name_start,
                        name_len: name.len(),
                    },
                    optional: false,
                });
                i = end;
                // `:name*` — the trailing `*` is part of the capture (run
                // semantics) and adds no separate Star element.
                if i < seg.len() && seg[i] == b'*' {
                    i += 1;
                }
            }
            b'?' => {
                // `?` makes the immediately preceding element optional.
                if let Some(last) = literal.pop() {
                    // A pending literal run takes precedence: `?` binds only its
                    // final byte. Flush the head literal, then push the final
                    // byte as its own optional literal element.
                    flush_literal!();
                    elements.push(Element {
                        kind: ElementKind::Literal(Box::from([last])),
                        optional: true,
                    });
                } else if let Some(last) = elements.last_mut() {
                    last.optional = true;
                } else {
                    // Leading `?` with nothing before it is a literal `?`.
                    literal.push(b'?');
                }
                i += 1;
            }
            other => {
                literal.push(other);
                i += 1;
            }
        }
    }
    flush_literal!();
    elements
}

// ----------------------------------------------------------------------
// Matching
// ----------------------------------------------------------------------
//
// Both match entry points share one greedy recursion. Without guards that
// recursion is exponential: a wildcard run tries every split point and an
// optional element forks, so a segment with many such *ambiguity sources*
// (or a pattern with many `**`) revisits the same `(position)` state over and
// over. Each level fixes that by memoizing *failed* states. Failure-only memo
// is sound because capture recording happens solely on the unique success
// path: a state proven unmatchable can never later succeed, so caching it
// cannot drop or corrupt a binding. The memo grid is allocated only for the
// pathological shapes (>= 2 ambiguity sources in a segment, >= 2 `**` in a
// pattern); simpler shapes recurse linearly with no allocation.

/// Dense 2D failure set (`rows × cols`), one bit per `(row, col)` state packed
/// into `u64` words — 8× tighter than a `bool` grid and fewer cache lines to
/// touch during the recursion. Only built for the pathological shapes that need
/// a memo; simpler patterns never allocate one.
struct BitGrid {
    words: Box<[u64]>,
    cols: usize,
}

impl BitGrid {
    fn new(rows: usize, cols: usize) -> Self {
        let words = vec![0u64; (rows * cols).div_ceil(64)].into_boxed_slice();
        Self { words, cols }
    }

    #[inline]
    fn bit(&self, row: usize, col: usize) -> (usize, u64) {
        let idx = row * self.cols + col;
        (idx >> 6, 1u64 << (idx & 63))
    }

    #[inline]
    fn get(&self, row: usize, col: usize) -> bool {
        let (word, mask) = self.bit(row, col);
        self.words[word] & mask != 0
    }

    #[inline]
    fn set(&mut self, row: usize, col: usize) {
        let (word, mask) = self.bit(row, col);
        self.words[word] |= mask;
    }
}

/// Failure memo for the cross-segment `**` search, keyed on the *remaining*
/// `(pattern, path-segment)` counts. Only allocated when a pattern has two or
/// more `**` (a single `**` can't revisit states).
enum SeqMemo {
    None,
    Grid {
        grid: BitGrid,
        base_pats: usize,
        base_segs: usize,
    },
}

impl SeqMemo {
    fn new(pats: &[PatternSegment], n_segs: usize) -> Self {
        let catch_alls = pats
            .iter()
            .filter(|p| {
                matches!(
                    p,
                    PatternSegment::CatchAll | PatternSegment::NamedCatchAll { .. }
                )
            })
            .count();
        if catch_alls >= 2 {
            Self::Grid {
                grid: BitGrid::new(pats.len() + 1, n_segs + 1),
                base_pats: pats.len(),
                base_segs: n_segs,
            }
        } else {
            Self::None
        }
    }

    /// `true` if the state with `pats_left`/`segs_left` remaining is known to
    /// fail. Both args are suffix lengths of the originals, so the advance from
    /// the start (the grid row/col) is `base − left`.
    fn is_failed(&self, pats_left: usize, segs_left: usize) -> bool {
        match self {
            Self::None => false,
            Self::Grid {
                grid,
                base_pats,
                base_segs,
            } => grid.get(base_pats - pats_left, base_segs - segs_left),
        }
    }

    fn mark_failed(&mut self, pats_left: usize, segs_left: usize) {
        if let Self::Grid {
            grid,
            base_pats,
            base_segs,
        } = self
        {
            grid.set(*base_pats - pats_left, *base_segs - segs_left);
        }
    }
}

/// Match a sequence of pattern segments against the path segments, with
/// backtracking across `**` catch-alls. Returns `true` on full match.
fn match_sequence<'p>(
    pats: &[PatternSegment],
    segs: &[&'p [u8]],
    opts: PathMatchOptions,
    sink: &mut Sink<'_, 'p>,
    memo: &mut SeqMemo,
) -> bool {
    if memo.is_failed(pats.len(), segs.len()) {
        return false;
    }

    let matched = match pats.split_first() {
        None => segs.is_empty(),
        Some((PatternSegment::CatchAll, rest)) => {
            match_catch_all(None, rest, segs, opts, sink, memo)
        }
        Some((
            PatternSegment::NamedCatchAll {
                name_start,
                name_len,
            },
            rest,
        )) => match_catch_all(Some((*name_start, *name_len)), rest, segs, opts, sink, memo),
        Some((PatternSegment::Normal { elems, ambiguity }, rest)) => {
            if let Some((seg, segs_rest)) = segs.split_first() {
                let mark = sink.len();
                if match_segment(elems, *ambiguity, seg, opts, sink)
                    && match_sequence(rest, segs_rest, opts, sink, memo)
                {
                    true
                } else {
                    sink.truncate(mark);
                    false
                }
            } else {
                false
            }
        }
    };

    if !matched {
        memo.mark_failed(pats.len(), segs.len());
    }
    matched
}

/// Match a catch-all (`**` or `:name**`) against `segs`, then the remaining
/// `rest` patterns against the tail. Consumes 1+ path segments, shortest first,
/// growing until the tail matches. On success records the matched run, '/'-joined
/// and decoded — as the anonymous glob when `name` is `None`, else a named binding.
fn match_catch_all<'p>(
    name: Option<(usize, usize)>,
    rest: &[PatternSegment],
    segs: &[&'p [u8]],
    opts: PathMatchOptions,
    sink: &mut Sink<'_, 'p>,
    memo: &mut SeqMemo,
) -> bool {
    for take in 1..=segs.len() {
        let mark = sink.len();
        if match_sequence(rest, &segs[take..], opts, sink, memo) {
            // Record only once the tail matched, so discarded attempts cost nothing.
            let value = join_decoded(&segs[..take], opts.percent_decode);
            let (name_start, name_len, is_glob) = match name {
                Some((start, len)) => (start, len, false),
                None => (0, 0, true),
            };
            sink.insert_at(
                mark,
                Binding {
                    name_start,
                    name_len,
                    value,
                    is_glob,
                },
            );
            return true;
        }
        sink.truncate(mark);
    }
    false
}

/// Match one pattern segment's elements against one path segment's bytes.
///
/// The path segment is decoded once (per `percent_decode`) up front, then
/// elements are matched against the decoded bytes via greedy backtracking.
/// `ambiguity` is the segment's precomputed backtrack-source count; >= 2
/// switches on failure memoization.
fn match_segment<'p>(
    elems: &[Element],
    ambiguity: usize,
    raw_seg: &'p [u8],
    opts: PathMatchOptions,
    sink: &mut Sink<'_, 'p>,
) -> bool {
    let decoded = maybe_decode(raw_seg, opts.percent_decode);
    if ambiguity >= 2 {
        let mut memo = ElemMemo::new(elems.len(), decoded.len());
        match_elems(elems, &decoded, opts, sink, &mut Some(&mut memo))
    } else {
        match_elems(elems, &decoded, opts, sink, &mut None)
    }
}

/// Failure memo for within-segment matching, keyed on the *remaining*
/// `(element, hay-byte)` counts.
struct ElemMemo {
    grid: BitGrid,
    base_elems: usize,
    base_hay: usize,
}

impl ElemMemo {
    fn new(n_elems: usize, n_hay: usize) -> Self {
        Self {
            grid: BitGrid::new(n_elems + 1, n_hay + 1),
            base_elems: n_elems,
            base_hay: n_hay,
        }
    }
    fn is_failed(&self, elems_left: usize, hay_left: usize) -> bool {
        self.grid
            .get(self.base_elems - elems_left, self.base_hay - hay_left)
    }
    fn mark_failed(&mut self, elems_left: usize, hay_left: usize) {
        self.grid
            .set(self.base_elems - elems_left, self.base_hay - hay_left);
    }
}

/// Greedy-with-backtracking match of `elems` against the (already decoded)
/// `hay` bytes. Captures record decoded substrings. `memo`, when present,
/// caches failed `(elems, hay)` states so the recursion stays polynomial.
fn match_elems<'p>(
    elems: &[Element],
    hay: &[u8],
    opts: PathMatchOptions,
    sink: &mut Sink<'_, 'p>,
    memo: &mut Option<&mut ElemMemo>,
) -> bool {
    if let Some(m) = memo
        && m.is_failed(elems.len(), hay.len())
    {
        return false;
    }

    let matched = match elems.split_first() {
        None => hay.is_empty(),
        Some((el, rest)) => match &el.kind {
            ElementKind::Literal(lit) => {
                (byte_starts_with(hay, lit, opts.ignore_ascii_case)
                    && match_elems(rest, &hay[lit.len()..], opts, sink, memo))
                    // Optional literal: skip it entirely.
                    || (el.optional && match_elems(rest, hay, opts, sink, memo))
            }
            // A run already matches zero bytes (the take == 0 split), so its
            // `?` flag is a no-op — handled identically to a non-optional run.
            ElementKind::Star => match_run(None, rest, hay, opts, sink, memo),
            ElementKind::Capture {
                name_start,
                name_len,
            } => match_run(Some((*name_start, *name_len)), rest, hay, opts, sink, memo),
        },
    };

    if !matched && let Some(m) = memo {
        m.mark_failed(elems.len(), hay.len());
    }
    matched
}

/// Match a wildcard run (anonymous `*` or named capture) followed by `rest`.
/// Greedy: try the longest run first, shrinking on backtrack. For a named
/// capture, record the matched (decoded) substring as a binding.
fn match_run<'p>(
    name: Option<(usize, usize)>,
    rest: &[Element],
    hay: &[u8],
    opts: PathMatchOptions,
    sink: &mut Sink<'_, 'p>,
    memo: &mut Option<&mut ElemMemo>,
) -> bool {
    // Try every split point, longest run first (greedy).
    for take in (0..=hay.len()).rev() {
        let mark = sink.len();
        if match_elems(rest, &hay[take..], opts, sink, memo) {
            if let Some((name_start, name_len)) = name {
                // `hay` is already decoded; just own the slice.
                let value = decoded_owned(&hay[..take]);
                // Insert before whatever `rest` recorded so order stays L-to-R.
                sink.insert_at(
                    mark,
                    Binding {
                        name_start,
                        name_len,
                        value,
                        is_glob: false,
                    },
                );
            }
            return true;
        }
        sink.truncate(mark);
    }
    false
}

/// '/'-join decoded segment values into an owned string, in a single pass
/// (no intermediate `Vec<String>`).
fn join_decoded<'p>(segs: &[&'p [u8]], decode: bool) -> Cow<'p, str> {
    // Decoded length ≤ raw length; pre-size for raw bytes plus separators.
    let cap = segs.iter().map(|s| s.len()).sum::<usize>() + segs.len();
    let mut out = String::with_capacity(cap);
    for (i, s) in segs.iter().enumerate() {
        if i > 0 {
            out.push('/');
        }
        out.push_str(&String::from_utf8_lossy(&maybe_decode(s, decode)));
    }
    Cow::Owned(out)
}

/// Own an already-decoded byte slice as a string, replacing invalid UTF-8
/// (reachable: a decoded `%ff` is byte `0xFF`) with U+FFFD.
fn decoded_owned<'p>(bytes: &[u8]) -> Cow<'p, str> {
    Cow::Owned(String::from_utf8_lossy(bytes).into_owned())
}
