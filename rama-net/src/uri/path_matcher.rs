//! Infallible path-pattern matching.
//!
//! [`PathPattern`] compiles a small brace-based glob/capture syntax and matches
//! it against a [`PathRef`](super::PathRef) segment-by-segment, decode-aware and
//! (by default) case-sensitive. Compilation never fails: anything that isn't a
//! recognized brace token is treated as a literal. The only metacharacters are
//! `{`, `}` and `?` — none of which is a valid unencoded URI path byte — so
//! `*`, `:`, `.` etc. are all literals. See [`PathPattern`] for the full syntax.

use std::{
    borrow::Cow,
    cmp::Reverse,
    fmt,
    hash::{Hash, Hasher},
};

use rama_core::{
    Service,
    extensions::{Extension, ExtensionsRef},
};
use rama_utils::collections::smallvec::SmallVec;

use crate::input_ext::PathInputExt;

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
/// A pattern is split on `/` into segments. The only metacharacters are `{`,
/// `}` and `?`; everything else (`*`, `:`, `.`, …) is a literal. Within a
/// segment:
///
/// - **literal** text must equal the (decoded) path segment value;
/// - `{name}` captures a run under `name`: a whole segment when alone
///   (`{id}`), or the run bounded by surrounding literals when affixed
///   (`{pkg}.json` captures the part before `.json`, `v{ver}-rc` the part
///   between);
/// - `{}` is an anonymous wildcard run (0+ chars), not captured (`{}.txt`);
/// - `?` makes the immediately preceding element optional (zero-or-one):
///   `a?` is an optional `a`, `{}?` an optional run, a trailing `/?` an
///   optional trailing slash;
/// - `{*}`, as a *whole* segment, is an anonymous catch-all matching one or
///   more path segments, available '/'-joined and decoded via
///   [`PathCaptures::glob`]. It may appear in the middle of a pattern;
/// - `{*name}`, as a *whole* segment, is the **named** catch-all: same 1+
///   segment match as `{*}`, but the run is recorded under `name` (read back,
///   '/'-joined and decoded, via [`PathCaptures::get`]). So `{name}` stays
///   within a segment; `{*name}` spans segments.
///
/// An unclosed `{`, or a brace group whose body isn't a valid token, is taken
/// literally. `{*}`/`{*name}` are catch-alls only as a *whole* segment.
///
/// Trailing slash is explicit: `/a` matches only `/a`, `/a/` matches only
/// `/a/`, and `/a/?` matches both.
///
/// ```
/// use rama_net::uri::{PathPattern, PathRef};
///
/// let pat = PathPattern::new("/p2/{vendor}/{pkg}.json");
/// let caps = pat.captures(PathRef::from_raw_str("/p2/acme/widget.json")).unwrap();
/// assert_eq!(caps.get("vendor"), Some("acme"));
/// assert_eq!(caps.get("pkg"), Some("widget"));
/// assert!(pat.captures(PathRef::from_raw_str("/p2/acme/widget.txt")).is_none());
///
/// let assets = PathPattern::new("/assets/{*}");
/// assert!(assets.is_match(PathRef::from_raw_str("/assets/css/app.css")));
/// assert!(!assets.is_match(PathRef::from_raw_str("/assets")));
///
/// // `{*name}` is the named catch-all (read back via `get`).
/// let files = PathPattern::new("/files/{*rest}");
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
    /// `true` for a prefix matcher ([`new_prefix`](PathPattern::new_prefix)):
    /// the pattern must match a *leading* run of the path's segments, and any
    /// trailing segments and trailing-slash are ignored.
    prefix: bool,
}

/// Coarse classification of a compiled [`PathPattern`] segment, exposed via
/// [`PathPattern::segment_kinds`] so callers (e.g. a router) can reason about
/// route specificity without re-parsing the pattern syntax themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathPatternSegmentKind {
    /// A fixed string: the segment matches exactly one literal value.
    Literal,
    /// Within-segment dynamic (a capture/wildcard or optional element) still
    /// bound to exactly one path segment.
    Dynamic,
    /// A whole-segment catch-all (`{*}` / `{*name}`) spanning 1+ segments.
    CatchAll,
}

/// Specificity metadata for one compiled [`PathPattern`] segment.
///
/// This lets callers rank overlapping patterns without re-parsing the pattern
/// syntax. The broad [`kind`](Self::kind) preserves the usual ordering
/// (literal > dynamic > catch-all), while the counters let a router break ties
/// between dynamic segments such as `{name}` and `{name}.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PathPatternSegmentSpecificity {
    /// Coarse segment kind.
    pub kind: PathPatternSegmentKind,
    /// Number of fixed literal bytes inside the segment.
    pub literal_bytes: usize,
    /// Number of wildcard/capture runs inside the segment.
    pub dynamic_parts: usize,
    /// Number of optional elements inside the segment.
    pub optional_parts: usize,
}

/// Policy for a path's trailing slash, derived from the pattern's own
/// trailing form (explicit, never inferred).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    /// `{*}` — matches one or more whole path segments (anonymous; read back
    /// via [`PathCaptures::glob`]).
    CatchAll,
    /// `{*name}` — like [`CatchAll`](Self::CatchAll) but records the matched,
    /// '/'-joined run under `name` (read back via [`PathCaptures::get`]).
    NamedCatchAll { name_start: usize, name_len: usize },
    /// A sequence of within-segment elements matched against a single path
    /// segment via greedy backtracking. Inline-sized for the common one- or
    /// two-element segment (a bare literal, capture, or `{pkg}.ext` pair).
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
    /// Anonymous wildcard run (`{}`, 0+ chars within the segment).
    Star,
    /// Named wildcard run that records what it matched. The name is the
    /// `name_bytes[start..start+len]` slice of the owning [`PathPattern`].
    Capture { name_start: usize, name_len: usize },
}

impl PartialEq for PathPattern {
    fn eq(&self, other: &Self) -> bool {
        self.trailing == other.trailing
            && self.opts == other.opts
            && self.prefix == other.prefix
            && self.segments.len() == other.segments.len()
            && self.segments.iter().zip(&other.segments).all(|(a, b)| {
                pattern_segments_eq(
                    a,
                    &self.name_bytes,
                    b,
                    &other.name_bytes,
                    self.opts.ignore_ascii_case,
                )
            })
    }
}

impl Eq for PathPattern {}

impl Hash for PathPattern {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.trailing.hash(state);
        self.opts.hash(state);
        self.prefix.hash(state);
        self.segments.len().hash(state);
        for segment in &self.segments {
            hash_pattern_segment(
                segment,
                &self.name_bytes,
                self.opts.ignore_ascii_case,
                state,
            );
        }
    }
}

fn pattern_segments_eq(
    a: &PatternSegment,
    a_names: &[u8],
    b: &PatternSegment,
    b_names: &[u8],
    ignore_ascii_case: bool,
) -> bool {
    match (a, b) {
        (PatternSegment::CatchAll, PatternSegment::CatchAll) => true,
        (
            PatternSegment::NamedCatchAll {
                name_start: a_start,
                name_len: a_len,
            },
            PatternSegment::NamedCatchAll {
                name_start: b_start,
                name_len: b_len,
            },
        ) => {
            let a = &a_names[*a_start..*a_start + *a_len];
            let b = &b_names[*b_start..*b_start + *b_len];
            a == b
        }
        (
            PatternSegment::Normal {
                elems: a_elems,
                ambiguity: a_ambiguity,
            },
            PatternSegment::Normal {
                elems: b_elems,
                ambiguity: b_ambiguity,
            },
        ) => {
            a_ambiguity == b_ambiguity
                && a_elems.len() == b_elems.len()
                && a_elems
                    .iter()
                    .zip(b_elems)
                    .all(|(a, b)| elements_eq(a, a_names, b, b_names, ignore_ascii_case))
        }
        _ => false,
    }
}

fn elements_eq(
    a: &Element,
    a_names: &[u8],
    b: &Element,
    b_names: &[u8],
    ignore_ascii_case: bool,
) -> bool {
    a.optional == b.optional
        && element_kinds_eq(&a.kind, a_names, &b.kind, b_names, ignore_ascii_case)
}

fn element_kinds_eq(
    a: &ElementKind,
    a_names: &[u8],
    b: &ElementKind,
    b_names: &[u8],
    ignore_ascii_case: bool,
) -> bool {
    match (a, b) {
        (ElementKind::Literal(a), ElementKind::Literal(b)) => literal_eq(a, b, ignore_ascii_case),
        (ElementKind::Star, ElementKind::Star) => true,
        (
            ElementKind::Capture {
                name_start: a_start,
                name_len: a_len,
            },
            ElementKind::Capture {
                name_start: b_start,
                name_len: b_len,
            },
        ) => {
            let a = &a_names[*a_start..*a_start + *a_len];
            let b = &b_names[*b_start..*b_start + *b_len];
            a == b
        }
        _ => false,
    }
}

fn literal_eq(a: &[u8], b: &[u8], ignore_ascii_case: bool) -> bool {
    if ignore_ascii_case {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

fn hash_pattern_segment<H: Hasher>(
    segment: &PatternSegment,
    names: &[u8],
    ignore_ascii_case: bool,
    state: &mut H,
) {
    match segment {
        PatternSegment::CatchAll => 0u8.hash(state),
        PatternSegment::NamedCatchAll {
            name_start,
            name_len,
        } => {
            1u8.hash(state);
            names[*name_start..*name_start + *name_len].hash(state);
        }
        PatternSegment::Normal { elems, ambiguity } => {
            2u8.hash(state);
            ambiguity.hash(state);
            elems.len().hash(state);
            for element in elems {
                hash_element(element, names, ignore_ascii_case, state);
            }
        }
    }
}

fn hash_element<H: Hasher>(
    element: &Element,
    names: &[u8],
    ignore_ascii_case: bool,
    state: &mut H,
) {
    element.optional.hash(state);
    match &element.kind {
        ElementKind::Literal(literal) => {
            0u8.hash(state);
            hash_literal(literal, ignore_ascii_case, state);
        }
        ElementKind::Star => 1u8.hash(state),
        ElementKind::Capture {
            name_start,
            name_len,
        } => {
            2u8.hash(state);
            names[*name_start..*name_start + *name_len].hash(state);
        }
    }
}

fn hash_literal<H: Hasher>(literal: &[u8], ignore_ascii_case: bool, state: &mut H) {
    if ignore_ascii_case {
        literal.len().hash(state);
        for byte in literal {
            byte.to_ascii_lowercase().hash(state);
        }
    } else {
        literal.hash(state);
    }
}

fn pattern_segment_capture_free(segment: &PatternSegment) -> bool {
    match segment {
        PatternSegment::CatchAll | PatternSegment::NamedCatchAll { .. } => false,
        PatternSegment::Normal { elems, .. } => elems
            .iter()
            .all(|element| !matches!(element.kind, ElementKind::Capture { .. })),
    }
}

/// A typed prefix router for URI paths.
///
/// Routes are compiled as [`PathPattern`] prefix matchers and looked up directly
/// against [`PathRef`], so matching does not require callers to lower-case,
/// trim, split, or allocate string lookup keys on the request path.
#[derive(Debug, Clone)]
pub struct PathRouter<T> {
    root: PathRouteNode<T>,
    len: usize,
}

#[derive(Debug, Clone)]
struct PathRouteNode<T> {
    routes: Vec<PathRoute<T>>,
    children: Vec<PathRouteEdge<T>>,
}

#[derive(Debug, Clone)]
struct PathRouteEdge<T> {
    segment: PatternSegment,
    name_bytes: Vec<u8>,
    opts: PathMatchOptions,
    rank: PathRouterSegmentRank,
    child: Box<PathRouteNode<T>>,
}

#[derive(Debug, Clone)]
struct PathRoute<T> {
    pattern: PathPattern,
    segment_count: usize,
    specificity: Box<[PathRouterSegmentRank]>,
    has_captures: bool,
    value: T,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct PathRouterSegmentRank {
    kind: u8,
    literal_bytes: usize,
    fewer_dynamic_parts: Reverse<usize>,
    fewer_optional_parts: Reverse<usize>,
}

/// Result of a successful [`PathRouter::match_prefix`] lookup.
#[derive(Debug)]
pub struct PathRouteMatch<'a, 'p, T> {
    value: &'a T,
    matched_segment_count: usize,
    captures: PathCaptures<'a, 'p>,
}

/// Decoded captures inserted by [`PathRouter`]'s [`Service`] implementation.
#[derive(Debug, Clone, Default, Extension)]
#[extension(tags(net))]
pub struct PathRouteCaptures {
    params: SmallVec<[(String, String); 4]>,
    glob: Option<String>,
}

/// Error produced by [`PathRouter`] when used as a [`Service`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathRouterError<E> {
    /// No registered path matched the input.
    NotFound,
    /// The matched service failed.
    Inner(E),
}

impl<E> fmt::Display for PathRouterError<E>
where
    E: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("no path route matched input"),
            Self::Inner(err) => err.fmt(f),
        }
    }
}

impl<E> std::error::Error for PathRouterError<E> where E: std::error::Error + 'static {}

impl<T> Default for PathRouteNode<T> {
    fn default() -> Self {
        Self {
            routes: Vec::new(),
            children: Vec::new(),
        }
    }
}

impl<T> Default for PathRouter<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> PathRouter<T> {
    /// Create an empty path router.
    #[must_use]
    pub fn new() -> Self {
        Self {
            root: PathRouteNode::default(),
            len: 0,
        }
    }

    /// Returns `true` when no routes are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Number of registered routes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Insert a prefix route using default [`PathMatchOptions`].
    ///
    /// If `pattern` ends in a whole-segment catch-all (`{*}` / `{*name}`), the
    /// catch-all is treated as "the nested target owns the remainder" and is
    /// not counted as part of the matched prefix.
    pub fn insert_prefix(&mut self, pattern: impl IntoUriComponent, value: T) -> Option<T> {
        self.insert_prefix_with_opts(pattern, PathMatchOptions::default(), value)
    }

    /// Insert a prefix route using explicit [`PathMatchOptions`].
    ///
    /// Re-inserting an equivalent compiled pattern replaces the stored value.
    pub fn insert_prefix_with_opts(
        &mut self,
        pattern: impl IntoUriComponent,
        opts: PathMatchOptions,
        value: T,
    ) -> Option<T> {
        let mut pattern = PathPattern::new_prefix_with_opts(pattern, opts);
        pattern.drop_trailing_catch_all();
        let segment_count = pattern.segment_count();
        let has_captures = !pattern.capture_free;
        let specificity = path_router_specificity(&pattern).into_boxed_slice();

        let mut node = &mut self.root;
        for (segment, rank) in pattern.segments.iter().zip(specificity.iter().copied()) {
            let child_idx = if let Some(idx) = node.children.iter().position(|edge| {
                edge.opts == pattern.opts
                    && pattern_segments_eq(
                        &edge.segment,
                        &edge.name_bytes,
                        segment,
                        &pattern.name_bytes,
                        pattern.opts.ignore_ascii_case,
                    )
            }) {
                idx
            } else {
                let idx = node.children.partition_point(|edge| edge.rank >= rank);
                let (segment, name_bytes) =
                    clone_pattern_segment_with_local_names(segment, &pattern.name_bytes);
                node.children.insert(
                    idx,
                    PathRouteEdge {
                        segment,
                        name_bytes,
                        opts: pattern.opts,
                        rank,
                        child: Box::default(),
                    },
                );
                idx
            };
            node = &mut node.children[child_idx].child;
        }

        if let Some(route) = node
            .routes
            .iter_mut()
            .find(|route| route.pattern == pattern)
        {
            return Some(std::mem::replace(&mut route.value, value));
        }

        let pos = node
            .routes
            .partition_point(|route| route.specificity.as_ref() >= specificity.as_ref());
        node.routes.insert(
            pos,
            PathRoute {
                pattern,
                segment_count,
                specificity,
                has_captures,
                value,
            },
        );
        self.len += 1;
        None
    }

    /// Match `path` against the most specific registered prefix.
    #[must_use]
    pub fn match_prefix<'a, 'p>(&'a self, path: PathRef<'p>) -> Option<PathRouteMatch<'a, 'p, T>> {
        let segments: SmallVec<[&'p [u8]; 8]> = path
            .segments()
            .map(|segment| segment.encoded_bytes_unchecked())
            .collect();
        let segments = prefix_content_segments(&segments);
        let matched = self.root.match_prefix(segments, 0)?;
        let captures = if matched.route.has_captures {
            matched.route.pattern.captures(path)?
        } else {
            PathCaptures::empty(&matched.route.pattern.name_bytes)
        };
        Some(PathRouteMatch {
            value: &matched.route.value,
            matched_segment_count: matched.consumed,
            captures,
        })
    }
}

impl<Input, T> Service<Input> for PathRouter<T>
where
    Input: ExtensionsRef + PathInputExt + Send + 'static,
    T: Service<Input>,
{
    type Output = T::Output;
    type Error = PathRouterError<T::Error>;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let Some((service, captures)) = self.match_service(input.path_ref()) else {
            return Err(PathRouterError::NotFound);
        };
        if !captures.is_empty() {
            input.extensions().insert(captures);
        }
        service.serve(input).await.map_err(PathRouterError::Inner)
    }
}

impl<T> PathRouter<T> {
    fn match_service<'a>(&'a self, path: PathRef<'_>) -> Option<(&'a T, PathRouteCaptures)> {
        let matched = self.match_prefix(path)?;
        let captures = PathRouteCaptures::from_captures(matched.captures());
        Some((matched.value(), captures))
    }
}

#[derive(Debug, Clone, Copy)]
struct PathRouteCandidate<'a, T> {
    route: &'a PathRoute<T>,
    consumed: usize,
}

impl<T> PathRouteNode<T> {
    fn match_prefix<'a>(
        &'a self,
        segments: &[&[u8]],
        index: usize,
    ) -> Option<PathRouteCandidate<'a, T>> {
        let mut best = self.routes.first().map(|route| PathRouteCandidate {
            route,
            consumed: index,
        });

        for edge in &self.children {
            match &edge.segment {
                PatternSegment::Normal { elems, ambiguity } => {
                    let Some(segment) = segments.get(index) else {
                        continue;
                    };
                    let mut sink = Sink::Ignore;
                    if !match_segment(elems, *ambiguity, segment, edge.opts, &mut sink) {
                        continue;
                    }
                    if let Some(candidate) = edge.child.match_prefix(segments, index + 1) {
                        best = best_route(best, candidate);
                    }
                }
                PatternSegment::CatchAll | PatternSegment::NamedCatchAll { .. } => {
                    for next in index + 1..=segments.len() {
                        if let Some(candidate) = edge.child.match_prefix(segments, next) {
                            best = best_route(best, candidate);
                        }
                    }
                }
            }
        }

        best
    }
}

fn best_route<'a, T>(
    current: Option<PathRouteCandidate<'a, T>>,
    candidate: PathRouteCandidate<'a, T>,
) -> Option<PathRouteCandidate<'a, T>> {
    let Some(current) = current else {
        return Some(candidate);
    };
    if candidate.consumed > current.consumed
        || (candidate.consumed == current.consumed
            && (candidate.route.segment_count > current.route.segment_count
                || (candidate.route.segment_count == current.route.segment_count
                    && candidate.route.specificity.as_ref() > current.route.specificity.as_ref())))
    {
        Some(candidate)
    } else {
        Some(current)
    }
}

fn prefix_content_segments<'s, 'p>(segments: &'s [&'p [u8]]) -> &'s [&'p [u8]] {
    match segments {
        [b""] => &segments[..0],
        [head @ .., b""] => head,
        _ => segments,
    }
}

fn clone_pattern_segment_with_local_names(
    segment: &PatternSegment,
    names: &[u8],
) -> (PatternSegment, Vec<u8>) {
    let mut local_names = Vec::new();
    let segment = match segment {
        PatternSegment::CatchAll => PatternSegment::CatchAll,
        PatternSegment::NamedCatchAll {
            name_start,
            name_len,
        } => {
            local_names.extend_from_slice(&names[*name_start..*name_start + *name_len]);
            PatternSegment::NamedCatchAll {
                name_start: 0,
                name_len: *name_len,
            }
        }
        PatternSegment::Normal { elems, ambiguity } => PatternSegment::Normal {
            elems: elems
                .iter()
                .map(|element| clone_element_with_local_names(element, names, &mut local_names))
                .collect(),
            ambiguity: *ambiguity,
        },
    };
    (segment, local_names)
}

fn clone_element_with_local_names(
    element: &Element,
    names: &[u8],
    local_names: &mut Vec<u8>,
) -> Element {
    let kind = match &element.kind {
        ElementKind::Literal(literal) => ElementKind::Literal(literal.clone()),
        ElementKind::Star => ElementKind::Star,
        ElementKind::Capture {
            name_start,
            name_len,
        } => {
            let local_start = local_names.len();
            local_names.extend_from_slice(&names[*name_start..*name_start + *name_len]);
            ElementKind::Capture {
                name_start: local_start,
                name_len: *name_len,
            }
        }
    };
    Element {
        kind,
        optional: element.optional,
    }
}

impl<'a, 'p, T> PathRouteMatch<'a, 'p, T> {
    /// Value stored for the matched route.
    #[must_use]
    pub fn value(&self) -> &'a T {
        self.value
    }

    /// Number of path segments covered by the matched prefix.
    #[must_use]
    pub fn matched_segment_count(&self) -> usize {
        self.matched_segment_count
    }

    /// Captures produced while matching the prefix.
    #[must_use]
    pub fn captures(&self) -> &PathCaptures<'a, 'p> {
        &self.captures
    }

    /// Decompose into owned match parts.
    #[must_use]
    pub fn into_parts(self) -> (&'a T, usize, PathCaptures<'a, 'p>) {
        (self.value, self.matched_segment_count, self.captures)
    }
}

impl PathRouteCaptures {
    fn from_captures(captures: &PathCaptures<'_, '_>) -> Self {
        Self {
            params: captures
                .iter()
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
                .collect(),
            glob: captures.glob().map(str::to_owned),
        }
    }

    /// The decoded value captured under `name`, or `None` if absent.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// Iterator over decoded named captures in match order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.params
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
    }

    /// The decoded anonymous `{*}` capture, if present.
    #[must_use]
    pub fn glob(&self) -> Option<&str> {
        self.glob.as_deref()
    }

    /// `true` when no named param and no anonymous glob were captured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.params.is_empty() && self.glob.is_none()
    }
}

fn path_router_specificity(pattern: &PathPattern) -> Vec<PathRouterSegmentRank> {
    pattern
        .segment_specificity()
        .map(|spec| PathRouterSegmentRank {
            kind: match spec.kind {
                PathPatternSegmentKind::Literal => 2,
                PathPatternSegmentKind::Dynamic => 1,
                PathPatternSegmentKind::CatchAll => 0,
            },
            literal_bytes: spec.literal_bytes,
            fewer_dynamic_parts: Reverse(spec.dynamic_parts),
            fewer_optional_parts: Reverse(spec.optional_parts),
        })
        .collect()
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
        Self::compile(&raw, opts, false)
    }

    /// Compile a **prefix** matcher: the pattern must match a leading run of the
    /// path's segments; any trailing segments and the path's trailing slash are
    /// ignored. So `/api` matches `/api`, `/api/`, and `/api/users` — but not
    /// `/apixyz` (segments are matched whole).
    ///
    /// ```
    /// use rama_net::uri::{PathPattern, PathRef};
    ///
    /// let api = PathPattern::new_prefix("/api");
    /// assert!(api.is_match(PathRef::from_raw_str("/api")));
    /// assert!(api.is_match(PathRef::from_raw_str("/api/users/42")));
    /// assert!(!api.is_match(PathRef::from_raw_str("/apixyz")));
    /// ```
    #[must_use]
    pub fn new_prefix(pattern: impl IntoUriComponent) -> Self {
        Self::new_prefix_with_opts(pattern, PathMatchOptions::default())
    }

    /// [`new_prefix`](Self::new_prefix) with explicit [`PathMatchOptions`].
    #[must_use]
    #[expect(
        clippy::needless_pass_by_value,
        reason = "by-value matches IntoUriComponent's signature on sibling APIs; this impl only borrows the input"
    )]
    pub fn new_prefix_with_opts(pattern: impl IntoUriComponent, opts: PathMatchOptions) -> Self {
        let raw = pattern.as_uri_component_bytes();
        Self::compile(&raw, opts, true)
    }

    fn compile(raw: &[u8], mut opts: PathMatchOptions, prefix: bool) -> Self {
        opts.partial = false;
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
                match parse_catchall(seg) {
                    Some(CatchAll::Anon) => {
                        capture_free = false;
                        segments.push(PatternSegment::CatchAll);
                        continue;
                    }
                    Some(CatchAll::Named(name)) => {
                        capture_free = false;
                        let name_start = name_bytes.len();
                        name_bytes.extend_from_slice(name);
                        segments.push(PatternSegment::NamedCatchAll {
                            name_start,
                            name_len: name.len(),
                        });
                        continue;
                    }
                    None => {}
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
            prefix,
        }
    }

    fn segment_count(&self) -> usize {
        self.segments.len()
    }

    fn drop_trailing_catch_all(&mut self) -> bool {
        let Some(PatternSegment::CatchAll | PatternSegment::NamedCatchAll { .. }) =
            self.segments.last()
        else {
            return false;
        };
        self.segments.pop();
        self.capture_free = self.segments.iter().all(pattern_segment_capture_free);
        true
    }

    /// The [kind](PathPatternSegmentKind) of each `/`-delimited pattern segment,
    /// in order — so callers can classify segments (literal vs dynamic vs
    /// catch-all) straight from the compiled pattern instead of re-parsing the
    /// syntax. A bare-root pattern (`/`) yields an empty iterator.
    ///
    /// ```
    /// use rama_net::uri::{PathPattern, PathPatternSegmentKind as K};
    ///
    /// let kinds: Vec<_> = PathPattern::new("/users/{id}/{*rest}").segment_kinds().collect();
    /// assert_eq!(kinds, [K::Literal, K::Dynamic, K::CatchAll]);
    /// // An invalid catch-all body is a literal, exactly as the matcher treats it.
    /// let kinds: Vec<_> = PathPattern::new("/api/{*bad name}").segment_kinds().collect();
    /// assert_eq!(kinds, [K::Literal, K::Literal]);
    /// ```
    pub fn segment_kinds(&self) -> impl ExactSizeIterator<Item = PathPatternSegmentKind> + '_ {
        self.segment_specificity().map(|spec| spec.kind)
    }

    /// Specificity metadata for each `/`-delimited pattern segment, in order.
    /// This is a richer version of [`segment_kinds`](Self::segment_kinds) for
    /// callers that need stable precedence among overlapping dynamic patterns.
    ///
    /// ```
    /// use rama_net::uri::{PathPattern, PathPatternSegmentKind as K};
    ///
    /// let specs: Vec<_> = PathPattern::new("/files/{name}.json")
    ///     .segment_specificity()
    ///     .collect();
    /// assert_eq!(specs[0].kind, K::Literal);
    /// assert_eq!(specs[1].kind, K::Dynamic);
    /// assert_eq!(specs[1].literal_bytes, 5);
    /// assert_eq!(specs[1].dynamic_parts, 1);
    /// ```
    pub fn segment_specificity(
        &self,
    ) -> impl ExactSizeIterator<Item = PathPatternSegmentSpecificity> + '_ {
        self.segments.iter().map(|seg| match seg {
            PatternSegment::CatchAll | PatternSegment::NamedCatchAll { .. } => {
                PathPatternSegmentSpecificity {
                    kind: PathPatternSegmentKind::CatchAll,
                    literal_bytes: 0,
                    dynamic_parts: 1,
                    optional_parts: 0,
                }
            }
            PatternSegment::Normal { elems, ambiguity } => {
                let literal_bytes = elems
                    .iter()
                    .map(|el| match &el.kind {
                        ElementKind::Literal(lit) => lit.len(),
                        ElementKind::Star | ElementKind::Capture { .. } => 0,
                    })
                    .sum();
                let dynamic_parts = elems
                    .iter()
                    .filter(|el| matches!(el.kind, ElementKind::Star | ElementKind::Capture { .. }))
                    .count();
                let optional_parts = elems.iter().filter(|el| el.optional).count();
                PathPatternSegmentSpecificity {
                    // `ambiguity == 0` means no wildcard/capture/optional
                    // element, so the segment is a fixed string.
                    kind: if *ambiguity == 0 {
                        PathPatternSegmentKind::Literal
                    } else {
                        PathPatternSegmentKind::Dynamic
                    },
                    literal_bytes,
                    dynamic_parts,
                    optional_parts,
                }
            }
        })
    }

    /// `true` when `path` matches. Allocation-free when the pattern has no
    /// captures and no catch-all.
    ///
    /// ```
    /// use rama_net::uri::{PathPattern, PathRef};
    ///
    /// let pat = PathPattern::new("/files/{}.txt");
    /// assert!(pat.is_match(PathRef::from_raw_str("/files/readme.txt")));
    /// assert!(!pat.is_match(PathRef::from_raw_str("/files/readme.md")));
    /// ```
    #[must_use]
    pub fn is_match(&self, path: PathRef<'_>) -> bool {
        // The fast path assumes a full, both-ends-anchored match; prefix matching
        // needs the segment-sequence engine, so route it through `captures`.
        if self.capture_free && !self.prefix {
            self.is_match_fast(path)
        } else {
            self.captures(path).is_some()
        }
    }

    /// Allocation-free match for capture-free patterns. A capture-free
    /// pattern has no catch-all, so every pattern segment matches exactly one path
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
                    if !match_segment(
                        elems,
                        *ambiguity,
                        seg.encoded_bytes_unchecked(),
                        self.opts,
                        &mut ignore,
                    ) {
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
    /// match. Uses inline storage for the common small number of bindings.
    ///
    /// ```
    /// use rama_net::uri::{PathPattern, PathRef};
    ///
    /// let pat = PathPattern::new("/simple/{name}/?");
    /// let caps = pat.captures(PathRef::from_raw_str("/simple/requests")).unwrap();
    /// assert_eq!(caps.get("name"), Some("requests"));
    /// ```
    #[must_use]
    pub fn captures<'p>(&self, path: PathRef<'p>) -> Option<PathCaptures<'_, 'p>> {
        // Inline the segment list: most paths have a handful of segments, so
        // this keeps the capturing path off the allocator in the common case.
        let all: SmallVec<[&'p [u8]; 8]> = path
            .segments()
            .map(|s| s.encoded_bytes_unchecked())
            .collect();
        // A prefix match ignores trailing segments + trailing-slash policy, so
        // it matches against all segments; a full match trims the trailing-`/`
        // marker and enforces the policy.
        let segs: &[&'p [u8]] = if self.prefix {
            &all
        } else {
            self.check_trailing(&all)?
        };
        let mut bindings: SmallVec<[Binding<'p>; 4]> = SmallVec::new();
        let mut sink = Sink::Record(&mut bindings);
        let mut seq_memo = SeqMemo::new(&self.segments, segs.len());
        if match_sequence(
            &self.segments,
            segs,
            self.opts,
            &mut sink,
            &mut seq_memo,
            self.prefix,
        ) {
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
    /// `true` for the `{*}` catch-all's joined value.
    is_glob: bool,
}

/// Where matched capture values go. The `is_match` fast path discards them
/// without allocating; `captures` records them.
enum Sink<'b, 'p> {
    Ignore,
    Record(&'b mut SmallVec<[Binding<'p>; 4]>),
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
/// let pat = PathPattern::new("/p2/{*}/{file}.txt");
/// let caps = pat.captures(PathRef::from_raw_str("/p2/a/b/c.txt")).unwrap();
/// assert_eq!(caps.glob(), Some("a/b"));
/// assert_eq!(caps.get("file"), Some("c"));
/// ```
#[derive(Debug, Clone)]
pub struct PathCaptures<'a, 'p> {
    name_bytes: &'a [u8],
    bindings: SmallVec<[Binding<'p>; 4]>,
}

impl<'a, 'p> PathCaptures<'a, 'p> {
    fn empty(name_bytes: &'a [u8]) -> Self {
        Self {
            name_bytes,
            bindings: SmallVec::new(),
        }
    }

    fn name_of(&self, b: &Binding<'p>) -> &'a str {
        let raw = &self.name_bytes[b.name_start..b.name_start + b.name_len];
        // Safety: capture names are pattern bytes copied verbatim; the
        // accepted name bytes are all ASCII (see `is_name_byte`).
        unsafe { std::str::from_utf8_unchecked(raw) }
    }

    /// The decoded value captured under `name`, or `None` if `name` was not
    /// bound. The `{*}` catch-all is reachable via [`glob`](Self::glob), not
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

    /// The `{*}` catch-all value, '/'-joined and decoded, or `None` when the
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

/// A whole-segment catch-all token.
enum CatchAll<'a> {
    /// `{*}`
    Anon,
    /// `{*name}` (name is non-empty, all [`is_pattern_name_byte`]).
    Named(&'a [u8]),
}

/// If `seg` is a whole-segment catch-all (`{*}` or `{*name}`), classify it.
/// Returns `None` for anything else — including mid-segment `{*…}` (handled as
/// a literal by [`parse_segment`]) and `{*bad name}` — which fall through.
fn parse_catchall(seg: &[u8]) -> Option<CatchAll<'_>> {
    let inner = seg.strip_prefix(b"{*")?.strip_suffix(b"}")?;
    if inner.is_empty() {
        return Some(CatchAll::Anon);
    }
    inner
        .iter()
        .all(|&b| is_pattern_name_byte(b))
        .then_some(CatchAll::Named(inner))
}

/// Parse one (non catch-all) pattern segment into a sequence of elements.
///
/// Scans for `{…}` brace groups (`{}` -> [`Star`](ElementKind::Star),
/// `{name}` -> [`Capture`](ElementKind::Capture)); everything outside braces is
/// literal. An unclosed `{`, or a group whose body isn't a valid token, is kept
/// literal. `name_bytes` accumulates capture-name bytes; element name indices
/// point into it. `capture_free` is cleared whenever a named capture is seen.
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
            b'{' => {
                // A `{…}` group is a token only when it closes and its body is
                // a valid name (or empty); otherwise the `{` is a literal byte.
                if let Some((kind, next)) = parse_brace(seg, i, name_bytes, capture_free) {
                    flush_literal!();
                    elements.push(Element {
                        kind,
                        optional: false,
                    });
                    i = next;
                } else {
                    literal.push(b'{');
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

/// Parse a within-segment `{…}` group starting at `seg[open] == '{'`. On a
/// valid token returns its [`ElementKind`] and the index just past the closing
/// `}`. `{}` -> Star, `{name}` -> Capture (name = non-empty
/// [`is_pattern_name_byte`] run). Returns `None` (so the caller keeps `{`
/// literal) for an unclosed brace or any non-name body — including `{*…}`,
/// which is a catch-all only as a whole segment.
fn parse_brace(
    seg: &[u8],
    open: usize,
    name_bytes: &mut Vec<u8>,
    capture_free: &mut bool,
) -> Option<(ElementKind, usize)> {
    let close = open + 1 + seg[open + 1..].iter().position(|&b| b == b'}')?;
    let inner = &seg[open + 1..close];
    let next = close + 1;
    if inner.is_empty() {
        return Some((ElementKind::Star, next));
    }
    if !inner.iter().all(|&b| is_pattern_name_byte(b)) {
        return None;
    }
    let name_start = name_bytes.len();
    name_bytes.extend_from_slice(inner);
    *capture_free = false;
    Some((
        ElementKind::Capture {
            name_start,
            name_len: inner.len(),
        },
        next,
    ))
}

// ----------------------------------------------------------------------
// Matching
// ----------------------------------------------------------------------
//
// Both match entry points share one greedy recursion. Without guards that
// recursion is exponential: a wildcard run tries every split point and an
// optional element forks, so a segment with many such *ambiguity sources*
// (or a pattern with many `{*}`) revisits the same `(position)` state over and
// over. Each level fixes that by memoizing *failed* states. Failure-only memo
// is sound because capture recording happens solely on the unique success
// path: a state proven unmatchable can never later succeed, so caching it
// cannot drop or corrupt a binding. The memo grid is allocated only for the
// pathological shapes (>= 2 ambiguity sources in a segment, >= 2 `{*}` in a
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

/// Failure memo for the cross-segment catch-all search, keyed on the *remaining*
/// `(pattern, path-segment)` counts. Only allocated when a pattern has two or
/// more catch-alls (a single one can't revisit states).
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
/// backtracking across `{*}` catch-alls. Returns `true` on a match. When
/// `prefix` is set, a path tail left over after the pattern is exhausted is
/// accepted (leading-run match) instead of requiring full consumption.
fn match_sequence<'p>(
    pats: &[PatternSegment],
    segs: &[&'p [u8]],
    opts: PathMatchOptions,
    sink: &mut Sink<'_, 'p>,
    memo: &mut SeqMemo,
    prefix: bool,
) -> bool {
    if memo.is_failed(pats.len(), segs.len()) {
        return false;
    }

    let matched = match pats.split_first() {
        None => prefix || segs.is_empty(),
        Some((PatternSegment::CatchAll, rest)) => {
            match_catch_all(None, rest, segs, opts, sink, memo, prefix)
        }
        Some((
            PatternSegment::NamedCatchAll {
                name_start,
                name_len,
            },
            rest,
        )) => match_catch_all(
            Some((*name_start, *name_len)),
            rest,
            segs,
            opts,
            sink,
            memo,
            prefix,
        ),
        Some((PatternSegment::Normal { elems, ambiguity }, rest)) => {
            if let Some((seg, segs_rest)) = segs.split_first() {
                let mark = sink.len();
                if match_segment(elems, *ambiguity, seg, opts, sink)
                    && match_sequence(rest, segs_rest, opts, sink, memo, prefix)
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

/// Match a catch-all (`{*}` or `{*name}`) against `segs`, then the remaining
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
    prefix: bool,
) -> bool {
    for take in 1..=segs.len() {
        let mark = sink.len();
        if match_sequence(rest, &segs[take..], opts, sink, memo, prefix) {
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

/// Match a wildcard run (anonymous `{}` or named capture) followed by `rest`.
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
