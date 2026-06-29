//! JSONPath parsing and typed construction.
//!
//! Rama targets RFC 9535 JSONPath. This module implements the selectors that
//! can be matched efficiently from the concrete path of a value observed by a
//! forward streaming parser.
//!
//! # RFC 9535 support matrix
//!
//! | Feature | Status | Notes |
//! | --- | --- | --- |
//! | Root selector `$` | supported | Always the implicit path root. |
//! | Dot member `.name` | supported | ASCII identifier shorthand. |
//! | Bracket member `['name']` / `["name"]` | supported | JSON string escapes, including surrogate pairs. |
//! | Wildcard `*` | supported | Child and descendant forms. |
//! | Array index `[0]` | supported | Non-negative indexes. |
//! | Array slice `[start:end:step]` | supported | Non-negative bounds and positive step only. |
//! | Selector lists / unions `[0,'name',*]` | supported | Child and descendant forms. |
//! | Descendant segment `..` | supported | Member, index, wildcard, slice, and union selectors. |
//! | Negative indexes / slices | unsupported | RFC semantics require array length, which a pure forward matcher does not know. |
//! | Filter selectors `[?(...)]` | unsupported | Requires an expression evaluator and possibly buffered subtrees. |

use std::fmt;
use std::num::NonZeroUsize;
use std::str::FromStr;

use crate::{JsonError, JsonErrorKind};

/// A compiled JSONPath expression.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JsonPath {
    segments: Box<[Segment]>,
}

impl JsonPath {
    /// Returns a typed JSONPath builder.
    #[must_use]
    pub fn builder() -> JsonPathBuilder {
        JsonPathBuilder::new()
    }

    /// Builds a path from already typed segments.
    #[must_use]
    pub fn from_segments(segments: impl Into<Vec<Segment>>) -> Self {
        Self {
            segments: segments.into().into_iter().map(normalize_segment).collect(),
        }
    }

    /// Path segments after the root `$`.
    #[must_use]
    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    /// Whether this path only contains exact member and index selectors.
    #[must_use]
    pub fn is_singular(&self) -> bool {
        self.segments
            .iter()
            .all(|s| matches!(s, Segment::Member(_) | Segment::Index(_)))
    }

    /// Returns whether this JSONPath matches an already tracked value path.
    #[must_use]
    pub fn matches_path(&self, path: &[PathElement]) -> bool {
        matches_from(&self.segments, 0, path, 0)
    }
}

impl FromStr for JsonPath {
    type Err = JsonError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Parser::new(s).parse()
    }
}

impl fmt::Display for JsonPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("$")?;
        for segment in &self.segments {
            write!(f, "{segment}")?;
        }
        Ok(())
    }
}

/// One JSONPath selector segment after the root.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Segment {
    /// `.name` / `['name']`.
    Member(Box<str>),
    /// `[index]`.
    Index(usize),
    /// `[start:end:step]`.
    Slice(Slice),
    /// `.*` / `[*]`.
    Wildcard,
    /// `[selector, ...]`.
    Union(Box<[Self]>),
    /// `..name`.
    DescendantMember(Box<str>),
    /// `..[index]`.
    DescendantIndex(usize),
    /// `..[start:end:step]`.
    DescendantSlice(Slice),
    /// `..*`.
    DescendantWildcard,
    /// `..[selector, ...]`.
    DescendantUnion(Box<[Self]>),
}

/// RFC 9535 array slice selector with streaming-compatible semantics.
///
/// Negative bounds and negative steps are intentionally not represented here:
/// those require knowing the array length before matching can be correct.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Slice {
    start: Option<usize>,
    end: Option<usize>,
    step: NonZeroUsize,
}

impl Slice {
    /// Creates a positive-step slice selector.
    #[must_use]
    pub const fn new(start: Option<usize>, end: Option<usize>, step: NonZeroUsize) -> Self {
        Self { start, end, step }
    }

    /// Inclusive start bound, or `None` for the default start.
    #[must_use]
    pub const fn start(self) -> Option<usize> {
        self.start
    }

    /// Exclusive end bound, or `None` for an open-ended slice.
    #[must_use]
    pub const fn end(self) -> Option<usize> {
        self.end
    }

    /// Positive step.
    #[must_use]
    pub const fn step(self) -> NonZeroUsize {
        self.step
    }

    /// Returns whether this slice includes `index`.
    #[must_use]
    pub fn contains(self, index: usize) -> bool {
        let start = self.start.unwrap_or(0);
        if index < start {
            return false;
        }
        if self.end.is_some_and(|end| index >= end) {
            return false;
        }
        (index - start).is_multiple_of(self.step.get())
    }
}

/// One concrete location segment for a value encountered in a JSON document.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PathElement {
    /// Object member.
    Member(Box<str>),
    /// Array element.
    Index(usize),
}

impl fmt::Display for PathElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Member(name) if is_dot_member_name(name) => write!(f, ".{name}"),
            Self::Member(name) => write_quoted_member(f, name),
            Self::Index(index) => write!(f, "[{index}]"),
        }
    }
}

fn matches_from(
    selector: &[Segment],
    selector_index: usize,
    path: &[PathElement],
    path_index: usize,
) -> bool {
    if selector_index == selector.len() {
        return path_index == path.len();
    }

    match &selector[selector_index] {
        Segment::Member(expected) => {
            matches!(path.get(path_index), Some(PathElement::Member(actual)) if actual == expected)
                && matches_from(selector, selector_index + 1, path, path_index + 1)
        }
        Segment::Index(expected) => {
            matches!(path.get(path_index), Some(PathElement::Index(actual)) if actual == expected)
                && matches_from(selector, selector_index + 1, path, path_index + 1)
        }
        Segment::Slice(slice) => {
            matches!(path.get(path_index), Some(PathElement::Index(actual)) if slice.contains(*actual))
                && matches_from(selector, selector_index + 1, path, path_index + 1)
        }
        Segment::Wildcard => {
            path_index < path.len()
                && matches_from(selector, selector_index + 1, path, path_index + 1)
        }
        Segment::Union(segments) => {
            path.get(path_index).is_some_and(|element| {
                segments
                    .iter()
                    .any(|segment| matches_child(segment, element))
            }) && matches_from(selector, selector_index + 1, path, path_index + 1)
        }
        Segment::DescendantMember(expected) => {
            for index in path_index..path.len() {
                if matches!(
                    path.get(index),
                    Some(PathElement::Member(actual)) if actual == expected
                ) && matches_from(selector, selector_index + 1, path, index + 1)
                {
                    return true;
                }
            }
            false
        }
        Segment::DescendantIndex(expected) => {
            for index in path_index..path.len() {
                if matches!(path.get(index), Some(PathElement::Index(actual)) if actual == expected)
                    && matches_from(selector, selector_index + 1, path, index + 1)
                {
                    return true;
                }
            }
            false
        }
        Segment::DescendantSlice(slice) => {
            for index in path_index..path.len() {
                if matches!(path.get(index), Some(PathElement::Index(actual)) if slice.contains(*actual))
                    && matches_from(selector, selector_index + 1, path, index + 1)
                {
                    return true;
                }
            }
            false
        }
        Segment::DescendantWildcard => {
            for index in path_index..path.len() {
                if matches_from(selector, selector_index + 1, path, index + 1) {
                    return true;
                }
            }
            false
        }
        Segment::DescendantUnion(segments) => {
            for index in path_index..path.len() {
                if path.get(index).is_some_and(|element| {
                    segments
                        .iter()
                        .any(|segment| matches_child(segment, element))
                }) && matches_from(selector, selector_index + 1, path, index + 1)
                {
                    return true;
                }
            }
            false
        }
    }
}

fn matches_child(selector: &Segment, element: &PathElement) -> bool {
    match (selector, element) {
        (Segment::Member(expected), PathElement::Member(actual)) => actual == expected,
        (Segment::Index(expected), PathElement::Index(actual)) => actual == expected,
        (Segment::Slice(slice), PathElement::Index(actual)) => slice.contains(*actual),
        (Segment::Wildcard, _) => true,
        (Segment::Union(segments), _) => segments
            .iter()
            .any(|segment| matches_child(segment, element)),
        _ => false,
    }
}

impl fmt::Display for Segment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Member(name) if is_dot_member_name(name) => write!(f, ".{name}"),
            Self::Member(name) => write_quoted_member(f, name),
            Self::Index(index) => write!(f, "[{index}]"),
            Self::Slice(slice) => write_slice(f, *slice, false),
            Self::Wildcard => f.write_str("[*]"),
            Self::Union(segments) => write_selector_list(f, segments, false),
            Self::DescendantMember(name) if is_dot_member_name(name) => write!(f, "..{name}"),
            Self::DescendantMember(name) => {
                f.write_str("..")?;
                write_quoted_member(f, name)
            }
            Self::DescendantIndex(index) => write!(f, "..[{index}]"),
            Self::DescendantSlice(slice) => {
                f.write_str("..")?;
                write_slice(f, *slice, false)
            }
            Self::DescendantWildcard => f.write_str("..*"),
            Self::DescendantUnion(segments) => write_selector_list(f, segments, true),
        }
    }
}

/// Typed builder for [`JsonPath`].
#[derive(Debug, Clone, Default)]
pub struct JsonPathBuilder {
    segments: Vec<Segment>,
}

impl JsonPathBuilder {
    /// Creates a new builder rooted at `$`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a child member selector.
    #[must_use]
    pub fn member(mut self, name: impl Into<Box<str>>) -> Self {
        self.segments.push(Segment::Member(name.into()));
        self
    }

    /// Adds a child array index selector.
    #[must_use]
    pub fn index(mut self, index: usize) -> Self {
        self.segments.push(Segment::Index(index));
        self
    }

    /// Adds a child array slice selector.
    #[must_use]
    pub fn slice(mut self, start: Option<usize>, end: Option<usize>, step: NonZeroUsize) -> Self {
        self.segments
            .push(Segment::Slice(Slice::new(start, end, step)));
        self
    }

    /// Adds a child wildcard selector.
    #[must_use]
    pub fn wildcard(mut self) -> Self {
        self.segments.push(Segment::Wildcard);
        self
    }

    /// Adds a child selector list.
    #[must_use]
    pub fn union(mut self, segments: impl Into<Vec<Segment>>) -> Self {
        self.segments
            .push(Segment::Union(segments.into().into_boxed_slice()));
        self
    }

    /// Adds a descendant member selector.
    #[must_use]
    pub fn descendant_member(mut self, name: impl Into<Box<str>>) -> Self {
        self.segments.push(Segment::DescendantMember(name.into()));
        self
    }

    /// Adds a descendant array index selector.
    #[must_use]
    pub fn descendant_index(mut self, index: usize) -> Self {
        self.segments.push(Segment::DescendantIndex(index));
        self
    }

    /// Adds a descendant array slice selector.
    #[must_use]
    pub fn descendant_slice(
        mut self,
        start: Option<usize>,
        end: Option<usize>,
        step: NonZeroUsize,
    ) -> Self {
        self.segments
            .push(Segment::DescendantSlice(Slice::new(start, end, step)));
        self
    }

    /// Adds a descendant wildcard selector.
    #[must_use]
    pub fn descendant_wildcard(mut self) -> Self {
        self.segments.push(Segment::DescendantWildcard);
        self
    }

    /// Adds a descendant selector list.
    #[must_use]
    pub fn descendant_union(mut self, segments: impl Into<Vec<Segment>>) -> Self {
        self.segments
            .push(Segment::DescendantUnion(segments.into().into_boxed_slice()));
        self
    }

    /// Finishes the path.
    #[must_use]
    pub fn build(self) -> JsonPath {
        JsonPath::from_segments(self.segments)
    }
}

fn normalize_segment(segment: Segment) -> Segment {
    match segment {
        Segment::Union(segments) => {
            let mut segments: Vec<_> = segments
                .into_vec()
                .into_iter()
                .map(normalize_segment)
                .collect();
            if segments.len() == 1 {
                segments.remove(0)
            } else {
                Segment::Union(segments.into_boxed_slice())
            }
        }
        Segment::DescendantUnion(segments) => {
            let mut segments: Vec<_> = segments
                .into_vec()
                .into_iter()
                .map(normalize_segment)
                .collect();
            if segments.len() == 1 {
                match segments.remove(0) {
                    Segment::Member(name) => Segment::DescendantMember(name),
                    Segment::Index(index) => Segment::DescendantIndex(index),
                    Segment::Slice(slice) => Segment::DescendantSlice(slice),
                    Segment::Wildcard => Segment::DescendantWildcard,
                    Segment::Union(segments) => Segment::DescendantUnion(segments),
                    segment @ (Segment::DescendantMember(_)
                    | Segment::DescendantIndex(_)
                    | Segment::DescendantSlice(_)
                    | Segment::DescendantWildcard
                    | Segment::DescendantUnion(_)) => segment,
                }
            } else {
                Segment::DescendantUnion(segments.into_boxed_slice())
            }
        }
        segment => segment,
    }
}

struct Parser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn parse(mut self) -> Result<JsonPath, JsonError> {
        if self.input.is_empty() {
            return Err(JsonError::new(JsonErrorKind::EmptyPath));
        }
        if !self.eat('$') {
            return Err(JsonError::new(JsonErrorKind::MissingRoot));
        }

        let mut segments = Vec::new();
        loop {
            match self.peek() {
                Some('.') => {
                    self.bump();
                    if self.eat('.') {
                        segments.push(self.parse_descendant()?);
                    } else {
                        segments.push(self.parse_dot_child()?);
                    }
                }
                Some('[') => segments.push(self.parse_bracket_child()?),
                Some(_) => {
                    return Err(JsonError::new(JsonErrorKind::InvalidJsonPath(
                        "expected selector",
                    )));
                }
                None => break,
            }
        }

        Ok(JsonPath {
            segments: segments.into_boxed_slice(),
        })
    }

    fn parse_dot_child(&mut self) -> Result<Segment, JsonError> {
        if self.eat('*') {
            return Ok(Segment::Wildcard);
        }
        Ok(Segment::Member(self.parse_name()?))
    }

    fn parse_descendant(&mut self) -> Result<Segment, JsonError> {
        if self.eat('*') {
            return Ok(Segment::DescendantWildcard);
        }
        if self.peek() == Some('[') {
            return descendant_from_child(self.parse_bracket_child()?);
        }
        Ok(Segment::DescendantMember(self.parse_name()?))
    }

    fn parse_bracket_child(&mut self) -> Result<Segment, JsonError> {
        self.expect('[')?;
        let mut selectors = Vec::new();
        selectors.push(self.parse_bracket_selector()?);
        while self.eat(',') {
            selectors.push(self.parse_bracket_selector()?);
        }
        self.expect(']')?;

        if selectors.len() == 1 {
            Ok(selectors.remove(0))
        } else {
            Ok(Segment::Union(selectors.into_boxed_slice()))
        }
    }

    fn parse_bracket_selector(&mut self) -> Result<Segment, JsonError> {
        match self.peek() {
            Some('*') => {
                self.bump();
                Ok(Segment::Wildcard)
            }
            Some('\'' | '"') => {
                let name = self.parse_quoted()?;
                Ok(Segment::Member(name))
            }
            Some('?') => Err(JsonError::new(JsonErrorKind::UnsupportedJsonPath(
                "filter selectors",
            ))),
            Some(':') => self.parse_slice(None),
            Some('-') => Err(JsonError::new(JsonErrorKind::UnsupportedJsonPath(
                "negative array indices and slices",
            ))),
            Some(c) if c.is_ascii_digit() => {
                let first = self.parse_index()?;
                if self.peek() == Some(':') {
                    self.parse_slice(Some(first))
                } else {
                    Ok(Segment::Index(first))
                }
            }
            _ => Err(JsonError::new(JsonErrorKind::InvalidJsonPath(
                "invalid bracket selector",
            ))),
        }
    }

    fn parse_slice(&mut self, start: Option<usize>) -> Result<Segment, JsonError> {
        self.expect(':')?;
        let end = self.parse_optional_slice_bound()?;
        let step = if self.eat(':') {
            self.parse_optional_slice_step()?
        } else {
            NonZeroUsize::MIN
        };
        Ok(Segment::Slice(Slice::new(start, end, step)))
    }

    fn parse_optional_slice_bound(&mut self) -> Result<Option<usize>, JsonError> {
        match self.peek() {
            Some('-') => Err(JsonError::new(JsonErrorKind::UnsupportedJsonPath(
                "negative array indices and slices",
            ))),
            Some(c) if c.is_ascii_digit() => self.parse_index().map(Some),
            _ => Ok(None),
        }
    }

    fn parse_optional_slice_step(&mut self) -> Result<NonZeroUsize, JsonError> {
        match self.peek() {
            Some('-') => Err(JsonError::new(JsonErrorKind::UnsupportedJsonPath(
                "negative array slices",
            ))),
            Some(c) if c.is_ascii_digit() => {
                let step = self.parse_index()?;
                NonZeroUsize::new(step).ok_or_else(|| {
                    JsonError::new(JsonErrorKind::InvalidJsonPath("slice step cannot be zero"))
                })
            }
            _ => Ok(NonZeroUsize::MIN),
        }
    }

    fn parse_name(&mut self) -> Result<Box<str>, JsonError> {
        let start = self.pos;
        match self.peek() {
            Some(c) if is_name_start(c) => self.bump(),
            _ => {
                return Err(JsonError::new(JsonErrorKind::InvalidJsonPath(
                    "expected member name",
                )));
            }
        };
        while self.peek().is_some_and(is_name_continue) {
            self.bump();
        }
        Ok(self.input[start..self.pos].into())
    }

    fn parse_index(&mut self) -> Result<usize, JsonError> {
        let start = self.pos;
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.bump();
        }
        self.input[start..self.pos]
            .parse()
            .map_err(|_err| JsonError::new(JsonErrorKind::InvalidJsonPath("array index overflow")))
    }

    fn parse_quoted(&mut self) -> Result<Box<str>, JsonError> {
        let quote = self
            .bump()
            .ok_or_else(|| JsonError::new(JsonErrorKind::UnexpectedEnd))?;
        let mut out = String::new();
        loop {
            match self.bump() {
                Some(c) if c == quote => return Ok(out.into_boxed_str()),
                Some('\\') => {
                    let escaped = self
                        .bump()
                        .ok_or_else(|| JsonError::new(JsonErrorKind::UnexpectedEnd))?;
                    match escaped {
                        '\'' | '"' | '\\' | '/' => out.push(escaped),
                        'b' => out.push('\u{0008}'),
                        'f' => out.push('\u{000c}'),
                        'n' => out.push('\n'),
                        'r' => out.push('\r'),
                        't' => out.push('\t'),
                        'u' => out.push(self.parse_unicode_escape()?),
                        _ => {
                            return Err(JsonError::new(JsonErrorKind::InvalidJsonPath(
                                "invalid string escape",
                            )));
                        }
                    }
                }
                Some(c) => out.push(c),
                None => return Err(JsonError::new(JsonErrorKind::UnexpectedEnd)),
            }
        }
    }

    fn parse_unicode_escape(&mut self) -> Result<char, JsonError> {
        let code = self.parse_hex_quad()?;
        if (0xd800..=0xdbff).contains(&code) {
            if !self.eat('\\') || !self.eat('u') {
                return Err(JsonError::new(JsonErrorKind::InvalidJsonPath(
                    "invalid unicode surrogate pair",
                )));
            }
            let low = self.parse_hex_quad()?;
            if !(0xdc00..=0xdfff).contains(&low) {
                return Err(JsonError::new(JsonErrorKind::InvalidJsonPath(
                    "invalid unicode surrogate pair",
                )));
            }
            let scalar = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
            return char::from_u32(scalar).ok_or_else(|| {
                JsonError::new(JsonErrorKind::InvalidJsonPath("invalid unicode scalar"))
            });
        }
        if (0xdc00..=0xdfff).contains(&code) {
            return Err(JsonError::new(JsonErrorKind::InvalidJsonPath(
                "invalid unicode surrogate pair",
            )));
        }
        char::from_u32(code)
            .ok_or_else(|| JsonError::new(JsonErrorKind::InvalidJsonPath("invalid unicode scalar")))
    }

    fn parse_hex_quad(&mut self) -> Result<u32, JsonError> {
        let start = self.pos;
        for _ in 0..4 {
            match self.peek() {
                Some(c) if c.is_ascii_hexdigit() => self.bump(),
                _ => {
                    return Err(JsonError::new(JsonErrorKind::InvalidJsonPath(
                        "invalid unicode escape",
                    )));
                }
            };
        }
        u32::from_str_radix(&self.input[start..self.pos], 16).map_err(|_err| {
            JsonError::new(JsonErrorKind::InvalidJsonPath("invalid unicode escape"))
        })
    }

    fn expect(&mut self, expected: char) -> Result<(), JsonError> {
        if self.eat(expected) {
            Ok(())
        } else {
            Err(JsonError::new(JsonErrorKind::InvalidJsonPath(
                "unexpected character",
            )))
        }
    }

    fn rest(&self) -> &'a str {
        self.input.get(self.pos..).unwrap_or("")
    }

    fn peek(&self) -> Option<char> {
        self.rest().chars().next()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += c.len_utf8();
        Some(c)
    }

    fn eat(&mut self, expected: char) -> bool {
        if self.peek() == Some(expected) {
            self.pos += expected.len_utf8();
            true
        } else {
            false
        }
    }
}

fn is_name_start(c: char) -> bool {
    c == '_' || c.is_ascii_alphabetic()
}

fn is_name_continue(c: char) -> bool {
    is_name_start(c) || c.is_ascii_digit()
}

fn is_dot_member_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(is_name_start) && chars.all(is_name_continue)
}

fn descendant_from_child(segment: Segment) -> Result<Segment, JsonError> {
    match segment {
        Segment::Member(name) => Ok(Segment::DescendantMember(name)),
        Segment::Index(index) => Ok(Segment::DescendantIndex(index)),
        Segment::Slice(slice) => Ok(Segment::DescendantSlice(slice)),
        Segment::Wildcard => Ok(Segment::DescendantWildcard),
        Segment::Union(segments) => Ok(Segment::DescendantUnion(segments)),
        Segment::DescendantMember(_)
        | Segment::DescendantIndex(_)
        | Segment::DescendantSlice(_)
        | Segment::DescendantWildcard
        | Segment::DescendantUnion(_) => Err(JsonError::new(JsonErrorKind::InvalidJsonPath(
            "nested descendant selector",
        ))),
    }
}

fn write_quoted_member(f: &mut fmt::Formatter<'_>, name: &str) -> fmt::Result {
    f.write_str("[\"")?;
    write_json_string_content(f, name)?;
    f.write_str("\"]")
}

fn write_selector_list(
    f: &mut fmt::Formatter<'_>,
    segments: &[Segment],
    descendant: bool,
) -> fmt::Result {
    if descendant {
        f.write_str("..")?;
    }
    f.write_str("[")?;
    for (index, segment) in segments.iter().enumerate() {
        if index > 0 {
            f.write_str(",")?;
        }
        write_bracket_selector(f, segment)?;
    }
    f.write_str("]")
}

fn write_bracket_selector(f: &mut fmt::Formatter<'_>, segment: &Segment) -> fmt::Result {
    match segment {
        Segment::Member(name) => {
            f.write_str("\"")?;
            write_json_string_content(f, name)?;
            f.write_str("\"")
        }
        Segment::Index(index) => write!(f, "{index}"),
        Segment::Slice(slice) => write_slice(f, *slice, true),
        Segment::Wildcard => f.write_str("*"),
        Segment::Union(segments) => {
            for (index, segment) in segments.iter().enumerate() {
                if index > 0 {
                    f.write_str(",")?;
                }
                write_bracket_selector(f, segment)?;
            }
            Ok(())
        }
        Segment::DescendantMember(_)
        | Segment::DescendantIndex(_)
        | Segment::DescendantSlice(_)
        | Segment::DescendantWildcard
        | Segment::DescendantUnion(_) => f.write_str("<invalid-descendant-selector>"),
    }
}

fn write_slice(f: &mut fmt::Formatter<'_>, slice: Slice, inside_brackets: bool) -> fmt::Result {
    if !inside_brackets {
        f.write_str("[")?;
    }
    if let Some(start) = slice.start() {
        write!(f, "{start}")?;
    }
    f.write_str(":")?;
    if let Some(end) = slice.end() {
        write!(f, "{end}")?;
    }
    if slice.step().get() != 1 {
        write!(f, ":{}", slice.step())?;
    }
    if !inside_brackets {
        f.write_str("]")?;
    }
    Ok(())
}

fn write_json_string_content(f: &mut fmt::Formatter<'_>, name: &str) -> fmt::Result {
    for c in name.chars() {
        match c {
            '"' => f.write_str("\\\"")?,
            '\\' => f.write_str("\\\\")?,
            '\u{0008}' => f.write_str("\\b")?,
            '\u{000c}' => f.write_str("\\f")?,
            '\n' => f.write_str("\\n")?,
            '\r' => f.write_str("\\r")?,
            '\t' => f.write_str("\\t")?,
            c if c.is_control() => write!(f, "\\u{:04x}", c as u32)?,
            c => write!(f, "{c}")?,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_supported_selectors() {
        let cases = [
            (
                "$.store.book[*].author",
                vec![
                    Segment::Member("store".into()),
                    Segment::Member("book".into()),
                    Segment::Wildcard,
                    Segment::Member("author".into()),
                ],
                false,
            ),
            (
                "$['weird.key'][12]",
                vec![Segment::Member("weird.key".into()), Segment::Index(12)],
                true,
            ),
            (
                "$..author",
                vec![Segment::DescendantMember("author".into())],
                false,
            ),
            (
                "$[0,\"name\",*]",
                vec![Segment::Union(
                    vec![
                        Segment::Index(0),
                        Segment::Member("name".into()),
                        Segment::Wildcard,
                    ]
                    .into_boxed_slice(),
                )],
                false,
            ),
            (
                "$[1:5:2]",
                vec![Segment::Slice(Slice::new(
                    Some(1),
                    Some(5),
                    NonZeroUsize::new(2).unwrap(),
                ))],
                false,
            ),
            (
                "$..[0,\"name\",*]",
                vec![Segment::DescendantUnion(
                    vec![
                        Segment::Index(0),
                        Segment::Member("name".into()),
                        Segment::Wildcard,
                    ]
                    .into_boxed_slice(),
                )],
                false,
            ),
            (
                "$..[1:4]",
                vec![Segment::DescendantSlice(Slice::new(
                    Some(1),
                    Some(4),
                    NonZeroUsize::new(1).unwrap(),
                ))],
                false,
            ),
        ];

        for (input, expected, singular) in cases {
            let path: JsonPath = input.parse().unwrap();
            assert_eq!(path.segments(), expected.as_slice(), "{input}");
            assert_eq!(path.is_singular(), singular, "{input}");
        }
    }

    #[test]
    fn builder_matches_parser() {
        let built = JsonPath::builder()
            .member("store")
            .member("book")
            .wildcard()
            .member("author")
            .union([
                Segment::Member("name".into()),
                Segment::Index(0),
                Segment::Slice(Slice::new(None, Some(4), NonZeroUsize::new(2).unwrap())),
            ])
            .descendant_index(1)
            .build();
        let parsed: JsonPath = "$.store.book[*].author[\"name\",0,:4:2]..[1]"
            .parse()
            .unwrap();
        assert_eq!(built, parsed);
    }

    #[test]
    fn display_roundtrips_basic_paths() {
        for input in [
            "$",
            "$.a[0].b",
            "$['weird.key'][*]",
            "$..author",
            "$[0,'name',*]",
            "$[1:5:2]",
            "$[:]",
            "$[::3]",
            "$..[0,'name',*]",
            "$..[1:4]",
            "$[\"\\uD834\\uDD1E\"]",
        ] {
            let path: JsonPath = input.parse().unwrap();
            let reparsed: JsonPath = path.to_string().parse().unwrap();
            assert_eq!(path, reparsed);
        }
    }

    #[test]
    fn display_formats_paths_canonically() {
        let cases = [
            (
                JsonPath::builder().member("alpha").build().to_string(),
                "$.alpha",
            ),
            (
                JsonPath::builder().member("weird.key").build().to_string(),
                "$[\"weird.key\"]",
            ),
            (
                JsonPath::builder()
                    .union([
                        Segment::Index(0),
                        Segment::Member("name".into()),
                        Segment::Wildcard,
                    ])
                    .build()
                    .to_string(),
                "$[0,\"name\",*]",
            ),
            (
                JsonPath::builder()
                    .descendant_member("alpha")
                    .build()
                    .to_string(),
                "$..alpha",
            ),
            (
                JsonPath::builder()
                    .descendant_member("weird.key")
                    .build()
                    .to_string(),
                "$..[\"weird.key\"]",
            ),
            (
                JsonPath::builder()
                    .descendant_union([
                        Segment::Member("a".into()),
                        Segment::Index(1),
                        Segment::Wildcard,
                    ])
                    .build()
                    .to_string(),
                "$..[\"a\",1,*]",
            ),
            (
                JsonPath::builder().member("\u{1}").build().to_string(),
                "$[\"\\u0001\"]",
            ),
        ];

        for (actual, expected) in cases {
            assert_eq!(actual, expected);
        }

        let nested_union = JsonPath::from_segments([Segment::Union(
            vec![
                Segment::Union(vec![Segment::Index(1), Segment::Index(2)].into_boxed_slice()),
                Segment::Index(3),
            ]
            .into_boxed_slice(),
        )]);
        assert_eq!(nested_union.to_string(), "$[1,2,3]");

        assert_eq!(PathElement::Member("alpha".into()).to_string(), ".alpha");
        assert_eq!(
            PathElement::Member("weird.key".into()).to_string(),
            "[\"weird.key\"]"
        );
        assert_eq!(PathElement::Index(7).to_string(), "[7]");
    }

    #[test]
    fn typed_builder_covers_all_segment_methods() {
        let path = JsonPath::builder()
            .index(2)
            .slice(Some(1), Some(3), NonZeroUsize::new(2).unwrap())
            .descendant_member("x")
            .descendant_slice(None, Some(2), NonZeroUsize::new(1).unwrap())
            .descendant_wildcard()
            .descendant_union([Segment::Member("a".into()), Segment::Index(1)])
            .build();

        assert_eq!(path.to_string(), "$[2][1:3:2]..x..[:2]..*..[\"a\",1]");
    }

    #[test]
    fn rejects_unsupported_rfc_features_explicitly() {
        let cases = [
            (
                "$[?(@.x)]",
                JsonErrorKind::UnsupportedJsonPath("filter selectors"),
            ),
            (
                "$[-1]",
                JsonErrorKind::UnsupportedJsonPath("negative array indices and slices"),
            ),
            (
                "$[:-1]",
                JsonErrorKind::UnsupportedJsonPath("negative array indices and slices"),
            ),
            (
                "$[1:-1]",
                JsonErrorKind::UnsupportedJsonPath("negative array indices and slices"),
            ),
            (
                "$[1:2:-1]",
                JsonErrorKind::UnsupportedJsonPath("negative array slices"),
            ),
            (
                "$[::0]",
                JsonErrorKind::InvalidJsonPath("slice step cannot be zero"),
            ),
        ];

        for (input, expected) in cases {
            let err = input.parse::<JsonPath>().unwrap_err();
            assert_eq!(err.kind(), &expected, "{input}");
        }
    }

    #[test]
    fn matches_concrete_paths() {
        let path: JsonPath = "$.store.book[*].author".parse().unwrap();
        let concrete = [
            PathElement::Member("store".into()),
            PathElement::Member("book".into()),
            PathElement::Index(3),
            PathElement::Member("author".into()),
        ];
        assert!(path.matches_path(&concrete));
        assert!(
            "$..author"
                .parse::<JsonPath>()
                .unwrap()
                .matches_path(&concrete)
        );
        assert!(
            "$.store.book[1:5:2].author"
                .parse::<JsonPath>()
                .unwrap()
                .matches_path(&concrete)
        );
        assert!(
            "$.store.book[0,3,5].author"
                .parse::<JsonPath>()
                .unwrap()
                .matches_path(&concrete)
        );
        assert!(
            "$.store.book[3].author"
                .parse::<JsonPath>()
                .unwrap()
                .matches_path(&concrete)
        );
        assert!(
            "$..[3].author"
                .parse::<JsonPath>()
                .unwrap()
                .matches_path(&concrete)
        );
        assert!(
            "$..[1:5:2].author"
                .parse::<JsonPath>()
                .unwrap()
                .matches_path(&concrete)
        );
        assert!(
            "$..[\"book\",3].author"
                .parse::<JsonPath>()
                .unwrap()
                .matches_path(&concrete)
        );
        assert!(
            "$.store..*.author"
                .parse::<JsonPath>()
                .unwrap()
                .matches_path(&concrete)
        );
        assert!(
            !"$.store.author"
                .parse::<JsonPath>()
                .unwrap()
                .matches_path(&concrete)
        );
        assert!(
            !"$.store.book[0:3].author"
                .parse::<JsonPath>()
                .unwrap()
                .matches_path(&concrete)
        );
    }

    #[test]
    fn slice_matching_is_start_inclusive_end_exclusive() {
        let cases = [
            ("$[1:4]", 0, false),
            ("$[1:4]", 1, true),
            ("$[1:4]", 3, true),
            ("$[1:4]", 4, false),
            ("$[1:6:2]", 1, true),
            ("$[1:6:2]", 2, false),
            ("$[1:6:2]", 5, true),
            ("$[:3]", 0, true),
            ("$[:3]", 3, false),
            ("$[2:]", 100, true),
            ("$[2::3]", 5, true),
            ("$[2::3]", 4, false),
        ];

        for (selector, index, expected) in cases {
            let path: JsonPath = selector.parse().unwrap();
            assert_eq!(
                path.matches_path(&[PathElement::Index(index)]),
                expected,
                "{selector} vs [{index}]"
            );
        }

        assert!(
            !"$[*]".parse::<JsonPath>().unwrap().matches_path(&[]),
            "wildcard must not match a missing path element"
        );
    }

    #[test]
    fn selectors_do_not_match_when_tail_or_current_element_differs() {
        let cases = [
            ("$.a.b", vec![PathElement::Member("a".into())]),
            (
                "$.a.b",
                vec![
                    PathElement::Member("a".into()),
                    PathElement::Member("x".into()),
                ],
            ),
            (
                "$.a[*].b",
                vec![PathElement::Member("a".into()), PathElement::Index(0)],
            ),
            (
                "$.a[*].b",
                vec![
                    PathElement::Member("a".into()),
                    PathElement::Member("x".into()),
                    PathElement::Member("c".into()),
                ],
            ),
            (
                "$[1:4].id",
                vec![PathElement::Index(0), PathElement::Member("id".into())],
            ),
            (
                "$[1].id",
                vec![PathElement::Index(2), PathElement::Member("id".into())],
            ),
            ("$[1:4].id", vec![PathElement::Index(1)]),
            (
                "$[1,\"a\"].id",
                vec![PathElement::Index(2), PathElement::Member("id".into())],
            ),
            ("$[1,\"a\"].id", vec![PathElement::Member("a".into())]),
            ("$..author.id", vec![PathElement::Member("author".into())]),
            ("$..*.author", vec![PathElement::Member("author".into())]),
            (
                "$..[1].id",
                vec![PathElement::Index(2), PathElement::Member("id".into())],
            ),
            ("$..[1].id", vec![PathElement::Index(1)]),
            (
                "$..[1:4].id",
                vec![PathElement::Index(0), PathElement::Member("id".into())],
            ),
            (
                "$..[1,\"a\"].id",
                vec![PathElement::Index(2), PathElement::Member("id".into())],
            ),
        ];

        for (selector, concrete) in cases {
            assert!(
                !selector
                    .parse::<JsonPath>()
                    .unwrap()
                    .matches_path(&concrete),
                "{selector} unexpectedly matched {concrete:?}"
            );
        }
    }

    #[test]
    fn unions_match_each_child_selector_kind() {
        let cases = [
            (
                "$.a[\"foo\",9].id".parse::<JsonPath>().unwrap(),
                vec![
                    PathElement::Member("a".into()),
                    PathElement::Member("foo".into()),
                    PathElement::Member("id".into()),
                ],
            ),
            (
                "$.a[1:4,9].id".parse::<JsonPath>().unwrap(),
                vec![
                    PathElement::Member("a".into()),
                    PathElement::Index(2),
                    PathElement::Member("id".into()),
                ],
            ),
            (
                "$.a[*,9].id".parse::<JsonPath>().unwrap(),
                vec![
                    PathElement::Member("a".into()),
                    PathElement::Member("anything".into()),
                    PathElement::Member("id".into()),
                ],
            ),
            (
                JsonPath::from_segments([
                    Segment::Member("a".into()),
                    Segment::Union(
                        vec![
                            Segment::Union(
                                vec![Segment::Member("foo".into()), Segment::Index(4)]
                                    .into_boxed_slice(),
                            ),
                            Segment::Index(9),
                        ]
                        .into_boxed_slice(),
                    ),
                    Segment::Member("id".into()),
                ]),
                vec![
                    PathElement::Member("a".into()),
                    PathElement::Member("foo".into()),
                    PathElement::Member("id".into()),
                ],
            ),
        ];

        for (selector, concrete) in cases {
            assert!(
                selector.matches_path(&concrete),
                "{selector} did not match {concrete:?}"
            );
        }
    }

    #[test]
    fn parses_json_string_escapes_in_member_names() {
        let path: JsonPath = r#"$["\"\\\/\b\f\n\r\t"]"#.parse().unwrap();
        assert_eq!(
            path.segments(),
            &[Segment::Member("\"\\/\u{8}\u{c}\n\r\t".into())]
        );

        let path: JsonPath = r#"$['\'']"#.parse().unwrap();
        assert_eq!(path.segments(), &[Segment::Member("'".into())]);

        let path: JsonPath = r#"$["\uD834\uDD1E"]"#.parse().unwrap();
        assert_eq!(path.segments(), &[Segment::Member("𝄞".into())]);
    }

    #[test]
    fn rejects_malformed_jsonpath_syntax() {
        let cases = [
            (
                "$[x]",
                JsonErrorKind::InvalidJsonPath("invalid bracket selector"),
            ),
            (
                "$[1:x]",
                JsonErrorKind::InvalidJsonPath("unexpected character"),
            ),
            (
                "$.0bad",
                JsonErrorKind::InvalidJsonPath("expected member name"),
            ),
            (
                r#"$["\uD834x"]"#,
                JsonErrorKind::InvalidJsonPath("invalid unicode surrogate pair"),
            ),
            (
                r#"$["\uDD1E"]"#,
                JsonErrorKind::InvalidJsonPath("invalid unicode surrogate pair"),
            ),
            (
                r#"$["\u12x4"]"#,
                JsonErrorKind::InvalidJsonPath("invalid unicode escape"),
            ),
            (
                "$[::x]",
                JsonErrorKind::InvalidJsonPath("unexpected character"),
            ),
        ];

        for (input, expected) in cases {
            let err = input.parse::<JsonPath>().unwrap_err();
            assert_eq!(err.kind(), &expected, "{input}");
        }
    }

    #[test]
    fn deterministic_path_fuzz_roundtrips_and_matches_consistently() {
        let mut seed = 0x4d59_5df4_d0f3_3173;
        for _ in 0..2048 {
            let path = fuzz_path(&mut seed);
            let rendered = path.to_string();
            let reparsed: JsonPath = rendered.parse().unwrap();
            assert_eq!(path, reparsed, "{rendered}");

            let concrete = fuzz_value_path(&mut seed);
            assert_eq!(
                path.matches_path(&concrete),
                reparsed.matches_path(&concrete),
                "{rendered} vs {concrete:?}"
            );
        }
    }

    fn fuzz_path(seed: &mut u64) -> JsonPath {
        let mut segments = Vec::new();
        let len = (next(seed) % 6) as usize;
        for _ in 0..len {
            segments.push(match next(seed) % 9 {
                0 => Segment::Member(fuzz_member(seed).into()),
                1 => Segment::Index((next(seed) % 8) as usize),
                2 => Segment::Wildcard,
                3 => Segment::Slice(fuzz_slice(seed)),
                4 => Segment::Union(fuzz_union(seed)),
                5 => Segment::DescendantMember(fuzz_member(seed).into()),
                6 => Segment::DescendantIndex((next(seed) % 8) as usize),
                7 => Segment::DescendantSlice(fuzz_slice(seed)),
                _ => Segment::DescendantUnion(fuzz_union(seed)),
            });
        }
        JsonPath::from_segments(segments)
    }

    fn fuzz_union(seed: &mut u64) -> Box<[Segment]> {
        let len = 1 + (next(seed) % 4) as usize;
        (0..len)
            .map(|_| match next(seed) % 4 {
                0 => Segment::Member(fuzz_member(seed).into()),
                1 => Segment::Index((next(seed) % 8) as usize),
                2 => Segment::Wildcard,
                _ => Segment::Slice(fuzz_slice(seed)),
            })
            .collect()
    }

    fn fuzz_slice(seed: &mut u64) -> Slice {
        let start = next(seed)
            .is_multiple_of(2)
            .then(|| (next(seed) % 5) as usize);
        let width = (next(seed) % 6) as usize;
        let end = start.map(|start| start + width);
        let step = NonZeroUsize::new(1 + (next(seed) % 4) as usize).unwrap();
        Slice::new(start, end, step)
    }

    fn fuzz_member(seed: &mut u64) -> &'static str {
        match next(seed) % 6 {
            0 => "a",
            1 => "b",
            2 => "book",
            3 => "author",
            4 => "weird.key",
            _ => "line\nbreak",
        }
    }

    fn fuzz_value_path(seed: &mut u64) -> Vec<PathElement> {
        let len = (next(seed) % 6) as usize;
        (0..len)
            .map(|_| {
                if next(seed).is_multiple_of(2) {
                    PathElement::Member(fuzz_member(seed).into())
                } else {
                    PathElement::Index((next(seed) % 8) as usize)
                }
            })
            .collect()
    }

    fn next(seed: &mut u64) -> u64 {
        *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        *seed
    }
}
