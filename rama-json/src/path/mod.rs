//! JSONPath parsing and typed construction.
//!
//! Rama targets RFC 9535 JSONPath. This module starts with the selectors that
//! can be matched efficiently in a streaming parser: root, member names, array
//! indices, wildcards, and descendant selectors. Slices and filters are modeled
//! as future extensions rather than silently accepting a partial language.

use std::fmt;
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
            segments: segments.into().into_boxed_slice(),
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
    /// `.*` / `[*]`.
    Wildcard,
    /// `..name`.
    DescendantMember(Box<str>),
    /// `..*`.
    DescendantWildcard,
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
        Segment::Wildcard => {
            path_index < path.len()
                && matches_from(selector, selector_index + 1, path, path_index + 1)
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
        Segment::DescendantWildcard => {
            for index in path_index..path.len() {
                if matches_from(selector, selector_index + 1, path, index + 1) {
                    return true;
                }
            }
            false
        }
    }
}

impl fmt::Display for Segment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Member(name) if is_dot_member_name(name) => write!(f, ".{name}"),
            Self::Member(name) => write_quoted_member(f, name),
            Self::Index(index) => write!(f, "[{index}]"),
            Self::Wildcard => f.write_str("[*]"),
            Self::DescendantMember(name) if is_dot_member_name(name) => write!(f, "..{name}"),
            Self::DescendantMember(name) => {
                f.write_str("..")?;
                write_quoted_member(f, name)
            }
            Self::DescendantWildcard => f.write_str("..*"),
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

    /// Adds a child wildcard selector.
    #[must_use]
    pub fn wildcard(mut self) -> Self {
        self.segments.push(Segment::Wildcard);
        self
    }

    /// Adds a descendant member selector.
    #[must_use]
    pub fn descendant_member(mut self, name: impl Into<Box<str>>) -> Self {
        self.segments.push(Segment::DescendantMember(name.into()));
        self
    }

    /// Adds a descendant wildcard selector.
    #[must_use]
    pub fn descendant_wildcard(mut self) -> Self {
        self.segments.push(Segment::DescendantWildcard);
        self
    }

    /// Finishes the path.
    #[must_use]
    pub fn build(self) -> JsonPath {
        JsonPath {
            segments: self.segments.into_boxed_slice(),
        }
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
        while !self.eof() {
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
        Ok(Segment::DescendantMember(self.parse_name()?))
    }

    fn parse_bracket_child(&mut self) -> Result<Segment, JsonError> {
        self.expect('[')?;
        match self.peek() {
            Some('*') => {
                self.bump();
                self.expect(']')?;
                Ok(Segment::Wildcard)
            }
            Some('\'' | '"') => {
                let name = self.parse_quoted()?;
                self.expect(']')?;
                Ok(Segment::Member(name))
            }
            Some('?') => Err(JsonError::new(JsonErrorKind::UnsupportedJsonPath(
                "filter selectors",
            ))),
            Some(':') => Err(JsonError::new(JsonErrorKind::UnsupportedJsonPath(
                "array slices",
            ))),
            Some('-') => Err(JsonError::new(JsonErrorKind::UnsupportedJsonPath(
                "negative array indices",
            ))),
            Some(c) if c.is_ascii_digit() => {
                let index = self.parse_index()?;
                self.expect(']')?;
                Ok(Segment::Index(index))
            }
            _ => Err(JsonError::new(JsonErrorKind::InvalidJsonPath(
                "invalid bracket selector",
            ))),
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
        let code = u32::from_str_radix(&self.input[start..self.pos], 16).map_err(|_err| {
            JsonError::new(JsonErrorKind::InvalidJsonPath("invalid unicode escape"))
        })?;
        char::from_u32(code)
            .ok_or_else(|| JsonError::new(JsonErrorKind::InvalidJsonPath("invalid unicode scalar")))
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

    fn eof(&self) -> bool {
        self.pos >= self.input.len()
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

fn write_quoted_member(f: &mut fmt::Formatter<'_>, name: &str) -> fmt::Result {
    f.write_str("[\"")?;
    for c in name.chars() {
        match c {
            '"' => f.write_str("\\\"")?,
            '\\' => f.write_str("\\\\")?,
            '\n' => f.write_str("\\n")?,
            '\r' => f.write_str("\\r")?,
            '\t' => f.write_str("\\t")?,
            c => write!(f, "{c}")?,
        }
    }
    f.write_str("\"]")
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
            .build();
        let parsed: JsonPath = "$.store.book[*].author".parse().unwrap();
        assert_eq!(built, parsed);
    }

    #[test]
    fn display_roundtrips_basic_paths() {
        for input in ["$", "$.a[0].b", "$['weird.key'][*]", "$..author"] {
            let path: JsonPath = input.parse().unwrap();
            let reparsed: JsonPath = path.to_string().parse().unwrap();
            assert_eq!(path, reparsed);
        }
    }

    #[test]
    fn rejects_filters_for_now() {
        let err = "$[?(@.x)]".parse::<JsonPath>().unwrap_err();
        assert_eq!(
            err.kind(),
            &JsonErrorKind::UnsupportedJsonPath("filter selectors")
        );
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
            !"$.store.author"
                .parse::<JsonPath>()
                .unwrap()
                .matches_path(&concrete)
        );
    }
}
