//! URI Templates ([RFC 6570]) up to level 3, with expansion and request matching.
//!
//! [`UriTemplate`] parses a template once into literal and expression parts and
//! expands it for string variables. [`UriTemplateMatcher`] matches a request path
//! and query back against a template, built on [`PathPattern`] for the path and
//! [`QueryRef`] pairs for the query. Level 4 modifiers (prefix `:n`, explode `*`),
//! list and associative values, and non-ASCII templates are not supported.
//!
//! [RFC 6570]: https://datatracker.ietf.org/doc/html/rfc6570

use core::{fmt, ops::Range};

use crate::std::{borrow::Cow, boxed::Box, string::String, sync::Arc, vec::Vec};

use percent_encoding::{percent_decode, percent_encode};
use rama_utils::collections::smallvec::SmallVec;

use super::{
    PathMatchOptions, PathPattern, PathRef, QueryRef,
    encode::{TEMPLATE_RESERVED_ENCODE_SET, TEMPLATE_UNRESERVED_ENCODE_SET},
};
use crate::byte_sets::{
    is_path_byte, is_pattern_name_byte, is_template_literal_byte, is_unreserved_byte,
};

/// Largest template accepted, in bytes.
const MAX_TEMPLATE_LEN: usize = 4096;

/// Most distinct variables a template may name.
const MAX_VARIABLES: usize = 64;

/// Most literal `name=value` query pairs a matcher requires.
const MAX_FIXED_QUERY_PAIRS: usize = 16;

/// A parsed [RFC 6570] URI Template, levels 1 to 3.
///
/// Cloning is cheap: the parsed form is shared. To match requests against it use
/// [`UriTemplateMatcher`]. Route patterns use [`PathPattern`] syntax, not RFC 6570:
/// `?` starts a query here but makes an element optional there. The
/// [`uri` module](super#patterns-and-templates) compares all URI patterns.
///
/// ```
/// use rama_net::uri::UriTemplate;
///
/// let template = UriTemplate::try_new("/masque{?target_host,target_port}").unwrap();
/// let host = template.variable("target_host").unwrap();
/// let port = template.variable("target_port").unwrap();
/// let expanded = template.expand(|v| {
///     if v == host { Some("2001:db8::42") } else if v == port { Some("443") } else { None }
/// });
/// assert_eq!(expanded, "/masque?target_host=2001%3Adb8%3A%3A42&target_port=443");
/// ```
///
/// [RFC 6570]: https://datatracker.ietf.org/doc/html/rfc6570
#[derive(Clone)]
pub struct UriTemplate(Arc<Inner>);

struct Inner {
    source: Box<str>,
    parts: Box<[Part]>,
    names: Box<[Range<u32>]>,
    literal_len: usize,
}

#[derive(Clone)]
enum Part {
    Literal(Range<u32>),
    Expression {
        operator: TemplateOperator,
        variables: SmallVec<[TemplateVariable; 2]>,
    },
}

/// The operator of a URI Template expression ([RFC 6570 §2.2]).
///
/// [RFC 6570 §2.2]: https://datatracker.ietf.org/doc/html/rfc6570#section-2.2
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TemplateOperator {
    /// `{var}`: simple string expansion.
    Simple,
    /// `{+var}`: reserved expansion.
    Reserved,
    /// `{#var}`: fragment expansion.
    Fragment,
    /// `{.var}`: label expansion with dot-prefix.
    Label,
    /// `{/var}`: path segment expansion.
    PathSegment,
    /// `{;var}`: path-style parameter expansion.
    PathParameter,
    /// `{?var}`: form-style query expansion.
    Query,
    /// `{&var}`: form-style query continuation.
    QueryContinuation,
}

impl TemplateOperator {
    fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            b'+' => Self::Reserved,
            b'#' => Self::Fragment,
            b'.' => Self::Label,
            b'/' => Self::PathSegment,
            b';' => Self::PathParameter,
            b'?' => Self::Query,
            b'&' => Self::QueryContinuation,
            _ => return None,
        })
    }

    fn first(self) -> &'static str {
        match self {
            Self::Simple | Self::Reserved => "",
            Self::Fragment => "#",
            Self::Label => ".",
            Self::PathSegment => "/",
            Self::PathParameter => ";",
            Self::Query => "?",
            Self::QueryContinuation => "&",
        }
    }

    fn separator(self) -> &'static str {
        match self {
            Self::Simple | Self::Reserved | Self::Fragment => ",",
            Self::Label => ".",
            Self::PathSegment => "/",
            Self::PathParameter => ";",
            Self::Query | Self::QueryContinuation => "&",
        }
    }

    fn named(self) -> bool {
        matches!(
            self,
            Self::PathParameter | Self::Query | Self::QueryContinuation
        )
    }

    fn if_empty(self) -> &'static str {
        match self {
            Self::Query | Self::QueryContinuation => "=",
            _ => "",
        }
    }

    fn allows_reserved(self) -> bool {
        matches!(self, Self::Reserved | Self::Fragment)
    }
}

/// A variable named by a [`UriTemplate`], resolved once with [`UriTemplate::variable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TemplateVariable(u16);

/// Why a URI Template could not be parsed or matched.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UriTemplateError {
    /// The template exceeds the supported length.
    TooLong,
    /// The template names more distinct variables than supported.
    TooManyVariables,
    /// A byte that may not appear in a template literal.
    InvalidLiteral {
        /// Byte offset in the template.
        offset: usize,
    },
    /// A `%` not followed by two hexadecimal digits.
    InvalidPercentEncoding {
        /// Byte offset in the template.
        offset: usize,
    },
    /// An expression without its closing `}`.
    UnclosedExpression {
        /// Byte offset of the opening `{`.
        offset: usize,
    },
    /// An empty or malformed variable name.
    InvalidVariableName {
        /// Byte offset of the expression.
        offset: usize,
    },
    /// An operator reserved for future extensions (`=`, `,`, `!`, `@`, `|`).
    ReservedOperator {
        /// Byte offset of the expression.
        offset: usize,
    },
    /// A level 4 modifier (`:n` prefix or `*` explode).
    UnsupportedModifier {
        /// Byte offset of the expression.
        offset: usize,
    },
    /// The template cannot be matched against requests.
    NotMatchable(&'static str),
}

impl fmt::Display for UriTemplateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong => write!(f, "uri template exceeds {MAX_TEMPLATE_LEN} bytes"),
            Self::TooManyVariables => {
                write!(f, "uri template names more than {MAX_VARIABLES} variables")
            }
            Self::InvalidLiteral { offset } => {
                write!(f, "invalid uri template literal byte at offset {offset}")
            }
            Self::InvalidPercentEncoding { offset } => {
                write!(
                    f,
                    "invalid percent-encoding in uri template at offset {offset}"
                )
            }
            Self::UnclosedExpression { offset } => {
                write!(f, "unclosed uri template expression at offset {offset}")
            }
            Self::InvalidVariableName { offset } => {
                write!(f, "invalid uri template variable name at offset {offset}")
            }
            Self::ReservedOperator { offset } => {
                write!(f, "reserved uri template operator at offset {offset}")
            }
            Self::UnsupportedModifier { offset } => write!(
                f,
                "unsupported level 4 uri template modifier at offset {offset}"
            ),
            Self::NotMatchable(reason) => write!(f, "uri template cannot be matched: {reason}"),
        }
    }
}

impl core::error::Error for UriTemplateError {}

impl UriTemplate {
    /// Parse a URI Template of level 3 or lower.
    pub fn try_new(template: impl AsRef<str>) -> Result<Self, UriTemplateError> {
        let source = template.as_ref();
        if source.len() > MAX_TEMPLATE_LEN {
            return Err(UriTemplateError::TooLong);
        }
        let bytes = source.as_bytes();
        let mut parts = Vec::new();
        let mut names: Vec<Range<u32>> = Vec::new();
        let mut literal_len = 0;
        let mut literal_start = 0;
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'{' => {
                    if literal_start < i {
                        parts.push(Part::Literal(range(literal_start, i)));
                        literal_len += i - literal_start;
                    }
                    let close = bytes[i..]
                        .iter()
                        .position(|&b| b == b'}')
                        .map(|p| i + p)
                        .ok_or(UriTemplateError::UnclosedExpression { offset: i })?;
                    parts.push(parse_expression(source, i, close, &mut names)?);
                    i = close + 1;
                    literal_start = i;
                }
                b'%' => {
                    if !is_pct_triplet(bytes, i) {
                        return Err(UriTemplateError::InvalidPercentEncoding { offset: i });
                    }
                    i += 3;
                }
                b if is_template_literal_byte(b) => i += 1,
                _ => return Err(UriTemplateError::InvalidLiteral { offset: i }),
            }
        }
        if literal_start < bytes.len() {
            parts.push(Part::Literal(range(literal_start, bytes.len())));
            literal_len += bytes.len() - literal_start;
        }
        Ok(Self(Arc::new(Inner {
            source: source.into(),
            parts: parts.into_boxed_slice(),
            names: names.into_boxed_slice(),
            literal_len,
        })))
    }

    /// The template text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0.source
    }

    /// The variable with this name, if the template names it.
    #[must_use]
    pub fn variable(&self, name: &str) -> Option<TemplateVariable> {
        self.0
            .names
            .iter()
            .position(|r| self.slice(r) == name)
            .map(|index| TemplateVariable(index as u16))
    }

    /// The name of a variable of this template.
    #[must_use]
    pub fn variable_name(&self, variable: TemplateVariable) -> Option<&str> {
        self.0.names.get(variable.0 as usize).map(|r| self.slice(r))
    }

    /// All distinct variables in order of first appearance.
    pub fn variables(&self) -> impl ExactSizeIterator<Item = TemplateVariable> + '_ {
        (0..self.0.names.len()).map(|index| TemplateVariable(index as u16))
    }

    /// Every operator used by the template's expressions, in order.
    pub fn operators(&self) -> impl Iterator<Item = TemplateOperator> + '_ {
        self.0.parts.iter().filter_map(|part| match part {
            Part::Expression { operator, .. } => Some(*operator),
            Part::Literal(_) => None,
        })
    }

    /// Expand the template; `value` returns `None` for an undefined variable.
    #[must_use]
    pub fn expand<'v>(&self, value: impl Fn(TemplateVariable) -> Option<&'v str>) -> String {
        let mut out = String::new();
        self.expand_to(&mut out, value);
        out
    }

    /// Expand the template, appending to `out`.
    pub fn expand_to<'v>(
        &self,
        out: &mut String,
        value: impl Fn(TemplateVariable) -> Option<&'v str>,
    ) {
        out.reserve(self.0.literal_len + 16);
        for part in &self.0.parts {
            match part {
                Part::Literal(r) => out.push_str(self.slice(r)),
                Part::Expression {
                    operator,
                    variables,
                } => {
                    let mut first = true;
                    for &variable in variables {
                        let Some(v) = value(variable) else {
                            continue;
                        };
                        out.push_str(if first {
                            operator.first()
                        } else {
                            operator.separator()
                        });
                        first = false;
                        if operator.named() {
                            out.push_str(self.slice(&self.0.names[variable.0 as usize]));
                            if v.is_empty() {
                                out.push_str(operator.if_empty());
                                continue;
                            }
                            out.push('=');
                        }
                        encode_value(out, v, operator.allows_reserved());
                    }
                }
            }
        }
    }

    fn slice(&self, r: &Range<u32>) -> &str {
        &self.0.source[r.start as usize..r.end as usize]
    }
}

impl fmt::Debug for UriTemplate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("UriTemplate").field(&self.as_str()).finish()
    }
}

impl fmt::Display for UriTemplate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl PartialEq for UriTemplate {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for UriTemplate {}

impl core::hash::Hash for UriTemplate {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.as_str().hash(state);
    }
}

fn range(start: usize, end: usize) -> Range<u32> {
    // MAX_TEMPLATE_LEN keeps every offset within u32.
    start as u32..end as u32
}

fn parse_expression(
    source: &str,
    open: usize,
    close: usize,
    names: &mut Vec<Range<u32>>,
) -> Result<Part, UriTemplateError> {
    let bytes = source.as_bytes();
    let mut start = open + 1;
    let operator = match bytes.get(start) {
        Some(b'=' | b',' | b'!' | b'@' | b'|') => {
            return Err(UriTemplateError::ReservedOperator { offset: open });
        }
        Some(&b) => match TemplateOperator::from_byte(b) {
            Some(operator) => {
                start += 1;
                operator
            }
            None => TemplateOperator::Simple,
        },
        None => return Err(UriTemplateError::InvalidVariableName { offset: open }),
    };
    let mut variables = SmallVec::new();
    let mut offset = start;
    for spec in source[start..close].split(',') {
        let spec_start = offset;
        offset += spec.len() + 1;
        if spec.ends_with('*') || spec.contains(':') {
            return Err(UriTemplateError::UnsupportedModifier { offset: open });
        }
        if !is_valid_varname(spec) {
            return Err(UriTemplateError::InvalidVariableName { offset: open });
        }
        let existing = names
            .iter()
            .position(|r| &source[r.start as usize..r.end as usize] == spec);
        let index = if let Some(index) = existing {
            index
        } else {
            if names.len() == MAX_VARIABLES {
                return Err(UriTemplateError::TooManyVariables);
            }
            names.push(range(spec_start, spec_start + spec.len()));
            names.len() - 1
        };
        variables.push(TemplateVariable(index as u16));
    }
    Ok(Part::Expression {
        operator,
        variables,
    })
}

/// RFC 6570 §2.3 `varname`: varchars (ALPHA / DIGIT / "_" / pct-encoded) joined by single dots.
fn is_valid_varname(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes[0] == b'.' || bytes[bytes.len() - 1] == b'.' {
        return false;
    }
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'.' if bytes[i - 1] == b'.' => return false,
            b'%' if is_pct_triplet(bytes, i) => i += 3,
            b if b.is_ascii_alphanumeric() || b == b'_' || b == b'.' => i += 1,
            _ => return false,
        }
    }
    true
}

fn is_pct_triplet(bytes: &[u8], i: usize) -> bool {
    bytes.get(i) == Some(&b'%')
        && bytes.get(i + 1).is_some_and(u8::is_ascii_hexdigit)
        && bytes.get(i + 2).is_some_and(u8::is_ascii_hexdigit)
}

/// Append `value` as a simple-expansion (`{x}`) value: everything outside `unreserved` encoded.
pub(crate) fn encode_template_value_to(out: &mut String, value: &str) {
    out.extend(percent_encode(
        value.as_bytes(),
        TEMPLATE_UNRESERVED_ENCODE_SET,
    ));
}

fn encode_value(out: &mut String, value: &str, allow_reserved: bool) {
    if !allow_reserved {
        encode_template_value_to(out, value);
        return;
    }
    // Reserved expansion keeps existing pct-encoded triplets (RFC 6570 §3.2.3).
    let bytes = value.as_bytes();
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        if is_pct_triplet(bytes, i) {
            out.extend(percent_encode(
                &bytes[start..i],
                TEMPLATE_RESERVED_ENCODE_SET,
            ));
            out.push_str(&value[i..i + 3]);
            i += 3;
            start = i;
        } else {
            i += 1;
        }
    }
    out.extend(percent_encode(
        &bytes[start..],
        TEMPLATE_RESERVED_ENCODE_SET,
    ));
}

/// Matches request paths and queries against a [`UriTemplate`].
///
/// The path part becomes a [`PathPattern`]; it may hold only literals and
/// single-variable simple expressions (`{name}`), with names made of ASCII
/// letters, digits, `_` and `-`. The query part may use `{?a,b}` / `{&a,b}`
/// expressions or literal `name={var}` pairs; literal `name=value` pairs are
/// required. Query pairs are matched by name in any order, unknown pairs are
/// ignored and repeated mapped names fail the match. Values are percent-decoded
/// once (RFC 3986, no form `+` handling). Requests whose path is not ASCII or
/// holds malformed percent-encoding never match.
///
/// [`PathPattern`] does all path matching, so a template path must also be a valid
/// route pattern; routes themselves use [`PathPattern`] syntax, not RFC 6570.
#[derive(Clone)]
pub struct UriTemplateMatcher {
    template: UriTemplate,
    path: PathPattern,
    path_variables: SmallVec<[TemplateVariable; 4]>,
    query_variables: SmallVec<[(Box<str>, TemplateVariable); 4]>,
    query_fixed: SmallVec<[(Box<str>, Option<Box<str>>); 2]>,
}

impl fmt::Debug for UriTemplateMatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UriTemplateMatcher")
            .field("template", &self.template)
            .finish_non_exhaustive()
    }
}

/// Variable values captured by [`UriTemplateMatcher::captures`].
#[derive(Debug, Clone, Default)]
pub struct UriTemplateCaptures<'a> {
    values: SmallVec<[(TemplateVariable, Cow<'a, str>); 4]>,
}

impl UriTemplateCaptures<'_> {
    /// The decoded value of a variable, if the request defined it.
    #[must_use]
    pub fn get(&self, variable: TemplateVariable) -> Option<&str> {
        self.values
            .iter()
            .find(|(v, _)| *v == variable)
            .map(|(_, value)| value.as_ref())
    }
}

impl UriTemplateMatcher {
    /// Build a matcher for `template`.
    pub fn try_new(template: &UriTemplate) -> Result<Self, UriTemplateError> {
        let parts = &template.0.parts;
        let mut pattern = String::with_capacity(template.0.literal_len + 16);
        let mut path_variables = SmallVec::new();
        let mut index = 0;
        // Path part: up to a literal `?` or the first `{?...}` expression.
        let mut query_literal_head: Option<&str> = None;
        // A path value must be followed by the path's end or a byte its encoding never
        // produces raw, so where it stops is unambiguous.
        let mut after_variable = false;
        while index < parts.len() {
            match &parts[index] {
                Part::Literal(r) => {
                    let literal = template.slice(r);
                    let (path, query) = match literal.find('?') {
                        Some(q) => (&literal[..q], Some(&literal[q..])),
                        None => (literal, None),
                    };
                    if after_variable
                        && path
                            .bytes()
                            .next()
                            .is_some_and(|b| b == b'%' || is_unreserved_byte(b))
                    {
                        return Err(UriTemplateError::NotMatchable(
                            "a path variable must be followed by '/', a reserved character or the end",
                        ));
                    }
                    after_variable = false;
                    if !path.bytes().all(is_path_byte) {
                        return Err(UriTemplateError::NotMatchable(
                            "path literal holds bytes that are not URI path characters",
                        ));
                    }
                    pattern.push_str(path);
                    if query.is_some() {
                        query_literal_head = query;
                        index += 1;
                        break;
                    }
                }
                Part::Expression {
                    operator: TemplateOperator::Query,
                    ..
                } => break,
                Part::Expression {
                    operator: TemplateOperator::Simple,
                    variables,
                } => {
                    let [variable] = variables.as_slice() else {
                        return Err(UriTemplateError::NotMatchable(
                            "path expressions must name exactly one variable",
                        ));
                    };
                    if after_variable {
                        return Err(UriTemplateError::NotMatchable(
                            "path variables must be separated by a literal",
                        ));
                    }
                    after_variable = true;
                    if path_variables.contains(variable) {
                        return Err(UriTemplateError::NotMatchable(
                            "a path variable may appear only once",
                        ));
                    }
                    let name = template.slice(&template.0.names[variable.0 as usize]);
                    if !name.bytes().all(is_pattern_name_byte) {
                        return Err(UriTemplateError::NotMatchable(
                            "path variable names must be ASCII letters, digits, '_' or '-'",
                        ));
                    }
                    pattern.push('{');
                    pattern.push_str(name);
                    pattern.push('}');
                    path_variables.push(*variable);
                }
                Part::Expression { .. } => {
                    return Err(UriTemplateError::NotMatchable(
                        "only {name} expressions are supported in the path",
                    ));
                }
            }
            index += 1;
        }
        if !pattern.starts_with('/') {
            return Err(UriTemplateError::NotMatchable("path must start with '/'"));
        }
        // PathPattern normalises empty segments away, so `//` would never match itself.
        if pattern.contains("//") {
            return Err(UriTemplateError::NotMatchable(
                "path may not contain empty segments",
            ));
        }

        let mut query_variables: SmallVec<[(Box<str>, TemplateVariable); 4]> = SmallVec::new();
        let mut query_fixed = SmallVec::new();
        // Whether a literal '?' or a `{?...}` already started the query.
        let mut query_started = query_literal_head.is_some();
        // Text of a literal still waiting for the expression it names (`...&name=`).
        let mut pending = query_literal_head.map(|head| head.strip_prefix('?').unwrap_or(head));
        let mut pending_is_start = true;
        loop {
            if let Some(text) = pending.take() {
                let text = if pending_is_start {
                    text
                } else {
                    text.strip_prefix('&')
                        .ok_or(UriTemplateError::NotMatchable(
                            "query values must be followed by '&' or the end",
                        ))?
                };
                let mut pairs = text.split('&').peekable();
                while let Some(pair) = pairs.next() {
                    let last = pairs.peek().is_none();
                    let next_is_simple = matches!(
                        parts.get(index),
                        Some(Part::Expression {
                            operator: TemplateOperator::Simple,
                            ..
                        })
                    );
                    if last && next_is_simple {
                        let name = pair
                            .strip_suffix('=')
                            .ok_or(UriTemplateError::NotMatchable(
                                "a query value expression must follow 'name='",
                            ))?;
                        // Requests split a pair at its first '=': the name may hold none.
                        if name.contains('=') {
                            return Err(UriTemplateError::NotMatchable(
                                "a query name may not contain '='",
                            ));
                        }
                        pending = Some(name);
                        break;
                    }
                    if pair.is_empty() {
                        continue;
                    }
                    let (name, value) = match pair.split_once('=') {
                        Some((name, value)) => (name, Some(decode_component(value)?)),
                        None => (pair, None),
                    };
                    query_fixed.push((decode_component(name)?, value));
                }
            }
            let Some(part) = parts.get(index) else {
                break;
            };
            index += 1;
            pending_is_start = false;
            let starts_query = !query_started;
            query_started = true;
            match part {
                Part::Literal(r) => pending = Some(template.slice(r)),
                Part::Expression {
                    operator: TemplateOperator::Simple,
                    variables,
                } => {
                    let [variable] = variables.as_slice() else {
                        return Err(UriTemplateError::NotMatchable(
                            "query value expressions must name exactly one variable",
                        ));
                    };
                    let name = pending.take().ok_or(UriTemplateError::NotMatchable(
                        "a query value expression must follow 'name='",
                    ))?;
                    push_query_variable(
                        &mut query_variables,
                        &path_variables,
                        decode_component(name)?,
                        *variable,
                    )?;
                }
                Part::Expression {
                    operator:
                        operator @ (TemplateOperator::Query | TemplateOperator::QueryContinuation),
                    variables,
                } => {
                    // `{?...}` starts the query; once started, only `{&...}` continues it.
                    if *operator == TemplateOperator::Query && !starts_query {
                        return Err(UriTemplateError::NotMatchable(
                            "{?...} may only start the query",
                        ));
                    }
                    for variable in variables {
                        let name = template.slice(&template.0.names[variable.0 as usize]);
                        push_query_variable(
                            &mut query_variables,
                            &path_variables,
                            decode_component(name)?,
                            *variable,
                        )?;
                    }
                }
                Part::Expression { .. } => {
                    return Err(UriTemplateError::NotMatchable(
                        "only {name}, {?...} and {&...} expressions are supported in the query",
                    ));
                }
            }
        }

        if query_fixed.len() > MAX_FIXED_QUERY_PAIRS {
            return Err(UriTemplateError::NotMatchable(
                "too many literal query pairs",
            ));
        }
        // Pairs are matched by name, so every name must be unique across the query.
        for (index, (name, _)) in query_fixed.iter().enumerate() {
            if query_fixed[..index]
                .iter()
                .any(|(earlier, _)| earlier == name)
                || query_variables.iter().any(|(variable, _)| variable == name)
            {
                return Err(UriTemplateError::NotMatchable(
                    "query names may appear only once",
                ));
            }
        }
        Ok(Self {
            template: template.clone(),
            // Raw comparison: an escaped delimiter inside a value must not look like a literal one.
            path: PathPattern::new_with_opts(
                pattern.as_str(),
                PathMatchOptions {
                    percent_decode: false,
                    ..PathMatchOptions::default()
                },
            ),
            path_variables,
            query_variables,
            query_fixed,
        })
    }

    /// The template this matcher was built from.
    #[must_use]
    pub fn template(&self) -> &UriTemplate {
        &self.template
    }

    /// Match a request's raw path and query.
    #[must_use]
    pub fn captures<'a>(
        &self,
        path: &'a str,
        query: Option<&'a str>,
    ) -> Option<UriTemplateCaptures<'a>> {
        if !is_ascii_with_valid_escapes(path.as_bytes()) {
            return None;
        }
        let path_captures = self.path.captures(PathRef::from_raw_str(path))?;
        let mut values = SmallVec::new();
        for &variable in &self.path_variables {
            let name = self.template.variable_name(variable)?;
            // Captures are raw here: decode each exactly once, refusing invalid UTF-8.
            let raw = path_captures.get(name)?;
            let value = decode_cow(Cow::Borrowed(raw))?.into_owned();
            values.push((variable, Cow::Owned(value)));
        }

        let mut fixed_seen = 0u32;
        if let Some(query) = query {
            for pair in QueryRef::from_raw_str(query).pairs() {
                let name = decode_cow(pair.name_encoded())?;
                let value = match pair.value_encoded() {
                    Some(value) => Some(decode_cow(value)?),
                    None => None,
                };
                if let Some((_, variable)) = self
                    .query_variables
                    .iter()
                    .find(|(n, _)| n.as_ref() == name.as_ref())
                {
                    if values.iter().any(|(v, _)| v == variable) {
                        return None;
                    }
                    values.push((*variable, value.unwrap_or(Cow::Borrowed(""))));
                } else if let Some(position) = self
                    .query_fixed
                    .iter()
                    .position(|(n, _)| n.as_ref() == name.as_ref())
                {
                    let (_, expected) = &self.query_fixed[position];
                    if expected.as_deref() != value.as_deref() {
                        return None;
                    }
                    fixed_seen |= 1 << position;
                }
            }
        }
        if fixed_seen.count_ones() as usize != self.query_fixed.len() {
            return None;
        }
        Some(UriTemplateCaptures { values })
    }
}

fn push_query_variable(
    query_variables: &mut SmallVec<[(Box<str>, TemplateVariable); 4]>,
    path_variables: &[TemplateVariable],
    name: Box<str>,
    variable: TemplateVariable,
) -> Result<(), UriTemplateError> {
    if path_variables.contains(&variable)
        || query_variables
            .iter()
            .any(|(n, v)| n.as_ref() == name.as_ref() || *v == variable)
    {
        return Err(UriTemplateError::NotMatchable(
            "query names and variables may appear only once",
        ));
    }
    query_variables.push((name, variable));
    Ok(())
}

fn is_ascii_with_valid_escapes(bytes: &[u8]) -> bool {
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if is_pct_triplet(bytes, i) => i += 3,
            b'%' => return false,
            b if b.is_ascii_graphic() => i += 1,
            _ => return false,
        }
    }
    true
}

fn decode_component(raw: &str) -> Result<Box<str>, UriTemplateError> {
    decode_cow(Cow::Borrowed(raw))
        .map(|value| value.into_owned().into_boxed_str())
        .ok_or(UriTemplateError::NotMatchable(
            "query literal is not valid percent-encoded UTF-8",
        ))
}

fn decode_cow(raw: Cow<'_, str>) -> Option<Cow<'_, str>> {
    if !is_ascii_with_valid_escapes(raw.as_bytes()) {
        return None;
    }
    if !raw.contains('%') {
        return Some(raw);
    }
    let decoded = percent_decode(raw.as_bytes()).decode_utf8().ok()?;
    Some(Cow::Owned(decoded.into_owned()))
}

#[cfg(test)]
mod tests;
