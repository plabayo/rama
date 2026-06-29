//! Streaming JSON rewriting.
//!
//! This module supports streaming replacement and removal for scalar values and
//! whole object/array subtrees. A replaced or removed container is suppressed as
//! the tokenizer streams through it, so non-capturing rewrites do not need to
//! buffer the subtree.

use std::borrow::Cow;

use serde::Serialize;

use crate::path::{JsonPath, PathElement};
use crate::select::ValuePath;
use crate::tokenizer::{
    DEFAULT_MAX_BUFFERED_BYTES, JsonNumber, Token, TokenSink, Tokenizer, tokenize,
};
use crate::{JsonError, JsonErrorKind};

/// Result returned by JSON rewrite handlers.
pub type HandlerResult = Result<(), JsonError>;

/// Handles a selected JSON value.
pub trait JsonValueHandler {
    /// Handles one selected value.
    ///
    /// `selector` is the index of the matching selector in registration order.
    fn handle_value(&mut self, selector: usize, value: &mut JsonValue<'_>) -> HandlerResult;
}

/// Streaming JSON rewriter.
pub struct JsonRewriter<H> {
    tokenizer: Tokenizer,
    sink: RewriteSink<H>,
}

impl<H: JsonValueHandler> JsonRewriter<H> {
    /// Creates a JSON rewriter.
    #[must_use]
    pub fn new(selectors: &[JsonPath], handler: H) -> Self {
        Self::with_max_buffered_bytes(selectors, handler, DEFAULT_MAX_BUFFERED_BYTES)
    }

    /// Creates a JSON rewriter with a custom tokenizer buffered-input limit.
    #[must_use]
    pub fn with_max_buffered_bytes(
        selectors: &[JsonPath],
        handler: H,
        max_buffered_bytes: usize,
    ) -> Self {
        Self {
            tokenizer: Tokenizer::with_max_buffered_bytes(max_buffered_bytes),
            sink: RewriteSink {
                selectors: selectors.to_vec(),
                handler,
                output: Vec::new(),
                stack: Vec::new(),
                path: ValuePath::root(),
                suppressed: None,
            },
        }
    }

    /// Returns the tokenizer buffered-input limit.
    #[must_use]
    pub const fn max_buffered_bytes(&self) -> usize {
        self.tokenizer.max_buffered_bytes()
    }

    /// Sets the tokenizer buffered-input limit.
    pub fn set_max_buffered_bytes(&mut self, max_buffered_bytes: usize) {
        self.tokenizer.set_max_buffered_bytes(max_buffered_bytes);
    }

    /// Feeds a JSON chunk.
    pub fn write(&mut self, chunk: &[u8]) -> Result<(), JsonError> {
        self.tokenizer.write(chunk, &mut self.sink)
    }

    /// Finalizes the JSON stream.
    pub fn end(&mut self) -> Result<(), JsonError> {
        self.tokenizer.end(&mut self.sink)
    }

    /// Drains rewritten output accumulated so far.
    #[must_use]
    pub fn take_output(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.sink.output)
    }

    /// Consumes the rewriter and returns the handler.
    #[must_use]
    pub fn into_handler(self) -> H {
        self.sink.handler
    }
}

impl<'h> JsonRewriter<JsonHandlers<'h>> {
    /// Creates a rewriter from closure-based handlers.
    #[must_use]
    pub fn from_handlers(mut handlers: JsonHandlers<'h>) -> Self {
        let selectors = std::mem::take(&mut handlers.selectors);
        Self {
            tokenizer: Tokenizer::new(),
            sink: RewriteSink {
                selectors,
                handler: handlers,
                output: Vec::new(),
                stack: Vec::new(),
                path: ValuePath::root(),
                suppressed: None,
            },
        }
    }
}

/// Closure-based handler builder.
#[derive(Default)]
pub struct JsonHandlers<'h> {
    selectors: Vec<JsonPath>,
    handlers: Vec<BoxedHandler<'h>>,
}

impl<'h> JsonHandlers<'h> {
    /// Creates an empty handler set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers `handler` for values matching `selector`.
    #[must_use]
    pub fn on(
        mut self,
        selector: JsonPath,
        handler: impl FnMut(&mut JsonValue<'_>) -> HandlerResult + 'h,
    ) -> Self {
        self.selectors.push(selector);
        self.handlers.push(Box::new(handler));
        self
    }
}

impl JsonValueHandler for JsonHandlers<'_> {
    fn handle_value(&mut self, selector: usize, value: &mut JsonValue<'_>) -> HandlerResult {
        match self.handlers.get_mut(selector) {
            Some(handler) => handler(value),
            None => Ok(()),
        }
    }
}

type BoxedHandler<'h> = Box<dyn FnMut(&mut JsonValue<'_>) -> HandlerResult + 'h>;

impl<F> JsonValueHandler for F
where
    F: FnMut(usize, &mut JsonValue<'_>) -> HandlerResult,
{
    fn handle_value(&mut self, selector: usize, value: &mut JsonValue<'_>) -> HandlerResult {
        self(selector, value)
    }
}

/// One selected JSON value.
pub struct JsonValue<'a> {
    path: ValuePath,
    token: Token<'a>,
    action: ValueAction,
}

impl<'a> JsonValue<'a> {
    fn new(path: ValuePath, token: Token<'a>) -> Self {
        Self {
            path,
            token,
            action: ValueAction::Keep,
        }
    }

    /// Concrete path to this value.
    #[must_use]
    pub const fn path(&self) -> &ValuePath {
        &self.path
    }

    /// Kind of JSON value.
    #[must_use]
    pub const fn kind(&self) -> JsonKind {
        match self.token {
            Token::StartObject(_) => JsonKind::Object,
            Token::StartArray(_) => JsonKind::Array,
            Token::String(_) => JsonKind::String,
            Token::Number(_) => JsonKind::Number,
            Token::True(_) | Token::False(_) => JsonKind::Bool,
            Token::Null(_) => JsonKind::Null,
            Token::Whitespace(_)
            | Token::EndObject(_)
            | Token::EndArray(_)
            | Token::Colon(_)
            | Token::Comma(_)
            | Token::ObjectKey(_) => JsonKind::NonValue,
        }
    }

    /// Raw source bytes for this value token.
    #[must_use]
    pub fn raw(&self) -> &'a [u8] {
        self.token.raw()
    }

    /// Decodes this value as a string, if it is one.
    ///
    /// Unescaped strings borrow from the source. Escaped strings are decoded
    /// into an owned string.
    #[must_use]
    pub fn as_str(&self) -> Option<Cow<'a, str>> {
        match self.token {
            Token::String(s) => s.as_str(),
            _ => None,
        }
    }

    /// Returns this value as a bool, if it is one.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match self.token {
            Token::True(_) => Some(true),
            Token::False(_) => Some(false),
            _ => None,
        }
    }

    /// Returns this value as raw number bytes, if it is a number.
    #[must_use]
    pub const fn as_number_raw(&self) -> Option<JsonNumber<'a>> {
        match self.token {
            Token::Number(n) => Some(n),
            _ => None,
        }
    }

    /// Replaces this value with a JSON writable value.
    pub fn replace<T: JsonWritable>(&mut self, value: T) -> HandlerResult {
        let mut replacement = Vec::new();
        value.write_json(&mut replacement)?;
        self.action = ValueAction::Replace(replacement);
        Ok(())
    }

    /// Replaces this value with already serialized JSON bytes.
    pub fn replace_raw(&mut self, raw: impl Into<Vec<u8>>) -> HandlerResult {
        self.replace(RawJson(raw.into()))
    }

    /// Removes this value.
    ///
    /// Removing the root value would leave no JSON document behind and is
    /// rejected by the rewriter.
    pub fn remove(&mut self) {
        self.action = ValueAction::Remove;
    }

    fn into_action(self) -> ValueAction {
        self.action
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ValueAction {
    Keep,
    Replace(Vec<u8>),
    Remove,
}

/// A value that can be written as JSON replacement bytes.
pub trait JsonWritable {
    /// Writes a complete JSON value to `output`.
    fn write_json(self, output: &mut Vec<u8>) -> HandlerResult;
}

/// Already serialized JSON replacement bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RawJson<T>(pub T);

/// Wraps already serialized JSON replacement bytes.
#[must_use]
pub const fn raw_json<T>(raw: T) -> RawJson<T> {
    RawJson(raw)
}

/// JSON replacement value encoded through serde.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SerdeJson<T>(pub T);

/// Wraps a value that should be encoded as JSON through serde.
#[must_use]
pub const fn serde_json_value<T>(value: T) -> SerdeJson<T> {
    SerdeJson(value)
}

impl<T: AsRef<[u8]>> JsonWritable for RawJson<T> {
    fn write_json(self, output: &mut Vec<u8>) -> HandlerResult {
        let raw = self.0.as_ref();
        validate_replacement(raw)?;
        output.extend_from_slice(raw);
        Ok(())
    }
}

impl<T: Serialize> JsonWritable for SerdeJson<T> {
    fn write_json(self, output: &mut Vec<u8>) -> HandlerResult {
        serde_json::to_writer(output, &self.0)
            .map_err(|_err| JsonError::new(JsonErrorKind::SerializationFailure))
    }
}

impl JsonWritable for () {
    fn write_json(self, output: &mut Vec<u8>) -> HandlerResult {
        output.extend_from_slice(b"null");
        Ok(())
    }
}

impl JsonWritable for bool {
    fn write_json(self, output: &mut Vec<u8>) -> HandlerResult {
        output.extend_from_slice(if self { &b"true"[..] } else { &b"false"[..] });
        Ok(())
    }
}

impl JsonWritable for &str {
    fn write_json(self, output: &mut Vec<u8>) -> HandlerResult {
        serde_json::to_writer(output, self)
            .map_err(|_err| JsonError::new(JsonErrorKind::SerializationFailure))
    }
}

impl JsonWritable for String {
    fn write_json(self, output: &mut Vec<u8>) -> HandlerResult {
        self.as_str().write_json(output)
    }
}

impl JsonWritable for Box<str> {
    fn write_json(self, output: &mut Vec<u8>) -> HandlerResult {
        self.as_ref().write_json(output)
    }
}

macro_rules! impl_integer_writable {
    ($($ty:ty),* $(,)?) => {
        $(
            impl JsonWritable for $ty {
                fn write_json(self, output: &mut Vec<u8>) -> HandlerResult {
                    let mut buf = itoa::Buffer::new();
                    output.extend_from_slice(buf.format(self).as_bytes());
                    Ok(())
                }
            }
        )*
    };
}

impl_integer_writable!(i8, i16, i32, i64, i128, isize);
impl_integer_writable!(u8, u16, u32, u64, u128, usize);

macro_rules! impl_float_writable {
    ($($ty:ty),* $(,)?) => {
        $(
            impl JsonWritable for $ty {
                fn write_json(self, output: &mut Vec<u8>) -> HandlerResult {
                    if !self.is_finite() {
                        return Err(JsonError::new(JsonErrorKind::InvalidNumber));
                    }
                    let mut buf = ryu::Buffer::new();
                    output.extend_from_slice(buf.format(self).as_bytes());
                    Ok(())
                }
            }
        )*
    };
}

impl_float_writable!(f32, f64);

/// JSON value kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum JsonKind {
    /// JSON object.
    Object,
    /// JSON array.
    Array,
    /// JSON string.
    String,
    /// JSON number.
    Number,
    /// JSON boolean.
    Bool,
    /// JSON null.
    Null,
    /// Token is not a value token.
    NonValue,
}

struct RewriteSink<H> {
    selectors: Vec<JsonPath>,
    handler: H,
    output: Vec<u8>,
    stack: Vec<Frame>,
    path: ValuePath,
    suppressed: Option<SuppressedSubtree>,
}

impl<H: JsonValueHandler> TokenSink for RewriteSink<H> {
    fn token(&mut self, token: Token<'_>) -> Result<(), JsonError> {
        if self.suppressed.is_some() {
            return self.suppress_token(token);
        }

        match token {
            Token::ObjectKey(key) => {
                let decoded = key.decode()?;
                let Some(Frame::Object { pending_key, .. }) = self.stack.last_mut() else {
                    return Err(JsonError::new(JsonErrorKind::UnexpectedToken("object key")));
                };
                *pending_key = Some(decoded.into_boxed_str());
                self.push_prefix(token.raw());
            }
            Token::StartObject(_) | Token::StartArray(_) => {
                let parent_path_len = self.push_value_path()?;
                match self.apply_handlers(token)? {
                    ValueAction::Keep => {
                        self.emit_prefix_for_visible_value();
                        self.output.extend_from_slice(token.raw());
                        match token {
                            Token::StartObject(_) => self.stack.push(Frame::Object {
                                parent_path_len,
                                pending_key: None,
                                prefix: Vec::new(),
                                visible_children: 0,
                            }),
                            Token::StartArray(_) => self.stack.push(Frame::Array {
                                parent_path_len,
                                next_index: 0,
                                prefix: Vec::new(),
                                visible_children: 0,
                            }),
                            _ => {}
                        }
                    }
                    ValueAction::Replace(replacement) => {
                        self.emit_prefix_for_visible_value();
                        self.output.extend_from_slice(&replacement);
                        self.suppressed = Some(SuppressedSubtree {
                            depth: 1,
                            parent_path_len,
                            visible: true,
                        });
                    }
                    ValueAction::Remove => {
                        if self.stack.is_empty() {
                            return Err(JsonError::new(JsonErrorKind::UnexpectedToken(
                                "remove root value",
                            )));
                        }
                        self.clear_prefix()?;
                        self.suppressed = Some(SuppressedSubtree {
                            depth: 1,
                            parent_path_len,
                            visible: false,
                        });
                    }
                }
            }
            Token::EndObject(_) | Token::EndArray(_) => {
                let Some(frame) = self.stack.pop() else {
                    return Err(JsonError::new(JsonErrorKind::UnexpectedToken(
                        "container end",
                    )));
                };
                self.output.extend_from_slice(frame.prefix());
                self.output.extend_from_slice(token.raw());
                self.finish_value_after_path(frame.parent_path_len(), true)?;
            }
            Token::String(_)
            | Token::Number(_)
            | Token::True(_)
            | Token::False(_)
            | Token::Null(_) => {
                let parent_path_len = self.push_value_path()?;
                match self.apply_handlers(token)? {
                    ValueAction::Keep => {
                        self.emit_prefix_for_visible_value();
                        self.output.extend_from_slice(token.raw());
                        self.finish_value_after_path(parent_path_len, true)?;
                    }
                    ValueAction::Replace(replacement) => {
                        self.emit_prefix_for_visible_value();
                        self.output.extend_from_slice(&replacement);
                        self.finish_value_after_path(parent_path_len, true)?;
                    }
                    ValueAction::Remove => {
                        if self.stack.is_empty() {
                            return Err(JsonError::new(JsonErrorKind::UnexpectedToken(
                                "remove root value",
                            )));
                        }
                        self.clear_prefix()?;
                        self.finish_value_after_path(parent_path_len, false)?;
                    }
                }
            }
            Token::Whitespace(_) | Token::Colon(_) | Token::Comma(_) => {
                self.push_prefix(token.raw());
            }
        }
        Ok(())
    }
}

impl<H: JsonValueHandler> RewriteSink<H> {
    fn apply_handlers(&mut self, token: Token<'_>) -> Result<ValueAction, JsonError> {
        let mut value = None;
        for index in 0..self.selectors.len() {
            if self.selectors[index].matches_path(self.path.segments()) {
                let value = value.get_or_insert_with(|| JsonValue::new(self.path.clone(), token));
                self.handler.handle_value(index, value)?;
            }
        }
        Ok(value.map_or(ValueAction::Keep, JsonValue::into_action))
    }

    fn suppress_token(&mut self, token: Token<'_>) -> Result<(), JsonError> {
        let Some(suppressed) = self.suppressed.as_mut() else {
            return Ok(());
        };

        match token {
            Token::StartObject(_) | Token::StartArray(_) => {
                suppressed.depth += 1;
            }
            Token::EndObject(_) | Token::EndArray(_) => {
                suppressed.depth -= 1;
                if suppressed.depth == 0 {
                    let parent_path_len = suppressed.parent_path_len;
                    let visible = suppressed.visible;
                    self.suppressed = None;
                    self.finish_value_after_path(parent_path_len, visible)?;
                }
            }
            Token::ObjectKey(_)
            | Token::String(_)
            | Token::Number(_)
            | Token::True(_)
            | Token::False(_)
            | Token::Null(_)
            | Token::Whitespace(_)
            | Token::Colon(_)
            | Token::Comma(_) => {}
        }
        Ok(())
    }
}

impl<H> RewriteSink<H> {
    fn push_prefix(&mut self, raw: &[u8]) {
        match self.stack.last_mut() {
            Some(frame) => {
                frame.prefix_mut().extend_from_slice(raw);
            }
            None => {
                self.output.extend_from_slice(raw);
            }
        }
    }

    fn emit_prefix_for_visible_value(&mut self) {
        let Some(frame) = self.stack.last_mut() else {
            return;
        };
        let first_visible = frame.visible_children() == 0;
        let prefix = std::mem::take(frame.prefix_mut());
        if first_visible {
            emit_without_first_comma(&mut self.output, &prefix);
        } else {
            self.output.extend_from_slice(&prefix);
        }
    }

    fn clear_prefix(&mut self) -> Result<(), JsonError> {
        match self.stack.last_mut() {
            Some(frame) => {
                frame.prefix_mut().clear();
                Ok(())
            }
            None => Err(JsonError::new(JsonErrorKind::UnexpectedToken(
                "missing parent container",
            ))),
        }
    }

    fn push_value_path(&mut self) -> Result<usize, JsonError> {
        let parent_path_len = self.path.segments().len();
        match self.stack.last_mut() {
            None => {}
            Some(Frame::Object { pending_key, .. }) => {
                let Some(key) = pending_key.take() else {
                    return Err(JsonError::new(JsonErrorKind::UnexpectedToken(
                        "object value",
                    )));
                };
                self.path.segments_mut().push(PathElement::Member(key));
            }
            Some(Frame::Array { next_index, .. }) => {
                self.path
                    .segments_mut()
                    .push(PathElement::Index(*next_index));
            }
        }
        Ok(parent_path_len)
    }

    fn finish_value_after_path(
        &mut self,
        parent_path_len: usize,
        visible: bool,
    ) -> Result<(), JsonError> {
        self.path.segments_mut().truncate(parent_path_len);
        match self.stack.last_mut() {
            Some(Frame::Object {
                visible_children, ..
            }) => {
                if visible {
                    *visible_children += 1;
                }
            }
            Some(Frame::Array {
                next_index,
                visible_children,
                ..
            }) => {
                *next_index += 1;
                if visible {
                    *visible_children += 1;
                }
            }
            None => {}
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
enum Frame {
    Object {
        parent_path_len: usize,
        pending_key: Option<Box<str>>,
        prefix: Vec<u8>,
        visible_children: usize,
    },
    Array {
        parent_path_len: usize,
        next_index: usize,
        prefix: Vec<u8>,
        visible_children: usize,
    },
}

#[derive(Debug, Clone, Copy)]
struct SuppressedSubtree {
    depth: usize,
    parent_path_len: usize,
    visible: bool,
}

impl Frame {
    fn parent_path_len(&self) -> usize {
        match self {
            Self::Object {
                parent_path_len, ..
            }
            | Self::Array {
                parent_path_len, ..
            } => *parent_path_len,
        }
    }

    fn prefix(&self) -> &[u8] {
        match self {
            Self::Object { prefix, .. } | Self::Array { prefix, .. } => prefix,
        }
    }

    fn prefix_mut(&mut self) -> &mut Vec<u8> {
        match self {
            Self::Object { prefix, .. } | Self::Array { prefix, .. } => prefix,
        }
    }

    fn visible_children(&self) -> usize {
        match self {
            Self::Object {
                visible_children, ..
            }
            | Self::Array {
                visible_children, ..
            } => *visible_children,
        }
    }
}

fn emit_without_first_comma(output: &mut Vec<u8>, prefix: &[u8]) {
    match prefix.iter().position(|b| !b.is_ascii_whitespace()) {
        Some(index) if prefix[index] == b',' => {
            output.extend_from_slice(&prefix[..index]);
            output.extend_from_slice(&prefix[index + 1..]);
        }
        _ => output.extend_from_slice(prefix),
    }
}

struct ValidateSink {
    values: usize,
}

impl TokenSink for ValidateSink {
    fn token(&mut self, token: Token<'_>) -> Result<(), JsonError> {
        match token {
            Token::StartObject(_)
            | Token::StartArray(_)
            | Token::String(_)
            | Token::Number(_)
            | Token::True(_)
            | Token::False(_)
            | Token::Null(_) => self.values += 1,
            Token::Whitespace(_)
            | Token::EndObject(_)
            | Token::EndArray(_)
            | Token::Colon(_)
            | Token::Comma(_)
            | Token::ObjectKey(_) => {}
        }
        Ok(())
    }
}

fn validate_replacement(raw: &[u8]) -> HandlerResult {
    let mut sink = ValidateSink { values: 0 };
    tokenize(raw, &mut sink)?;
    if sink.values == 0 {
        return Err(JsonError::new(JsonErrorKind::UnexpectedEnd));
    }
    Ok(())
}

/// Rewrites a complete JSON byte slice.
pub fn rewrite_bytes(input: &[u8], handlers: JsonHandlers<'_>) -> Result<Vec<u8>, JsonError> {
    let mut rewriter = JsonRewriter::from_handlers(handlers);
    rewriter.write(input)?;
    rewriter.end()?;
    Ok(rewriter.take_output())
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::*;

    fn path(s: &str) -> JsonPath {
        s.parse().unwrap()
    }

    #[test]
    fn unmatched_passes_through_verbatim() {
        let input = br#"{"a":1,"b":[true,null,"x"]}"#;
        let out = rewrite_bytes(input, JsonHandlers::new()).unwrap();
        assert_eq!(out, input);
    }

    #[test]
    fn unmatched_keeps_commas_inside_member_names() {
        let cases: &[&[u8]] = &[
            br#"{"a,b":1,"c":2}"#,
            br#"{"outer":{"a,b":1,"c":2}}"#,
            br#"[{"a,b":1},{"c,d":2}]"#,
        ];

        for input in cases {
            let out = rewrite_bytes(input, JsonHandlers::new()).unwrap();
            assert_eq!(out.as_slice(), *input);
        }
    }

    #[test]
    fn replaces_selected_scalars() {
        let out = rewrite_bytes(
            br#"{"user":{"name":"Alice","active":true},"count":1}"#,
            JsonHandlers::new()
                .on(path("$.user.name"), |value| {
                    let decoded = value.as_str().unwrap();
                    assert_eq!(decoded, "Alice");
                    assert!(matches!(decoded, Cow::Borrowed("Alice")));
                    value.replace("Bob")
                })
                .on(path("$.count"), |value| {
                    assert_eq!(value.as_number_raw().map(|n| n.raw()), Some(&b"1"[..]));
                    value.replace(2u8)
                }),
        )
        .unwrap();
        assert_eq!(out, br#"{"user":{"name":"Bob","active":true},"count":2}"#);
    }

    #[test]
    fn selected_values_expose_raw_and_bool_accessors() {
        let seen = std::cell::RefCell::new(Vec::new());
        let out = rewrite_bytes(
            br#"{"yes":true,"no":false}"#,
            JsonHandlers::new()
                .on(path("$.yes"), |value| {
                    seen.borrow_mut()
                        .push((value.raw().to_vec(), value.as_bool()));
                    Ok(())
                })
                .on(path("$.no"), |value| {
                    seen.borrow_mut()
                        .push((value.raw().to_vec(), value.as_bool()));
                    Ok(())
                }),
        )
        .unwrap();
        assert_eq!(out, br#"{"yes":true,"no":false}"#);
        assert_eq!(
            seen.into_inner(),
            vec![
                (b"true".to_vec(), Some(true)),
                (b"false".to_vec(), Some(false)),
            ]
        );
    }

    #[test]
    fn replaces_with_explicit_serde_value() {
        #[derive(Serialize)]
        struct Profile {
            name: &'static str,
            active: bool,
        }

        let out = rewrite_bytes(
            br#"{"profile":null}"#,
            JsonHandlers::new().on(path("$.profile"), |value| {
                value.replace(serde_json_value(Profile {
                    name: "Ada",
                    active: true,
                }))
            }),
        )
        .unwrap();
        assert_eq!(out, br#"{"profile":{"name":"Ada","active":true}}"#);
    }

    #[test]
    fn handlers_can_observe_container_values() {
        let seen = std::cell::RefCell::new(Vec::new());
        let out = rewrite_bytes(
            br#"{"user":{"name":"Ada"},"items":[1]}"#,
            JsonHandlers::new()
                .on(path("$.user"), |value| {
                    seen.borrow_mut()
                        .push((value.path().to_string(), value.kind()));
                    Ok(())
                })
                .on(path("$.items"), |value| {
                    seen.borrow_mut()
                        .push((value.path().to_string(), value.kind()));
                    Ok(())
                }),
        )
        .unwrap();
        assert_eq!(out, br#"{"user":{"name":"Ada"},"items":[1]}"#);
        assert_eq!(
            seen.into_inner(),
            vec![
                ("$.user".to_owned(), JsonKind::Object),
                ("$.items".to_owned(), JsonKind::Array),
            ]
        );
    }

    #[test]
    fn replaces_container_subtrees() {
        let cases: &[(&str, &[u8], &[u8], &[u8])] = &[
            (
                "$.user",
                br#"{"user":{"name":"Ada","roles":["admin"]},"ok":true}"#,
                br#"{"name":"redacted"}"#,
                br#"{"user":{"name":"redacted"},"ok":true}"#,
            ),
            (
                "$.items",
                br#"{"items":[{"id":1},{"id":2}],"ok":true}"#,
                br#"[]"#,
                br#"{"items":[],"ok":true}"#,
            ),
            (
                "$",
                br#"{"items":[{"id":1},{"id":2}]}"#,
                br#"{"replaced":true}"#,
                br#"{"replaced":true}"#,
            ),
        ];

        for (selector, input, replacement, expected) in cases {
            let out = rewrite_bytes(
                input,
                JsonHandlers::new().on(path(selector), |value| {
                    value.replace(raw_json(*replacement))
                }),
            )
            .unwrap();
            assert_eq!(out, *expected, "{selector}");
        }
    }

    #[test]
    fn removes_container_subtrees_with_comma_repair() {
        assert_remove_cases(&[
            (
                "$.prompt",
                br#"{"id":1,"prompt":{"text":"secret","meta":{"x":1}},"ok":true}"#,
                br#"{"id":1,"ok":true}"#,
            ),
            (
                "$.extensions",
                br#"{"extensions":[{"id":1},{"id":2}],"ok":true}"#,
                br#"{"ok":true}"#,
            ),
            (
                "$.items[1]",
                br#"{"items":[{"id":1},{"id":2,"nested":[1,2]},{"id":3}]}"#,
                br#"{"items":[{"id":1},{"id":3}]}"#,
            ),
            (
                "$.items[0]",
                br#"{"items":[{"id":1},{"id":2}]}"#,
                br#"{"items":[{"id":2}]}"#,
            ),
            (
                "$.items[1]",
                br#"{"items":[{"id":1},{"id":2}]}"#,
                br#"{"items":[{"id":1}]}"#,
            ),
        ]);
    }

    #[test]
    fn rewrites_across_chunks() {
        let selectors = [path("$..id")];
        let mut rewriter = JsonRewriter::new(&selectors, |_: usize, value: &mut JsonValue<'_>| {
            value.replace(raw_json(b"9"))
        });
        for chunk in br#"{"items":[{"id":1},{"id":2}]}"#.chunks(2) {
            rewriter.write(chunk).unwrap();
        }
        rewriter.end().unwrap();
        assert_eq!(rewriter.take_output(), br#"{"items":[{"id":9},{"id":9}]}"#);
    }

    #[test]
    fn rewrites_container_across_chunks() {
        let selectors = [path("$.items[1]")];
        let mut rewriter = JsonRewriter::new(&selectors, |_: usize, value: &mut JsonValue<'_>| {
            value.replace(raw_json(br#"{"id":9}"#))
        });
        for chunk in br#"{"items":[{"id":1},{"id":2,"nested":[1,2,3]},{"id":3}]}"#.chunks(3) {
            rewriter.write(chunk).unwrap();
        }
        rewriter.end().unwrap();
        assert_eq!(
            rewriter.take_output(),
            br#"{"items":[{"id":1},{"id":9},{"id":3}]}"#
        );
    }

    #[test]
    fn rewrite_path_recovers_after_nested_container() {
        let out = rewrite_bytes(
            br#"{"items":[{"nested":{"id":1}},{"id":2}]}"#,
            JsonHandlers::new().on(path("$.items[1].id"), |value| value.replace(9u8)),
        )
        .unwrap();
        assert_eq!(out, br#"{"items":[{"nested":{"id":1}},{"id":9}]}"#);
    }

    #[test]
    fn removes_object_members_with_comma_repair() {
        assert_remove_cases(&[
            ("$.b", br#"{"a":1,"b":2,"c":3}"#, br#"{"a":1,"c":3}"#),
            ("$.a", br#"{"a":1,"b":2,"c":3}"#, br#"{"b":2,"c":3}"#),
            ("$.c", br#"{"a":1,"b":2,"c":3}"#, br#"{"a":1,"b":2}"#),
            ("$.a", br#"{"a":1,"b,c":2,"d":3}"#, br#"{"b,c":2,"d":3}"#),
            ("$.a", b"{\"a\":1 \n , \"b,c\":2}", b"{ \n  \"b,c\":2}"),
        ]);
    }

    #[test]
    fn removes_array_items_with_comma_repair() {
        assert_remove_cases(&[
            ("$[1]", br#"[1,2,3]"#, br#"[1,3]"#),
            ("$[0]", br#"[1,2,3]"#, br#"[2,3]"#),
            ("$[2]", br#"[1,2,3]"#, br#"[1,2]"#),
        ]);
    }

    #[test]
    fn removes_all_children() {
        assert_remove_cases(&[
            ("$.*", br#"{"a":1,"b":2}"#, br#"{}"#),
            ("$[*]", br#"[1,2]"#, br#"[]"#),
        ]);
    }

    #[test]
    fn removal_preserves_valid_whitespace() {
        assert_remove_cases(&[
            (
                "$.a",
                b"{\n  \"a\": 1,\n  \"b\": 2,\n  \"c\": 3\n}",
                b"{\n  \"b\": 2,\n  \"c\": 3\n}",
            ),
            ("$[0]", b"[\n  1,\n  2,\n  3\n]", b"[\n  2,\n  3\n]"),
        ]);
    }

    #[test]
    fn removes_across_chunks() {
        let selectors = [path("$..secret")];
        let mut rewriter = JsonRewriter::new(&selectors, |_: usize, value: &mut JsonValue<'_>| {
            value.remove();
            Ok(())
        });
        for chunk in br#"{"items":[{"id":1,"secret":true},{"secret":false,"id":2}]}"#.chunks(4) {
            rewriter.write(chunk).unwrap();
        }
        rewriter.end().unwrap();
        assert_eq!(rewriter.take_output(), br#"{"items":[{"id":1},{"id":2}]}"#);
    }

    #[test]
    fn rejects_root_removal() {
        let err = rewrite_bytes(
            br#"true"#,
            JsonHandlers::new().on(path("$"), |value| {
                value.remove();
                Ok(())
            }),
        )
        .unwrap_err();
        assert!(matches!(
            err.kind(),
            JsonErrorKind::UnexpectedToken("remove root value")
        ));
    }

    #[test]
    fn rejects_invalid_raw_replacement() {
        let err = rewrite_bytes(
            br#"{"x":1}"#,
            JsonHandlers::new().on(path("$.x"), |value| value.replace_raw(b"not json".to_vec())),
        )
        .unwrap_err();
        assert!(matches!(
            err.kind(),
            JsonErrorKind::UnexpectedByte(_) | JsonErrorKind::InvalidNumber
        ));
    }

    #[test]
    fn rewriter_buffered_limit_can_be_configured() {
        let selectors = [path("$.name")];
        let mut rewriter = JsonRewriter::new(&selectors, JsonHandlers::new());
        assert_eq!(rewriter.max_buffered_bytes(), DEFAULT_MAX_BUFFERED_BYTES);
        rewriter.set_max_buffered_bytes(8);
        assert_eq!(rewriter.max_buffered_bytes(), 8);
    }

    #[test]
    fn rewriter_end_rejects_truncated_input() {
        let selectors = [path("$.name")];
        let mut rewriter = JsonRewriter::new(&selectors, JsonHandlers::new());
        rewriter.write(br#"{"name":"#).unwrap();
        let err = rewriter.end().unwrap_err();
        assert_eq!(err.kind(), &JsonErrorKind::UnexpectedEnd);
    }

    #[test]
    fn rejects_input_that_exceeds_buffered_limit() {
        let selectors = [path("$.name")];
        let mut rewriter =
            JsonRewriter::with_max_buffered_bytes(&selectors, JsonHandlers::new(), 8);
        rewriter.write(br#"{"name":"#).unwrap();
        let err = rewriter.write(br#""unterminated"#).unwrap_err();
        assert_eq!(err.kind(), &JsonErrorKind::InputBufferLimitExceeded(8));
    }

    fn assert_remove_cases(cases: &[(&str, &[u8], &[u8])]) {
        for (selector, input, expected) in cases {
            let out = rewrite_bytes(
                input,
                JsonHandlers::new().on(path(selector), |value| {
                    value.remove();
                    Ok(())
                }),
            )
            .unwrap_or_else(|err| panic!("{selector} failed for {input:?}: {err}"));
            assert_eq!(
                out.as_slice(),
                *expected,
                "selector {selector} input {}",
                String::from_utf8_lossy(input)
            );
        }
    }
}
