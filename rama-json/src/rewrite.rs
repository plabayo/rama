//! Streaming JSON rewriting.
//!
//! This slice supports scalar value replacement and removal. Object/array
//! subtree capture builds on the same tokenizer/path state but is intentionally
//! left for a later implementation phase.

use serde::Serialize;

use crate::path::{JsonPath, PathElement};
use crate::select::ValuePath;
use crate::tokenizer::{JsonNumber, Token, TokenSink, Tokenizer, tokenize};
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
        Self {
            tokenizer: Tokenizer::new(),
            sink: RewriteSink {
                selectors: selectors.to_vec(),
                handler,
                output: Vec::new(),
                stack: Vec::new(),
            },
        }
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
    pub fn from_handlers(handlers: JsonHandlers<'h>) -> Self {
        let selectors = handlers.selectors.clone();
        Self::new(&selectors, handlers)
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
    pub fn as_str(&self) -> Result<Option<String>, JsonError> {
        match self.token {
            Token::String(s) => s.decode().map(Some),
            _ => Ok(None),
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

    /// Replaces this value with a serializable JSON value.
    pub fn replace_json<T: Serialize>(&mut self, value: &T) -> HandlerResult {
        self.action = ValueAction::Replace(serde_json::to_vec(value).map_err(|_err| {
            JsonError::new(JsonErrorKind::UnexpectedToken("json serialization failure"))
        })?);
        Ok(())
    }

    /// Replaces this value with already serialized JSON bytes.
    pub fn replace_raw(&mut self, raw: impl Into<Vec<u8>>) -> HandlerResult {
        let raw = raw.into();
        validate_replacement(&raw)?;
        self.action = ValueAction::Replace(raw);
        Ok(())
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
}

impl<H: JsonValueHandler> TokenSink for RewriteSink<H> {
    fn token(&mut self, token: Token<'_>) -> Result<(), JsonError> {
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
                let path = self.current_value_path()?;
                self.emit_prefix_for_visible_value();
                self.output.extend_from_slice(token.raw());
                match token {
                    Token::StartObject(_) => self.stack.push(Frame::Object {
                        path,
                        pending_key: None,
                        prefix: Vec::new(),
                        visible_children: 0,
                    }),
                    Token::StartArray(_) => self.stack.push(Frame::Array {
                        path,
                        next_index: 0,
                        prefix: Vec::new(),
                        visible_children: 0,
                    }),
                    _ => {}
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
                self.finish_value(true)?;
            }
            Token::String(_)
            | Token::Number(_)
            | Token::True(_)
            | Token::False(_)
            | Token::Null(_) => {
                let path = self.current_value_path()?;
                let mut value = JsonValue::new(path, token);
                for index in 0..self.selectors.len() {
                    if self.selectors[index].matches_path(value.path().segments()) {
                        self.handler.handle_value(index, &mut value)?;
                    }
                }
                match value.into_action() {
                    ValueAction::Keep => {
                        self.emit_prefix_for_visible_value();
                        self.output.extend_from_slice(token.raw());
                        self.finish_value(true)?;
                    }
                    ValueAction::Replace(replacement) => {
                        self.emit_prefix_for_visible_value();
                        self.output.extend_from_slice(&replacement);
                        self.finish_value(true)?;
                    }
                    ValueAction::Remove => {
                        if self.stack.is_empty() {
                            return Err(JsonError::new(JsonErrorKind::UnexpectedToken(
                                "remove root value",
                            )));
                        }
                        self.clear_prefix()?;
                        self.finish_value(false)?;
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

    fn current_value_path(&self) -> Result<ValuePath, JsonError> {
        match self.stack.last() {
            None => Ok(ValuePath::root()),
            Some(Frame::Object {
                path, pending_key, ..
            }) => {
                let mut value_path = path.clone();
                let Some(key) = pending_key else {
                    return Err(JsonError::new(JsonErrorKind::UnexpectedToken(
                        "object value",
                    )));
                };
                value_path
                    .segments_mut()
                    .push(PathElement::Member(key.clone()));
                Ok(value_path)
            }
            Some(Frame::Array {
                path, next_index, ..
            }) => {
                let mut value_path = path.clone();
                value_path
                    .segments_mut()
                    .push(PathElement::Index(*next_index));
                Ok(value_path)
            }
        }
    }

    fn finish_value(&mut self, visible: bool) -> Result<(), JsonError> {
        match self.stack.last_mut() {
            Some(Frame::Object {
                pending_key,
                visible_children,
                ..
            }) => {
                pending_key.take();
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
        path: ValuePath,
        pending_key: Option<Box<str>>,
        prefix: Vec<u8>,
        visible_children: usize,
    },
    Array {
        path: ValuePath,
        next_index: usize,
        prefix: Vec<u8>,
        visible_children: usize,
    },
}

impl Frame {
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
    match prefix.iter().position(|b| *b == b',') {
        Some(index) => {
            output.extend_from_slice(&prefix[..index]);
            output.extend_from_slice(&prefix[index + 1..]);
        }
        None => output.extend_from_slice(prefix),
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
    fn replaces_selected_scalars() {
        let out = rewrite_bytes(
            br#"{"user":{"name":"Alice","active":true},"count":1}"#,
            JsonHandlers::new()
                .on(path("$.user.name"), |value| {
                    assert_eq!(value.as_str()?.as_deref(), Some("Alice"));
                    value.replace_json(&"Bob")
                })
                .on(path("$.count"), |value| {
                    assert_eq!(value.as_number_raw().map(|n| n.raw()), Some(&b"1"[..]));
                    value.replace_raw(b"2".to_vec())
                }),
        )
        .unwrap();
        assert_eq!(out, br#"{"user":{"name":"Bob","active":true},"count":2}"#);
    }

    #[test]
    fn rewrites_across_chunks() {
        let selectors = [path("$..id")];
        let mut rewriter = JsonRewriter::new(&selectors, |_: usize, value: &mut JsonValue<'_>| {
            value.replace_raw(b"9".to_vec())
        });
        for chunk in br#"{"items":[{"id":1},{"id":2}]}"#.chunks(2) {
            rewriter.write(chunk).unwrap();
        }
        rewriter.end().unwrap();
        assert_eq!(rewriter.take_output(), br#"{"items":[{"id":9},{"id":9}]}"#);
    }

    #[test]
    fn removes_object_members_with_comma_repair() {
        let out = rewrite_bytes(
            br#"{"a":1,"b":2,"c":3}"#,
            JsonHandlers::new().on(path("$.b"), |value| {
                value.remove();
                Ok(())
            }),
        )
        .unwrap();
        assert_eq!(out, br#"{"a":1,"c":3}"#);

        let out = rewrite_bytes(
            br#"{"a":1,"b":2,"c":3}"#,
            JsonHandlers::new().on(path("$.a"), |value| {
                value.remove();
                Ok(())
            }),
        )
        .unwrap();
        assert_eq!(out, br#"{"b":2,"c":3}"#);

        let out = rewrite_bytes(
            br#"{"a":1,"b":2,"c":3}"#,
            JsonHandlers::new().on(path("$.c"), |value| {
                value.remove();
                Ok(())
            }),
        )
        .unwrap();
        assert_eq!(out, br#"{"a":1,"b":2}"#);
    }

    #[test]
    fn removes_array_items_with_comma_repair() {
        let out = rewrite_bytes(
            br#"[1,2,3]"#,
            JsonHandlers::new().on(path("$[1]"), |value| {
                value.remove();
                Ok(())
            }),
        )
        .unwrap();
        assert_eq!(out, br#"[1,3]"#);

        let out = rewrite_bytes(
            br#"[1,2,3]"#,
            JsonHandlers::new().on(path("$[0]"), |value| {
                value.remove();
                Ok(())
            }),
        )
        .unwrap();
        assert_eq!(out, br#"[2,3]"#);

        let out = rewrite_bytes(
            br#"[1,2,3]"#,
            JsonHandlers::new().on(path("$[2]"), |value| {
                value.remove();
                Ok(())
            }),
        )
        .unwrap();
        assert_eq!(out, br#"[1,2]"#);
    }

    #[test]
    fn removes_all_children() {
        let out = rewrite_bytes(
            br#"{"a":1,"b":2}"#,
            JsonHandlers::new().on(path("$.*"), |value| {
                value.remove();
                Ok(())
            }),
        )
        .unwrap();
        assert_eq!(out, br#"{}"#);

        let out = rewrite_bytes(
            br#"[1,2]"#,
            JsonHandlers::new().on(path("$[*]"), |value| {
                value.remove();
                Ok(())
            }),
        )
        .unwrap();
        assert_eq!(out, br#"[]"#);
    }

    #[test]
    fn removal_preserves_valid_whitespace() {
        let out = rewrite_bytes(
            b"{\n  \"a\": 1,\n  \"b\": 2,\n  \"c\": 3\n}",
            JsonHandlers::new().on(path("$.a"), |value| {
                value.remove();
                Ok(())
            }),
        )
        .unwrap();
        assert_eq!(out, b"{\n  \"b\": 2,\n  \"c\": 3\n}");

        let out = rewrite_bytes(
            b"[\n  1,\n  2,\n  3\n]",
            JsonHandlers::new().on(path("$[0]"), |value| {
                value.remove();
                Ok(())
            }),
        )
        .unwrap();
        assert_eq!(out, b"[\n  2,\n  3\n]");
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
}
