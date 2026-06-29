//! Streaming JSON value capture.
//!
//! Capturing is intended for small selected values that a caller wants to
//! inspect or deserialize as a whole. Non-matching input is still processed as a
//! stream, while matching object and array subtrees are bounded by
//! `max_capture_bytes`.

use std::{borrow::Cow, fmt};

use serde::de::DeserializeOwned;

use crate::path::{JsonPath, PathElement};
use crate::select::ValuePath;
use crate::tokenizer::{DEFAULT_MAX_BUFFERED_BYTES, Token, TokenSink, Tokenizer};
use crate::{JsonError, JsonErrorKind};

/// Result returned by JSON capture handlers.
pub type CaptureResult = Result<(), JsonError>;

/// One captured JSON value.
#[derive(Clone, Copy)]
pub struct CapturedValue<'a> {
    path: &'a ValuePath,
    json: CapturedJson<'a>,
    handler_index: usize,
}

impl<'a> CapturedValue<'a> {
    /// Concrete path to the captured value.
    #[must_use]
    #[inline(always)]
    pub const fn path(self) -> &'a ValuePath {
        self.path
    }

    /// Raw JSON bytes for the captured value.
    #[must_use]
    #[inline(always)]
    pub const fn as_raw_bytes(self) -> &'a [u8] {
        self.json.raw
    }

    /// Decodes this value as a string, if it is one.
    ///
    /// Unescaped strings borrow from the captured JSON source. Escaped strings
    /// are decoded into an owned string.
    #[must_use]
    pub fn as_str(self) -> Option<Cow<'a, str>> {
        match self.as_raw_bytes() {
            [b'"', body @ .., b'"'] if !body.contains(&b'\\') => {
                std::str::from_utf8(body).map(Cow::Borrowed).ok()
            }
            [b'"', ..] => serde_json::from_slice(self.as_raw_bytes())
                .map(Cow::Owned)
                .ok(),
            _ => None,
        }
    }

    /// Returns this value as a bool, if it is one.
    #[must_use]
    #[inline(always)]
    pub const fn as_bool(self) -> Option<bool> {
        match self.as_raw_bytes() {
            b"true" => Some(true),
            b"false" => Some(false),
            _ => None,
        }
    }

    /// Returns true if this value is JSON null.
    #[must_use]
    #[inline(always)]
    pub const fn is_null(self) -> bool {
        matches!(self.as_raw_bytes(), b"null")
    }

    /// Parses this value as an i8, if it is a number.
    #[must_use]
    pub fn as_i8(self) -> Option<i8> {
        parse_number(self.as_raw_bytes())
    }

    /// Parses this value as an i16, if it is a number.
    #[must_use]
    pub fn as_i16(self) -> Option<i16> {
        parse_number(self.as_raw_bytes())
    }

    /// Parses this value as an i32, if it is a number.
    #[must_use]
    pub fn as_i32(self) -> Option<i32> {
        parse_number(self.as_raw_bytes())
    }

    /// Parses this value as an i64, if it is a number.
    #[must_use]
    pub fn as_i64(self) -> Option<i64> {
        parse_number(self.as_raw_bytes())
    }

    /// Parses this value as an i128, if it is a number.
    #[must_use]
    pub fn as_i128(self) -> Option<i128> {
        parse_number(self.as_raw_bytes())
    }

    /// Parses this value as an isize, if it is a number.
    #[must_use]
    pub fn as_isize(self) -> Option<isize> {
        parse_number(self.as_raw_bytes())
    }

    /// Parses this value as a u8, if it is a number.
    #[must_use]
    pub fn as_u8(self) -> Option<u8> {
        parse_number(self.as_raw_bytes())
    }

    /// Parses this value as a u16, if it is a number.
    #[must_use]
    pub fn as_u16(self) -> Option<u16> {
        parse_number(self.as_raw_bytes())
    }

    /// Parses this value as a u32, if it is a number.
    #[must_use]
    pub fn as_u32(self) -> Option<u32> {
        parse_number(self.as_raw_bytes())
    }

    /// Parses this value as a u64, if it is a number.
    #[must_use]
    pub fn as_u64(self) -> Option<u64> {
        parse_number(self.as_raw_bytes())
    }

    /// Parses this value as a u128, if it is a number.
    #[must_use]
    pub fn as_u128(self) -> Option<u128> {
        parse_number(self.as_raw_bytes())
    }

    /// Parses this value as a usize, if it is a number.
    #[must_use]
    pub fn as_usize(self) -> Option<usize> {
        parse_number(self.as_raw_bytes())
    }

    /// Parses this value as an f32, if it is a number.
    #[must_use]
    pub fn as_f32(self) -> Option<f32> {
        parse_number(self.as_raw_bytes())
    }

    /// Parses this value as an f64, if it is a number.
    #[must_use]
    pub fn as_f64(self) -> Option<f64> {
        parse_number(self.as_raw_bytes())
    }

    /// Deserializes the captured JSON value.
    pub fn deserialize<T: DeserializeOwned>(self) -> Result<T, JsonError> {
        self.json.deserialize()
    }
}

impl fmt::Debug for CapturedValue<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CapturedValue")
            .field("path", self.path)
            .field("raw", &self.json.raw)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy)]
struct CapturedJson<'a> {
    raw: &'a [u8],
}

impl<'a> CapturedJson<'a> {
    #[inline(always)]
    fn deserialize<T: DeserializeOwned>(self) -> Result<T, JsonError> {
        serde_json::from_slice(self.raw)
            .map_err(|_err| JsonError::new(JsonErrorKind::DeserializationFailure))
    }
}

#[inline(always)]
fn parse_number<T: DeserializeOwned>(raw: &[u8]) -> Option<T> {
    serde_json::from_slice(raw).ok()
}

/// Handles selected JSON values captured as raw JSON.
pub trait CaptureHandler {
    /// Handles one captured JSON value.
    fn handle_capture(&mut self, value: CapturedValue<'_>) -> CaptureResult;
}

/// Streaming JSON capturer for selected values.
#[derive(Debug)]
pub struct JsonCapturer<H> {
    tokenizer: Tokenizer,
    sink: CaptureSink<H>,
}

impl<H: CaptureHandler> JsonCapturer<H> {
    /// Creates a JSON capturer.
    #[must_use]
    pub fn new(selectors: &[JsonPath], max_capture_bytes: usize, handler: H) -> Self {
        Self::with_max_buffered_bytes(
            selectors,
            max_capture_bytes,
            DEFAULT_MAX_BUFFERED_BYTES,
            handler,
        )
    }

    /// Creates a JSON capturer with a custom tokenizer buffered-input limit.
    #[must_use]
    pub fn with_max_buffered_bytes(
        selectors: &[JsonPath],
        max_capture_bytes: usize,
        max_buffered_bytes: usize,
        handler: H,
    ) -> Self {
        Self {
            tokenizer: Tokenizer::with_max_buffered_bytes(max_buffered_bytes),
            sink: CaptureSink {
                selectors: selectors.to_vec(),
                handler,
                max_capture_bytes,
                stack: Vec::new(),
                active: Vec::new(),
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

    /// Consumes the capturer and returns the handler.
    #[must_use]
    pub fn into_handler(self) -> H {
        self.sink.handler
    }
}

impl<'h> JsonCapturer<CaptureHandlers<'h>> {
    /// Creates a capturer from selector-bundled capture handlers.
    #[must_use]
    pub fn from_handlers(handlers: CaptureHandlers<'h>, max_capture_bytes: usize) -> Self {
        let selectors = handlers.selectors();
        Self::new(&selectors, max_capture_bytes, handlers)
    }
}

/// Selector-bundled capture handlers.
#[derive(Debug, Default)]
pub struct CaptureHandlers<'h> {
    handlers: Vec<CaptureHandlerEntry<'h>>,
}

impl<'h> CaptureHandlers<'h> {
    /// Creates an empty handler set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers `handler` for values matching `selector`.
    #[must_use]
    pub fn on(mut self, selector: JsonPath, handler: impl CaptureHandler + 'h) -> Self {
        self.push_handler(selector, handler);
        self
    }

    /// Registers a closure for values matching `selector`.
    #[must_use]
    pub fn on_fn(
        mut self,
        selector: JsonPath,
        handler: impl FnMut(CapturedValue<'_>) -> CaptureResult + 'h,
    ) -> Self {
        self.push_handler(selector, CaptureFn(handler));
        self
    }

    fn push_handler(&mut self, selector: JsonPath, handler: impl CaptureHandler + 'h) {
        self.handlers.push(CaptureHandlerEntry {
            selector,
            handler: Box::new(handler),
        });
    }

    fn selectors(&self) -> Vec<JsonPath> {
        self.handlers
            .iter()
            .map(|entry| entry.selector.clone())
            .collect()
    }
}

impl CaptureHandler for CaptureHandlers<'_> {
    fn handle_capture(&mut self, value: CapturedValue<'_>) -> CaptureResult {
        match self.handlers.get_mut(value.handler_index) {
            Some(entry) => entry.handler.handle_capture(value),
            None => Ok(()),
        }
    }
}

struct CaptureHandlerEntry<'h> {
    selector: JsonPath,
    handler: BoxedCaptureHandler<'h>,
}

impl fmt::Debug for CaptureHandlerEntry<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CaptureHandlerEntry")
            .field("selector", &self.selector)
            .field("handler", &"<dyn CaptureHandler>")
            .finish()
    }
}

type BoxedCaptureHandler<'h> = Box<dyn CaptureHandler + 'h>;

struct CaptureFn<F>(F);

impl<F> fmt::Debug for CaptureFn<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("CaptureFn").field(&"<closure>").finish()
    }
}

impl<F> CaptureHandler for CaptureFn<F>
where
    F: FnMut(CapturedValue<'_>) -> CaptureResult,
{
    fn handle_capture(&mut self, value: CapturedValue<'_>) -> CaptureResult {
        self.0(value)
    }
}

#[derive(Debug)]
struct CaptureSink<H> {
    selectors: Vec<JsonPath>,
    handler: H,
    max_capture_bytes: usize,
    stack: Vec<Frame>,
    active: Vec<ActiveCapture>,
}

impl<H: CaptureHandler> TokenSink for CaptureSink<H> {
    fn token(&mut self, token: Token<'_>) -> Result<(), JsonError> {
        match token {
            Token::ObjectKey(key) => {
                self.append_active(token.raw())?;
                let decoded = key.decode()?;
                let Some(Frame::Object { pending_key, .. }) = self.stack.last_mut() else {
                    return Err(JsonError::new(JsonErrorKind::UnexpectedToken("object key")));
                };
                *pending_key = Some(decoded.into_boxed_str());
            }
            Token::StartObject(_) | Token::StartArray(_) => {
                let path = self.current_value_path()?;
                self.append_active(token.raw())?;
                self.increment_active_depth();
                self.start_captures(&path, token.raw())?;
                match token {
                    Token::StartObject(_) => self.stack.push(Frame::Object {
                        path,
                        pending_key: None,
                    }),
                    Token::StartArray(_) => self.stack.push(Frame::Array {
                        path,
                        next_index: 0,
                    }),
                    _ => {}
                }
            }
            Token::EndObject(_) | Token::EndArray(_) => {
                self.append_active(token.raw())?;
                self.finish_active_containers()?;
                if self.stack.pop().is_none() {
                    return Err(JsonError::new(JsonErrorKind::UnexpectedToken(
                        "container end",
                    )));
                }
                self.finish_value();
            }
            Token::String(_)
            | Token::Number(_)
            | Token::True(_)
            | Token::False(_)
            | Token::Null(_) => {
                let path = self.current_value_path()?;
                self.append_active(token.raw())?;
                self.capture_scalar(&path, token.raw())?;
                self.finish_value();
            }
            Token::Whitespace(_) | Token::Colon(_) | Token::Comma(_) => {
                self.append_active(token.raw())?;
            }
        }
        Ok(())
    }
}

impl<H: CaptureHandler> CaptureSink<H> {
    fn start_captures(&mut self, path: &ValuePath, raw: &[u8]) -> Result<(), JsonError> {
        for index in 0..self.selectors.len() {
            if self.selectors[index].matches_path(path.segments()) {
                let mut captured = Vec::new();
                extend_limited(&mut captured, raw, self.max_capture_bytes)?;
                self.active.push(ActiveCapture {
                    handler: index,
                    path: path.clone(),
                    raw: captured,
                    depth: 1,
                });
            }
        }
        Ok(())
    }

    fn capture_scalar(&mut self, path: &ValuePath, raw: &[u8]) -> Result<(), JsonError> {
        for index in 0..self.selectors.len() {
            if self.selectors[index].matches_path(path.segments()) {
                if raw.len() > self.max_capture_bytes {
                    return Err(JsonError::new(JsonErrorKind::CaptureLimitExceeded(
                        self.max_capture_bytes,
                    )));
                }
                self.dispatch_capture(index, path, raw)?;
            }
        }
        Ok(())
    }

    fn finish_active_containers(&mut self) -> Result<(), JsonError> {
        let mut index = 0;
        while index < self.active.len() {
            self.active[index].depth -= 1;
            if self.active[index].depth == 0 {
                let capture = self.active.remove(index);
                self.dispatch_capture(capture.handler, &capture.path, &capture.raw)?;
            } else {
                index += 1;
            }
        }
        Ok(())
    }

    fn dispatch_capture(
        &mut self,
        handler_index: usize,
        path: &ValuePath,
        raw: &[u8],
    ) -> CaptureResult {
        self.handler.handle_capture(CapturedValue {
            path,
            json: CapturedJson { raw },
            handler_index,
        })
    }

    fn append_active(&mut self, raw: &[u8]) -> Result<(), JsonError> {
        for capture in &mut self.active {
            extend_limited(&mut capture.raw, raw, self.max_capture_bytes)?;
        }
        Ok(())
    }

    fn increment_active_depth(&mut self) {
        for capture in &mut self.active {
            capture.depth += 1;
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

    fn finish_value(&mut self) {
        match self.stack.last_mut() {
            Some(Frame::Object { pending_key, .. }) => {
                pending_key.take();
            }
            Some(Frame::Array { next_index, .. }) => {
                *next_index += 1;
            }
            None => {}
        }
    }
}

#[derive(Debug, Clone)]
struct ActiveCapture {
    handler: usize,
    path: ValuePath,
    raw: Vec<u8>,
    depth: usize,
}

#[derive(Debug, Clone)]
enum Frame {
    Object {
        path: ValuePath,
        pending_key: Option<Box<str>>,
    },
    Array {
        path: ValuePath,
        next_index: usize,
    },
}

fn extend_limited(buf: &mut Vec<u8>, raw: &[u8], limit: usize) -> Result<(), JsonError> {
    if buf.len().saturating_add(raw.len()) > limit {
        return Err(JsonError::new(JsonErrorKind::CaptureLimitExceeded(limit)));
    }
    buf.extend_from_slice(raw);
    Ok(())
}

/// Captures selected values from a complete JSON byte slice.
pub fn capture_bytes(
    input: &[u8],
    max_capture_bytes: usize,
    handlers: CaptureHandlers<'_>,
) -> Result<(), JsonError> {
    let mut capturer = JsonCapturer::from_handlers(handlers, max_capture_bytes);
    capturer.write(input)?;
    capturer.end()
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::*;

    fn path(s: &str) -> JsonPath {
        s.parse().unwrap()
    }

    #[test]
    fn captures_scalars_and_objects() {
        let hits = std::cell::RefCell::new(Vec::new());
        capture_bytes(
            br#"{"id":7,"user":{"name":"Ada","active":true}}"#,
            128,
            CaptureHandlers::new()
                .on_fn(path("$.id"), |value| {
                    hits.borrow_mut()
                        .push((value.path().to_string(), value.as_raw_bytes().to_vec()));
                    Ok(())
                })
                .on_fn(path("$.user"), |value| {
                    hits.borrow_mut()
                        .push((value.path().to_string(), value.as_raw_bytes().to_vec()));
                    Ok(())
                }),
        )
        .unwrap();
        assert_eq!(
            hits.into_inner(),
            vec![
                ("$.id".to_owned(), b"7".to_vec()),
                (
                    "$.user".to_owned(),
                    br#"{"name":"Ada","active":true}"#.to_vec()
                ),
            ]
        );
    }

    #[test]
    fn capture_value_can_be_interpreted() {
        let hits = std::cell::RefCell::new(Vec::new());
        capture_bytes(
            br#"{"items":[{"id":1},{"id":2}]}"#,
            128,
            CaptureHandlers::new().on_fn(path("$.items[1]"), |value| {
                let item: serde_json::Value = value.deserialize()?;
                hits.borrow_mut().push((
                    value.path().to_string(),
                    std::str::from_utf8(value.as_raw_bytes())
                        .unwrap()
                        .to_owned(),
                    item,
                ));
                Ok(())
            }),
        )
        .unwrap();
        assert_eq!(
            hits.into_inner(),
            vec![(
                "$.items[1]".to_owned(),
                r#"{"id":2}"#.to_owned(),
                serde_json::json!({"id": 2})
            )]
        );
    }

    #[test]
    fn capture_value_exposes_primitives() {
        capture_bytes(
            br#"{"s":"Ada","esc":"A\nB","b":true,"n":42,"f":1.5,"nil":null,"obj":{}}"#,
            128,
            CaptureHandlers::new()
                .on_fn(path("$.s"), |value| {
                    let decoded = value.as_str().unwrap();
                    assert_eq!(decoded, "Ada");
                    assert!(matches!(decoded, Cow::Borrowed("Ada")));
                    assert_eq!(value.as_bool(), None);
                    assert_eq!(value.as_i64(), None);
                    assert!(!value.is_null());
                    Ok(())
                })
                .on_fn(path("$.esc"), |value| {
                    let decoded = value.as_str().unwrap();
                    assert_eq!(decoded, "A\nB");
                    assert!(matches!(decoded, Cow::Owned(ref s) if s == "A\nB"));
                    Ok(())
                })
                .on_fn(path("$.b"), |value| {
                    assert_eq!(value.as_bool(), Some(true));
                    assert_eq!(value.as_str(), None);
                    assert_eq!(value.as_u64(), None);
                    assert!(!value.is_null());
                    Ok(())
                })
                .on_fn(path("$.n"), |value| {
                    assert_eq!(value.as_i8(), Some(42));
                    assert_eq!(value.as_i16(), Some(42));
                    assert_eq!(value.as_i32(), Some(42));
                    assert_eq!(value.as_i64(), Some(42));
                    assert_eq!(value.as_i128(), Some(42));
                    assert_eq!(value.as_isize(), Some(42));
                    assert_eq!(value.as_u8(), Some(42));
                    assert_eq!(value.as_u16(), Some(42));
                    assert_eq!(value.as_u32(), Some(42));
                    assert_eq!(value.as_u64(), Some(42));
                    assert_eq!(value.as_u128(), Some(42));
                    assert_eq!(value.as_usize(), Some(42));
                    assert_eq!(value.as_f32(), Some(42.0));
                    assert_eq!(value.as_f64(), Some(42.0));
                    assert_eq!(value.as_bool(), None);
                    Ok(())
                })
                .on_fn(path("$.f"), |value| {
                    assert_eq!(value.as_f32(), Some(1.5));
                    assert_eq!(value.as_f64(), Some(1.5));
                    assert_eq!(value.as_i64(), None);
                    Ok(())
                })
                .on_fn(path("$.nil"), |value| {
                    assert!(value.is_null());
                    assert_eq!(value.as_bool(), None);
                    assert_eq!(value.as_str(), None);
                    assert_eq!(value.as_f64(), None);
                    Ok(())
                })
                .on_fn(path("$.obj"), |value| {
                    assert!(!value.is_null());
                    assert_eq!(value.as_bool(), None);
                    assert_eq!(value.as_str(), None);
                    assert_eq!(value.as_i64(), None);
                    Ok(())
                }),
        )
        .unwrap();
    }

    #[test]
    fn captures_nested_matches() {
        let hits = std::cell::RefCell::new(Vec::new());
        capture_bytes(
            br#"{"item":{"item":1},"list":[{"item":2}]}"#,
            128,
            CaptureHandlers::new().on_fn(path("$..item"), |value| {
                hits.borrow_mut().push(value.as_raw_bytes().to_vec());
                Ok(())
            }),
        )
        .unwrap();
        assert_eq!(
            hits.into_inner(),
            vec![b"1".to_vec(), br#"{"item":1}"#.to_vec(), b"2".to_vec()]
        );
    }

    #[test]
    fn captures_across_chunks() {
        let handlers = CaptureHandlers::new().on_fn(path("$.items[1]"), |value| {
            assert_eq!(value.path().to_string(), "$.items[1]");
            assert_eq!(value.as_raw_bytes(), br#"{"id":2}"#);
            Ok(())
        });
        let mut capturer = JsonCapturer::from_handlers(handlers, 64);
        for chunk in br#"{"items":[{"id":1},{"id":2}]}"#.chunks(3) {
            capturer.write(chunk).unwrap();
        }
        capturer.end().unwrap();
    }

    #[derive(Default)]
    struct IdCollector {
        values: Vec<u64>,
    }

    impl CaptureHandler for IdCollector {
        fn handle_capture(&mut self, value: CapturedValue<'_>) -> CaptureResult {
            self.values.push(value.deserialize()?);
            Ok(())
        }
    }

    #[test]
    fn handler_trait_can_keep_state() {
        let selectors = [path("$..id")];
        let mut capturer = JsonCapturer::new(&selectors, 16, IdCollector::default());
        capturer.write(br#"{"items":[{"id":1},{"id":2}]}"#).unwrap();
        capturer.end().unwrap();
        assert_eq!(capturer.into_handler().values, vec![1, 2]);
    }

    #[test]
    fn bundled_handlers_accept_trait_impls() {
        #[derive(Clone)]
        struct SharedCollector {
            values: std::rc::Rc<std::cell::RefCell<Vec<u64>>>,
        }

        impl CaptureHandler for SharedCollector {
            fn handle_capture(&mut self, value: CapturedValue<'_>) -> CaptureResult {
                self.values.borrow_mut().push(value.deserialize()?);
                Ok(())
            }
        }

        let values = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let handlers = CaptureHandlers::new().on(
            path("$..id"),
            SharedCollector {
                values: values.clone(),
            },
        );
        let mut capturer = JsonCapturer::from_handlers(handlers, 16);
        capturer.write(br#"{"items":[{"id":1},{"id":2}]}"#).unwrap();
        capturer.end().unwrap();
        assert_eq!(*values.borrow(), vec![1, 2]);
    }

    #[test]
    fn rejects_values_over_capture_limit() {
        let err = capture_bytes(
            br#"{"item":{"name":"too big"}}"#,
            8,
            CaptureHandlers::new().on_fn(path("$.item"), |_| Ok(())),
        )
        .unwrap_err();
        assert_eq!(err.kind(), &JsonErrorKind::CaptureLimitExceeded(8));
    }

    #[test]
    fn rejects_input_that_exceeds_buffered_limit() {
        let selectors = [path("$.name")];
        let mut capturer =
            JsonCapturer::with_max_buffered_bytes(&selectors, 128, 8, CaptureHandlers::new());
        capturer.write(br#"{"name":"#).unwrap();
        let err = capturer.write(br#""unterminated"#).unwrap_err();
        assert_eq!(err.kind(), &JsonErrorKind::InputBufferLimitExceeded(8));
    }
}
