//! Streaming JSON value capture.
//!
//! Capturing is intended for small selected values that a caller wants to
//! inspect or deserialize as a whole. Non-matching input is still processed as a
//! stream, while matching object and array subtrees are bounded by
//! `max_capture_bytes`.

use crate::path::{JsonPath, PathElement};
use crate::select::ValuePath;
use crate::tokenizer::{Token, TokenSink, Tokenizer, tokenize};
use crate::{JsonError, JsonErrorKind};

/// Result returned by JSON capture handlers.
pub type CaptureResult = Result<(), JsonError>;

/// Handles one selected JSON value captured as raw JSON bytes.
pub trait JsonCaptureHandler {
    /// Handles a selected value.
    ///
    /// `selector` is the index of the matching selector in registration order.
    fn handle_capture(&mut self, selector: usize, path: &ValuePath, raw: &[u8]) -> CaptureResult;
}

/// Streaming JSON capturer for selected values.
pub struct JsonCapturer<H> {
    tokenizer: Tokenizer,
    sink: CaptureSink<H>,
}

impl<H: JsonCaptureHandler> JsonCapturer<H> {
    /// Creates a JSON capturer.
    #[must_use]
    pub fn new(selectors: &[JsonPath], max_capture_bytes: usize, handler: H) -> Self {
        Self {
            tokenizer: Tokenizer::new(),
            sink: CaptureSink {
                selectors: selectors.to_vec(),
                handler,
                max_capture_bytes,
                stack: Vec::new(),
                active: Vec::new(),
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

    /// Consumes the capturer and returns the handler.
    #[must_use]
    pub fn into_handler(self) -> H {
        self.sink.handler
    }
}

impl<'h> JsonCapturer<JsonCaptureHandlers<'h>> {
    /// Creates a capturer from closure-based handlers.
    #[must_use]
    pub fn from_handlers(max_capture_bytes: usize, handlers: JsonCaptureHandlers<'h>) -> Self {
        let selectors = handlers.selectors.clone();
        Self::new(&selectors, max_capture_bytes, handlers)
    }
}

/// Closure-based capture handler builder.
#[derive(Default)]
pub struct JsonCaptureHandlers<'h> {
    selectors: Vec<JsonPath>,
    handlers: Vec<BoxedCaptureHandler<'h>>,
}

impl<'h> JsonCaptureHandlers<'h> {
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
        handler: impl FnMut(&ValuePath, &[u8]) -> CaptureResult + 'h,
    ) -> Self {
        self.selectors.push(selector);
        self.handlers.push(Box::new(handler));
        self
    }
}

impl JsonCaptureHandler for JsonCaptureHandlers<'_> {
    fn handle_capture(&mut self, selector: usize, path: &ValuePath, raw: &[u8]) -> CaptureResult {
        match self.handlers.get_mut(selector) {
            Some(handler) => handler(path, raw),
            None => Ok(()),
        }
    }
}

type BoxedCaptureHandler<'h> = Box<dyn FnMut(&ValuePath, &[u8]) -> CaptureResult + 'h>;

impl<F> JsonCaptureHandler for F
where
    F: FnMut(usize, &ValuePath, &[u8]) -> CaptureResult,
{
    fn handle_capture(&mut self, selector: usize, path: &ValuePath, raw: &[u8]) -> CaptureResult {
        self(selector, path, raw)
    }
}

struct CaptureSink<H> {
    selectors: Vec<JsonPath>,
    handler: H,
    max_capture_bytes: usize,
    stack: Vec<Frame>,
    active: Vec<ActiveCapture>,
}

impl<H: JsonCaptureHandler> TokenSink for CaptureSink<H> {
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

impl<H: JsonCaptureHandler> CaptureSink<H> {
    fn start_captures(&mut self, path: &ValuePath, raw: &[u8]) -> Result<(), JsonError> {
        for selector in 0..self.selectors.len() {
            if self.selectors[selector].matches_path(path.segments()) {
                let mut captured = Vec::new();
                extend_limited(&mut captured, raw, self.max_capture_bytes)?;
                self.active.push(ActiveCapture {
                    selector,
                    path: path.clone(),
                    raw: captured,
                    depth: 1,
                });
            }
        }
        Ok(())
    }

    fn capture_scalar(&mut self, path: &ValuePath, raw: &[u8]) -> Result<(), JsonError> {
        for selector in 0..self.selectors.len() {
            if self.selectors[selector].matches_path(path.segments()) {
                if raw.len() > self.max_capture_bytes {
                    return Err(JsonError::new(JsonErrorKind::CaptureLimitExceeded(
                        self.max_capture_bytes,
                    )));
                }
                self.handler.handle_capture(selector, path, raw)?;
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
                self.handler
                    .handle_capture(capture.selector, &capture.path, &capture.raw)?;
            } else {
                index += 1;
            }
        }
        Ok(())
    }
}

impl<H> CaptureSink<H> {
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
    selector: usize,
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
    handlers: JsonCaptureHandlers<'_>,
) -> Result<(), JsonError> {
    let mut capturer = JsonCapturer::from_handlers(max_capture_bytes, handlers);
    capturer.write(input)?;
    capturer.end()
}

/// Captures selected values from a complete JSON byte slice with a custom
/// handler.
pub fn capture_bytes_with<H: JsonCaptureHandler>(
    input: &[u8],
    selectors: &[JsonPath],
    max_capture_bytes: usize,
    handler: H,
) -> Result<H, JsonError> {
    let mut sink = CaptureSink {
        selectors: selectors.to_vec(),
        handler,
        max_capture_bytes,
        stack: Vec::new(),
        active: Vec::new(),
    };
    tokenize(input, &mut sink)?;
    Ok(sink.handler)
}

#[cfg(test)]
mod tests {
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
            JsonCaptureHandlers::new()
                .on(path("$.id"), |path, raw| {
                    hits.borrow_mut().push((path.to_string(), raw.to_vec()));
                    Ok(())
                })
                .on(path("$.user"), |path, raw| {
                    hits.borrow_mut().push((path.to_string(), raw.to_vec()));
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
    fn captures_nested_matches() {
        let selectors = [path("$..item")];
        let hits = capture_bytes_with(
            br#"{"item":{"item":1},"list":[{"item":2}]}"#,
            &selectors,
            128,
            Vec::<Vec<u8>>::new(),
        )
        .unwrap();
        assert_eq!(
            hits,
            vec![b"1".to_vec(), br#"{"item":1}"#.to_vec(), b"2".to_vec()]
        );
    }

    #[test]
    fn captures_across_chunks() {
        let selectors = [path("$.items[1]")];
        let mut capturer =
            JsonCapturer::new(&selectors, 64, |_: usize, path: &ValuePath, raw: &[u8]| {
                assert_eq!(path.to_string(), "$.items[1]");
                assert_eq!(raw, br#"{"id":2}"#);
                Ok(())
            });
        for chunk in br#"{"items":[{"id":1},{"id":2}]}"#.chunks(3) {
            capturer.write(chunk).unwrap();
        }
        capturer.end().unwrap();
    }

    #[test]
    fn rejects_values_over_capture_limit() {
        let err = capture_bytes(
            br#"{"item":{"name":"too big"}}"#,
            8,
            JsonCaptureHandlers::new().on(path("$.item"), |_, _| Ok(())),
        )
        .unwrap_err();
        assert_eq!(err.kind(), &JsonErrorKind::CaptureLimitExceeded(8));
    }

    impl JsonCaptureHandler for Vec<Vec<u8>> {
        fn handle_capture(&mut self, _: usize, _: &ValuePath, raw: &[u8]) -> CaptureResult {
            self.push(raw.to_vec());
            Ok(())
        }
    }
}
