//! Strict incremental JSON tokenizer.
//!
//! The tokenizer accepts byte chunks through [`Tokenizer::write`] and emits
//! borrowed [`Token`] views into the buffered input. Whitespace and punctuation
//! are emitted as tokens too so an identity sink can reproduce the original
//! byte stream exactly.
//!
//! The shape follows JSON's small grammar, shown here in an ASCII form inspired
//! by the diagrams at <https://www.json.org/json-en.html>:
//!
//! ```text
//! json
//!   -> ws value ws
//!
//! value
//!   -> object
//!   -> array
//!   -> string
//!   -> number
//!   -> "true"
//!   -> "false"
//!   -> "null"
//!
//! object
//!   -> "{" ws "}"
//!   -> "{" members "}"
//!
//! members
//!   -> member
//!   -> member "," members
//!
//! member
//!   -> ws string ws ":" element
//!
//! array
//!   -> "[" ws "]"
//!   -> "[" elements "]"
//!
//! elements
//!   -> element
//!   -> element "," elements
//!
//! element
//!   -> ws value ws
//! ```

use std::borrow::Cow;

use rama_utils::octets::mib;

use crate::{JsonError, JsonErrorKind};

/// Default maximum buffered JSON input before tokenization must make progress.
///
/// This bounds a single incomplete token, plus any surrounding bytes that have
/// not yet been emitted. Callers that accept very large scalar values can raise
/// the limit explicitly.
pub const DEFAULT_MAX_BUFFERED_BYTES: usize = mib(8);

/// Consumes JSON tokens emitted by [`Tokenizer`].
pub trait TokenSink {
    /// Handles one token.
    ///
    /// Returning an error aborts tokenization and surfaces the error from
    /// [`Tokenizer::write`] or [`Tokenizer::end`].
    fn token(&mut self, token: Token<'_>) -> Result<(), JsonError>;
}

/// A borrowed JSON token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Token<'a> {
    /// One or more JSON whitespace bytes.
    Whitespace(&'a [u8]),
    /// `{`.
    StartObject(&'a [u8]),
    /// `}`.
    EndObject(&'a [u8]),
    /// `[`.
    StartArray(&'a [u8]),
    /// `]`.
    EndArray(&'a [u8]),
    /// `:`.
    Colon(&'a [u8]),
    /// `,`.
    Comma(&'a [u8]),
    /// An object member name, including surrounding quotes in [`Self::raw`].
    ObjectKey(JsonString<'a>),
    /// A string value, including surrounding quotes in [`Self::raw`].
    String(JsonString<'a>),
    /// A JSON number.
    Number(JsonNumber<'a>),
    /// `true`.
    True(&'a [u8]),
    /// `false`.
    False(&'a [u8]),
    /// `null`.
    Null(&'a [u8]),
}

impl<'a> Token<'a> {
    /// Raw source bytes for this token.
    #[must_use]
    pub const fn raw(self) -> &'a [u8] {
        match self {
            Self::Whitespace(raw)
            | Self::StartObject(raw)
            | Self::EndObject(raw)
            | Self::StartArray(raw)
            | Self::EndArray(raw)
            | Self::Colon(raw)
            | Self::Comma(raw)
            | Self::True(raw)
            | Self::False(raw)
            | Self::Null(raw) => raw,
            Self::ObjectKey(s) | Self::String(s) => s.raw(),
            Self::Number(n) => n.raw(),
        }
    }
}

/// Borrowed JSON string token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonString<'a> {
    raw: &'a [u8],
}

impl<'a> JsonString<'a> {
    /// Raw source bytes including the surrounding quotes.
    #[must_use]
    pub const fn raw(self) -> &'a [u8] {
        self.raw
    }

    /// String body bytes excluding the surrounding quotes.
    #[must_use]
    pub fn body(self) -> &'a [u8] {
        self.raw
            .get(1..self.raw.len().saturating_sub(1))
            .unwrap_or(b"")
    }

    /// Decodes this JSON string.
    ///
    /// Unescaped strings borrow from the source. Escaped strings are decoded
    /// into an owned string.
    #[must_use]
    pub fn as_str(self) -> Option<Cow<'a, str>> {
        match self.body() {
            body if !body.contains(&b'\\') => std::str::from_utf8(body).map(Cow::Borrowed).ok(),
            _ => self.decode().map(Cow::Owned).ok(),
        }
    }

    /// Decodes this JSON string into an owned Rust [`String`].
    ///
    /// This is intentionally explicit: most tokenizer consumers can keep using
    /// [`raw`](Self::raw), [`body`](Self::body), or [`as_str`](Self::as_str)
    /// and avoid allocation.
    pub fn decode(self) -> Result<String, JsonError> {
        serde_json::from_slice(self.raw).map_err(|_err| JsonError::new(JsonErrorKind::InvalidUtf8))
    }
}

/// Borrowed JSON number token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonNumber<'a> {
    raw: &'a [u8],
}

impl<'a> JsonNumber<'a> {
    /// Raw source bytes for the number.
    #[must_use]
    pub const fn raw(self) -> &'a [u8] {
        self.raw
    }
}

/// Incremental strict JSON tokenizer.
#[derive(Debug)]
pub struct Tokenizer {
    buf: Vec<u8>,
    max_buffered_bytes: usize,
    absolute: usize,
    stack: Vec<Frame>,
    top: TopState,
    ended: bool,
}

impl Tokenizer {
    /// Creates an empty tokenizer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            max_buffered_bytes: DEFAULT_MAX_BUFFERED_BYTES,
            absolute: 0,
            stack: Vec::new(),
            top: TopState::Value,
            ended: false,
        }
    }

    /// Creates an empty tokenizer with a custom buffered-input limit.
    #[must_use]
    pub fn with_max_buffered_bytes(max_buffered_bytes: usize) -> Self {
        Self {
            max_buffered_bytes,
            ..Self::new()
        }
    }

    /// Returns the configured buffered-input limit.
    #[must_use]
    pub const fn max_buffered_bytes(&self) -> usize {
        self.max_buffered_bytes
    }

    /// Sets the buffered-input limit.
    pub fn set_max_buffered_bytes(&mut self, max_buffered_bytes: usize) {
        self.max_buffered_bytes = max_buffered_bytes;
    }

    /// Feeds a chunk into the tokenizer.
    ///
    /// Complete tokens are emitted to `sink`; an incomplete final token is kept
    /// until a later [`write`](Self::write) or [`end`](Self::end).
    pub fn write(&mut self, chunk: &[u8], sink: &mut impl TokenSink) -> Result<(), JsonError> {
        if self.ended {
            return Err(JsonError::at(
                JsonErrorKind::UnexpectedToken("write after end"),
                self.absolute + self.buf.len(),
            ));
        }
        let mut chunk = chunk;
        while !chunk.is_empty() {
            let available = self.max_buffered_bytes.saturating_sub(self.buf.len());
            if available == 0 {
                self.parse_available(false, sink)?;
                if self.buf.len() >= self.max_buffered_bytes {
                    return Err(JsonError::at(
                        JsonErrorKind::InputBufferLimitExceeded(self.max_buffered_bytes),
                        self.absolute + self.buf.len(),
                    ));
                }
                continue;
            }

            let len = chunk.len().min(available);
            self.buf.extend_from_slice(&chunk[..len]);
            chunk = &chunk[len..];
            self.parse_available(false, sink)?;
        }
        Ok(())
    }

    /// Finalizes the tokenizer.
    pub fn end(&mut self, sink: &mut impl TokenSink) -> Result<(), JsonError> {
        self.ended = true;
        self.parse_available(true, sink)?;
        if !self.buf.is_empty() {
            return Err(JsonError::at(JsonErrorKind::UnexpectedEnd, self.absolute));
        }
        if !self.stack.is_empty() || self.top != TopState::Done {
            return Err(JsonError::at(JsonErrorKind::UnexpectedEnd, self.absolute));
        }
        Ok(())
    }

    fn parse_available(
        &mut self,
        final_input: bool,
        sink: &mut impl TokenSink,
    ) -> Result<(), JsonError> {
        let mut pos = 0;

        while pos < self.buf.len() {
            let b = self.buf[pos];
            let offset = self.absolute + pos;
            let parsed = match b {
                b' ' | b'\n' | b'\r' | b'\t' => {
                    let len = scan_ws(&self.buf[pos..]);
                    let raw = &self.buf[pos..pos + len];
                    sink.token(Token::Whitespace(raw))?;
                    Parsed::Complete(len)
                }
                b'{' => {
                    self.start_container(offset)?;
                    sink.token(Token::StartObject(&self.buf[pos..pos + 1]))?;
                    self.stack.push(Frame::Object(ObjectState::KeyOrEnd));
                    Parsed::Complete(1)
                }
                b'}' => {
                    self.end_object(offset)?;
                    sink.token(Token::EndObject(&self.buf[pos..pos + 1]))?;
                    Parsed::Complete(1)
                }
                b'[' => {
                    self.start_container(offset)?;
                    sink.token(Token::StartArray(&self.buf[pos..pos + 1]))?;
                    self.stack.push(Frame::Array(ArrayState::ValueOrEnd));
                    Parsed::Complete(1)
                }
                b']' => {
                    self.end_array(offset)?;
                    sink.token(Token::EndArray(&self.buf[pos..pos + 1]))?;
                    Parsed::Complete(1)
                }
                b':' => {
                    self.colon(offset)?;
                    sink.token(Token::Colon(&self.buf[pos..pos + 1]))?;
                    Parsed::Complete(1)
                }
                b',' => {
                    self.comma(offset)?;
                    sink.token(Token::Comma(&self.buf[pos..pos + 1]))?;
                    Parsed::Complete(1)
                }
                b'"' => match scan_string(&self.buf[pos..], final_input) {
                    Scan::Complete(len) => {
                        if self.object_expects_key() {
                            self.object_key(offset)?;
                            let raw = &self.buf[pos..pos + len];
                            sink.token(Token::ObjectKey(JsonString { raw }))?;
                        } else {
                            self.scalar_value("string", offset)?;
                            let raw = &self.buf[pos..pos + len];
                            sink.token(Token::String(JsonString { raw }))?;
                        }
                        Parsed::Complete(len)
                    }
                    Scan::Incomplete => Parsed::Incomplete,
                    Scan::Invalid(kind, at) => {
                        return Err(JsonError::at(kind, offset + at));
                    }
                },
                b'-' | b'0'..=b'9' => match scan_number(&self.buf[pos..], final_input) {
                    Scan::Complete(len) => {
                        self.scalar_value("number", offset)?;
                        sink.token(Token::Number(JsonNumber {
                            raw: &self.buf[pos..pos + len],
                        }))?;
                        Parsed::Complete(len)
                    }
                    Scan::Incomplete => Parsed::Incomplete,
                    Scan::Invalid(kind, at) => {
                        return Err(JsonError::at(kind, offset + at));
                    }
                },
                b't' => self.literal(pos, b"true", LiteralKind::True, final_input, sink)?,
                b'f' => self.literal(pos, b"false", LiteralKind::False, final_input, sink)?,
                b'n' => self.literal(pos, b"null", LiteralKind::Null, final_input, sink)?,
                other => {
                    return Err(JsonError::at(JsonErrorKind::UnexpectedByte(other), offset));
                }
            };

            match parsed {
                Parsed::Complete(len) => pos += len,
                Parsed::Incomplete => break,
            }
        }

        if pos > 0 {
            self.buf.drain(..pos);
            self.absolute += pos;
        }
        Ok(())
    }

    fn literal(
        &mut self,
        pos: usize,
        lit: &'static [u8],
        kind: LiteralKind,
        final_input: bool,
        sink: &mut impl TokenSink,
    ) -> Result<Parsed, JsonError> {
        let offset = self.absolute + pos;
        if self.buf.len() - pos < lit.len() {
            if final_input || !lit.starts_with(&self.buf[pos..]) {
                return Err(JsonError::at(
                    JsonErrorKind::UnexpectedByte(self.buf[pos]),
                    offset,
                ));
            }
            return Ok(Parsed::Incomplete);
        }
        if &self.buf[pos..pos + lit.len()] != lit {
            return Err(JsonError::at(
                JsonErrorKind::UnexpectedByte(self.buf[pos]),
                offset,
            ));
        }
        self.scalar_value(std::str::from_utf8(lit).unwrap_or("literal"), offset)?;
        let raw = &self.buf[pos..pos + lit.len()];
        let token = match kind {
            LiteralKind::True => Token::True(raw),
            LiteralKind::False => Token::False(raw),
            LiteralKind::Null => Token::Null(raw),
        };
        sink.token(token)?;
        Ok(Parsed::Complete(lit.len()))
    }

    fn object_expects_key(&self) -> bool {
        matches!(
            self.stack.last(),
            Some(Frame::Object(ObjectState::KeyOrEnd | ObjectState::Key))
        )
    }

    fn start_container(&self, offset: usize) -> Result<(), JsonError> {
        self.expect_value("container", offset)
    }

    fn scalar_value(&mut self, token: &'static str, offset: usize) -> Result<(), JsonError> {
        self.expect_value(token, offset)?;
        self.finish_value(offset)
    }

    fn expect_value(&self, token: &'static str, offset: usize) -> Result<(), JsonError> {
        match self.stack.last() {
            Some(
                Frame::Object(ObjectState::Value)
                | Frame::Array(ArrayState::ValueOrEnd | ArrayState::Value),
            ) => Ok(()),
            Some(Frame::Object(_) | Frame::Array(_)) => {
                Err(JsonError::at(JsonErrorKind::UnexpectedToken(token), offset))
            }
            None if self.top == TopState::Value => Ok(()),
            None if self.top == TopState::Done => {
                Err(JsonError::at(JsonErrorKind::TrailingValue, offset))
            }
            None => Err(JsonError::at(JsonErrorKind::UnexpectedToken(token), offset)),
        }
    }

    fn finish_value(&mut self, offset: usize) -> Result<(), JsonError> {
        match self.stack.last_mut() {
            Some(Frame::Object(state @ ObjectState::Value)) => {
                *state = ObjectState::CommaOrEnd;
                Ok(())
            }
            Some(Frame::Array(state @ (ArrayState::ValueOrEnd | ArrayState::Value))) => {
                *state = ArrayState::CommaOrEnd;
                Ok(())
            }
            Some(_) => Err(JsonError::at(
                JsonErrorKind::UnexpectedToken("value"),
                offset,
            )),
            None if self.top == TopState::Value => {
                self.top = TopState::Done;
                Ok(())
            }
            None => Err(JsonError::at(JsonErrorKind::TrailingValue, offset)),
        }
    }

    fn object_key(&mut self, offset: usize) -> Result<(), JsonError> {
        match self.stack.last_mut() {
            Some(Frame::Object(state @ (ObjectState::KeyOrEnd | ObjectState::Key))) => {
                *state = ObjectState::Colon;
                Ok(())
            }
            _ => Err(JsonError::at(
                JsonErrorKind::UnexpectedToken("object key"),
                offset,
            )),
        }
    }

    fn colon(&mut self, offset: usize) -> Result<(), JsonError> {
        match self.stack.last_mut() {
            Some(Frame::Object(state @ ObjectState::Colon)) => {
                *state = ObjectState::Value;
                Ok(())
            }
            _ => Err(JsonError::at(JsonErrorKind::UnexpectedToken(":"), offset)),
        }
    }

    fn comma(&mut self, offset: usize) -> Result<(), JsonError> {
        match self.stack.last_mut() {
            Some(Frame::Object(state @ ObjectState::CommaOrEnd)) => {
                *state = ObjectState::Key;
                Ok(())
            }
            Some(Frame::Array(state @ ArrayState::CommaOrEnd)) => {
                *state = ArrayState::Value;
                Ok(())
            }
            _ => Err(JsonError::at(JsonErrorKind::UnexpectedToken(","), offset)),
        }
    }

    fn end_object(&mut self, offset: usize) -> Result<(), JsonError> {
        match self.stack.last() {
            Some(Frame::Object(ObjectState::KeyOrEnd | ObjectState::CommaOrEnd)) => {
                self.stack.pop();
                self.finish_value(offset)
            }
            Some(Frame::Object(_)) => {
                Err(JsonError::at(JsonErrorKind::UnexpectedToken("}"), offset))
            }
            _ => Err(JsonError::at(JsonErrorKind::UnexpectedToken("}"), offset)),
        }
    }

    fn end_array(&mut self, offset: usize) -> Result<(), JsonError> {
        match self.stack.last() {
            Some(Frame::Array(ArrayState::ValueOrEnd | ArrayState::CommaOrEnd)) => {
                self.stack.pop();
                self.finish_value(offset)
            }
            Some(Frame::Array(_)) => {
                Err(JsonError::at(JsonErrorKind::UnexpectedToken("]"), offset))
            }
            _ => Err(JsonError::at(JsonErrorKind::UnexpectedToken("]"), offset)),
        }
    }
}

impl Default for Tokenizer {
    fn default() -> Self {
        Self::new()
    }
}

/// Tokenizes a complete byte slice.
pub fn tokenize(input: &[u8], sink: &mut impl TokenSink) -> Result<(), JsonError> {
    let mut tokenizer = Tokenizer::new();
    tokenizer.write(input, sink)?;
    tokenizer.end(sink)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum TopState {
    #[default]
    Value,
    Done,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Frame {
    Object(ObjectState),
    Array(ArrayState),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObjectState {
    KeyOrEnd,
    Key,
    Colon,
    Value,
    CommaOrEnd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArrayState {
    ValueOrEnd,
    Value,
    CommaOrEnd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Parsed {
    Complete(usize),
    Incomplete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Scan {
    Complete(usize),
    Incomplete,
    Invalid(JsonErrorKind, usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LiteralKind {
    True,
    False,
    Null,
}

fn scan_ws(input: &[u8]) -> usize {
    input
        .iter()
        .position(|b| !matches!(b, b' ' | b'\n' | b'\r' | b'\t'))
        .unwrap_or(input.len())
}

fn scan_string(input: &[u8], final_input: bool) -> Scan {
    let mut i = 1;
    while i < input.len() {
        match input[i] {
            b'"' => {
                let raw = &input[..=i];
                if std::str::from_utf8(raw).is_err() {
                    return Scan::Invalid(JsonErrorKind::InvalidUtf8, 0);
                }
                return Scan::Complete(i + 1);
            }
            b'\\' => {
                i += 1;
                if i >= input.len() {
                    return if final_input {
                        Scan::Invalid(JsonErrorKind::UnexpectedEnd, i)
                    } else {
                        Scan::Incomplete
                    };
                }
                match input[i] {
                    b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => i += 1,
                    b'u' => {
                        if input.len() < i + 5 {
                            return if final_input {
                                Scan::Invalid(JsonErrorKind::UnexpectedEnd, input.len())
                            } else {
                                Scan::Incomplete
                            };
                        }
                        if input[i + 1..i + 5].iter().all(u8::is_ascii_hexdigit) {
                            i += 5;
                        } else {
                            return Scan::Invalid(JsonErrorKind::InvalidEscape, i);
                        }
                    }
                    _ => return Scan::Invalid(JsonErrorKind::InvalidEscape, i),
                }
            }
            b if b < 0x20 => return Scan::Invalid(JsonErrorKind::ControlCharacterInString, i),
            _ => i += 1,
        }
    }

    if final_input {
        Scan::Invalid(JsonErrorKind::UnexpectedEnd, input.len())
    } else {
        Scan::Incomplete
    }
}

fn scan_number(input: &[u8], final_input: bool) -> Scan {
    let mut i = 0;
    if input.get(i) == Some(&b'-') {
        i += 1;
        if i == input.len() {
            return incomplete_or_invalid(final_input, i);
        }
    }

    match input.get(i).copied() {
        Some(b'0') => {
            i += 1;
            if matches!(input.get(i), Some(b'0'..=b'9')) {
                return Scan::Invalid(JsonErrorKind::InvalidNumber, i);
            }
        }
        Some(b'1'..=b'9') => {
            i += 1;
            while matches!(input.get(i), Some(b'0'..=b'9')) {
                i += 1;
            }
        }
        _ => return Scan::Invalid(JsonErrorKind::InvalidNumber, i),
    }

    if input.get(i) == Some(&b'.') {
        i += 1;
        let start = i;
        while matches!(input.get(i), Some(b'0'..=b'9')) {
            i += 1;
        }
        if i == start {
            return incomplete_or_invalid(final_input, i);
        }
    }

    if matches!(input.get(i), Some(b'e' | b'E')) {
        i += 1;
        if matches!(input.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        let start = i;
        while matches!(input.get(i), Some(b'0'..=b'9')) {
            i += 1;
        }
        if i == start {
            return incomplete_or_invalid(final_input, i);
        }
    }

    match input.get(i).copied() {
        None if final_input => Scan::Complete(i),
        None => Scan::Incomplete,
        Some(b) if is_value_delimiter(b) => Scan::Complete(i),
        Some(_) => Scan::Invalid(JsonErrorKind::InvalidNumber, i),
    }
}

fn incomplete_or_invalid(final_input: bool, offset: usize) -> Scan {
    if final_input {
        Scan::Invalid(JsonErrorKind::InvalidNumber, offset)
    } else {
        Scan::Incomplete
    }
}

fn is_value_delimiter(b: u8) -> bool {
    matches!(b, b' ' | b'\n' | b'\r' | b'\t' | b',' | b']' | b'}')
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::*;

    #[derive(Debug, Default)]
    struct RawSink {
        out: Vec<u8>,
        names: Vec<&'static str>,
    }

    impl TokenSink for RawSink {
        fn token(&mut self, token: Token<'_>) -> Result<(), JsonError> {
            self.out.extend_from_slice(token.raw());
            self.names.push(match token {
                Token::Whitespace(_) => "ws",
                Token::StartObject(_) => "{",
                Token::EndObject(_) => "}",
                Token::StartArray(_) => "[",
                Token::EndArray(_) => "]",
                Token::Colon(_) => ":",
                Token::Comma(_) => ",",
                Token::ObjectKey(_) => "key",
                Token::String(_) => "string",
                Token::Number(_) => "number",
                Token::True(_) => "true",
                Token::False(_) => "false",
                Token::Null(_) => "null",
            });
            Ok(())
        }
    }

    fn tokenize_raw(input: &[u8]) -> Result<RawSink, JsonError> {
        let mut sink = RawSink::default();
        tokenize(input, &mut sink)?;
        Ok(sink)
    }

    #[test]
    fn identity_tokenization() {
        let input = br#" { "a": [1, true, null, "x\u0041"], "b": -12.3e+4 } "#;
        let sink = tokenize_raw(input).unwrap();
        assert_eq!(sink.out, input);
        assert!(sink.names.contains(&"key"));
        assert!(sink.names.contains(&"number"));
    }

    #[test]
    fn coalesces_adjacent_whitespace_into_one_token() {
        let sink = tokenize_raw(b"  \n\ttrue").unwrap();
        assert_eq!(sink.names, vec!["ws", "true"]);
    }

    #[test]
    fn supports_chunk_boundaries_inside_tokens() {
        let input = br#"{"key":"value","n":12345}"#;
        let mut tokenizer = Tokenizer::new();
        let mut sink = RawSink::default();
        for chunk in input.chunks(1) {
            tokenizer.write(chunk, &mut sink).unwrap();
        }
        tokenizer.end(&mut sink).unwrap();
        assert_eq!(sink.out, input);
    }

    #[test]
    fn buffered_limit_can_be_configured() {
        let mut tokenizer = Tokenizer::new();
        assert_eq!(tokenizer.max_buffered_bytes(), DEFAULT_MAX_BUFFERED_BYTES);
        tokenizer.set_max_buffered_bytes(4);
        assert_eq!(tokenizer.max_buffered_bytes(), 4);
    }

    #[test]
    fn limits_buffered_incomplete_tokens() {
        let mut tokenizer = Tokenizer::with_max_buffered_bytes(4);
        let mut sink = RawSink::default();
        tokenizer.write(br#""abc"#, &mut sink).unwrap();
        let err = tokenizer.write(b"d", &mut sink).unwrap_err();
        assert_eq!(err.kind(), &JsonErrorKind::InputBufferLimitExceeded(4));
        assert_eq!(err.offset(), Some(4));
    }

    #[test]
    fn limit_allows_large_chunks_when_tokens_make_progress() {
        let mut tokenizer = Tokenizer::with_max_buffered_bytes(4);
        let mut sink = RawSink::default();
        tokenizer.write(b"[1,2,3,4]", &mut sink).unwrap();
        tokenizer.end(&mut sink).unwrap();
        assert_eq!(sink.out, b"[1,2,3,4]");
    }

    #[test]
    fn write_after_end_reports_absolute_offset() {
        let mut tokenizer = Tokenizer::new();
        let mut sink = RawSink::default();
        tokenizer.write(b"true", &mut sink).unwrap();
        tokenizer.end(&mut sink).unwrap();
        let err = tokenizer.write(b"false", &mut sink).unwrap_err();
        assert_eq!(
            err.kind(),
            &JsonErrorKind::UnexpectedToken("write after end")
        );
        assert_eq!(err.offset(), Some(4));
    }

    #[test]
    fn write_after_failed_end_reports_buffered_offset() {
        let mut tokenizer = Tokenizer::new();
        let mut sink = RawSink::default();
        tokenizer.write(br#""abc"#, &mut sink).unwrap();
        let err = tokenizer.end(&mut sink).unwrap_err();
        assert_eq!(err.kind(), &JsonErrorKind::UnexpectedEnd);

        let err = tokenizer.write(b"\"", &mut sink).unwrap_err();
        assert_eq!(
            err.kind(),
            &JsonErrorKind::UnexpectedToken("write after end")
        );
        assert_eq!(err.offset(), Some(4));
    }

    #[test]
    fn string_decode_borrows_when_possible() {
        #[derive(Default)]
        struct StringSink {
            values: Vec<(String, bool)>,
        }

        impl TokenSink for StringSink {
            fn token(&mut self, token: Token<'_>) -> Result<(), JsonError> {
                if let Token::String(s) = token {
                    let decoded = s.as_str().unwrap();
                    let borrowed = matches!(decoded, Cow::Borrowed(_));
                    self.values.push((decoded.into_owned(), borrowed));
                }
                Ok(())
            }
        }

        let mut sink = StringSink::default();
        tokenize(br#"["plain","A\nB"]"#, &mut sink).unwrap();
        assert_eq!(
            sink.values,
            vec![("plain".to_owned(), true), ("A\nB".to_owned(), false)]
        );
    }

    #[test]
    fn rejects_invalid_inputs() {
        let cases: &[(&[u8], JsonErrorKind)] = &[
            (b"true false", JsonErrorKind::TrailingValue),
            (b"true {}", JsonErrorKind::TrailingValue),
            (b"01", JsonErrorKind::InvalidNumber),
            (b"tru", JsonErrorKind::UnexpectedByte(b't')),
            (br#""\x""#, JsonErrorKind::InvalidEscape),
            (br#"{"a" {}}"#, JsonErrorKind::UnexpectedToken("container")),
        ];

        for (input, expected) in cases {
            let err = tokenize_raw(input).unwrap_err();
            assert_eq!(err.kind(), expected, "input {input:?}");
        }

        let err = tokenize_raw(br#"{"a":1,}"#).unwrap_err();
        assert!(
            matches!(
                err.kind(),
                JsonErrorKind::UnexpectedToken("object key" | "}")
            ),
            "input {:?}",
            br#"{"a":1,}"#
        );
    }

    #[test]
    fn reports_offsets_after_leading_whitespace() {
        let cases: &[(&[u8], JsonErrorKind, usize)] = &[
            (br#" "\x""#, JsonErrorKind::InvalidEscape, 3),
            (b"  01", JsonErrorKind::InvalidNumber, 3),
            (b" truX", JsonErrorKind::UnexpectedByte(b't'), 1),
        ];

        for (input, expected_kind, expected_offset) in cases {
            let err = tokenize_raw(input).unwrap_err();
            assert_eq!(err.kind(), expected_kind, "input {input:?}");
            assert_eq!(err.offset(), Some(*expected_offset), "input {input:?}");
        }
    }

    #[test]
    fn rejects_empty_input() {
        let err = tokenize_raw(b"").unwrap_err();
        assert_eq!(err.kind(), &JsonErrorKind::UnexpectedEnd);
        assert_eq!(err.offset(), Some(0));
    }

    #[test]
    fn trailing_values_do_not_emit_extra_tokens() {
        let cases: &[(&[u8], &[u8])] = &[
            (b"true false", b"true "),
            (b"true {}", b"true "),
            (b"{} {}", b"{} "),
        ];

        for (input, expected_output) in cases {
            let mut tokenizer = Tokenizer::new();
            let mut sink = RawSink::default();
            let err = tokenizer.write(input, &mut sink).unwrap_err();
            assert_eq!(err.kind(), &JsonErrorKind::TrailingValue, "input {input:?}");
            assert_eq!(sink.out, *expected_output, "input {input:?}");
        }
    }

    #[test]
    fn end_rejects_unclosed_empty_container() {
        let mut tokenizer = Tokenizer::new();
        let mut sink = RawSink::default();
        tokenizer.write(b"[", &mut sink).unwrap();
        let err = tokenizer.end(&mut sink).unwrap_err();
        assert_eq!(err.kind(), &JsonErrorKind::UnexpectedEnd);
        assert_eq!(err.offset(), Some(1));
    }
}
