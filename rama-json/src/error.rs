use std::fmt;

/// Error produced while parsing, selecting, or rewriting JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonError {
    kind: JsonErrorKind,
    offset: Option<usize>,
}

impl JsonError {
    /// Creates an error without a byte offset.
    #[must_use]
    pub const fn new(kind: JsonErrorKind) -> Self {
        Self { kind, offset: None }
    }

    /// Creates an error at an absolute input byte offset.
    #[must_use]
    pub const fn at(kind: JsonErrorKind, offset: usize) -> Self {
        Self {
            kind,
            offset: Some(offset),
        }
    }

    /// The reason for the failure.
    #[must_use]
    pub const fn kind(&self) -> &JsonErrorKind {
        &self.kind
    }

    /// Absolute byte offset of the failure, when known.
    #[must_use]
    pub const fn offset(&self) -> Option<usize> {
        self.offset
    }
}

/// Reason for a JSON failure.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum JsonErrorKind {
    /// Input ended before a complete JSON token or document was available.
    UnexpectedEnd,
    /// A byte is not valid at the current position.
    UnexpectedByte(u8),
    /// A token appeared where the JSON grammar does not allow it.
    UnexpectedToken(&'static str),
    /// A string literal contains an invalid escape sequence.
    InvalidEscape,
    /// A string literal contains a control character.
    ControlCharacterInString,
    /// A string literal is not valid UTF-8.
    InvalidUtf8,
    /// A number literal does not follow the JSON number grammar.
    InvalidNumber,
    /// A JSON value could not be serialized.
    SerializationFailure,
    /// A JSON value could not be deserialized.
    DeserializationFailure,
    /// More than one top-level JSON value was found.
    TrailingValue,
    /// Buffered input exceeded the configured tokenizer limit.
    InputBufferLimitExceeded(usize),
    /// A JSONPath expression was empty.
    EmptyPath,
    /// A JSONPath expression did not start with `$`.
    MissingRoot,
    /// A JSONPath expression contains a feature not implemented yet.
    UnsupportedJsonPath(&'static str),
    /// A JSON rewrite operation is not supported yet.
    UnsupportedRewrite(&'static str),
    /// A JSONPath expression contains malformed syntax.
    InvalidJsonPath(&'static str),
    /// A selected JSON value exceeded the configured capture limit.
    CaptureLimitExceeded(usize),
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            JsonErrorKind::UnexpectedEnd => f.write_str("unexpected end of JSON input")?,
            JsonErrorKind::UnexpectedByte(b) => write!(f, "unexpected byte {b:#04x}")?,
            JsonErrorKind::UnexpectedToken(token) => write!(f, "unexpected JSON token {token}")?,
            JsonErrorKind::InvalidEscape => f.write_str("invalid JSON string escape")?,
            JsonErrorKind::ControlCharacterInString => {
                f.write_str("control character in JSON string")?
            }
            JsonErrorKind::InvalidUtf8 => f.write_str("JSON string is not valid UTF-8")?,
            JsonErrorKind::InvalidNumber => f.write_str("invalid JSON number")?,
            JsonErrorKind::SerializationFailure => f.write_str("JSON serialization failure")?,
            JsonErrorKind::DeserializationFailure => f.write_str("JSON deserialization failure")?,
            JsonErrorKind::TrailingValue => f.write_str("trailing top-level JSON value")?,
            JsonErrorKind::InputBufferLimitExceeded(limit) => {
                write!(f, "buffered JSON input exceeded limit of {limit} bytes")?
            }
            JsonErrorKind::EmptyPath => f.write_str("empty JSONPath expression")?,
            JsonErrorKind::MissingRoot => f.write_str("JSONPath expression must start with `$`")?,
            JsonErrorKind::UnsupportedJsonPath(feature) => {
                write!(f, "unsupported JSONPath feature: {feature}")?
            }
            JsonErrorKind::UnsupportedRewrite(feature) => {
                write!(f, "unsupported JSON rewrite operation: {feature}")?
            }
            JsonErrorKind::InvalidJsonPath(reason) => write!(f, "invalid JSONPath: {reason}")?,
            JsonErrorKind::CaptureLimitExceeded(limit) => write!(
                f,
                "selected JSON value exceeded capture limit of {limit} bytes"
            )?,
        }

        if let Some(offset) = self.offset {
            write!(f, " at byte offset {offset}")?;
        }
        Ok(())
    }
}

impl std::error::Error for JsonError {}
