use std::borrow::Cow;
use std::fmt;
use std::io::ErrorKind as IoErrorKind;

#[derive(Debug, Clone)]
pub struct InvalidInput(pub Cow<'static, str>);

impl fmt::Display for InvalidInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid input: {}", self.0)
    }
}

impl std::error::Error for InvalidInput {}

#[derive(Debug, Clone)]
pub enum DecodeError {
    UnexpectedEof,
    RemainingBytes(usize),
    InvalidInput(InvalidInput),
    InvalidProtobufStream(prost::DecodeError),
    /// A frame declared a data length beyond the protocol maximum; the payload was
    /// discarded from the wire and only this error remains to be reported per-stream.
    OversizedMessage {
        length: usize,
        max: usize,
    },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof => f.write_str("Unexpected EOF reading input buffer"),
            Self::RemainingBytes(n) => write!(f, "Remaining bytes in input buffer: {n} bytes"),
            Self::InvalidInput(err) => write!(f, "Error decoding message: {err}"),
            Self::InvalidProtobufStream(err) => {
                write!(f, "Error decoding message: Invalid protobuf stream: {err}")
            }
            // mirrors the Go implementation's wording (containerd/ttrpc channel.go `recv`)
            Self::OversizedMessage { length, max } => write!(
                f,
                "message length {length} exceed maximum message size of {max}"
            ),
        }
    }
}

impl std::error::Error for DecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidInput(err) => Some(err),
            Self::InvalidProtobufStream(err) => Some(err),
            Self::UnexpectedEof | Self::RemainingBytes(_) | Self::OversizedMessage { .. } => None,
        }
    }
}

impl From<InvalidInput> for DecodeError {
    fn from(err: InvalidInput) -> Self {
        Self::InvalidInput(err)
    }
}

impl From<prost::DecodeError> for DecodeError {
    fn from(err: prost::DecodeError) -> Self {
        Self::InvalidProtobufStream(err)
    }
}

impl<T: Into<Cow<'static, str>>> From<T> for InvalidInput {
    fn from(msg: T) -> Self {
        Self(msg.into())
    }
}

impl From<InvalidInput> for std::io::Error {
    fn from(value: InvalidInput) -> Self {
        Self::new(IoErrorKind::InvalidInput, value)
    }
}
