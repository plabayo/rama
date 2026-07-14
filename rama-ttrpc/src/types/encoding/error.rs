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
pub enum EncodeError {
    InvalidInput(InvalidInput),
    InsuficientCapacity { required: usize, capacity: usize },
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(err) => write!(f, "Error encoding message: {err}"),
            Self::InsuficientCapacity { required, capacity } => write!(
                f,
                "Insufficient buffer capacity ({required} bytes > {capacity} bytes)"
            ),
        }
    }
}

impl std::error::Error for EncodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidInput(err) => Some(err),
            Self::InsuficientCapacity { .. } => None,
        }
    }
}

impl From<InvalidInput> for EncodeError {
    fn from(err: InvalidInput) -> Self {
        Self::InvalidInput(err)
    }
}

#[derive(Debug, Clone)]
pub enum DecodeError {
    UnexpectedEof,
    RemainingBytes(usize),
    InvalidInput(InvalidInput),
    InvalidProtobufStream(prost::DecodeError),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof => f.write_str("Unexpected EOF reading input byffer"),
            Self::RemainingBytes(n) => write!(f, "Remaining bytes in input buffer: {n} bytes"),
            Self::InvalidInput(err) => write!(f, "Error decoding message: {err}"),
            Self::InvalidProtobufStream(err) => {
                write!(f, "Error decoding message: Invalid protobuf stream: {err}")
            }
        }
    }
}

impl std::error::Error for DecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidInput(err) => Some(err),
            Self::InvalidProtobufStream(err) => Some(err),
            Self::UnexpectedEof | Self::RemainingBytes(_) => None,
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

impl From<prost::EncodeError> for EncodeError {
    fn from(err: prost::EncodeError) -> Self {
        Self::InsuficientCapacity {
            required: err.required_capacity(),
            capacity: err.remaining(),
        }
    }
}

impl From<InvalidInput> for std::io::Error {
    fn from(value: InvalidInput) -> Self {
        Self::new(IoErrorKind::InvalidInput, value)
    }
}
