use rama_core::error::BoxError;
use std::fmt;

#[derive(Debug)]
pub enum ProtocolError {
    /// An I/O error during reading or writing.
    IO(std::io::Error),
    /// Unexpected byte at the given position.
    UnexpectedByte { pos: usize, byte: u8 },
    /// Unexpected value (e.g. wrong protocol version).
    Unexpected(BoxError),
    /// Record content is too large to fit in a single FastCGI record.
    ContentTooLarge(usize),
}

impl ProtocolError {
    #[must_use]
    pub fn unexpected_byte(pos: usize, byte: u8) -> Self {
        Self::UnexpectedByte { pos, byte }
    }

    #[must_use]
    pub fn content_too_large(len: usize) -> Self {
        Self::ContentTooLarge(len)
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IO(err) => write!(f, "fastcgi protocol error: I/O: {err}"),
            Self::UnexpectedByte { pos, byte } => write!(
                f,
                "fastcgi protocol error: unexpected byte {byte:#04x} at position {pos}"
            ),
            Self::Unexpected(err) => write!(f, "fastcgi protocol error: unexpected: {err}"),
            Self::ContentTooLarge(len) => write!(
                f,
                "fastcgi protocol error: content length {len} exceeds maximum of 65535"
            ),
        }
    }
}

impl std::error::Error for ProtocolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IO(err) => Some(err as &(dyn std::error::Error + 'static)),
            Self::UnexpectedByte { .. } | Self::ContentTooLarge(_) => None,
            Self::Unexpected(err) => Some(err.source().unwrap_or(err.as_ref())),
        }
    }
}

impl From<std::io::Error> for ProtocolError {
    fn from(value: std::io::Error) -> Self {
        Self::IO(value)
    }
}

impl From<BoxError> for ProtocolError {
    fn from(value: BoxError) -> Self {
        Self::Unexpected(value)
    }
}
