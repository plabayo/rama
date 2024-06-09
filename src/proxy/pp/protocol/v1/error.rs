//! Errors for the text proxy protocol.

use std::fmt;

/// An error in parsing a text PROXY protocol header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Header must start with 'PROXY'.
    InvalidPrefix,
    /// Header is only partially present.
    Partial,
    /// Header is empty.
    MissingPrefix,
    /// Header does not end with the string '\r\n'.
    MissingNewLine,
    /// Header missing protocol.
    MissingProtocol,
    /// Header missing source address.
    MissingSourceAddress,
    /// Header missing destination address.
    MissingDestinationAddress,
    /// Header missing source port.
    MissingSourcePort,
    /// Header missing destination port.
    MissingDestinationPort,
    /// Header does not fit within the expected buffer size of 107 bytes (plus 1 byte for null-terminated strings).
    HeaderTooLong,
    /// Header has an invalid protocol.
    InvalidProtocol,
    /// Header must end in '\r\n'.
    InvalidSuffix,
    /// Header contains invalid IP address for the source.
    InvalidSourceAddress(std::net::AddrParseError),
    /// Header contains invalid IP address for the destination.
    InvalidDestinationAddress(std::net::AddrParseError),
    /// Header contains invalid TCP port for the source.
    InvalidSourcePort(Option<std::num::ParseIntError>),
    /// Header contains invalid TCP port for the destination.]
    InvalidDestinationPort(Option<std::num::ParseIntError>),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPrefix => write!(f, "Header must start with 'PROXY'."),
            Self::Partial => write!(f, "Header is only partially present."),
            Self::MissingPrefix => write!(f, "Header is empty."),
            Self::MissingNewLine => write!(f, "Header does not end with the string '\\r\\n'."),
            Self::MissingProtocol => write!(f, "Header missing protocol."),
            Self::MissingSourceAddress => write!(f, "Header missing source address."),
            Self::MissingDestinationAddress => write!(f, "Header missing destination address."),
            Self::MissingSourcePort => write!(f, "Header missing source port."),
            Self::MissingDestinationPort => write!(f, "Header missing destination port."),
            Self::HeaderTooLong => write!(f, "Header does not fit within the expected buffer size of 107 bytes (plus 1 byte for null-terminated strings)."),
            Self::InvalidProtocol => write!(f, "Header has an invalid protocol."),
            Self::InvalidSuffix => write!(f, "Header must end in '\r\n'."),
            Self::InvalidSourceAddress(source) => write!(f, "Header contains invalid IP address for the source: {}", source),
            Self::InvalidDestinationAddress(destination) => write!(f, "Header contains invalid IP address for the destination: {}", destination),
            Self::InvalidSourcePort(port) => write!(f, "Header contains invalid TCP port for the source: {}", port.as_ref().map(|e| e.to_string()).unwrap_or_default()),
            Self::InvalidDestinationPort(port) => write!(f, "Header contains invalid TCP port for the destination: {}", port.as_ref().map(|e| e.to_string()).unwrap_or_default()),
        }
    }
}

impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidSourceAddress(source) => Some(source),
            Self::InvalidDestinationAddress(destination) => Some(destination),
            Self::InvalidSourcePort(port) => port.as_ref().map(|e| e as &dyn std::error::Error),
            Self::InvalidDestinationPort(port) => {
                port.as_ref().map(|e| e as &dyn std::error::Error)
            }
            _ => None,
        }
    }
}

/// An error in parsing a text PROXY protocol header that is represented as a byte slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BinaryParseError {
    /// An error in parsing a binary PROXY protocol header.
    Parse(ParseError),
    /// Header is not valid UTF-8.
    InvalidUtf8(std::str::Utf8Error),
}

impl From<ParseError> for BinaryParseError {
    fn from(error: ParseError) -> Self {
        Self::Parse(error)
    }
}

impl From<std::str::Utf8Error> for BinaryParseError {
    fn from(error: std::str::Utf8Error) -> Self {
        Self::InvalidUtf8(error)
    }
}

impl fmt::Display for BinaryParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(error) => write!(f, "{}", error),
            Self::InvalidUtf8(error) => write!(f, "Header is not valid UTF-8: {}", error),
        }
    }
}

impl std::error::Error for BinaryParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Parse(error) => Some(error),
            Self::InvalidUtf8(error) => Some(error),
        }
    }
}
