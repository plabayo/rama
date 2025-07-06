use rama_core::error::OpaqueError;

use super::common::ReadError;
use std::{fmt, string::FromUtf8Error};

#[derive(Debug)]
pub enum ProtocolError {
    /// An I/O Error during reading or writing of data from I/O.
    IO(std::io::Error),
    /// Unexpected byte at tbe paired position
    UnexpectedByte { pos: usize, byte: u8 },
    /// Unexpected error happened
    Unexpected(OpaqueError),
    /// Utf-8 error in case something went wrong during bytes to utf-8 conversion
    Utf8(FromUtf8Error),
}

impl ProtocolError {
    pub fn unexpected_byte(pos: usize, byte: u8) -> Self {
        Self::UnexpectedByte { pos, byte }
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolError::IO(error) => write!(f, "protocol error: I/O: {error}"),
            ProtocolError::UnexpectedByte { pos, byte } => {
                write!(
                    f,
                    "protocol error: unexpected byte x'{byte:x}' at position {pos}"
                )
            }
            ProtocolError::Unexpected(error) => {
                write!(f, "protocol error: unexpected: {error}")
            }
            ProtocolError::Utf8(error) => {
                write!(f, "protocol error: utf-8 conversion: {error}")
            }
        }
    }
}

impl std::error::Error for ProtocolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ProtocolError::IO(err) => Some(err as &(dyn std::error::Error + 'static)),
            ProtocolError::UnexpectedByte { .. } => None,
            ProtocolError::Unexpected(err) => Some(
                err.source()
                    .unwrap_or(err as &(dyn std::error::Error + 'static)),
            ),
            ProtocolError::Utf8(err) => Some(err as &(dyn std::error::Error + 'static)),
        }
    }
}

impl From<std::io::Error> for ProtocolError {
    fn from(value: std::io::Error) -> Self {
        ProtocolError::IO(value)
    }
}

impl From<OpaqueError> for ProtocolError {
    fn from(value: OpaqueError) -> Self {
        ProtocolError::Unexpected(value)
    }
}

impl From<FromUtf8Error> for ProtocolError {
    fn from(value: FromUtf8Error) -> Self {
        ProtocolError::Utf8(value)
    }
}

impl From<ReadError> for ProtocolError {
    fn from(value: ReadError) -> Self {
        match value {
            ReadError::IO(error) => ProtocolError::IO(error),
            ReadError::UnexpectedByte { pos, byte } => ProtocolError::UnexpectedByte { pos, byte },
            ReadError::Unexpected(error) => ProtocolError::Unexpected(error),
        }
    }
}
