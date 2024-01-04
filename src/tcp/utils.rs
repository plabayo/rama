//! Utilities for the TCP protocol.

use std::io;

/// Check if the error is a connection error,
/// in which case the error can be ignored.
pub fn is_connection_error(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::UnexpectedEof
    )
}
