//! What ends a connection, as the application is told it.

use std::io;

use crate::proto::{
    TransportError, Version,
    frame::{self, Close},
};

/// Reasons why a connection might be lost
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionError {
    /// The server answered the first flight with a Version Negotiation packet listing these
    /// versions, none of which is the one this attempt used (RFC 9000 §6, RFC 9368 §2.1).
    ///
    /// The endpoint driver restarts an attempt with a mutually supported version on its own;
    /// this reaches the application when there is none, or when the attempt had already
    /// reacted to one.
    VersionMismatch {
        /// What the server offered, as it listed it, reserved versions included.
        offered: Vec<Version>,
    },
    /// The peer violated the QUIC specification as understood by this implementation
    TransportError(TransportError),
    /// The peer's QUIC stack aborted the connection automatically
    ConnectionClosed(frame::ConnectionClose),
    /// The peer closed the connection
    ApplicationClosed(frame::ApplicationClose),
    /// The peer is unable to continue processing this connection, usually due to having restarted
    Reset,
    /// The handshake deadline or negotiated idle timeout elapsed.
    ///
    /// The local handshake deadline also applies when idle timeout is disabled.
    /// After connecting, a long enough idle period can time out even if the peer is
    /// still reachable. See [`TransportConfig::set_max_idle_timeout`](crate::proto::config::TransportConfig::set_max_idle_timeout) and
    /// [`TransportConfig::set_keep_alive_interval`](crate::proto::config::TransportConfig::set_keep_alive_interval).
    TimedOut,
    /// The local application closed the connection
    LocallyClosed,
    /// The connection could not be created because not enough of the CID space is available
    ///
    /// Try using longer connection IDs.
    CidsExhausted,
}

impl core::fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::VersionMismatch { .. } => {
                f.write_str("peer doesn't implement any supported version")
            }
            Self::TransportError(inner) => core::fmt::Display::fmt(inner, f),
            Self::ConnectionClosed(field0) => write!(f, "aborted by peer: {field0}"),
            Self::ApplicationClosed(field0) => write!(f, "closed by peer: {field0}"),
            Self::Reset => f.write_str("reset by peer"),
            Self::TimedOut => f.write_str("timed out"),
            Self::LocallyClosed => f.write_str("closed"),
            Self::CidsExhausted => f.write_str("CIDs exhausted"),
        }
    }
}

impl std::error::Error for ConnectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::TransportError(inner) => Some(inner),
            _ => None,
        }
    }
}

impl From<TransportError> for ConnectionError {
    fn from(value: TransportError) -> Self {
        Self::TransportError(value)
    }
}

impl From<Close> for ConnectionError {
    fn from(x: Close) -> Self {
        match x {
            Close::Connection(reason) => Self::ConnectionClosed(reason),
            Close::Application(reason) => Self::ApplicationClosed(reason),
        }
    }
}

// For compatibility with API consumers
impl From<ConnectionError> for io::Error {
    fn from(x: ConnectionError) -> Self {
        let kind = match x {
            ConnectionError::TimedOut => io::ErrorKind::TimedOut,
            ConnectionError::Reset => io::ErrorKind::ConnectionReset,
            ConnectionError::ApplicationClosed(_) | ConnectionError::ConnectionClosed(_) => {
                io::ErrorKind::ConnectionAborted
            }
            ConnectionError::TransportError(_)
            | ConnectionError::VersionMismatch { .. }
            | ConnectionError::LocallyClosed
            | ConnectionError::CidsExhausted => io::ErrorKind::Other,
        };
        Self::new(kind, x)
    }
}
