//! HTTP/3 errors retain the protocol code and its connection/stream scope.

use rama_http_types::proto::h3::Code;

use super::frame::FrameError;
use super::qpack::{ErrorScope, QpackError};

/// A terminal HTTP/3 protocol error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    code: Code,
    scope: ErrorScope,
    reason: &'static str,
    peer_stopped: bool,
}

impl Error {
    /// Construct a connection error.
    #[must_use]
    pub const fn connection(code: Code, reason: &'static str) -> Self {
        Self {
            code,
            scope: ErrorScope::Connection,
            reason,
            peer_stopped: false,
        }
    }

    /// Construct an error affecting one request or push stream.
    #[must_use]
    pub const fn stream(code: Code, reason: &'static str) -> Self {
        Self {
            code,
            scope: ErrorScope::Stream,
            reason,
            peer_stopped: false,
        }
    }

    pub(crate) fn peer_stopped(code: Code) -> Self {
        Self {
            code,
            scope: ErrorScope::Stream,
            reason: "peer stopped sending",
            peer_stopped: true,
        }
    }

    pub(crate) const fn is_peer_stop(self) -> bool {
        self.peer_stopped
    }

    pub(crate) fn is_clean_close(self) -> bool {
        self.scope == ErrorScope::Connection && self.code == Code::H3_NO_ERROR
    }

    pub(crate) fn from_transport(error: &rama_quic::ConnectionError) -> Self {
        match error {
            rama_quic::ConnectionError::ApplicationClosed(close) => Self::connection(
                Code::new(close.error_code.into_inner()),
                "peer closed HTTP/3 connection",
            ),
            rama_quic::ConnectionError::LocallyClosed => {
                Self::connection(Code::H3_NO_ERROR, "local connection closed")
            }
            // HTTP/3 defines no timeout application code. Retain a terminal
            // local error, with an explicit transport cause rather than claiming
            // the peer violated HTTP/3. This code was not received from the peer.
            rama_quic::ConnectionError::TimedOut => {
                Self::connection(Code::H3_GENERAL_PROTOCOL_ERROR, "QUIC connection timed out")
            }
            _ => Self::connection(Code::H3_GENERAL_PROTOCOL_ERROR, "QUIC connection failed"),
        }
    }

    /// The HTTP/3 application error code.
    ///
    /// Transport failures use a local classification when no application code
    /// was received; a closed transport cannot deliver it to the peer.
    #[must_use]
    pub const fn code(self) -> Code {
        self.code
    }

    /// Whether the connection or the affected stream must be terminated.
    #[must_use]
    pub const fn scope(self) -> ErrorScope {
        self.scope
    }

    /// Whether the peer explicitly rejected this request without processing it.
    #[must_use]
    pub fn is_rejected(self) -> bool {
        self.code == Code::H3_REQUEST_REJECTED
    }

    /// Map a terminal compression error, preserving local output backpressure as `None`.
    #[must_use]
    pub fn from_qpack(error: QpackError) -> Option<Self> {
        Some(Self {
            code: error.code()?,
            scope: error.scope()?,
            reason: error.reason(),
            peer_stopped: false,
        })
    }

    /// Map a frame error; rejected local input is backpressure, not a peer error.
    #[must_use]
    pub fn from_frame(error: &FrameError) -> Option<Self> {
        let (code, reason) = match error {
            FrameError::InputBufferFull => return None,
            FrameError::UnexpectedH2Frame(_) => {
                (Code::H3_FRAME_UNEXPECTED, "HTTP/2 frame on H3 stream")
            }
            FrameError::FrameTooLarge { .. } | FrameError::TooManySettings => {
                (Code::H3_EXCESSIVE_LOAD, "frame exceeds local budget")
            }
            FrameError::Malformed(_) => (Code::H3_FRAME_ERROR, "malformed frame"),
            FrameError::Settings(_) => (Code::H3_SETTINGS_ERROR, "invalid settings"),
        };
        Some(Self::connection(code, reason))
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({}, {:?})", self.reason, self.code, self.scope)
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_timeout_remains_terminal_with_specific_cause() {
        let error = Error::from_transport(&rama_quic::ConnectionError::TimedOut);
        assert!(!error.is_clean_close());
        assert_eq!(error.scope(), ErrorScope::Connection);
        assert!(error.to_string().contains("timed out"));
    }
}
