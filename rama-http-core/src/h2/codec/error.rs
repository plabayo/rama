use crate::h2::proto::Error;
use rama_http_types::proto::h2::frame::StreamIdOverflow;

use std::{error, fmt, io};

/// Errors caused by sending a message
#[derive(Debug)]
pub enum SendError {
    Connection(Error),
    User(UserError),
}

/// Errors caused by users of the library
#[derive(Debug, Clone)]
pub enum UserError {
    /// The stream ID is no longer accepting frames.
    InactiveStreamId,

    /// The stream is not currently expecting a frame of this type.
    UnexpectedFrameType,

    /// The payload size is too big
    PayloadTooBig,

    /// The application attempted to initiate too many streams to remote.
    Rejected,

    /// The released capacity is larger than claimed capacity.
    ReleaseCapacityTooBig,

    /// The stream ID space is overflowed.
    ///
    /// A new connection is needed.
    OverflowedStreamId,

    /// Illegal headers, such as connection-specific headers.
    MalformedHeaders,

    /// Request submitted with relative URI.
    MissingUriSchemeAndAuthority,

    /// Calls `SendResponse::poll_reset` after having called `send_response`.
    PollResetAfterSendResponse,

    /// Calls `PingPong::send_ping` before receiving a pong.
    SendPingWhilePending,

    /// Tries to update local SETTINGS while ACK has not been received.
    SendSettingsWhilePending,

    /// Tries to send push promise to peer who has disabled server push
    PeerDisabledServerPush,
}

// ===== impl SendError =====

impl error::Error for SendError {}

impl fmt::Display for SendError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Connection(ref e) => e.fmt(fmt),
            Self::User(ref e) => e.fmt(fmt),
        }
    }
}

impl From<io::Error> for SendError {
    fn from(src: io::Error) -> Self {
        Self::Connection(src.into())
    }
}

impl From<UserError> for SendError {
    fn from(src: UserError) -> Self {
        SendError::User(src)
    }
}

impl From<StreamIdOverflow> for SendError {
    fn from(_: StreamIdOverflow) -> Self {
        UserError::OverflowedStreamId.into()
    }
}

// ===== impl UserError =====

impl error::Error for UserError {}

impl fmt::Display for UserError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str(match *self {
            UserError::InactiveStreamId => "inactive stream",
            UserError::UnexpectedFrameType => "unexpected frame type",
            UserError::PayloadTooBig => "payload too big",
            UserError::Rejected => "rejected",
            UserError::ReleaseCapacityTooBig => "release capacity too big",
            UserError::OverflowedStreamId => "stream ID overflowed",
            UserError::MalformedHeaders => "malformed headers",
            UserError::MissingUriSchemeAndAuthority => "request URI missing scheme and authority",
            UserError::PollResetAfterSendResponse => "poll_reset after send_response is illegal",
            UserError::SendPingWhilePending => "send_ping before received previous pong",
            UserError::SendSettingsWhilePending => "sending SETTINGS before received previous ACK",
            UserError::PeerDisabledServerPush => {
                "sending PUSH_PROMISE to peer who disabled server push"
            }
        })
    }
}
