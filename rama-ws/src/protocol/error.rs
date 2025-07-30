use crate::protocol::{frame::coding::OpCodeData, message::Message};
use rama_core::error::OpaqueError;
use rama_net::conn::is_connection_error;
use rama_utils::str::utf8;
use std::{error, fmt, io};

/// Indicates the specific type/cause of a protocol error.
#[derive(Debug)]
pub enum ProtocolError {
    /// a utf-8 decode error
    Utf8(OpaqueError),
    /// Input-output error.
    ///
    /// These are generally errors with the
    /// underlying connection and you should probably consider them fatal.
    Io(io::Error),
    /// Encountered an invalid opcode.
    InvalidOpcode(u8),
    /// The payload for the closing frame is invalid.
    InvalidCloseSequence,
    /// Received header is too long.
    ///
    /// Message is bigger than the maximum allowed size.
    MessageTooLong {
        /// The size of the message.
        size: usize,
        /// The maximum allowed message size.
        max_size: usize,
    },
    /// The server must close the connection when an unmasked frame is received.
    UnmaskedFrameFromClient,
    /// Message write buffer is full.
    WriteBufferFull(Message),
    /// Not allowed to send after having sent a closing frame.
    SendAfterClosing,
    /// Remote sent data after sending a closing frame.
    ReceivedAfterClosing,
    /// Reserved bits in frame header are non-zero.
    NonZeroReservedBits,
    /// The client must close the connection when a masked frame is received.
    MaskedFrameFromServer,
    /// Control frames must not be fragmented.
    FragmentedControlFrame,
    /// Control frames must have a payload of 125 bytes or less.
    ControlFrameTooBig,
    /// Type of control frame not recognised.
    UnknownControlFrameType(u8),
    /// Connection closed without performing the closing handshake.
    ResetWithoutClosingHandshake,
    /// Received a continue frame despite there being nothing to continue.
    UnexpectedContinueFrame,
    /// Received data while waiting for more fragments.
    ExpectedFragment(OpCodeData),
    /// Type of data frame not recognised.
    UnknownDataFrameType(u8),
}

impl ProtocolError {
    /// Check if the error is a connection error,
    /// in which case the error can be ignored.
    pub fn is_connection_error(&self) -> bool {
        if let Self::Io(err) = self {
            is_connection_error(err)
        } else {
            false
        }
    }
}

impl From<utf8::DecodeError<'_>> for ProtocolError {
    fn from(value: utf8::DecodeError<'_>) -> Self {
        Self::Utf8(OpaqueError::from_display(value.to_string()))
    }
}

impl From<std::str::Utf8Error> for ProtocolError {
    fn from(value: std::str::Utf8Error) -> Self {
        Self::Utf8(OpaqueError::from_std(value))
    }
}

impl From<io::Error> for ProtocolError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Utf8(err) => write!(f, "UTF-8 error: {err:?}"),
            Self::Io(err) => write!(f, "I/O error: {err:?}"),
            Self::InvalidOpcode(code) => write!(f, "Encountered invalid opcode: {code}"),
            Self::InvalidCloseSequence => write!(f, "Invalid close sequence"),
            Self::MessageTooLong { size, max_size } => {
                write!(f, "Message too long: {size} > {max_size}")
            }
            Self::UnmaskedFrameFromClient => {
                write!(f, "Received an unmasked frame from client")
            }
            Self::WriteBufferFull(_) => write!(f, "Write buffer is full"),
            Self::SendAfterClosing => {
                write!(f, "Sending after closing is not allowed")
            }
            Self::ReceivedAfterClosing => {
                write!(f, "Remote sent after having closed")
            }
            Self::NonZeroReservedBits => {
                write!(f, "Reserved bits are non-zero")
            }
            Self::MaskedFrameFromServer => {
                write!(f, "Received a masked frame from server")
            }
            Self::FragmentedControlFrame => {
                write!(f, "Fragmented control frame")
            }
            Self::ControlFrameTooBig => {
                write!(
                    f,
                    "Control frame too big (payload must be 125 bytes or less)"
                )
            }
            Self::UnknownControlFrameType(t) => {
                write!(f, "Unknown control frame type: {t}")
            }
            Self::ResetWithoutClosingHandshake => {
                write!(f, "Connection reset without closing handshake")
            }
            Self::UnexpectedContinueFrame => {
                write!(f, "Continue frame but nothing to continue")
            }
            Self::ExpectedFragment(data) => {
                write!(f, "While waiting for more fragments received: {data}")
            }
            Self::UnknownDataFrameType(t) => {
                write!(f, "Unknown data frame type: {t}")
            }
        }
    }
}

impl error::Error for ProtocolError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Utf8(err) => Some(err as &(dyn error::Error + 'static)),
            Self::Io(err) => Some(err as &(dyn std::error::Error + 'static)),
            Self::InvalidOpcode(_)
            | Self::InvalidCloseSequence
            | Self::MessageTooLong { .. }
            | Self::UnmaskedFrameFromClient
            | Self::WriteBufferFull(_)
            | Self::SendAfterClosing
            | Self::ReceivedAfterClosing
            | Self::NonZeroReservedBits
            | Self::MaskedFrameFromServer
            | Self::FragmentedControlFrame
            | Self::ControlFrameTooBig
            | Self::UnknownControlFrameType(_)
            | Self::ResetWithoutClosingHandshake
            | Self::UnexpectedContinueFrame
            | Self::ExpectedFragment(_)
            | Self::UnknownDataFrameType(_) => None,
        }
    }
}
