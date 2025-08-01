//! Various codes defined in RFC 6455.

use std::{
    convert::{From, Into},
    fmt,
};
/// WebSocket message opcode as in RFC 6455.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum OpCode {
    /// Data (text or binary).
    Data(OpCodeData),
    /// Control message (close, ping, pong).
    Control(OpCodeControl),
}

/// Data opcodes as in RFC 6455
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum OpCodeData {
    /// 0x0 denotes a continuation frame
    Continue,
    /// 0x1 denotes a text frame
    Text,
    /// 0x2 denotes a binary frame
    Binary,
    /// 0x3-7 are reserved for further non-control frames
    Reserved(u8),
}

/// Control opcodes as in RFC 6455
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum OpCodeControl {
    /// 0x8 denotes a connection close
    Close,
    /// 0x9 denotes a ping
    Ping,
    /// 0xa denotes a pong
    Pong,
    /// 0xb-f are reserved for further control frames
    Reserved(u8),
}

impl fmt::Display for OpCodeData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Continue => write!(f, "CONTINUE"),
            Self::Text => write!(f, "TEXT"),
            Self::Binary => write!(f, "BINARY"),
            Self::Reserved(x) => write!(f, "RESERVED_DATA_{x}"),
        }
    }
}

impl fmt::Display for OpCodeControl {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Close => write!(f, "CLOSE"),
            Self::Ping => write!(f, "PING"),
            Self::Pong => write!(f, "PONG"),
            Self::Reserved(x) => write!(f, "RESERVED_CONTROL_{x}"),
        }
    }
}

impl fmt::Display for OpCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Self::Data(d) => d.fmt(f),
            Self::Control(c) => c.fmt(f),
        }
    }
}

impl From<OpCode> for u8 {
    fn from(code: OpCode) -> Self {
        use self::{
            OpCodeControl::{Close, Ping, Pong},
            OpCodeData::{Binary, Continue, Text},
        };
        match code {
            OpCode::Data(Continue) => 0,
            OpCode::Data(Text) => 1,
            OpCode::Data(Binary) => 2,

            OpCode::Control(Close) => 8,
            OpCode::Control(Ping) => 9,
            OpCode::Control(Pong) => 10,

            OpCode::Data(self::OpCodeData::Reserved(i))
            | OpCode::Control(self::OpCodeControl::Reserved(i)) => i,
        }
    }
}

impl From<u8> for OpCode {
    fn from(byte: u8) -> Self {
        use self::{
            OpCodeControl::{Close, Ping, Pong},
            OpCodeData::{Binary, Continue, Text},
        };
        match byte {
            0 => Self::Data(Continue),
            1 => Self::Data(Text),
            2 => Self::Data(Binary),
            i @ 3..=7 => Self::Data(self::OpCodeData::Reserved(i)),
            8 => Self::Control(Close),
            9 => Self::Control(Ping),
            10 => Self::Control(Pong),
            i @ 11..=15 => Self::Control(self::OpCodeControl::Reserved(i)),
            _ => panic!("Bug: OpCode out of range"),
        }
    }
}

/// Status code used to indicate why an endpoint is closing the WebSocket connection.
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
#[allow(clippy::manual_non_exhaustive)]
pub enum CloseCode {
    /// Indicates a normal closure, meaning that the purpose for
    /// which the connection was established has been fulfilled.
    Normal,
    /// Indicates that an endpoint is "going away", such as a server
    /// going down or a browser having navigated away from a page.
    Away,
    /// Indicates that an endpoint is terminating the connection due
    /// to a protocol error.
    Protocol,
    /// Indicates that an endpoint is terminating the connection
    /// because it has received a type of data it cannot accept (e.g., an
    /// endpoint that understands only text data MAY send this if it
    /// receives a binary message).
    Unsupported,
    /// Indicates that no status code was included in a closing frame. This
    /// close code makes it possible to use a single method, `on_close` to
    /// handle even cases where no close code was provided.
    Status,
    /// Indicates an abnormal closure. If the abnormal closure was due to an
    /// error, this close code will not be used. Instead, the `on_error` method
    /// of the handler will be called with the error. However, if the connection
    /// is simply dropped, without an error, this close code will be sent to the
    /// handler.
    Abnormal,
    /// Indicates that an endpoint is terminating the connection
    /// because it has received data within a message that was not
    /// consistent with the type of the message (e.g., non-UTF-8 \[RFC3629\]
    /// data within a text message).
    Invalid,
    /// Indicates that an endpoint is terminating the connection
    /// because it has received a message that violates its policy.  This
    /// is a generic status code that can be returned when there is no
    /// other more suitable status code (e.g., Unsupported or Size) or if there
    /// is a need to hide specific details about the policy.
    Policy,
    /// Indicates that an endpoint is terminating the connection
    /// because it has received a message that is too big for it to
    /// process.
    Size,
    /// Indicates that an endpoint (client) is terminating the
    /// connection because it has expected the server to negotiate one or
    /// more extension, but the server didn't return them in the response
    /// message of the WebSocket handshake.  The list of extensions that
    /// are needed should be given as the reason for closing.
    /// Note that this status code is not used by the server, because it
    /// can fail the WebSocket handshake instead.
    Extension,
    /// Indicates that a server is terminating the connection because
    /// it encountered an unexpected condition that prevented it from
    /// fulfilling the request.
    Error,
    /// Indicates that the server is restarting. A client may choose to reconnect,
    /// and if it does, it should use a randomized delay of 5-30 seconds between attempts.
    Restart,
    /// Indicates that the server is overloaded and the client should either connect
    /// to a different IP (when multiple targets exist), or reconnect to the same IP
    /// when a user has performed an action.
    Again,
    #[doc(hidden)]
    Tls,
    #[doc(hidden)]
    Reserved(u16),
    #[doc(hidden)]
    Iana(u16),
    #[doc(hidden)]
    Library(u16),
    #[doc(hidden)]
    Bad(u16),
}

impl CloseCode {
    /// Check if this CloseCode is allowed.
    #[must_use]
    pub fn is_allowed(self) -> bool {
        !matches!(
            self,
            Self::Bad(_) | Self::Reserved(_) | Self::Status | Self::Abnormal | Self::Tls
        )
    }
}

impl fmt::Display for CloseCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let code: u16 = self.into();
        write!(f, "{code}")
    }
}

impl From<CloseCode> for u16 {
    fn from(code: CloseCode) -> Self {
        match code {
            CloseCode::Normal => 1000,
            CloseCode::Away => 1001,
            CloseCode::Protocol => 1002,
            CloseCode::Unsupported => 1003,
            CloseCode::Status => 1005,
            CloseCode::Abnormal => 1006,
            CloseCode::Invalid => 1007,
            CloseCode::Policy => 1008,
            CloseCode::Size => 1009,
            CloseCode::Extension => 1010,
            CloseCode::Error => 1011,
            CloseCode::Restart => 1012,
            CloseCode::Again => 1013,
            CloseCode::Tls => 1015,
            CloseCode::Reserved(code)
            | CloseCode::Iana(code)
            | CloseCode::Library(code)
            | CloseCode::Bad(code) => code,
        }
    }
}

impl<'t> From<&'t CloseCode> for u16 {
    fn from(code: &'t CloseCode) -> Self {
        (*code).into()
    }
}

impl From<u16> for CloseCode {
    fn from(code: u16) -> Self {
        match code {
            1000 => Self::Normal,
            1001 => Self::Away,
            1002 => Self::Protocol,
            1003 => Self::Unsupported,
            1005 => Self::Status,
            1006 => Self::Abnormal,
            1007 => Self::Invalid,
            1008 => Self::Policy,
            1009 => Self::Size,
            1010 => Self::Extension,
            1011 => Self::Error,
            1012 => Self::Restart,
            1013 => Self::Again,
            1015 => Self::Tls,
            1016..=2999 => Self::Reserved(code),
            3000..=3999 => Self::Iana(code),
            4000..=4999 => Self::Library(code),
            _ => Self::Bad(code),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_from_u8() {
        let byte = 2u8;
        assert_eq!(OpCode::from(byte), OpCode::Data(OpCodeData::Binary));
    }

    #[test]
    fn opcode_into_u8() {
        let text = OpCode::Data(OpCodeData::Text);
        let byte: u8 = text.into();
        assert_eq!(byte, 1u8);
    }

    #[test]
    fn closecode_from_u16() {
        let byte = 1008u16;
        assert_eq!(CloseCode::from(byte), CloseCode::Policy);
    }

    #[test]
    fn closecode_into_u16() {
        let text = CloseCode::Away;
        let byte: u16 = text.into();
        assert_eq!(byte, 1001u16);
        assert_eq!(u16::from(text), 1001u16);
    }
}
