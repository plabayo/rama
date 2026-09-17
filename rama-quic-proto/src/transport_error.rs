use alloc::borrow::Cow;
use core::fmt;

use rama_core::{
    bytes::{Buf, BufMut},
    error::ArcError,
};

use crate::{
    coding::{self, BufExt, BufMutExt},
    frame::FrameType,
};

/// Transport-level errors occur when a peer violates the protocol specification
///
/// # Note
///
/// The `PartialEq` implementation for this type performs comparison on the `code` field only
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Error {
    /// Type of error
    pub code: Code,
    /// Frame type that triggered the error
    pub frame: Option<FrameType>,
    /// Human-readable explanation of the reason, which is what goes on the wire in
    /// CONNECTION_CLOSE. A literal is borrowed for the life of the program and costs nothing;
    /// text built at the point of failure is owned. Local diagnostics live in `cause` and never
    /// reach the peer.
    pub reason: Cow<'static, str>,
    /// An underlying TLS or local runtime failure, shared: this error is cloned for every
    /// stream, waiter and close reason that reports it, and the cause is rarely cloneable.
    pub cause: Option<ArcError>,
}

impl Error {
    /// Preserve a local failure underlying a transport shutdown.
    #[must_use]
    pub fn with_cause(mut self, cause: impl core::error::Error + Send + Sync + 'static) -> Self {
        self.cause = Some(ArcError::new(cause));
        self
    }

    /// Construct an error with a code and a reason
    pub fn new(code: Code, reason: impl Into<Cow<'static, str>>) -> Self {
        Self {
            code,
            frame: None,
            reason: reason.into(),
            cause: None,
        }
    }

    /// What kind of error this is, as RFC 9000 §20 numbers them.
    #[must_use]
    pub fn code(&self) -> Code {
        self.code
    }

    /// The frame that caused it, when one did.
    #[must_use]
    pub fn frame_type(&self) -> Option<FrameType> {
        self.frame
    }

    /// The reason as it goes to the peer, empty when none was given.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// The local underlying error, when this one came from another. It stays local:
    /// CONNECTION_CLOSE carries [`Self::code`], [`Self::frame_type`] and [`Self::reason`], and
    /// nothing of this.
    #[must_use]
    pub fn cause(&self) -> Option<&ArcError> {
        self.cause.as_ref()
    }
}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        self.code == other.code
    }
}

impl Eq for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.code.fmt(f)?;
        if let Some(frame) = self.frame {
            write!(f, " in {frame}")?;
        }
        if !self.reason.is_empty() {
            write!(f, ": {}", self.reason)?;
        }
        Ok(())
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        // The sharing is how this error keeps its cause, not a step in the chain: what follows
        // the transport error is the failure itself, as it was before it was shared.
        self.cause.as_ref().map(ArcError::as_error)
    }
}

impl From<Code> for Error {
    fn from(x: Code) -> Self {
        Self {
            code: x,
            frame: None,
            reason: Cow::Borrowed(""),
            cause: None,
        }
    }
}

/// Transport-level error code
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Code(u64);

impl Code {
    /// Create QUIC error code from TLS alert code
    #[must_use]
    pub fn crypto(code: u8) -> Self {
        Self(0x100 | u64::from(code))
    }

    /// The code as it goes on the wire.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// The TLS alert this code carries, when it carries one. RFC 9001 §4.8 gives the handshake
    /// 0x100 to 0x1ff, one code per alert description.
    #[must_use]
    pub fn tls_alert(self) -> Option<u8> {
        (0x100..0x200).contains(&self.0).then_some(self.0 as u8)
    }
}

impl coding::Codec for Code {
    fn decode<B: Buf>(buf: &mut B) -> coding::Result<Self> {
        Ok(Self(buf.get_var()?))
    }
    fn encode<B: BufMut>(&self, buf: &mut B) {
        buf.write_var(self.0)
    }
}

impl From<Code> for u64 {
    fn from(x: Code) -> Self {
        x.0
    }
}

macro_rules! errors {
    {$($name:ident($val:expr) $desc:expr;)*} => {
        #[expect(non_snake_case, reason = "constructors are named after the RFC 9000 error codes")]
        impl Error {
            $(
            pub fn $name<T>(reason: T) -> Self where T: Into<Cow<'static, str>> {
                Self {
                    code: Code::$name,
                    frame: None,
                    reason: reason.into(),
                    cause: None,
                }
            }
            )*
        }

        impl Code {
            $(#[doc = $desc] pub const $name: Self = Code($val);)*
        }

        impl fmt::Debug for Code {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self.0 {
                    $($val => f.write_str(stringify!($name)),)*
                    x if (0x100..0x200).contains(&x) => write!(f, "Code::crypto({:02x})", self.0 as u8),
                    _ => write!(f, "Code({:x})", self.0),
                }
            }
        }

        impl fmt::Display for Code {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self.0 {
                    $($val => f.write_str($desc),)*
                    // We're trying to be abstract over the crypto protocol, so human-readable descriptions here is tricky.
                    _ if self.0 >= 0x100 && self.0 < 0x200 => write!(f, "the cryptographic handshake failed: error {}", self.0 & 0xFF),
                    _ => f.write_str("unknown error"),
                }
            }
        }
    }
}

errors! {
    NO_ERROR(0x0) "the connection is being closed abruptly in the absence of any error";
    INTERNAL_ERROR(0x1) "the endpoint encountered an internal error and cannot continue with the connection";
    CONNECTION_REFUSED(0x2) "the server refused to accept a new connection";
    FLOW_CONTROL_ERROR(0x3) "received more data than permitted in advertised data limits";
    STREAM_LIMIT_ERROR(0x4) "received a frame for a stream identifier that exceeded advertised the stream limit for the corresponding stream type";
    STREAM_STATE_ERROR(0x5) "received a frame for a stream that was not in a state that permitted that frame";
    FINAL_SIZE_ERROR(0x6) "received a STREAM frame or a RESET_STREAM frame containing a different final size to the one already established";
    FRAME_ENCODING_ERROR(0x7) "received a frame that was badly formatted";
    TRANSPORT_PARAMETER_ERROR(0x8) "received transport parameters that were badly formatted, included an invalid value, was absent even though it is mandatory, was present though it is forbidden, or is otherwise in error";
    CONNECTION_ID_LIMIT_ERROR(0x9) "the number of connection IDs provided by the peer exceeds the advertised active_connection_id_limit";
    PROTOCOL_VIOLATION(0xA) "detected an error with protocol compliance that was not covered by more specific error codes";
    INVALID_TOKEN(0xB) "received an invalid Retry Token in a client Initial";
    APPLICATION_ERROR(0xC) "the application or application protocol caused the connection to be closed during the handshake";
    CRYPTO_BUFFER_EXCEEDED(0xD) "received more data in CRYPTO frames than can be buffered";
    KEY_UPDATE_ERROR(0xE) "key update error";
    AEAD_LIMIT_REACHED(0xF) "the endpoint has reached the confidentiality or integrity limit for the AEAD algorithm";
    NO_VIABLE_PATH(0x10) "no viable network path exists";
    VERSION_NEGOTIATION_ERROR(0x11) "error negotiating version";
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::ConnectionClose;

    /// A literal reason is borrowed all the way to the frame. The frame's bytes are the same
    /// bytes as the literal, which a copy would not be.
    #[test]
    fn a_literal_reason_is_borrowed_to_the_wire() {
        const REASON: &str = "frame in the wrong space";
        let error = Error::PROTOCOL_VIOLATION(REASON);
        assert!(matches!(error.reason, Cow::Borrowed(_)));
        let close = ConnectionClose::from(error);
        assert_eq!(&close.reason[..], REASON.as_bytes());
        assert_eq!(
            close.reason.as_ptr(),
            REASON.as_ptr(),
            "the frame points at the literal itself"
        );
    }

    /// Text built where the failure happened is owned, and its buffer moves to the frame rather
    /// than being copied into a new one.
    #[test]
    fn a_built_reason_is_owned_and_moves_to_the_wire() {
        let built = format!("stream {} is not open", 7);
        let address = built.as_ptr();
        let error = Error::PROTOCOL_VIOLATION(built);
        assert!(matches!(error.reason, Cow::Owned(_)));
        let close = ConnectionClose::from(error);
        assert_eq!(&close.reason[..], b"stream 7 is not open");
        assert_eq!(
            close.reason.as_ptr(),
            address,
            "the frame holds the buffer that was built, not a copy of it"
        );
    }

    /// A failure that names a frame reports it through the public accessors, and the frame
    /// carries into the close object built from it. This is the field, not the encoding.
    #[test]
    fn a_frame_typed_error_names_the_frame() {
        let mut error = Error::FRAME_ENCODING_ERROR("an ack frame with no ranges");
        error.frame = Some(FrameType::ACK);
        let named = error.frame_type().expect("the frame is named");
        assert_eq!(named.as_u64(), 0x02, "the ACK type of RFC 9000 §19.3");
        assert_eq!(
            error.code().as_u64(),
            0x7,
            "and the code is the encoding one"
        );
        assert_eq!(ConnectionClose::from(error).frame_type(), Some(named));
    }

    /// What the peer is told is the reason, never the local cause or the context around it.
    #[test]
    fn the_local_cause_stays_local() {
        let error = Error::INTERNAL_ERROR("send failed").with_cause(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "the socket said no",
        ));
        let close = ConnectionClose::from(error.clone());
        assert_eq!(&close.reason[..], b"send failed");
        assert!(
            core::error::Error::source(&error).is_some(),
            "while the cause is still there for this side"
        );
    }
}
