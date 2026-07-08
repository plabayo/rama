use std::fmt::{self, Display};

pub(crate) use prost_types::Any;

pub(crate) use super::Code;
use crate::io::SendError;
use crate::types::encoding::DecodeError;
use crate::types::flags::Flags;
use crate::types::message::MessageType;

#[derive(Clone, PartialEq, prost::Message)]
pub struct Status {
    /// The status code, which should be an enum value of `Code`.
    #[prost(enumeration = "Code")]
    pub code: i32,

    /// A developer-facing error message, which should be in English. Any
    /// user-facing error message should be localized and sent in the
    /// `details` field, or localized by the client.
    #[prost(string)]
    pub message: String,

    /// A list of messages that carry the error details. There is a common set of
    /// message types for APIs to use.
    #[prost(message, repeated)]
    pub details: Vec<Any>,
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Error code {}: {}", code_to_str(self.code), self.message)
    }
}

impl std::error::Error for Status {}

macro_rules! constructor {
    ($method:ident, $variant:ident) => {
        pub fn $method(message: impl Into<String>) -> Self {
            Status {
                code: Code::$variant as i32,
                message: message.into(),
                details: vec![],
            }
        }
    };
}

impl Status {
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        let code = code as i32;
        let message = message.into();
        let details = vec![];
        Self {
            code,
            message,
            details,
        }
    }

    constructor! {cancelled, Cancelled}
    constructor! {unknown, Unknown}
    constructor! {invalid_argument, InvalidArgument}
    constructor! {deadline_exceeded, DeadlineExceeded}
    constructor! {not_found, NotFound}
    constructor! {already_exists, AlreadyExists}
    constructor! {permission_denied, PermissionDenied}
    constructor! {unauthenticated, Unauthenticated}
    constructor! {resource_exhausted, ResourceExhausted}
    constructor! {failed_precondition, FailedPrecondition}
    constructor! {aborted, Aborted}
    constructor! {out_of_range, OutOfRange}
    constructor! {unimplemented, Unimplemented}
    constructor! {internal, Internal}
    constructor! {unavailable, Unavailable}
    constructor! {data_loss, DataLoss}

    pub(crate) fn stream_in_use(stream_id: u32) -> Self {
        Self::invalid_argument(format!("Stream `{stream_id}` is already in use"))
    }

    pub(crate) fn invalid_stream_id(stream_id: u32) -> Self {
        Self::invalid_argument(format!("Stream id must be odd, found `{stream_id}`"))
    }

    pub(crate) fn stream_closed(stream_id: u32) -> Self {
        Self::invalid_argument(format!("Channel on stream `{stream_id}` is closed"))
    }

    pub(crate) fn channel_closed() -> Self {
        Self::aborted("Channel closed")
    }

    pub(crate) fn expected_request(stream_id: u32, ty: MessageType) -> Self {
        const TY: MessageType = MessageType::Request;
        let msg = format!("Invalid message type {ty:?} on stream `{stream_id}`, expected {TY:?}",);
        Self::invalid_argument(msg)
    }

    pub(crate) fn method_not_found(service: impl Display, method: impl Display) -> Self {
        let msg = format!("/{service}/{method} is not supported");
        Self::not_found(msg)
    }

    #[expect(clippy::needless_pass_by_value)]
    pub(crate) fn failed_to_decode(err: DecodeError) -> Self {
        Self::invalid_argument(format!("Error decoding message: {err}"))
    }

    #[expect(clippy::needless_pass_by_value)]
    pub(crate) fn send_error(err: SendError) -> Self {
        Self::internal(format!("Error sending message: {err}"))
    }

    pub(crate) fn invalid_request_flags(expected: Flags, actual: Flags) -> Self {
        Self::invalid_argument(format!(
            "Invalid request flags. Expected {expected:?}, found {actual:?}"
        ))
    }

    pub(crate) fn timeout() -> Self {
        Self::deadline_exceeded("Request timed out")
    }

    pub fn from_error(err: impl std::error::Error) -> Self {
        Self::unknown(err.to_string())
    }
}

pub trait StatusExt {
    type Output;
    fn or_status(self, code: Code) -> Result<Self::Output, Status>;
}

impl<T, E: ToString> StatusExt for Result<T, E> {
    type Output = T;
    fn or_status(self, code: Code) -> Result<Self::Output, Status> {
        match self {
            Ok(val) => Ok(val),
            Err(err) => Err(Status {
                code: code as i32,
                message: err.to_string(),
                details: vec![],
            }),
        }
    }
}

impl From<std::io::Error> for Status {
    fn from(error: std::io::Error) -> Self {
        Self::internal(error.to_string())
    }
}

fn code_to_str(code: i32) -> &'static str {
    let Ok(code) = Code::try_from(code) else {
        return "<None>";
    };
    code.as_str_name()
}
