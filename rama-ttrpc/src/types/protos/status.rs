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

    pub(crate) fn stream_id_not_increasing(stream_id: u32, last_stream_id: u32) -> Self {
        Self::invalid_argument(format!(
            "Stream id `{stream_id}` must be greater than the last request id `{last_stream_id}`"
        ))
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

    /// Unknown service or method. `UNIMPLEMENTED`, matching the Go implementation
    /// (containerd/ttrpc services.go `codes.Unimplemented`), which capability-probing
    /// clients (e.g. NRI) branch on.
    pub(crate) fn method_unimplemented(service: impl Display, method: impl Display) -> Self {
        let msg = format!("/{service}/{method} is not supported");
        Self::unimplemented(msg)
    }

    #[expect(clippy::needless_pass_by_value)]
    pub(crate) fn failed_to_decode(err: DecodeError) -> Self {
        // An oversized message is a resource rejection, not a malformed one
        // (containerd/ttrpc channel.go responds `codes.ResourceExhausted`).
        let code = match &err {
            DecodeError::OversizedMessage { .. } => Code::ResourceExhausted,
            _ => Code::InvalidArgument,
        };
        Self::new(code, format!("Error decoding message: {err}"))
    }

    #[expect(clippy::needless_pass_by_value)]
    pub(crate) fn send_error(err: SendError) -> Self {
        Self::internal(format!("Error sending message: {err}"))
    }

    pub(crate) fn invalid_request_flags(actual: Flags, requirement: &'static str) -> Self {
        Self::invalid_argument(format!("Invalid request flags {actual:?}: {requirement}"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_constructors_carry_code_and_context() {
        let cases: [(Status, Code, &str); 9] = [
            (Status::stream_in_use(7), Code::InvalidArgument, "7"),
            (Status::invalid_stream_id(4), Code::InvalidArgument, "4"),
            (
                Status::stream_id_not_increasing(3, 5),
                Code::InvalidArgument,
                "5",
            ),
            (Status::stream_closed(9), Code::InvalidArgument, "9"),
            (Status::channel_closed(), Code::Aborted, "closed"),
            (
                Status::expected_request(3, MessageType::Data),
                Code::InvalidArgument,
                "Data",
            ),
            (
                Status::method_unimplemented("svc", "m"),
                Code::Unimplemented,
                "/svc/m",
            ),
            (Status::timeout(), Code::DeadlineExceeded, "timed out"),
            (
                Status::invalid_request_flags(Flags::REMOTE_OPEN, "not like this"),
                Code::InvalidArgument,
                "not like this",
            ),
        ];
        for (status, code, needle) in cases {
            assert_eq!(status.code, code as i32, "{status}");
            assert!(status.message.contains(needle), "{status}");
        }

        let oversized =
            Status::failed_to_decode(DecodeError::OversizedMessage { length: 5, max: 4 });
        assert_eq!(oversized.code, Code::ResourceExhausted as i32);
        let malformed = Status::failed_to_decode(DecodeError::UnexpectedEof);
        assert_eq!(malformed.code, Code::InvalidArgument as i32);

        let send = Status::send_error(SendError::channel_closed());
        assert_eq!(send.code, Code::Internal as i32);

        let io: Status = std::io::Error::other("io boom").into();
        assert_eq!(io.code, Code::Internal as i32);
        assert!(io.message.contains("io boom"));

        let from_err = Status::from_error(std::io::Error::other("generic"));
        assert_eq!(from_err.code, Code::Unknown as i32);
    }

    #[test]
    fn display_names_the_code() {
        let status = Status::new(Code::NotFound, "nothing here");
        let shown = status.to_string();
        assert!(shown.contains("NOT_FOUND"), "{shown}");
        assert!(shown.contains("nothing here"), "{shown}");
        assert_eq!(code_to_str(9999), "<None>");
    }

    #[test]
    fn or_status_maps_err_to_code() {
        let ok: Result<u8, std::io::Error> = Ok(1);
        assert_eq!(ok.or_status(Code::Internal).expect("stays ok"), 1);

        let err: Result<u8, std::io::Error> = Err(std::io::Error::other("nope"));
        let status = err.or_status(Code::Aborted).expect_err("becomes status");
        assert_eq!(status.code, Code::Aborted as i32);
        assert!(status.message.contains("nope"));
    }
}
