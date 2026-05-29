#![expect(
    clippy::allow_attributes,
    reason = "macro-generated `#[allow]` attributes whose underlying lints fire only for some expansions"
)]

use super::{ClassifiedResponse, ClassifyEos, ClassifyResponse, SharedClassifier};
use crate::{HeaderMap, Response};
use bitflags::bitflags;
use percent_encoding::percent_decode;
use std::{fmt, num::NonZeroI32};

/// gRPC status codes. Used in [`GrpcErrorsAsFailures`].
///
/// These variants match the [gRPC status codes].
///
/// [gRPC status codes]: https://github.com/grpc/grpc/blob/master/doc/statuscodes.md#status-codes-and-their-use-in-grpc
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(i32)]
#[non_exhaustive]
pub enum GrpcCode {
    /// The operation completed successfully.
    Ok = 0,
    /// The operation was cancelled.
    Cancelled = 1,
    /// Unknown error.
    Unknown = 2,
    /// Client specified an invalid argument.
    InvalidArgument = 3,
    /// Deadline expired before operation could complete.
    DeadlineExceeded = 4,
    /// Some requested entity was not found.
    NotFound = 5,
    /// Some entity that we attempted to create already exists.
    AlreadyExists = 6,
    /// The caller does not have permission to execute the specified operation.
    PermissionDenied = 7,
    /// Some resource has been exhausted.
    ResourceExhausted = 8,
    /// The system is not in a state required for the operation's execution.
    FailedPrecondition = 9,
    /// The operation was aborted.
    Aborted = 10,
    /// Operation was attempted past the valid range.
    OutOfRange = 11,
    /// Operation is not implemented or not supported.
    Unimplemented = 12,
    /// Internal error.
    Internal = 13,
    /// The service is currently unavailable.
    Unavailable = 14,
    /// Unrecoverable data loss or corruption.
    DataLoss = 15,
    /// The request does not have valid authentication credentials
    Unauthenticated = 16,
}

impl GrpcCode {
    pub(crate) const fn into_bitmask(self) -> GrpcCodeBitmask {
        match self {
            Self::Ok => GrpcCodeBitmask::OK,
            Self::Cancelled => GrpcCodeBitmask::CANCELLED,
            Self::Unknown => GrpcCodeBitmask::UNKNOWN,
            Self::InvalidArgument => GrpcCodeBitmask::INVALID_ARGUMENT,
            Self::DeadlineExceeded => GrpcCodeBitmask::DEADLINE_EXCEEDED,
            Self::NotFound => GrpcCodeBitmask::NOT_FOUND,
            Self::AlreadyExists => GrpcCodeBitmask::ALREADY_EXISTS,
            Self::PermissionDenied => GrpcCodeBitmask::PERMISSION_DENIED,
            Self::ResourceExhausted => GrpcCodeBitmask::RESOURCE_EXHAUSTED,
            Self::FailedPrecondition => GrpcCodeBitmask::FAILED_PRECONDITION,
            Self::Aborted => GrpcCodeBitmask::ABORTED,
            Self::OutOfRange => GrpcCodeBitmask::OUT_OF_RANGE,
            Self::Unimplemented => GrpcCodeBitmask::UNIMPLEMENTED,
            Self::Internal => GrpcCodeBitmask::INTERNAL,
            Self::Unavailable => GrpcCodeBitmask::UNAVAILABLE,
            Self::DataLoss => GrpcCodeBitmask::DATA_LOSS,
            Self::Unauthenticated => GrpcCodeBitmask::UNAUTHENTICATED,
        }
    }

    fn from_i32(code: i32) -> Option<Self> {
        match code {
            0 => Some(Self::Ok),
            1 => Some(Self::Cancelled),
            2 => Some(Self::Unknown),
            3 => Some(Self::InvalidArgument),
            4 => Some(Self::DeadlineExceeded),
            5 => Some(Self::NotFound),
            6 => Some(Self::AlreadyExists),
            7 => Some(Self::PermissionDenied),
            8 => Some(Self::ResourceExhausted),
            9 => Some(Self::FailedPrecondition),
            10 => Some(Self::Aborted),
            11 => Some(Self::OutOfRange),
            12 => Some(Self::Unimplemented),
            13 => Some(Self::Internal),
            14 => Some(Self::Unavailable),
            15 => Some(Self::DataLoss),
            16 => Some(Self::Unauthenticated),
            _ => None,
        }
    }
}

/// Converts an `i32` gRPC status code into a [`GrpcCode`].
///
/// Unrecognized codes (outside 0-16) map to [`GrpcCode::Unknown`].
impl From<i32> for GrpcCode {
    fn from(value: i32) -> Self {
        if value == 2 {
            return Self::Unknown;
        }

        match value {
            0 => Self::Ok,
            1 => Self::Cancelled,
            3 => Self::InvalidArgument,
            4 => Self::DeadlineExceeded,
            5 => Self::NotFound,
            6 => Self::AlreadyExists,
            7 => Self::PermissionDenied,
            8 => Self::ResourceExhausted,
            9 => Self::FailedPrecondition,
            10 => Self::Aborted,
            11 => Self::OutOfRange,
            12 => Self::Unimplemented,
            13 => Self::Internal,
            14 => Self::Unavailable,
            15 => Self::DataLoss,
            16 => Self::Unauthenticated,
            _ => Self::Unknown,
        }
    }
}

impl From<NonZeroI32> for GrpcCode {
    fn from(value: NonZeroI32) -> Self {
        Self::from(value.get())
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub(crate) struct GrpcCodeBitmask: u32 {
        const OK                  = 0b00000000000000001;
        const CANCELLED           = 0b00000000000000010;
        const UNKNOWN             = 0b00000000000000100;
        const INVALID_ARGUMENT    = 0b00000000000001000;
        const DEADLINE_EXCEEDED   = 0b00000000000010000;
        const NOT_FOUND           = 0b00000000000100000;
        const ALREADY_EXISTS      = 0b00000000001000000;
        const PERMISSION_DENIED   = 0b00000000010000000;
        const RESOURCE_EXHAUSTED  = 0b00000000100000000;
        const FAILED_PRECONDITION = 0b00000001000000000;
        const ABORTED             = 0b00000010000000000;
        const OUT_OF_RANGE        = 0b00000100000000000;
        const UNIMPLEMENTED       = 0b00001000000000000;
        const INTERNAL            = 0b00010000000000000;
        const UNAVAILABLE         = 0b00100000000000000;
        const DATA_LOSS           = 0b01000000000000000;
        const UNAUTHENTICATED     = 0b10000000000000000;
    }
}

impl From<GrpcCode> for GrpcCodeBitmask {
    fn from(code: GrpcCode) -> Self {
        match code {
            GrpcCode::Ok => Self::OK,
            GrpcCode::Cancelled => Self::CANCELLED,
            GrpcCode::Unknown => Self::UNKNOWN,
            GrpcCode::InvalidArgument => Self::INVALID_ARGUMENT,
            GrpcCode::DeadlineExceeded => Self::DEADLINE_EXCEEDED,
            GrpcCode::NotFound => Self::NOT_FOUND,
            GrpcCode::AlreadyExists => Self::ALREADY_EXISTS,
            GrpcCode::PermissionDenied => Self::PERMISSION_DENIED,
            GrpcCode::ResourceExhausted => Self::RESOURCE_EXHAUSTED,
            GrpcCode::FailedPrecondition => Self::FAILED_PRECONDITION,
            GrpcCode::Aborted => Self::ABORTED,
            GrpcCode::OutOfRange => Self::OUT_OF_RANGE,
            GrpcCode::Unimplemented => Self::UNIMPLEMENTED,
            GrpcCode::Internal => Self::INTERNAL,
            GrpcCode::Unavailable => Self::UNAVAILABLE,
            GrpcCode::DataLoss => Self::DATA_LOSS,
            GrpcCode::Unauthenticated => Self::UNAUTHENTICATED,
        }
    }
}

/// Response classifier for gRPC responses.
///
/// gRPC doesn't use normal HTTP statuses for indicating success or failure but instead a special
/// header that might appear in a trailer.
///
/// Responses are considered successful if
///
/// - `grpc-status` header value contains a success value.
/// - `grpc-status` header is missing.
/// - `grpc-status` header value isn't a valid `String`.
/// - `grpc-status` header value can't parsed into an `i32`.
///
/// All others are considered failures.
#[derive(Debug, Clone)]
pub struct GrpcErrorsAsFailures {
    success_codes: GrpcCodeBitmask,
}

impl Default for GrpcErrorsAsFailures {
    fn default() -> Self {
        Self::new()
    }
}

impl GrpcErrorsAsFailures {
    /// Create a new [`GrpcErrorsAsFailures`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            success_codes: GrpcCodeBitmask::OK,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Change which gRPC codes are considered success.
        ///
        /// Defaults to only considering `Ok` as success.
        ///
        /// `Ok` will always be considered a success.
        pub fn success(mut self, code: GrpcCode) -> Self {
            self.success_codes |= code.into_bitmask();
            self
        }
    }

    /// Returns a [`MakeClassifier`](super::MakeClassifier) that produces `GrpcErrorsAsFailures`.
    ///
    /// This is a convenience function that simply calls `SharedClassifier::new`.
    #[must_use]
    pub fn make_classifier() -> SharedClassifier<Self> {
        SharedClassifier::new(Self::new())
    }
}

impl ClassifyResponse for GrpcErrorsAsFailures {
    type FailureClass = GrpcFailureClass;
    type ClassifyEos = GrpcEosErrorsAsFailures;

    fn classify_response<B>(
        self,
        res: &Response<B>,
    ) -> ClassifiedResponse<Self::FailureClass, Self::ClassifyEos> {
        match classify_grpc_metadata(res.headers(), self.success_codes) {
            ParsedGrpcStatus::Success | ParsedGrpcStatus::HeaderNotGrpcCode => {
                ClassifiedResponse::Ready(Ok(()))
            }
            ParsedGrpcStatus::NonSuccess(status) => {
                ClassifiedResponse::Ready(Err(GrpcFailureClass::Status(status)))
            }
            ParsedGrpcStatus::GrpcStatusHeaderMissing => {
                ClassifiedResponse::RequiresEos(GrpcEosErrorsAsFailures {
                    success_codes: self.success_codes,
                })
            }
        }
    }

    fn classify_error<E>(self, error: &E) -> Self::FailureClass
    where
        E: fmt::Display,
    {
        GrpcFailureClass::Error(error.to_string())
    }
}

/// The [`ClassifyEos`] for [`GrpcErrorsAsFailures`].
#[derive(Debug, Clone)]
pub struct GrpcEosErrorsAsFailures {
    success_codes: GrpcCodeBitmask,
}

impl ClassifyEos for GrpcEosErrorsAsFailures {
    type FailureClass = GrpcFailureClass;

    fn classify_eos(self, trailers: Option<&HeaderMap>) -> Result<(), Self::FailureClass> {
        if let Some(trailers) = trailers {
            match classify_grpc_metadata(trailers, self.success_codes) {
                ParsedGrpcStatus::Success
                | ParsedGrpcStatus::GrpcStatusHeaderMissing
                | ParsedGrpcStatus::HeaderNotGrpcCode => Ok(()),
                ParsedGrpcStatus::NonSuccess(status) => Err(GrpcFailureClass::Status(status)),
            }
        } else {
            Ok(())
        }
    }

    fn classify_error<E>(self, error: &E) -> Self::FailureClass
    where
        E: fmt::Display,
    {
        GrpcFailureClass::Error(error.to_string())
    }
}

impl Default for GrpcEosErrorsAsFailures {
    fn default() -> Self {
        Self {
            success_codes: GrpcCodeBitmask::OK,
        }
    }
}

/// The failure class for [`GrpcErrorsAsFailures`].
#[derive(Debug)]
#[non_exhaustive]
pub enum GrpcFailureClass {
    /// A gRPC response was classified as a failure with the corresponding status.
    Status(GrpcStatus),
    /// A gRPC response was classified as an error with the corresponding error description.
    Error(String),
}

impl fmt::Display for GrpcFailureClass {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Status(status) => write!(f, "Status: {status}"),
            Self::Error(error) => write!(f, "Error: {error}"),
        }
    }
}

impl std::error::Error for GrpcFailureClass {}

#[allow(clippy::match_result_ok)]
pub(crate) fn classify_grpc_metadata(
    headers: &HeaderMap,
    success_codes: GrpcCodeBitmask,
) -> ParsedGrpcStatus {
    macro_rules! or_else {
        ($expr:expr, $other:ident) => {
            if let Some(value) = $expr {
                value
            } else {
                return ParsedGrpcStatus::$other;
            }
        };
    }

    let code_header = or_else!(headers.get("grpc-status"), GrpcStatusHeaderMissing);
    let code_value: i32 = or_else!(
        code_header.to_str().ok().and_then(|s| s.parse().ok()),
        HeaderNotGrpcCode
    );
    let grpc_code = GrpcCode::from_i32(code_value);

    if let Some(code) = grpc_code
        && success_codes.contains(GrpcCodeBitmask::from(code))
    {
        return ParsedGrpcStatus::Success;
    }

    let message = headers.get("grpc-message").map(|header| {
        percent_decode(header.as_bytes())
            .decode_utf8_lossy()
            .into_owned()
    });

    ParsedGrpcStatus::NonSuccess(GrpcStatus {
        code: grpc_code,
        code_raw: code_value,
        message,
    })
}

/// A gRPC status extracted from response headers/trailers.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct GrpcStatus {
    code: Option<GrpcCode>,
    code_raw: i32,
    message: Option<String>,
}

impl GrpcStatus {
    /// Returns the status code as a [`GrpcCode`], or `None` if the code is not recognized.
    pub fn code(&self) -> Option<GrpcCode> {
        self.code
    }

    /// Returns the raw integer status code.
    pub fn code_raw(&self) -> i32 {
        self.code_raw
    }

    /// Returns the percent-decoded gRPC error message, if present.
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
}

impl fmt::Display for GrpcStatus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.code {
            Some(code) => write!(f, "{code:?}")?,
            None => write!(f, "Code({})", self.code_raw)?,
        }
        if let Some(message) = self.message.as_ref() {
            write!(f, ": {message}")?;
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub(crate) enum ParsedGrpcStatus {
    Success,
    NonSuccess(GrpcStatus),
    GrpcStatusHeaderMissing,
    // this is treated as `Success` but kept separate for clarity
    HeaderNotGrpcCode,
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! classify_grpc_metadata_test {
        (
            name: $name:ident,
            status: $status:expr,
            success_flags: $success_flags:expr,
            expected: $expected:expr,
        ) => {
            classify_grpc_metadata_test!(
                name: $name,
                status: $status,
                message: "",
                success_flags: $success_flags,
                expected: $expected,
            );
        };
        (
            name: $name:ident,
            status: $status:expr,
            message: $message:expr,
            success_flags: $success_flags:expr,
            expected: $expected:expr,
        ) => {
            #[test]
            fn $name() {
                let mut headers = HeaderMap::new();
                headers.insert("grpc-status", $status.parse().unwrap());
                if !$message.is_empty() {
                    headers.insert("grpc-message", $message.parse().unwrap());
                }
                let status = classify_grpc_metadata(&headers, $success_flags);
                assert_eq!(status, $expected);
            }
        };
    }

    classify_grpc_metadata_test! {
        name: basic_ok,
        status: "0",
        success_flags: GrpcCodeBitmask::OK,
        expected: ParsedGrpcStatus::Success,
    }

    classify_grpc_metadata_test! {
        name: basic_error,
        status: "1",
        success_flags: GrpcCodeBitmask::OK,
        expected: ParsedGrpcStatus::NonSuccess(GrpcStatus{
            code: Some(GrpcCode::Cancelled),
            code_raw: 1,
            message: None,
        }),
    }

    classify_grpc_metadata_test! {
        name: two_success_codes_first_matches,
        status: "0",
        success_flags: GrpcCodeBitmask::OK | GrpcCodeBitmask::INVALID_ARGUMENT,
        expected: ParsedGrpcStatus::Success,
    }

    classify_grpc_metadata_test! {
        name: two_success_codes_second_matches,
        status: "3",
        success_flags: GrpcCodeBitmask::OK | GrpcCodeBitmask::INVALID_ARGUMENT,
        expected: ParsedGrpcStatus::Success,
    }

    classify_grpc_metadata_test! {
        name: two_success_codes_none_matches,
        status: "16",
        message: "mock message",
        success_flags: GrpcCodeBitmask::OK | GrpcCodeBitmask::INVALID_ARGUMENT,
        expected: ParsedGrpcStatus::NonSuccess(GrpcStatus{
            code: Some(GrpcCode::Unauthenticated),
            code_raw: 16,
            message: Some("mock message".to_owned()),
        }),
    }

    classify_grpc_metadata_test! {
        name: percent_encoded_message,
        status: "2",
        message: "hello%20world",
        success_flags: GrpcCodeBitmask::OK,
        expected: ParsedGrpcStatus::NonSuccess(GrpcStatus{
            code: Some(GrpcCode::Unknown),
            code_raw: 2,
            message: Some("hello world".to_owned()),
        }),
    }

    classify_grpc_metadata_test! {
        name: invalid_percent_encoding,
        status: "13",
        message: "bad%2Gencode",
        success_flags: GrpcCodeBitmask::OK,
        expected: ParsedGrpcStatus::NonSuccess(GrpcStatus{
            code: Some(GrpcCode::Internal),
            code_raw: 13,
            message: Some("bad%2Gencode".to_owned()),
        }),
    }

    classify_grpc_metadata_test! {
        name: empty_grpc_message,
        status: "5",
        message: "",
        success_flags: GrpcCodeBitmask::OK,
        expected: ParsedGrpcStatus::NonSuccess(GrpcStatus{
            code: Some(GrpcCode::NotFound),
            code_raw: 5,
            message: None,
        }),
    }

    classify_grpc_metadata_test! {
        name: unknown_status_code_above_16,
        status: "99",
        message: "custom error",
        success_flags: GrpcCodeBitmask::OK,
        expected: ParsedGrpcStatus::NonSuccess(GrpcStatus{
            code: None,
            code_raw: 99,
            message: Some("custom error".to_owned()),
        }),
    }

    #[test]
    fn invalid_utf8_after_percent_decode() {
        let mut headers = HeaderMap::new();
        headers.insert("grpc-status", "2".parse().unwrap());
        // %80 is an invalid UTF-8 start byte; lossy decode replaces it with U+FFFD
        headers.insert("grpc-message", "bad%80byte".parse().unwrap());
        let status = classify_grpc_metadata(&headers, GrpcCodeBitmask::OK);
        assert_eq!(
            status,
            ParsedGrpcStatus::NonSuccess(GrpcStatus {
                code: Some(GrpcCode::Unknown),
                code_raw: 2,
                message: Some("bad\u{FFFD}byte".to_owned()),
            })
        );
    }

    #[test]
    fn valid_utf8_percent_encoded() {
        let mut headers = HeaderMap::new();
        headers.insert("grpc-status", "3".parse().unwrap());
        // %C3%A9 is the percent-encoded form of 'é' (U+00E9) in UTF-8
        headers.insert("grpc-message", "caf%C3%A9".parse().unwrap());
        let status = classify_grpc_metadata(&headers, GrpcCodeBitmask::OK);
        assert_eq!(
            status,
            ParsedGrpcStatus::NonSuccess(GrpcStatus {
                code: Some(GrpcCode::InvalidArgument),
                code_raw: 3,
                message: Some("café".to_owned()),
            })
        );
    }

    #[test]
    fn grpc_ok_classified_as_success() {
        let res = Response::builder()
            .header("grpc-status", "0")
            .body(())
            .unwrap();

        let classifier = GrpcErrorsAsFailures::new();
        let result = classifier.classify_response(&res);
        assert!(matches!(result, ClassifiedResponse::Ready(Ok(()))));
    }

    #[test]
    fn grpc_code_from_i32_known_codes() {
        assert!(matches!(GrpcCode::from(0), GrpcCode::Ok));
        assert!(matches!(GrpcCode::from(1), GrpcCode::Cancelled));
        assert!(matches!(GrpcCode::from(4), GrpcCode::DeadlineExceeded));
        assert!(matches!(GrpcCode::from(13), GrpcCode::Internal));
        assert!(matches!(GrpcCode::from(16), GrpcCode::Unauthenticated));
    }

    #[test]
    fn grpc_code_from_i32_unknown_codes() {
        assert!(matches!(GrpcCode::from(17), GrpcCode::Unknown));
        assert!(matches!(GrpcCode::from(-1), GrpcCode::Unknown));
        assert!(matches!(GrpcCode::from(9999), GrpcCode::Unknown));
    }

    #[test]
    fn grpc_code_from_non_zero_i32() {
        let code = NonZeroI32::new(7).unwrap();
        assert!(matches!(GrpcCode::from(code), GrpcCode::PermissionDenied));

        let code = NonZeroI32::new(99).unwrap();
        assert!(matches!(GrpcCode::from(code), GrpcCode::Unknown));
    }
}
