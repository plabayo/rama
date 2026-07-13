/// Get from https://github.com/googleapis/googleapis/blob/master/google/rpc/code.proto
/// The canonical error codes for Google APIs.
///
///
/// Sometimes multiple error codes may apply.  Services should return
/// the most specific error code that applies.  For example, prefer
/// `OUT_OF_RANGE` over `FAILED_PRECONDITION` if both codes apply.
/// Similarly prefer `NOT_FOUND` or `ALREADY_EXISTS` over `FAILED_PRECONDITION`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum Code {
    /// Not an error; returned on success
    ///
    /// HTTP Mapping: 200 OK
    Ok = 0,

    /// The operation was cancelled, typically by the caller.
    ///
    /// HTTP Mapping: 499 Client Closed Request
    Cancelled = 1,

    /// Unknown error.  For example, this error may be returned when
    /// a `Status` value received from another address space belongs to
    /// an error space that is not known in this address space.  Also
    /// errors raised by APIs that do not return enough error information
    /// may be converted to this error.
    ///
    /// HTTP Mapping: 500 Internal Server Error
    Unknown = 2,

    /// The client specified an invalid argument.  Note that this differs
    /// from `FAILED_PRECONDITION`.  `INVALID_ARGUMENT` indicates arguments
    /// that are problematic regardless of the state of the system
    /// (e.g., a malformed file name).
    ///
    /// HTTP Mapping: 400 Bad Request
    InvalidArgument = 3,

    /// The deadline expired before the operation could complete. For operations
    /// that change the state of the system, this error may be returned
    /// even if the operation has completed successfully.  For example, a
    /// successful response from a server could have been delayed long
    /// enough for the deadline to expire.
    ///
    /// HTTP Mapping: 504 Gateway Timeout
    DeadlineExceeded = 4,

    /// Some requested entity (e.g., file or directory) was not found.
    ///
    /// Note to server developers: if a request is denied for an entire class
    /// of users, such as gradual feature rollout or undocumented whitelist,
    /// `NOT_FOUND` may be used. If a request is denied for some users within
    /// a class of users, such as user-based access control, `PERMISSION_DENIED`
    /// must be used.
    ///
    /// HTTP Mapping: 404 Not Found
    NotFound = 5,

    /// The entity that a client attempted to create (e.g., file or directory)
    /// already exists.
    ///
    /// HTTP Mapping: 409 Conflict
    AlreadyExists = 6,

    /// The caller does not have permission to execute the specified
    /// operation. `PERMISSION_DENIED` must not be used for rejections
    /// caused by exhausting some resource (use `RESOURCE_EXHAUSTED`
    /// instead for those errors). `PERMISSION_DENIED` must not be
    /// used if the caller can not be identified (use `UNAUTHENTICATED`
    /// instead for those errors). This error code does not imply the
    /// request is valid or the requested entity exists or satisfies
    /// other pre-conditions.
    ///
    /// HTTP Mapping: 403 Forbidden
    PermissionDenied = 7,

    /// The request does not have valid authentication credentials for the
    /// operation.
    ///
    /// HTTP Mapping: 401 Unauthorized
    Unauthenticated = 16,

    /// Some resource has been exhausted, perhaps a per-user quota, or
    /// perhaps the entire file system is out of space.
    ///
    /// HTTP Mapping: 429 Too Many Requests
    ResourceExhausted = 8,

    /// The operation was rejected because the system is not in a state
    /// required for the operation's execution.  For example, the directory
    /// to be deleted is non-empty, an rmdir operation is applied to
    /// a non-directory, etc.
    ///
    /// Service implementors can use the following guidelines to decide
    /// between `FAILED_PRECONDITION`, `ABORTED`, and `UNAVAILABLE`:
    ///   (a) Use `UNAVAILABLE` if the client can retry just the failing call.
    ///   (b) Use `ABORTED` if the client should retry at a higher level
    ///       (e.g., when a client-specified test-and-set fails, indicating the
    ///       client should restart a read-modify-write sequence).
    ///   (c) Use `FAILED_PRECONDITION` if the client should not retry until
    ///       the system state has been explicitly fixed.  E.g., if an "rmdir"
    ///       fails because the directory is non-empty, `FAILED_PRECONDITION`
    ///       should be returned since the client should not retry unless
    ///       the files are deleted from the directory.
    ///
    /// HTTP Mapping: 400 Bad Request
    FailedPrecondition = 9,

    /// The operation was aborted, typically due to a concurrency issue such as
    /// a sequencer check failure or transaction abort.
    ///
    /// See the guidelines above for deciding between `FAILED_PRECONDITION`,
    /// `ABORTED`, and `UNAVAILABLE`.
    ///
    /// HTTP Mapping: 409 Conflict
    Aborted = 10,

    /// The operation was attempted past the valid range.  E.g., seeking or
    /// reading past end-of-file.
    ///
    /// Unlike `INVALID_ARGUMENT`, this error indicates a problem that may
    /// be fixed if the system state changes. For example, a 32-bit file
    /// system will generate `INVALID_ARGUMENT` if asked to read at an
    /// offset that is not in the range \[0,2^32-1\], but it will generate
    /// `OUT_OF_RANGE` if asked to read from an offset past the current
    /// file size.
    ///
    /// There is a fair bit of overlap between `FAILED_PRECONDITION` and
    /// `OUT_OF_RANGE`.  We recommend using `OUT_OF_RANGE` (the more specific
    /// error) when it applies so that callers who are iterating through
    /// a space can easily look for an `OUT_OF_RANGE` error to detect when
    /// they are done.
    ///
    /// HTTP Mapping: 400 Bad Request
    OutOfRange = 11,

    /// The operation is not implemented or is not supported/enabled in this
    /// service.
    ///
    /// HTTP Mapping: 501 Not Implemented
    Unimplemented = 12,

    /// Internal errors.  This means that some invariants expected by the
    /// underlying system have been broken.  This error code is reserved
    /// for serious errors.
    ///
    /// HTTP Mapping: 500 Internal Server Error
    Internal = 13,

    /// The service is currently unavailable.  This is most likely a
    /// transient condition, which can be corrected by retrying with
    /// a backoff.
    ///
    /// See the guidelines above for deciding between `FAILED_PRECONDITION`,
    /// `ABORTED`, and `UNAVAILABLE`.
    ///
    /// HTTP Mapping: 503 Service Unavailable
    Unavailable = 14,

    /// Unrecoverable data loss or corruption.
    ///
    /// HTTP Mapping: 500 Internal Server Error
    DataLoss = 15,
}

impl Code {
    /// String value of the enum field names used in the protobuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the protobuf definition does not change) and safe for programmatic use.
    #[must_use]
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Cancelled => "CANCELLED",
            Self::Unknown => "UNKNOWN",
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::DeadlineExceeded => "DEADLINE_EXCEEDED",
            Self::NotFound => "NOT_FOUND",
            Self::AlreadyExists => "ALREADY_EXISTS",
            Self::PermissionDenied => "PERMISSION_DENIED",
            Self::Unauthenticated => "UNAUTHENTICATED",
            Self::ResourceExhausted => "RESOURCE_EXHAUSTED",
            Self::FailedPrecondition => "FAILED_PRECONDITION",
            Self::Aborted => "ABORTED",
            Self::OutOfRange => "OUT_OF_RANGE",
            Self::Unimplemented => "UNIMPLEMENTED",
            Self::Internal => "INTERNAL",
            Self::Unavailable => "UNAVAILABLE",
            Self::DataLoss => "DATA_LOSS",
        }
    }

    /// Creates an enum from field names used in the protobuf definition.
    #[must_use]
    pub fn from_str_name(value: &str) -> Option<Self> {
        match value {
            "OK" => Some(Self::Ok),
            "CANCELLED" => Some(Self::Cancelled),
            "UNKNOWN" => Some(Self::Unknown),
            "INVALID_ARGUMENT" => Some(Self::InvalidArgument),
            "DEADLINE_EXCEEDED" => Some(Self::DeadlineExceeded),
            "NOT_FOUND" => Some(Self::NotFound),
            "ALREADY_EXISTS" => Some(Self::AlreadyExists),
            "PERMISSION_DENIED" => Some(Self::PermissionDenied),
            "UNAUTHENTICATED" => Some(Self::Unauthenticated),
            "RESOURCE_EXHAUSTED" => Some(Self::ResourceExhausted),
            "FAILED_PRECONDITION" => Some(Self::FailedPrecondition),
            "ABORTED" => Some(Self::Aborted),
            "OUT_OF_RANGE" => Some(Self::OutOfRange),
            "UNIMPLEMENTED" => Some(Self::Unimplemented),
            "INTERNAL" => Some(Self::Internal),
            "UNAVAILABLE" => Some(Self::Unavailable),
            "DATA_LOSS" => Some(Self::DataLoss),
            _ => None,
        }
    }
}
