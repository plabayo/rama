use std::{borrow::Cow, error::Error, fmt, sync::Arc};

use base64::Engine as _;
use rama_core::telemetry::tracing;
use rama_utils::str::arcstr::ArcStr;

use ::{
    rama_core::{
        bytes::Bytes,
        extensions::ExtensionsMut as _,
        telemetry::tracing::{debug, trace, warn},
    },
    rama_http_types::{
        HeaderName,
        header::{HeaderMap, HeaderValue},
    },
    rama_net::uri::util::percent_encoding::{AsciiSet, CONTROLS, percent_decode, percent_encode},
};

use crate::metadata::GRPC_CONTENT_TYPE;
use crate::metadata::MetadataMap;

const ENCODING_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'`')
    .add(b'?')
    .add(b'{')
    .add(b'}');

/// A gRPC status describing the result of an RPC call.
///
/// Values can be created using the `new` function or one of the specialized
/// associated functions.
/// ```rust
/// # use rama_grpc::{Status, Code};
/// let status1 = Status::new(Code::InvalidArgument, "name is invalid");
/// let status2 = Status::invalid_argument("name is invalid");
///
/// assert_eq!(status1.code(), Code::InvalidArgument);
/// assert_eq!(status1.code(), status2.code());
/// ```
#[derive(Clone)]
pub struct Status(Box<StatusInner>);

/// Box the contents of Status to avoid large error variants
#[derive(Clone)]
struct StatusInner {
    /// The gRPC status code, found in the `grpc-status` header.
    code: Code,
    /// A relevant error message, found in the `grpc-message` header.
    message: ArcStr,
    /// Binary opaque details, found in the `grpc-status-details-bin` header.
    details: Bytes,
    /// Custom metadata, found in the user-defined headers.
    /// If the metadata contains any headers with names reserved either by the gRPC spec
    /// or by `Status` fields above, they will be ignored.
    metadata: MetadataMap,
    /// Optional underlying error.
    source: Option<Arc<dyn Error + Send + Sync + 'static>>,
}

impl StatusInner {
    fn into_status(self) -> Status {
        Status(Box::new(self))
    }
}

/// gRPC status codes used by [`Status`].
///
/// These variants match the [gRPC status codes].
///
/// [gRPC status codes]: https://github.com/grpc/grpc/blob/master/doc/statuscodes.md#status-codes-and-their-use-in-grpc
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Code {
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

impl Code {
    /// Get description of this `Code`.
    /// ```
    /// fn make_grpc_request() -> rama_grpc::Code {
    ///     // ...
    ///     rama_grpc::Code::Ok
    /// }
    /// let code = make_grpc_request();
    /// println!("Operation completed. Human readable description: {}", code.description());
    /// ```
    /// If you only need description in `println`, `format`, `log` and other
    /// formatting contexts, you may want to use `Display` impl for `Code`
    /// instead.
    #[must_use]
    pub fn description(&self) -> &'static str {
        match self {
            Self::Ok => "The operation completed successfully",
            Self::Cancelled => "The operation was cancelled",
            Self::Unknown => "Unknown error",
            Self::InvalidArgument => "Client specified an invalid argument",
            Self::DeadlineExceeded => "Deadline expired before operation could complete",
            Self::NotFound => "Some requested entity was not found",
            Self::AlreadyExists => "Some entity that we attempted to create already exists",
            Self::PermissionDenied => {
                "The caller does not have permission to execute the specified operation"
            }
            Self::ResourceExhausted => "Some resource has been exhausted",
            Self::FailedPrecondition => {
                "The system is not in a state required for the operation's execution"
            }
            Self::Aborted => "The operation was aborted",
            Self::OutOfRange => "Operation was attempted past the valid range",
            Self::Unimplemented => "Operation is not implemented or not supported",
            Self::Internal => "Internal error",
            Self::Unavailable => "The service is currently unavailable",
            Self::DataLoss => "Unrecoverable data loss or corruption",
            Self::Unauthenticated => "The request does not have valid authentication credentials",
        }
    }
}

impl std::fmt::Display for Code {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self.description(), f)
    }
}

// ===== impl Status =====

impl Status {
    /// Create a new `Status` with the associated code and message.
    pub fn new(code: Code, message: impl Into<ArcStr>) -> Self {
        StatusInner {
            code,
            message: message.into(),
            details: Bytes::new(),
            metadata: MetadataMap::new(),
            source: None,
        }
        .into_status()
    }

    /// The operation completed successfully.
    pub fn ok(message: impl Into<ArcStr>) -> Self {
        Self::new(Code::Ok, message)
    }

    /// The operation was cancelled (typically by the caller).
    pub fn cancelled(message: impl Into<ArcStr>) -> Self {
        Self::new(Code::Cancelled, message)
    }

    /// Unknown error. An example of where this error may be returned is if a
    /// `Status` value received from another address space belongs to an error-space
    /// that is not known in this address space. Also errors raised by APIs that
    /// do not return enough error information may be converted to this error.
    pub fn unknown(message: impl Into<ArcStr>) -> Self {
        Self::new(Code::Unknown, message)
    }

    /// Client specified an invalid argument. Note that this differs from
    /// `FailedPrecondition`. `InvalidArgument` indicates arguments that are
    /// problematic regardless of the state of the system (e.g., a malformed file
    /// name).
    pub fn invalid_argument(message: impl Into<ArcStr>) -> Self {
        Self::new(Code::InvalidArgument, message)
    }

    /// Deadline expired before operation could complete. For operations that
    /// change the state of the system, this error may be returned even if the
    /// operation has completed successfully. For example, a successful response
    /// from a server could have been delayed long enough for the deadline to
    /// expire.
    pub fn deadline_exceeded(message: impl Into<ArcStr>) -> Self {
        Self::new(Code::DeadlineExceeded, message)
    }

    /// Some requested entity (e.g., file or directory) was not found.
    pub fn not_found(message: impl Into<ArcStr>) -> Self {
        Self::new(Code::NotFound, message)
    }

    /// Some entity that we attempted to create (e.g., file or directory) already
    /// exists.
    pub fn already_exists(message: impl Into<ArcStr>) -> Self {
        Self::new(Code::AlreadyExists, message)
    }

    /// The caller does not have permission to execute the specified operation.
    /// `PermissionDenied` must not be used for rejections caused by exhausting
    /// some resource (use `ResourceExhausted` instead for those errors).
    /// `PermissionDenied` must not be used if the caller cannot be identified
    /// (use `Unauthenticated` instead for those errors).
    pub fn permission_denied(message: impl Into<ArcStr>) -> Self {
        Self::new(Code::PermissionDenied, message)
    }

    /// Some resource has been exhausted, perhaps a per-user quota, or perhaps
    /// the entire file system is out of space.
    pub fn resource_exhausted(message: impl Into<ArcStr>) -> Self {
        Self::new(Code::ResourceExhausted, message)
    }

    /// Operation was rejected because the system is not in a state required for
    /// the operation's execution. For example, directory to be deleted may be
    /// non-empty, an rmdir operation is applied to a non-directory, etc.
    ///
    /// A litmus test that may help a service implementor in deciding between
    /// `FailedPrecondition`, `Aborted`, and `Unavailable`:
    /// (a) Use `Unavailable` if the client can retry just the failing call.
    /// (b) Use `Aborted` if the client should retry at a higher-level (e.g.,
    ///     restarting a read-modify-write sequence).
    /// (c) Use `FailedPrecondition` if the client should not retry until the
    ///     system state has been explicitly fixed.  E.g., if an "rmdir" fails
    ///     because the directory is non-empty, `FailedPrecondition` should be
    ///     returned since the client should not retry unless they have first
    ///     fixed up the directory by deleting files from it.
    pub fn failed_precondition(message: impl Into<ArcStr>) -> Self {
        Self::new(Code::FailedPrecondition, message)
    }

    /// The operation was aborted, typically due to a concurrency issue like
    /// sequencer check failures, transaction aborts, etc.
    ///
    /// See litmus test above for deciding between `FailedPrecondition`,
    /// `Aborted`, and `Unavailable`.
    pub fn aborted(message: impl Into<ArcStr>) -> Self {
        Self::new(Code::Aborted, message)
    }

    /// Operation was attempted past the valid range. E.g., seeking or reading
    /// past end of file.
    ///
    /// Unlike `InvalidArgument`, this error indicates a problem that may be
    /// fixed if the system state changes. For example, a 32-bit file system will
    /// generate `InvalidArgument` if asked to read at an offset that is not in the
    /// range [0,2^32-1], but it will generate `OutOfRange` if asked to read from
    /// an offset past the current file size.
    ///
    /// There is a fair bit of overlap between `FailedPrecondition` and
    /// `OutOfRange`. We recommend using `OutOfRange` (the more specific error)
    /// when it applies so that callers who are iterating through a space can
    /// easily look for an `OutOfRange` error to detect when they are done.
    pub fn out_of_range(message: impl Into<ArcStr>) -> Self {
        Self::new(Code::OutOfRange, message)
    }

    /// Operation is not implemented or not supported/enabled in this service.
    pub fn unimplemented(message: impl Into<ArcStr>) -> Self {
        Self::new(Code::Unimplemented, message)
    }

    /// Internal errors. Means some invariants expected by underlying system has
    /// been broken. If you see one of these errors, something is very broken.
    pub fn internal(message: impl Into<ArcStr>) -> Self {
        Self::new(Code::Internal, message)
    }

    /// The service is currently unavailable.  This is a most likely a transient
    /// condition and may be corrected by retrying with a back-off.
    ///
    /// See litmus test above for deciding between `FailedPrecondition`,
    /// `Aborted`, and `Unavailable`.
    pub fn unavailable(message: impl Into<ArcStr>) -> Self {
        Self::new(Code::Unavailable, message)
    }

    /// Unrecoverable data loss or corruption.
    pub fn data_loss(message: impl Into<ArcStr>) -> Self {
        Self::new(Code::DataLoss, message)
    }

    /// The request does not have valid authentication credentials for the
    /// operation.
    pub fn unauthenticated(message: impl Into<ArcStr>) -> Self {
        Self::new(Code::Unauthenticated, message)
    }

    pub(crate) fn from_error_generic(
        err: impl Into<Box<dyn Error + Send + Sync + 'static>>,
    ) -> Self {
        Self::from_error(err.into())
    }

    /// Create a `Status` from various types of `Error`.
    ///
    /// Inspects the error source chain for recognizable errors, including statuses and
    /// `rama-http-core`, and attempts to maps them to a `Status`, or else returns an Unknown `Status`.
    #[must_use]
    pub fn from_error(err: Box<dyn Error + Send + Sync + 'static>) -> Self {
        Self::try_from_error(err).unwrap_or_else(|err| {
            let mut status = Self::new(Code::Unknown, err.to_string());
            status.0.source = Some(err.into());
            status
        })
    }

    /// Create a `Status` from various types of `Error`.
    ///
    /// Returns the error if a status could not be created.
    ///
    /// # Downcast stability
    /// This function does not provide any stability guarantees around how it will downcast errors into
    /// status codes.
    pub fn try_from_error(
        err: Box<dyn Error + Send + Sync + 'static>,
    ) -> Result<Self, Box<dyn Error + Send + Sync + 'static>> {
        let err = match err.downcast::<Self>() {
            Ok(status) => {
                return Ok(*status);
            }
            Err(err) => err,
        };

        #[cfg(feature = "transport")]
        let err = match err.downcast::<rama_http_core::h2::Error>() {
            Ok(h2) => {
                return Ok(Self::from_h2_error(h2));
            }
            Err(err) => err,
        };

        // TOOD: if in future we have tower-like load-shed capabilities
        // we can react here with `Status::resource_exhausted` when overloaded...
        // (see `tonic::status`)

        if let Some(mut status) = find_status_in_source_chain(&*err) {
            status.0.source = Some(err.into());
            return Ok(status);
        }

        Err(err)
    }

    // FIXME: bubble this into `transport` and expose generic http2 reasons.
    #[cfg(feature = "transport")]
    fn from_h2_error(err: Box<rama_http_core::h2::Error>) -> Self {
        let code = Self::code_from_h2(&err);

        let mut status = Self::new(code, format!("h2 protocol error: {err}"));
        status.0.source = Some(Arc::new(*err));
        status
    }

    #[cfg(feature = "transport")]
    fn code_from_h2(err: &rama_http_core::h2::Error) -> Code {
        // See https://github.com/grpc/grpc/blob/3977c30/doc/PROTOCOL-HTTP2.md#errors
        match err.reason() {
            Some(
                rama_http_core::h2::Reason::NO_ERROR
                | rama_http_core::h2::Reason::PROTOCOL_ERROR
                | rama_http_core::h2::Reason::INTERNAL_ERROR
                | rama_http_core::h2::Reason::FLOW_CONTROL_ERROR
                | rama_http_core::h2::Reason::SETTINGS_TIMEOUT
                | rama_http_core::h2::Reason::COMPRESSION_ERROR
                | rama_http_core::h2::Reason::CONNECT_ERROR,
            ) => Code::Internal,
            Some(rama_http_core::h2::Reason::REFUSED_STREAM) => Code::Unavailable,
            Some(rama_http_core::h2::Reason::CANCEL) => Code::Cancelled,
            Some(rama_http_core::h2::Reason::ENHANCE_YOUR_CALM) => Code::ResourceExhausted,
            Some(rama_http_core::h2::Reason::INADEQUATE_SECURITY) => Code::PermissionDenied,

            _ => Code::Unknown,
        }
    }

    #[cfg(feature = "transport")]
    fn to_h2_error(&self) -> rama_http_core::h2::Error {
        // conservatively transform to h2 error codes...
        let reason = match self.code() {
            Code::Cancelled => rama_http_core::h2::Reason::CANCEL,
            _ => rama_http_core::h2::Reason::INTERNAL_ERROR,
        };

        reason.into()
    }

    /// Handles http (core) errors specifically
    ///
    /// These expose a number of different parameters about the http stream's error.
    ///
    /// Returns Some if there's a way to handle the error, or None if the information from this
    /// rama-http-core error, but perhaps not its source, should be ignored.
    #[cfg(feature = "transport")]
    fn from_http_error(err: &rama_http_core::Error) -> Option<Self> {
        // is_timeout results from hyper's keep-alive logic
        // (https://docs.rs/hyper/0.14.11/src/hyper/error.rs.html#192-194).  Per the grpc spec
        // > An expired client initiated PING will cause all calls to be closed with an UNAVAILABLE
        // > status. Note that the frequency of PINGs is highly dependent on the network
        // > environment, implementations are free to adjust PING frequency based on network and
        // > application requirements, which is why it's mapped to unavailable here.
        if err.is_timeout() {
            return Some(Self::unavailable(err.to_string()));
        }

        if err.is_canceled() {
            return Some(Self::cancelled(err.to_string()));
        }

        if let Some(h2_err) = err
            .source()
            .and_then(|e| e.downcast_ref::<rama_http_core::h2::Error>())
        {
            let code = Self::code_from_h2(h2_err);
            let status = Self::new(code, format!("h2 protocol error: {err}"));

            return Some(status);
        }

        None
    }

    pub(crate) fn map_error<E>(err: E) -> Self
    where
        E: Into<Box<dyn Error + Send + Sync>>,
    {
        let err: Box<dyn Error + Send + Sync> = err.into();
        Self::from_error(err)
    }

    /// Extract a [`Status`] from a [`rama_http_types::HeaderMap`].
    pub fn from_header_map(header_map: &HeaderMap) -> Option<Self> {
        let code = Code::from_bytes(header_map.get(Self::GRPC_STATUS)?.as_ref());

        let error_message = match header_map.get(Self::GRPC_MESSAGE) {
            Some(header) => percent_decode(header.as_bytes())
                .decode_utf8()
                .map(|cow| cow.into()),
            None => Ok(ArcStr::new()),
        };

        let details = match header_map.get(Self::GRPC_STATUS_DETAILS) {
            Some(header) => match crate::util::base64::STANDARD.decode(header.as_bytes()) {
                Ok(v) => v.into(),
                Err(err) => {
                    tracing::debug!("failed to b64 decode grpc status details: {err}");
                    Bytes::new()
                }
            },
            None => Bytes::new(),
        };

        let other_headers = {
            let mut header_map = header_map.clone();
            header_map.remove(Self::GRPC_STATUS);
            header_map.remove(Self::GRPC_MESSAGE);
            header_map.remove(Self::GRPC_STATUS_DETAILS);
            header_map
        };

        let (code, message) = match error_message {
            Ok(message) => (code, message),
            Err(e) => {
                let error_message =
                    format!("Error deserializing status message header: {e}").into();
                warn!("{error_message}");
                (Code::Unknown, error_message)
            }
        };

        Some(
            StatusInner {
                code,
                message,
                details,
                metadata: MetadataMap::from_headers(other_headers),
                source: None,
            }
            .into_status(),
        )
    }

    /// Get the gRPC `Code` of this `Status`.
    #[must_use]
    pub fn code(&self) -> Code {
        self.0.code
    }

    /// Get the text error message of this `Status`.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.0.message
    }

    /// Get the opaque error details of this `Status`.
    #[must_use]
    pub fn details(&self) -> &[u8] {
        &self.0.details
    }

    /// Get a reference to the custom metadata.
    #[must_use]
    pub fn metadata(&self) -> &MetadataMap {
        &self.0.metadata
    }

    /// Get a mutable reference to the custom metadata.
    pub fn metadata_mut(&mut self) -> &mut MetadataMap {
        &mut self.0.metadata
    }

    pub(crate) fn to_header_map(&self) -> Result<HeaderMap, Self> {
        let mut header_map = HeaderMap::with_capacity(3 + self.0.metadata.len());
        self.add_header(&mut header_map)?;
        Ok(header_map)
    }

    /// Add headers from this `Status` into `header_map`.
    pub fn add_header(&self, header_map: &mut HeaderMap) -> Result<(), Self> {
        header_map.extend(self.0.metadata.clone().into_sanitized_headers());

        header_map.insert(Self::GRPC_STATUS, self.0.code.to_header_value());

        if !self.0.message.is_empty() {
            let to_write = Bytes::copy_from_slice(
                Cow::from(percent_encode(self.message().as_bytes(), ENCODING_SET)).as_bytes(),
            );

            header_map.insert(
                Self::GRPC_MESSAGE,
                HeaderValue::from_maybe_shared(to_write).map_err(invalid_header_value_byte)?,
            );
        }

        if !self.0.details.is_empty() {
            let details = crate::util::base64::STANDARD_NO_PAD.encode(&self.0.details[..]);

            header_map.insert(
                Self::GRPC_STATUS_DETAILS,
                HeaderValue::from_maybe_shared(details).map_err(invalid_header_value_byte)?,
            );
        }

        Ok(())
    }

    /// Create a new `Status` with the associated code, message, and binary details field.
    pub fn with_details(code: Code, message: impl Into<ArcStr>, details: Bytes) -> Self {
        Self::with_details_and_metadata(code, message, details, MetadataMap::new())
    }

    /// Create a new `Status` with the associated code, message, and custom metadata
    pub fn with_metadata(code: Code, message: impl Into<ArcStr>, metadata: MetadataMap) -> Self {
        Self::with_details_and_metadata(code, message, Bytes::new(), metadata)
    }

    /// Create a new `Status` with the associated code, message, binary details field and custom metadata
    pub fn with_details_and_metadata(
        code: Code,
        message: impl Into<ArcStr>,
        details: Bytes,
        metadata: MetadataMap,
    ) -> Self {
        StatusInner {
            code,
            message: message.into(),
            details,
            metadata,
            source: None,
        }
        .into_status()
    }

    /// Add a source error to this status.
    pub fn set_source(&mut self, source: Arc<dyn Error + Send + Sync + 'static>) -> &mut Self {
        self.0.source = Some(source);
        self
    }

    /// Build an `http::Response` from the given `Status`.
    pub fn try_into_http<B: Default>(self) -> Result<rama_http_types::Response<B>, Self> {
        let mut response = rama_http_types::Response::new(B::default());
        response
            .headers_mut()
            .insert(rama_http_types::header::CONTENT_TYPE, GRPC_CONTENT_TYPE);
        self.add_header(response.headers_mut())?;
        response.extensions_mut().insert(self);
        Ok(response)
    }

    #[doc(hidden)]
    pub const GRPC_STATUS: HeaderName = HeaderName::from_static("grpc-status");
    #[doc(hidden)]
    pub const GRPC_MESSAGE: HeaderName = HeaderName::from_static("grpc-message");
    #[doc(hidden)]
    pub const GRPC_STATUS_DETAILS: HeaderName = HeaderName::from_static("grpc-status-details-bin");
}

fn find_status_in_source_chain(err: &(dyn Error + 'static)) -> Option<Status> {
    let mut source = Some(err);

    while let Some(err) = source {
        if let Some(status) = err.downcast_ref::<Status>() {
            return Some(
                StatusInner {
                    code: status.0.code,
                    message: status.0.message.clone(),
                    details: status.0.details.clone(),
                    metadata: status.0.metadata.clone(),
                    // Since `Status` is not `Clone`, any `source` on the original Status
                    // cannot be cloned so must remain with the original `Status`.
                    source: None,
                }
                .into_status(),
            );
        }

        if let Some(timeout) = err.downcast_ref::<TimeoutExpired>() {
            return Some(Status::cancelled(timeout.to_string()));
        }

        // If we are unable to connect to the server, map this to UNAVAILABLE.  This is
        // consistent with the behavior of a C++ gRPC client when the server is not running, and
        // matches the spec of:
        // > The service is currently unavailable. This is most likely a transient condition that
        // > can be corrected if retried with a backoff.
        if let Some(connect) = err.downcast_ref::<ConnectError>() {
            return Some(Status::unavailable(connect.to_string()));
        }

        #[cfg(feature = "transport")]
        if let Some(http_err) = err
            .downcast_ref::<rama_http_core::Error>()
            .and_then(Status::from_http_error)
        {
            return Some(http_err);
        }

        source = err.source();
    }

    None
}

impl fmt::Debug for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Debug for StatusInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // A manual impl to reduce the noise of frequently empty fields.
        let mut builder = f.debug_struct("Status");

        builder.field("code", &self.code);

        if !self.message.is_empty() {
            builder.field("message", &self.message);
        }

        if !self.details.is_empty() {
            builder.field("details", &self.details);
        }

        if !self.metadata.is_empty() {
            builder.field("metadata", &self.metadata);
        }

        builder.field("source", &self.source);

        builder.finish()
    }
}

fn invalid_header_value_byte<Error: fmt::Display>(err: Error) -> Status {
    debug!("Invalid header: {}", err);
    Status::new(
        Code::Internal,
        "Couldn't serialize non-text grpc status header".to_owned(),
    )
}

#[cfg(feature = "transport")]
impl From<rama_http_core::h2::Error> for Status {
    #[inline(always)]
    fn from(err: rama_http_core::h2::Error) -> Self {
        Self::from_h2_error(Box::new(err))
    }
}

#[cfg(feature = "transport")]
impl From<Status> for rama_http_core::h2::Error {
    #[inline(always)]
    fn from(status: Status) -> Self {
        status.to_h2_error()
    }
}

impl From<std::io::Error> for Status {
    fn from(err: std::io::Error) -> Self {
        use std::io::ErrorKind;
        let code = match err.kind() {
            ErrorKind::BrokenPipe
            | ErrorKind::WouldBlock
            | ErrorKind::WriteZero
            | ErrorKind::Interrupted => Code::Internal,
            ErrorKind::ConnectionRefused
            | ErrorKind::ConnectionReset
            | ErrorKind::NotConnected
            | ErrorKind::AddrInUse
            | ErrorKind::AddrNotAvailable => Code::Unavailable,
            ErrorKind::AlreadyExists => Code::AlreadyExists,
            ErrorKind::ConnectionAborted => Code::Aborted,
            ErrorKind::InvalidData => Code::DataLoss,
            ErrorKind::InvalidInput => Code::InvalidArgument,
            ErrorKind::NotFound => Code::NotFound,
            ErrorKind::PermissionDenied => Code::PermissionDenied,
            ErrorKind::TimedOut => Code::DeadlineExceeded,
            ErrorKind::UnexpectedEof => Code::OutOfRange,
            _ => Code::Unknown,
        };
        Self::new(code, err.to_string())
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "code: '{}'", self.code())?;

        if !self.message().is_empty() {
            write!(f, ", message: {:?}", self.message())?;
        }
        // We intentionally omit `self.details` since it's binary data, not fit for human eyes.
        if !self.metadata().is_empty() {
            write!(f, ", metadata: {:?}", self.metadata().as_ref())?;
        }
        if let Some(source) = self.source() {
            write!(f, ", source: {source:?}")?;
        }
        Ok(())
    }
}

impl Error for Status {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.0.source.as_ref().map(|err| (&**err) as _)
    }
}

/// Take the `Status` value from `trailers` if it is available, else from `status_code`.
pub(crate) fn infer_grpc_status(
    trailers: Option<&HeaderMap>,
    status_code: rama_http_types::StatusCode,
) -> Result<(), Option<Status>> {
    if let Some(trailers) = trailers
        && let Some(status) = Status::from_header_map(trailers)
    {
        if status.code() == Code::Ok {
            return Ok(());
        } else {
            return Err(status.into());
        }
    }
    trace!("trailers missing grpc-status");
    let code = match status_code {
        // Borrowed from https://github.com/grpc/grpc/blob/master/doc/http-grpc-status-mapping.md
        rama_http_types::StatusCode::BAD_REQUEST => Code::Internal,
        rama_http_types::StatusCode::UNAUTHORIZED => Code::Unauthenticated,
        rama_http_types::StatusCode::FORBIDDEN => Code::PermissionDenied,
        rama_http_types::StatusCode::NOT_FOUND => Code::Unimplemented,
        rama_http_types::StatusCode::TOO_MANY_REQUESTS
        | rama_http_types::StatusCode::BAD_GATEWAY
        | rama_http_types::StatusCode::SERVICE_UNAVAILABLE
        | rama_http_types::StatusCode::GATEWAY_TIMEOUT => Code::Unavailable,
        // We got a 200 but no trailers, we can infer that this request is finished.
        //
        // This can happen when a streaming response sends two Status but
        // gRPC requires that we end the stream after the first status.
        //
        // https://github.com/hyperium/tonic/issues/681
        rama_http_types::StatusCode::OK => return Err(None),
        _ => Code::Unknown,
    };

    let msg = format!(
        "grpc-status header missing, mapped from HTTP status code {}",
        status_code.as_u16(),
    );
    let status = Status::new(code, msg);
    Err(status.into())
}

// ===== impl Code =====

impl Code {
    /// Get the `Code` that represents the integer, if known.
    ///
    /// If not known, returns `Code::Unknown` (surprise!).
    #[must_use]
    #[allow(clippy::match_same_arms)]
    pub const fn from_i32(i: i32) -> Self {
        match i {
            0 => Self::Ok,
            1 => Self::Cancelled,
            2 => Self::Unknown,
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

    /// Convert the string representation of a `Code` (as stored, for example, in the `grpc-status`
    /// header in a response) into a `Code`. Returns `Code::Unknown` if the code string is not a
    /// valid gRPC status code.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        match bytes.len() {
            1 => match bytes[0] {
                b'0' => Self::Ok,
                b'1' => Self::Cancelled,
                b'2' => Self::Unknown,
                b'3' => Self::InvalidArgument,
                b'4' => Self::DeadlineExceeded,
                b'5' => Self::NotFound,
                b'6' => Self::AlreadyExists,
                b'7' => Self::PermissionDenied,
                b'8' => Self::ResourceExhausted,
                b'9' => Self::FailedPrecondition,
                _ => Self::parse_err(),
            },
            2 => match (bytes[0], bytes[1]) {
                (b'1', b'0') => Self::Aborted,
                (b'1', b'1') => Self::OutOfRange,
                (b'1', b'2') => Self::Unimplemented,
                (b'1', b'3') => Self::Internal,
                (b'1', b'4') => Self::Unavailable,
                (b'1', b'5') => Self::DataLoss,
                (b'1', b'6') => Self::Unauthenticated,
                _ => Self::parse_err(),
            },
            _ => Self::parse_err(),
        }
    }

    fn to_header_value(self) -> HeaderValue {
        match self {
            Self::Ok => HeaderValue::from_static("0"),
            Self::Cancelled => HeaderValue::from_static("1"),
            Self::Unknown => HeaderValue::from_static("2"),
            Self::InvalidArgument => HeaderValue::from_static("3"),
            Self::DeadlineExceeded => HeaderValue::from_static("4"),
            Self::NotFound => HeaderValue::from_static("5"),
            Self::AlreadyExists => HeaderValue::from_static("6"),
            Self::PermissionDenied => HeaderValue::from_static("7"),
            Self::ResourceExhausted => HeaderValue::from_static("8"),
            Self::FailedPrecondition => HeaderValue::from_static("9"),
            Self::Aborted => HeaderValue::from_static("10"),
            Self::OutOfRange => HeaderValue::from_static("11"),
            Self::Unimplemented => HeaderValue::from_static("12"),
            Self::Internal => HeaderValue::from_static("13"),
            Self::Unavailable => HeaderValue::from_static("14"),
            Self::DataLoss => HeaderValue::from_static("15"),
            Self::Unauthenticated => HeaderValue::from_static("16"),
        }
    }

    fn parse_err() -> Self {
        trace!("error parsing grpc-status");
        Self::Unknown
    }
}

impl From<i32> for Code {
    fn from(i: i32) -> Self {
        Self::from_i32(i)
    }
}

impl From<Code> for i32 {
    #[inline]
    fn from(code: Code) -> Self {
        code as Self
    }
}

#[cfg(test)]
mod tests {
    use rama_core::error::BoxError;

    use super::*;

    #[derive(Debug)]
    struct Nested(BoxError);

    impl fmt::Display for Nested {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "nested error: {}", self.0)
        }
    }

    impl std::error::Error for Nested {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&*self.0)
        }
    }

    #[test]
    fn from_error_status() {
        let orig = Status::new(Code::OutOfRange, "weeaboo");
        let found = Status::from_error(Box::new(orig));

        assert_eq!(found.code(), Code::OutOfRange);
        assert_eq!(found.message(), "weeaboo");
    }

    #[test]
    fn from_error_unknown() {
        let orig: BoxError = "peek-a-boo".into();
        let found = Status::from_error(orig);

        assert_eq!(found.code(), Code::Unknown);
        assert_eq!(found.message(), "peek-a-boo");
    }

    #[test]
    fn from_error_nested() {
        let orig = Nested(Box::new(Status::new(Code::OutOfRange, "weeaboo")));
        let found = Status::from_error(Box::new(orig));

        assert_eq!(found.code(), Code::OutOfRange);
        assert_eq!(found.message(), "weeaboo");
    }

    #[test]
    #[cfg(feature = "transport")]
    fn from_error_h2() {
        use std::error::Error as _;

        let orig = rama_http_core::h2::Error::from(rama_http_core::h2::Reason::CANCEL);
        let found = Status::from_error(Box::new(orig));

        assert_eq!(found.code(), Code::Cancelled);

        let source = found
            .source()
            .and_then(|err| err.downcast_ref::<rama_http_core::h2::Error>())
            .unwrap();
        assert_eq!(source.reason(), Some(rama_http_core::h2::Reason::CANCEL));
    }

    #[test]
    #[cfg(feature = "transport")]
    fn to_h2_error() {
        let orig = Status::new(Code::Cancelled, "stop eet!");
        let err = orig.to_h2_error();

        assert_eq!(err.reason(), Some(rama_http_core::h2::Reason::CANCEL));
    }

    #[test]
    fn code_from_i32() {
        // This for loop should catch if we ever add a new variant and don't
        // update From<i32>.
        for i in 0..(Code::Unauthenticated as i32) {
            let code = Code::from(i);
            assert_eq!(
                i, code as i32,
                "Code::from({}) returned {:?} which is {}",
                i, code, code as i32,
            );
        }

        assert_eq!(Code::from(-1), Code::Unknown);
    }

    #[test]
    fn constructors() {
        assert_eq!(Status::ok("").code(), Code::Ok);
        assert_eq!(Status::cancelled("").code(), Code::Cancelled);
        assert_eq!(Status::unknown("").code(), Code::Unknown);
        assert_eq!(Status::invalid_argument("").code(), Code::InvalidArgument);
        assert_eq!(Status::deadline_exceeded("").code(), Code::DeadlineExceeded);
        assert_eq!(Status::not_found("").code(), Code::NotFound);
        assert_eq!(Status::already_exists("").code(), Code::AlreadyExists);
        assert_eq!(Status::permission_denied("").code(), Code::PermissionDenied);
        assert_eq!(
            Status::resource_exhausted("").code(),
            Code::ResourceExhausted
        );
        assert_eq!(
            Status::failed_precondition("").code(),
            Code::FailedPrecondition
        );
        assert_eq!(Status::aborted("").code(), Code::Aborted);
        assert_eq!(Status::out_of_range("").code(), Code::OutOfRange);
        assert_eq!(Status::unimplemented("").code(), Code::Unimplemented);
        assert_eq!(Status::internal("").code(), Code::Internal);
        assert_eq!(Status::unavailable("").code(), Code::Unavailable);
        assert_eq!(Status::data_loss("").code(), Code::DataLoss);
        assert_eq!(Status::unauthenticated("").code(), Code::Unauthenticated);
    }

    #[test]
    fn details() {
        const DETAILS: &[u8] = &[0, 2, 3];

        let status = Status::with_details(Code::Unavailable, "some message", DETAILS.into());

        assert_eq!(status.details(), DETAILS);

        let header_map = status.to_header_map().unwrap();

        let b64_details = crate::util::base64::STANDARD_NO_PAD.encode(DETAILS);

        assert_eq!(header_map[Status::GRPC_STATUS_DETAILS], b64_details);

        let status = Status::from_header_map(&header_map).unwrap();

        assert_eq!(status.details(), DETAILS);
    }
}

/// Error returned if a request didn't complete within the configured timeout.
///
/// Timeouts can be supported via [`GrpcTimeout`](crate::service::GrpcTimeout)
/// and make use of the [`grpc-timeout` metadata value][spec].
///
/// [spec]: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md
#[derive(Debug)]
pub struct TimeoutExpired(pub ());

impl fmt::Display for TimeoutExpired {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Timeout expired")
    }
}

// std::error::Error only requires a type to impl Debug and Display
impl std::error::Error for TimeoutExpired {}

/// Wrapper type to indicate that an error occurs during the connection
/// process, so that the appropriate gRPC Status can be inferred.
#[derive(Debug)]
pub struct ConnectError(pub Box<dyn std::error::Error + Send + Sync>);

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl std::error::Error for ConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}
