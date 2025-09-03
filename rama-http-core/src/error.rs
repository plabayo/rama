//! Error and Result module.

use std::error::Error as StdError;
use std::fmt;

use crate::h2;
use rama_core::error::BoxError;
use rama_http_types as http;

/// Result type often returned from methods that can have hyper `Error`s.
pub type Result<T> = std::result::Result<T, Error>;

type Cause = BoxError;

/// Represents errors that can occur handling HTTP streams.
///
/// # Formatting
///
/// The `Display` implementation of this type will only print the details of
/// this level of error, even though it may have been caused by another error
/// and contain that error in its source. To print all the relevant
/// information, including the source chain, using something like
/// `std::error::Report`, or equivalent 3rd party types.
///
/// The contents of the formatted error message of this specific `Error` type
/// is unspecified. **You must not depend on it.** The wording and details may
/// change in any version, with the goal of improving error messages.
///
/// # Source
///
/// A `rama_http_core::Error` may be caused by another error. To aid in debugging,
/// those are exposed in `Error::source()` as erased types. While it is
/// possible to check the exact type of the sources, they **can not be depended
/// on**. They may come from private internal dependencies, and are subject to
/// change at any moment.
pub struct Error {
    inner: Box<ErrorImpl>,
}

struct ErrorImpl {
    kind: Kind,
    cause: Option<Cause>,
}

#[derive(Debug)]
pub(super) enum Kind {
    Parse(Parse),
    User(User),
    /// A message reached EOF, but is not complete.
    IncompleteMessage,
    /// A connection received a message (or bytes) when not waiting for one.
    UnexpectedMessage,
    /// A pending item was dropped before ever being processed.
    Canceled,
    /// Indicates a channel (client or body sender) is closed.
    ChannelClosed,
    /// An `io::Error` that occurred while trying to read or write to a network stream.
    Io,
    /// User took too long to send headers
    HeaderTimeout,
    /// Error while reading a body from connection.
    Body,
    /// Error while writing a body to connection.
    BodyWrite,
    /// Error calling AsyncWrite::shutdown()
    Shutdown,

    /// A general error from h2.
    Http2,
}

#[derive(Debug)]
pub(super) enum Parse {
    Method,
    Version,
    VersionH2,
    Uri,
    UriTooLong,
    Header(Header),
    TooLarge,
    Status,
    Internal,
}

#[derive(Debug)]
pub(super) enum Header {
    Token,
    ContentLengthInvalid,
    TransferEncodingInvalid,
    TransferEncodingUnexpected,
}

#[derive(Debug)]
pub(super) enum User {
    /// Error calling user's Body::poll_data().
    Body,
    /// The user aborted writing of the outgoing body.
    BodyWriteAborted,
    /// Error from future of user's Service.
    Service,
    /// User tried to send a certain header in an unexpected context.
    ///
    /// For example, sending both `content-length` and `transfer-encoding`.
    UnexpectedHeader,
    /// User tried to respond with a 1xx (not 101) response code.
    UnsupportedStatusCode,

    /// The dispatch task is gone.
    DispatchGone,
}

// Sentinel type to indicate the error was caused by a timeout.
#[derive(Debug)]
pub(super) struct TimedOut;

impl Error {
    /// Returns true if this was an HTTP parse error.
    #[must_use]
    pub fn is_parse(&self) -> bool {
        matches!(self.inner.kind, Kind::Parse(_))
    }

    /// Returns true if this was an HTTP parse error caused by a message that was too large.
    #[must_use]
    pub fn is_parse_too_large(&self) -> bool {
        matches!(
            self.inner.kind,
            Kind::Parse(Parse::TooLarge | Parse::UriTooLong)
        )
    }

    /// Returns true if this was an HTTP parse error caused by an invalid response status code or
    /// reason phrase.
    #[must_use]
    pub fn is_parse_status(&self) -> bool {
        matches!(self.inner.kind, Kind::Parse(Parse::Status))
    }

    /// Returns true if this error was caused by user code.
    #[must_use]
    pub fn is_user(&self) -> bool {
        matches!(self.inner.kind, Kind::User(_))
    }

    /// Returns true if this was about a `Request` that was canceled.
    #[must_use]
    pub fn is_canceled(&self) -> bool {
        matches!(self.inner.kind, Kind::Canceled)
    }

    /// Returns true if a sender's channel is closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        matches!(self.inner.kind, Kind::ChannelClosed)
    }

    /// Returns true if the connection closed before a message could complete.
    #[must_use]
    pub fn is_incomplete_message(&self) -> bool {
        matches!(self.inner.kind, Kind::IncompleteMessage)
    }

    /// Returns true if the body write was aborted.
    #[must_use]
    pub fn is_body_write_aborted(&self) -> bool {
        matches!(self.inner.kind, Kind::User(User::BodyWriteAborted))
    }

    /// Returns true if the error was caused while calling `AsyncWrite::shutdown()`.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        if matches!(self.inner.kind, Kind::Shutdown) {
            return true;
        }
        false
    }

    /// Returns true if the error was caused by a timeout.
    #[must_use]
    pub fn is_timeout(&self) -> bool {
        if matches!(self.inner.kind, Kind::HeaderTimeout) {
            return true;
        }
        self.find_source::<TimedOut>().is_some()
    }

    pub(super) fn new(kind: Kind) -> Self {
        Self {
            inner: Box::new(ErrorImpl { kind, cause: None }),
        }
    }

    pub(super) fn with<C: Into<Cause>>(mut self, cause: C) -> Self {
        self.inner.cause = Some(cause.into());
        self
    }

    pub(super) fn kind(&self) -> &Kind {
        &self.inner.kind
    }

    pub(crate) fn find_source<E: StdError + 'static>(&self) -> Option<&E> {
        let mut cause = self.source();
        while let Some(err) = cause {
            if let Some(typed) = err.downcast_ref() {
                return Some(typed);
            }
            cause = err.source();
        }

        // else
        None
    }

    pub(super) fn h2_reason(&self) -> h2::Reason {
        // Find an h2::Reason somewhere in the cause stack, if it exists,
        // otherwise assume an INTERNAL_ERROR.
        self.find_source::<h2::Error>()
            .and_then(|h2_err| h2_err.reason())
            .unwrap_or(h2::Reason::INTERNAL_ERROR)
    }

    pub(super) fn new_canceled() -> Self {
        Self::new(Kind::Canceled)
    }

    pub(super) fn new_incomplete() -> Self {
        Self::new(Kind::IncompleteMessage)
    }

    pub(super) fn new_too_large() -> Self {
        Self::new(Kind::Parse(Parse::TooLarge))
    }

    pub(super) fn new_version_h2() -> Self {
        Self::new(Kind::Parse(Parse::VersionH2))
    }

    pub(super) fn new_unexpected_message() -> Self {
        Self::new(Kind::UnexpectedMessage)
    }

    pub(super) fn new_io(cause: std::io::Error) -> Self {
        Self::new(Kind::Io).with(cause)
    }

    pub(super) fn new_closed() -> Self {
        Self::new(Kind::ChannelClosed)
    }

    pub(super) fn new_body<E: Into<Cause>>(cause: E) -> Self {
        Self::new(Kind::Body).with(cause)
    }

    pub(super) fn new_body_write<E: Into<Cause>>(cause: E) -> Self {
        Self::new(Kind::BodyWrite).with(cause)
    }

    pub(super) fn new_body_write_aborted() -> Self {
        Self::new(Kind::User(User::BodyWriteAborted))
    }

    fn new_user(user: User) -> Self {
        Self::new(Kind::User(user))
    }

    pub(super) fn new_user_header() -> Self {
        Self::new_user(User::UnexpectedHeader)
    }

    pub(super) fn new_header_timeout() -> Self {
        Self::new(Kind::HeaderTimeout)
    }

    pub(super) fn new_user_unsupported_status_code() -> Self {
        Self::new_user(User::UnsupportedStatusCode)
    }

    pub(super) fn new_user_service<E: Into<Cause>>(cause: E) -> Self {
        Self::new_user(User::Service).with(cause)
    }

    pub(super) fn new_user_body<E: Into<Cause>>(cause: E) -> Self {
        Self::new_user(User::Body).with(cause)
    }

    pub(super) fn new_shutdown(cause: std::io::Error) -> Self {
        Self::new(Kind::Shutdown).with(cause)
    }

    pub(super) fn new_user_dispatch_gone() -> Self {
        Self::new(Kind::User(User::DispatchGone))
    }

    pub(super) fn new_h2(cause: h2::Error) -> Self {
        if cause.is_io() {
            Self::new_io(cause.into_io().expect("h2::Error::is_io"))
        } else {
            Self::new(Kind::Http2).with(cause)
        }
    }

    fn description(&self) -> &str {
        match self.inner.kind {
            Kind::Parse(Parse::Method) => "invalid HTTP method parsed",
            Kind::Parse(Parse::Version) => "invalid HTTP version parsed",
            Kind::Parse(Parse::VersionH2) => "invalid HTTP version parsed (found HTTP2 preface)",
            Kind::Parse(Parse::Uri) => "invalid URI",
            Kind::Parse(Parse::UriTooLong) => "URI too long",
            Kind::Parse(Parse::Header(Header::Token)) => "invalid HTTP header parsed",
            Kind::Parse(Parse::Header(Header::ContentLengthInvalid)) => {
                "invalid content-length parsed"
            }
            Kind::Parse(Parse::Header(Header::TransferEncodingInvalid)) => {
                "invalid transfer-encoding parsed"
            }
            Kind::Parse(Parse::Header(Header::TransferEncodingUnexpected)) => {
                "unexpected transfer-encoding parsed"
            }
            Kind::Parse(Parse::TooLarge) => "message head is too large",
            Kind::Parse(Parse::Status) => "invalid HTTP status-code parsed",
            Kind::Parse(Parse::Internal) => {
                "internal error inside rama_http_core and/or its dependencies, please report"
            }
            Kind::IncompleteMessage => "connection closed before message completed",
            Kind::UnexpectedMessage => "received unexpected message from connection",
            Kind::ChannelClosed => "channel closed",
            Kind::Canceled => "operation was canceled",
            Kind::HeaderTimeout => "read header from client timeout",
            Kind::Body => "error reading a body from connection",
            Kind::BodyWrite => "error writing a body to connection",
            Kind::Shutdown => "error shutting down connection",
            Kind::Http2 => "http2 error",
            Kind::Io => "connection error",
            Kind::User(User::Body) => "error from user's Body stream",
            Kind::User(User::BodyWriteAborted) => "user body write aborted",
            Kind::User(User::Service) => "error from user's Service",
            Kind::User(User::UnexpectedHeader) => "user sent unexpected header",
            Kind::User(User::UnsupportedStatusCode) => {
                "response has 1xx status code, not supported by server"
            }
            Kind::User(User::DispatchGone) => "dispatch task is gone",
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_tuple("rama_http_core::Error");
        f.field(&self.inner.kind);
        if let Some(ref cause) = self.inner.cause {
            f.field(cause);
        }
        f.finish()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.description())
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.inner
            .cause
            .as_ref()
            .map(|cause| &**cause as &(dyn StdError + 'static))
    }
}

#[doc(hidden)]
impl From<Parse> for Error {
    fn from(err: Parse) -> Self {
        Self::new(Kind::Parse(err))
    }
}

impl Parse {
    pub(crate) fn content_length_invalid() -> Self {
        Self::Header(Header::ContentLengthInvalid)
    }

    pub(crate) fn transfer_encoding_invalid() -> Self {
        Self::Header(Header::TransferEncodingInvalid)
    }

    pub(crate) fn transfer_encoding_unexpected() -> Self {
        Self::Header(Header::TransferEncodingUnexpected)
    }
}

impl From<httparse::Error> for Parse {
    fn from(err: httparse::Error) -> Self {
        match err {
            httparse::Error::HeaderName
            | httparse::Error::HeaderValue
            | httparse::Error::NewLine
            | httparse::Error::Token => Self::Header(Header::Token),
            httparse::Error::Status => Self::Status,
            httparse::Error::TooManyHeaders => Self::TooLarge,
            httparse::Error::Version => Self::Version,
        }
    }
}

impl From<http::method::InvalidMethod> for Parse {
    fn from(_: http::method::InvalidMethod) -> Self {
        Self::Method
    }
}

impl From<http::status::InvalidStatusCode> for Parse {
    fn from(_: http::status::InvalidStatusCode) -> Self {
        Self::Status
    }
}

impl From<http::uri::InvalidUri> for Parse {
    fn from(_: http::uri::InvalidUri) -> Self {
        Self::Uri
    }
}

impl From<http::uri::InvalidUriParts> for Parse {
    fn from(_: http::uri::InvalidUriParts) -> Self {
        Self::Uri
    }
}

// ===== impl TimedOut ====

impl fmt::Display for TimedOut {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("operation timed out")
    }
}

impl StdError for TimedOut {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    fn assert_send_sync<T: Send + Sync + 'static>() {}

    #[test]
    fn error_satisfies_send_sync() {
        assert_send_sync::<Error>()
    }

    #[test]
    fn error_size_of() {
        assert_eq!(mem::size_of::<Error>(), mem::size_of::<usize>());
    }

    #[test]
    fn h2_reason_unknown() {
        let closed = Error::new_closed();
        assert_eq!(closed.h2_reason(), h2::Reason::INTERNAL_ERROR);
    }

    #[test]
    fn h2_reason_one_level() {
        let body_err = Error::new_user_body(h2::Error::from(h2::Reason::ENHANCE_YOUR_CALM));
        assert_eq!(body_err.h2_reason(), h2::Reason::ENHANCE_YOUR_CALM);
    }

    #[test]
    fn h2_reason_nested() {
        let recvd = Error::new_h2(h2::Error::from(h2::Reason::HTTP_1_1_REQUIRED));
        // Suppose a user were proxying the received error
        let svc_err = Error::new_user_service(recvd);
        assert_eq!(svc_err.h2_reason(), h2::Reason::HTTP_1_1_REQUIRED);
    }
}
