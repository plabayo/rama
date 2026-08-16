//! types and logic for [`HttpPeekRouter`]

use std::time::Duration;

use rama_core::{
    Service,
    bytes::BytesMut,
    error::{BoxError, ErrorContext},
    io::{
        PeekIoProvider, PrefixedIo, ReplayReader,
        peek::{PeekTimeoutError, PeekTimeoutPolicy},
    },
    service::RejectService,
    telemetry::tracing,
};
use rama_utils::octets::kib;
use tokio::{io::AsyncReadExt as _, time::Instant};

use crate::{
    byte_sets::{is_control_byte, is_http_token_byte, is_scheme_first_byte, is_scheme_rest_byte},
    uri::parser::validate_http_request_target,
};

/// Default maximum number of bytes inspected for an HTTP/1 request-line.
///
/// RFC 9112 recommends that HTTP senders and recipients support request-lines
/// of at least 8000 octets. The slightly larger power-of-two default leaves
/// room for the terminating CRLF while keeping protocol detection bounded.
pub const DEFAULT_HTTP1_REQUEST_LINE_MAX_SIZE: usize = kib(8);

/// Default maximum number of bytes requested from the transport per peek read.
pub const DEFAULT_HTTP_PEEK_READ_BUFFER_SIZE: usize = 512;

/// Known non-HTTP protocol prefixes which resemble HTTP/1 methods.
///
/// Covers Redis, IRC, SMTP, FTP, SSH and HAProxy PROXY v1. Matching is
/// case-sensitive and fail-fast, so it can also reject HTTP extension methods
/// with one of these prefixes. Server-first protocols are only recognized once
/// a listed client prefix arrives.
pub const KNOWN_NON_HTTP_PROTOCOL_METHODS: &[&str] =
    &["PING", "EHLO", "HELO", "USER", "NICK", "SSH", "PROXY"];

/// Initial HTTP peek read size.
///
/// This covers the overwhelming majority of HTTP/1 request lines in one
/// transport read while retaining geometric growth for unusually long targets.
const INITIAL_HTTP_PEEK_READ_BUFFER_SIZE: usize = 128;

/// Configuration used while detecting HTTP on a byte stream.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpPeekConfig {
    /// timeout applied to the complete HTTP peek operation
    pub timeout: Option<Duration>,
    /// policy applied when the timeout expires before HTTP detection reaches a
    /// definitive match or rejection
    pub timeout_policy: PeekTimeoutPolicy,
    /// maximum number of bytes inspected for an HTTP/1 request-line
    pub max_http1_request_line_size: usize,
    /// maximum number of bytes requested per transport read
    pub read_buffer_size: usize,
    /// HTTP/1 method prefixes routed to the fallback before a delimiter.
    ///
    /// Matching is case-sensitive and fail-fast, so `PING` also skips `PINGX`.
    /// Empty or invalid method tokens cannot match.
    pub skipped_http1_methods: &'static [&'static str],
}

impl Default for HttpPeekConfig {
    fn default() -> Self {
        Self {
            timeout: None,
            timeout_policy: PeekTimeoutPolicy::default(),
            max_http1_request_line_size: DEFAULT_HTTP1_REQUEST_LINE_MAX_SIZE,
            read_buffer_size: DEFAULT_HTTP_PEEK_READ_BUFFER_SIZE,
            skipped_http1_methods: &[],
        }
    }
}

impl HttpPeekConfig {
    /// Create an HTTP peek configuration using the defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set how an inconclusive HTTP peek timeout is handled.
        ///
        /// Defaults to [`PeekTimeoutPolicy::FailOpen`]. A definitive non-HTTP
        /// prefix remains a normal non-match under either policy.
        pub fn timeout_policy(mut self, timeout_policy: PeekTimeoutPolicy) -> Self {
            self.timeout_policy = timeout_policy;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Use [`KNOWN_NON_HTTP_PROTOCOL_METHODS`] as the skipped method list.
        pub fn known_non_http_protocol_methods(mut self) -> Self {
            self.skipped_http1_methods = KNOWN_NON_HTTP_PROTOCOL_METHODS;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set [`HttpPeekConfig::skipped_http1_methods`].
        pub fn skipped_http1_methods(
            mut self,
            skipped_http1_methods: &'static [&'static str],
        ) -> Self {
            self.skipped_http1_methods = skipped_http1_methods;
            self
        }
    }
}

/// A [`Service`] router that can be used to support
/// http/1x and h2 traffic as well as non-tls traffic.
///
/// By default non-http traffic is rejected using [`RejectService`].
/// Use [`HttpPeekRouter::with_fallback`] to configure the fallback service.
/// A definitive non-HTTP prefix invokes that fallback under either timeout
/// policy; an inconclusive timeout is fail-open by default and can be made
/// fail-closed with [`HttpPeekRouter::with_peek_timeout_policy`].
#[derive(Debug, Clone)]
pub struct HttpPeekRouter<T, F = RejectService<(), NoHttpRejectError>> {
    http_acceptor: T,
    fallback: F,
    peek_config: HttpPeekConfig,
}

/// Type wrapper used by [`HttpPeekRouter::new_dual`]
/// to serve http/1x and h2 separately.
#[derive(Debug, Clone)]
pub struct HttpDualAcceptor<T, U> {
    http1: T,
    h2: U,
}

/// Type wrapper used by [`HttpPeekRouter::new`]
/// to serve http/1x and h2 with a single service.
#[derive(Debug, Clone)]
pub struct HttpAutoAcceptor<T>(T);

/// Type wrapper used by [`HttpPeekRouter::new_http1`]
/// to only serve http/1x, and send h2 to the fallback.
#[derive(Debug, Clone)]
pub struct Http1Acceptor<T>(T);

/// Type wrapper used by [`HttpPeekRouter::new_h2`]
/// to only serve h2, and send http/1x to the fallback.
#[derive(Debug, Clone)]
pub struct H2Acceptor<T>(T);

rama_utils::macros::error::static_str_error! {
    #[doc = "non-http connection is rejected"]
    pub struct NoHttpRejectError;
}

impl<T> HttpPeekRouter<HttpAutoAcceptor<T>> {
    /// Create a new [`HttpPeekRouter`] using a service
    /// which can handle h2 and http/1x versions alike.
    pub fn new(auto_acceptor: T) -> Self {
        Self {
            http_acceptor: HttpAutoAcceptor(auto_acceptor),
            fallback: RejectService::new(NoHttpRejectError),
            peek_config: HttpPeekConfig::default(),
        }
    }
}

impl<T> HttpPeekRouter<Http1Acceptor<T>> {
    /// Create a new [`HttpPeekRouter`] using a service
    /// which handles http/1x traffic but forwards h2 traffic to fallback.
    pub fn new_http1(http1_acceptor: T) -> Self {
        Self {
            http_acceptor: Http1Acceptor(http1_acceptor),
            fallback: RejectService::new(NoHttpRejectError),
            peek_config: HttpPeekConfig::default(),
        }
    }
}

impl<T> HttpPeekRouter<H2Acceptor<T>> {
    /// Create a new [`HttpPeekRouter`] using a service
    /// which handles h2 traffic but forwards http/1x traffic to fallback.
    pub fn new_h2(h2_acceptor: T) -> Self {
        Self {
            http_acceptor: H2Acceptor(h2_acceptor),
            fallback: RejectService::new(NoHttpRejectError),
            peek_config: HttpPeekConfig::default(),
        }
    }
}

impl<T> HttpPeekRouter<T> {
    /// Attach a fallback [`Service`].
    pub fn with_fallback<F>(self, fallback: F) -> HttpPeekRouter<T, F> {
        HttpPeekRouter {
            http_acceptor: self.http_acceptor,
            fallback,
            peek_config: self.peek_config,
        }
    }
}

impl<T, F> HttpPeekRouter<T, F> {
    rama_utils::macros::generate_set_and_with! {
        /// Use [`KNOWN_NON_HTTP_PROTOCOL_METHODS`] as the skipped method list.
        pub fn known_non_http_protocol_methods(mut self) -> Self {
            self.peek_config = self.peek_config.with_known_non_http_protocol_methods();
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the maximum time spent peeking for HTTP.
        ///
        /// A timeout is inconclusive. Use
        /// [`HttpPeekRouter::with_peek_timeout_policy`] to choose whether it
        /// invokes the fallback or rejects the connection.
        pub fn peek_timeout(mut self, peek_timeout: Option<Duration>) -> Self {
            self.peek_config.timeout = peek_timeout;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set how an inconclusive HTTP peek timeout is handled.
        ///
        /// Defaults to [`PeekTimeoutPolicy::FailOpen`]. A definitive non-HTTP
        /// prefix invokes the fallback under either policy.
        pub fn peek_timeout_policy(mut self, peek_timeout_policy: PeekTimeoutPolicy) -> Self {
            self.peek_config.timeout_policy = peek_timeout_policy;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the configuration used while peeking for HTTP.
        pub fn peek_config(mut self, peek_config: HttpPeekConfig) -> Self {
            self.peek_config = peek_config;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set [`HttpPeekConfig::skipped_http1_methods`].
        pub fn skipped_http1_methods(
            mut self,
            skipped_http1_methods: &'static [&'static str],
        ) -> Self {
            self.peek_config.skipped_http1_methods = skipped_http1_methods;
            self
        }
    }
}

impl<T, U> HttpPeekRouter<HttpDualAcceptor<T, U>> {
    /// Create a new [`HttpPeekRouter`] using a service
    /// which handles http/1x and h2 in two separate services.
    pub fn new_dual(http1_acceptor: T, h2_acceptor: U) -> Self {
        Self {
            http_acceptor: HttpDualAcceptor {
                http1: http1_acceptor,
                h2: h2_acceptor,
            },
            fallback: RejectService::new(NoHttpRejectError),
            peek_config: HttpPeekConfig::default(),
        }
    }
}

impl<PeekableInput, Output, T, F> Service<PeekableInput> for HttpPeekRouter<HttpAutoAcceptor<T>, F>
where
    PeekableInput: PeekIoProvider<PeekIo: Unpin>,
    Output: Send + 'static,
    T: Service<
            PeekableInput::Mapped<HttpPrefixedIo<PeekableInput::PeekIo>>,
            Output = Output,
            Error: Into<BoxError>,
        >,
    F: Service<
            PeekableInput::Mapped<HttpPrefixedIo<PeekableInput::PeekIo>>,
            Output = Output,
            Error: Into<BoxError>,
        >,
{
    type Output = Output;
    type Error = BoxError;

    async fn serve(&self, input: PeekableInput) -> Result<Self::Output, Self::Error> {
        let (version, peek_input) = peek_http_input_with_config(input, self.peek_config).await?;
        if version.is_some() {
            tracing::debug!(
                "http peek [auto]: HTTP detect: version = {version:?}; continue with http_acceptor svc"
            );
            self.http_acceptor
                .0
                .serve(peek_input)
                .await
                .into_box_error()
        } else {
            tracing::debug!("http peek [auto]: HTTP not detect: continue with fallback svc");
            self.fallback.serve(peek_input).await.into_box_error()
        }
    }
}

impl<PeekableInput, Output, T, F> Service<PeekableInput> for HttpPeekRouter<Http1Acceptor<T>, F>
where
    PeekableInput: PeekIoProvider<PeekIo: Unpin>,
    Output: Send + 'static,
    T: Service<
            PeekableInput::Mapped<HttpPrefixedIo<PeekableInput::PeekIo>>,
            Output = Output,
            Error: Into<BoxError>,
        >,
    F: Service<
            PeekableInput::Mapped<HttpPrefixedIo<PeekableInput::PeekIo>>,
            Output = Output,
            Error: Into<BoxError>,
        >,
{
    type Output = Output;
    type Error = BoxError;

    async fn serve(&self, input: PeekableInput) -> Result<Self::Output, Self::Error> {
        let (version, peek_input) = peek_http_input_with_config(input, self.peek_config).await?;
        if version == Some(HttpPeekVersion::Http1x) {
            tracing::debug!("http peek: serve[http1]: http/1x acceptor; version = {version:?}");
            self.http_acceptor
                .0
                .serve(peek_input)
                .await
                .into_box_error()
        } else {
            tracing::debug!("http peek: serve[http1]: fallback; version = {version:?}");
            self.fallback.serve(peek_input).await.into_box_error()
        }
    }
}

impl<PeekableInput, Output, T, F> Service<PeekableInput> for HttpPeekRouter<H2Acceptor<T>, F>
where
    PeekableInput: PeekIoProvider<PeekIo: Unpin>,
    Output: Send + 'static,
    T: Service<
            PeekableInput::Mapped<HttpPrefixedIo<PeekableInput::PeekIo>>,
            Output = Output,
            Error: Into<BoxError>,
        >,
    F: Service<
            PeekableInput::Mapped<HttpPrefixedIo<PeekableInput::PeekIo>>,
            Output = Output,
            Error: Into<BoxError>,
        >,
{
    type Output = Output;
    type Error = BoxError;

    async fn serve(&self, input: PeekableInput) -> Result<Self::Output, Self::Error> {
        let (version, peek_input) = peek_http_input_with_config(input, self.peek_config).await?;
        if version == Some(HttpPeekVersion::H2) {
            tracing::debug!("http peek: serve[h2]: http acceptor; version = {version:?}");
            self.http_acceptor
                .0
                .serve(peek_input)
                .await
                .into_box_error()
        } else {
            tracing::debug!("http peek: serve[h2]: fallback; version = {version:?}");
            self.fallback.serve(peek_input).await.into_box_error()
        }
    }
}

impl<PeekableInput, Output, T, U, F> Service<PeekableInput>
    for HttpPeekRouter<HttpDualAcceptor<T, U>, F>
where
    PeekableInput: PeekIoProvider<PeekIo: Unpin>,
    Output: Send + 'static,
    T: Service<
            PeekableInput::Mapped<HttpPrefixedIo<PeekableInput::PeekIo>>,
            Output = Output,
            Error: Into<BoxError>,
        >,
    U: Service<
            PeekableInput::Mapped<HttpPrefixedIo<PeekableInput::PeekIo>>,
            Output = Output,
            Error: Into<BoxError>,
        >,
    F: Service<
            PeekableInput::Mapped<HttpPrefixedIo<PeekableInput::PeekIo>>,
            Output = Output,
            Error: Into<BoxError>,
        >,
{
    type Output = Output;
    type Error = BoxError;

    async fn serve(&self, input: PeekableInput) -> Result<Self::Output, Self::Error> {
        let (version, peek_input) = peek_http_input_with_config(input, self.peek_config).await?;
        match version {
            Some(HttpPeekVersion::H2) => {
                tracing::trace!("http peek: serve[dual]: h2 acceptor; version = {version:?}");
                self.http_acceptor
                    .h2
                    .serve(peek_input)
                    .await
                    .into_box_error()
            }
            Some(HttpPeekVersion::Http1x) => {
                tracing::trace!("http peek: serve[dual]: http/1x acceptor; version = {version:?}");
                self.http_acceptor
                    .http1
                    .serve(peek_input)
                    .await
                    .into_box_error()
            }
            None => {
                tracing::trace!("http peek: serve[dual]: fallback; version = {version:?}");
                self.fallback.serve(peek_input).await.into_box_error()
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpPeekVersion {
    Http1x,
    H2,
}

#[derive(Debug, Clone, Copy)]
enum Http1PeekState {
    /// A leading `\r` was read; only the `\n` completing an empty line may follow.
    LeadingLf,
    Method {
        start: usize,
        len: usize,
    },
    Target {
        method_start: usize,
        method_end: usize,
        target: HttpRequestTargetState,
    },
    Http09Lf {
        method_start: usize,
        method_end: usize,
        target_end: usize,
    },
    Version {
        method_start: usize,
        method_end: usize,
        target_end: usize,
        offset: usize,
        minor: u8,
    },
    Matched,
    Invalid,
}

#[derive(Debug)]
struct HttpPeekState {
    http1: Http1PeekState,
    h2_offset: Option<usize>,
    max_http1_request_line_size: usize,
    skipped_http1_methods: &'static [&'static str],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HttpPeekDecision {
    Continue,
    Matched(HttpPeekVersion),
    Reject,
}

#[derive(Debug, Clone, Copy)]
enum HttpRequestTargetState {
    Start,
    Origin,
    Asterisk,
    Scheme { len: usize },
    Absolute,
    Authority,
}

impl HttpRequestTargetState {
    fn push(self, byte: u8) -> Option<Self> {
        if !is_http_request_target_prefix_byte(byte) {
            return None;
        }

        match self {
            Self::Start if byte == b'/' => Some(Self::Origin),
            Self::Start if byte == b'*' => Some(Self::Asterisk),
            Self::Start if is_scheme_first_byte(byte) => Some(Self::Scheme { len: 1 }),
            Self::Origin if byte != b'#' => Some(Self::Origin),
            Self::Scheme { len: _ } if byte == b':' => Some(Self::Absolute),
            Self::Scheme { len }
                if len < crate::proto::MAX_SCHEME_LEN && is_scheme_rest_byte(byte) =>
            {
                Some(Self::Scheme { len: len + 1 })
            }
            Self::Absolute if byte != b'#' => Some(Self::Absolute),
            Self::Authority if !matches!(byte, b'/' | b'?' | b'#') => Some(Self::Authority),
            _ => None,
        }
    }
}

impl HttpPeekState {
    fn new(
        max_http1_request_line_size: usize,
        skipped_http1_methods: &'static [&'static str],
    ) -> Self {
        Self {
            http1: if max_http1_request_line_size == 0 {
                Http1PeekState::Invalid
            } else {
                Http1PeekState::Method { start: 0, len: 0 }
            },
            h2_offset: Some(0),
            max_http1_request_line_size,
            skipped_http1_methods,
        }
    }

    fn max_peek_len(&self) -> usize {
        let http1 = if matches!(
            self.http1,
            Http1PeekState::Invalid | Http1PeekState::Matched
        ) {
            0
        } else {
            self.max_http1_request_line_size
        };
        let h2 = self.h2_offset.map(|_| H2_MAGIC_PREFIX.len()).unwrap_or(0);
        http1.max(h2)
    }

    fn push_byte(&mut self, byte: u8, total_len: usize, buffer: &[u8]) -> HttpPeekDecision {
        if let Some(offset) = self.h2_offset {
            if H2_MAGIC_PREFIX.get(offset) == Some(&byte) {
                let next = offset + 1;
                if next == H2_MAGIC_PREFIX.len() {
                    tracing::trace!(version = "HTTP/2", "HTTP peek matched client preface");
                    return HttpPeekDecision::Matched(HttpPeekVersion::H2);
                }
                self.h2_offset = Some(next);
            } else {
                self.h2_offset = None;
            }
        }

        self.push_http1_byte(byte, total_len, buffer);

        if matches!(self.http1, Http1PeekState::Matched) {
            return HttpPeekDecision::Matched(HttpPeekVersion::Http1x);
        }

        if total_len >= self.max_http1_request_line_size {
            self.http1 = Http1PeekState::Invalid;
        }

        if matches!(self.http1, Http1PeekState::Invalid) && self.h2_offset.is_none() {
            HttpPeekDecision::Reject
        } else {
            HttpPeekDecision::Continue
        }
    }

    fn push_http1_byte(&mut self, byte: u8, total_len: usize, buffer: &[u8]) {
        // `HTTP/1.` + any minor digit + line terminator.
        const VERSION_PREFIX: &[u8] = b"HTTP/1.";

        let state = core::mem::replace(&mut self.http1, Http1PeekState::Invalid);
        self.http1 = match state {
            Http1PeekState::Method { start, len } => {
                if is_http_token_byte(byte) {
                    let len = len + 1;
                    let method = &buffer[start..start + len];
                    if self
                        .skipped_http1_methods
                        .iter()
                        .any(|skipped| method == skipped.as_bytes())
                    {
                        tracing::trace!(
                            method = ?core::str::from_utf8(method).ok(),
                            "HTTP/1 peek rejected configured method"
                        );
                        Http1PeekState::Invalid
                    } else {
                        Http1PeekState::Method { start, len }
                    }
                } else if byte == b' ' && len > 0 {
                    Http1PeekState::Target {
                        method_start: start,
                        method_end: start + len,
                        target: if &buffer[start..start + len] == b"CONNECT" {
                            HttpRequestTargetState::Authority
                        } else {
                            HttpRequestTargetState::Start
                        },
                    }
                } else if len == 0 && byte == b'\n' {
                    // httparse parity: skip empty lines before the request-line
                    Http1PeekState::Method {
                        start: total_len,
                        len: 0,
                    }
                } else if len == 0 && byte == b'\r' {
                    Http1PeekState::LeadingLf
                } else {
                    tracing::trace!(byte, "HTTP/1 peek rejected invalid method byte");
                    Http1PeekState::Invalid
                }
            }
            Http1PeekState::LeadingLf => {
                if byte == b'\n' {
                    Http1PeekState::Method {
                        start: total_len,
                        len: 0,
                    }
                } else {
                    tracing::trace!(byte, "HTTP/1 peek rejected bare CR before request-line");
                    Http1PeekState::Invalid
                }
            }
            Http1PeekState::Target {
                method_start,
                method_end,
                target,
            } => {
                if matches!(byte, b' ' | b'\r' | b'\n') {
                    let target_start = method_end + 1;
                    let target_end = total_len - 1;
                    let method = &buffer[method_start..method_end];
                    let target = &buffer[target_start..target_end];
                    let authority_form = method == b"CONNECT";
                    if target == b"*" && method != b"OPTIONS" {
                        tracing::trace!(
                            "HTTP/1 peek rejected asterisk-form for method other than OPTIONS"
                        );
                        Http1PeekState::Invalid
                    } else {
                        match validate_http_request_target(target, authority_form) {
                            Ok(()) if byte == b' ' => Http1PeekState::Version {
                                method_start,
                                method_end,
                                target_end,
                                offset: 0,
                                minor: 0,
                            },
                            Ok(()) if method == b"GET" => {
                                if byte == b'\n' {
                                    // httparse parity: bare LF terminates the simple-request
                                    trace_http1_match(
                                        buffer,
                                        method_start,
                                        method_end,
                                        target_end,
                                        "HTTP/0.9",
                                    );
                                    Http1PeekState::Matched
                                } else {
                                    Http1PeekState::Http09Lf {
                                        method_start,
                                        method_end,
                                        target_end,
                                    }
                                }
                            }
                            Ok(()) => {
                                tracing::trace!("HTTP/0.9 peek rejected method other than GET");
                                Http1PeekState::Invalid
                            }
                            Err(err) => {
                                tracing::trace!(%err, "HTTP/1 peek rejected invalid request target");
                                Http1PeekState::Invalid
                            }
                        }
                    }
                } else if let Some(target) = target.push(byte) {
                    Http1PeekState::Target {
                        method_start,
                        method_end,
                        target,
                    }
                } else {
                    tracing::trace!(byte, "HTTP/1 peek rejected invalid request-target byte");
                    Http1PeekState::Invalid
                }
            }
            Http1PeekState::Http09Lf {
                method_start,
                method_end,
                target_end,
            } => {
                if byte == b'\n' {
                    trace_http1_match(buffer, method_start, method_end, target_end, "HTTP/0.9");
                    Http1PeekState::Matched
                } else {
                    tracing::trace!(byte, "HTTP/0.9 peek rejected invalid line ending");
                    Http1PeekState::Invalid
                }
            }
            Http1PeekState::Version {
                method_start,
                method_end,
                target_end,
                offset,
                minor,
            } => {
                if offset < VERSION_PREFIX.len() {
                    if byte == VERSION_PREFIX[offset] {
                        Http1PeekState::Version {
                            method_start,
                            method_end,
                            target_end,
                            offset: offset + 1,
                            minor,
                        }
                    } else {
                        tracing::trace!(byte, offset, "HTTP/1 peek rejected invalid version byte");
                        Http1PeekState::Invalid
                    }
                } else if offset == VERSION_PREFIX.len() {
                    if byte.is_ascii_digit() {
                        Http1PeekState::Version {
                            method_start,
                            method_end,
                            target_end,
                            offset: offset + 1,
                            minor: byte,
                        }
                    } else {
                        tracing::trace!(byte, offset, "HTTP/1 peek rejected invalid version byte");
                        Http1PeekState::Invalid
                    }
                } else if byte == b'\n' {
                    // httparse parity: bare LF may terminate the request-line
                    trace_http1_version_match(buffer, method_start, method_end, target_end, minor);
                    Http1PeekState::Matched
                } else if byte == b'\r' && offset == VERSION_PREFIX.len() + 1 {
                    Http1PeekState::Version {
                        method_start,
                        method_end,
                        target_end,
                        offset: offset + 1,
                        minor,
                    }
                } else {
                    tracing::trace!(byte, offset, "HTTP/1 peek rejected invalid line ending");
                    Http1PeekState::Invalid
                }
            }
            state @ (Http1PeekState::Matched | Http1PeekState::Invalid) => state,
        };
    }
}

#[inline]
fn trace_http1_match(
    buffer: &[u8],
    method_start: usize,
    method_end: usize,
    target_end: usize,
    version: &'static str,
) {
    // Method bytes are RFC 9110 `tchar`, and target validation guarantees
    // UTF-8, so both views are safe and borrow the single replay buffer.
    let method = unsafe { core::str::from_utf8_unchecked(&buffer[method_start..method_end]) };
    let target = unsafe { core::str::from_utf8_unchecked(&buffer[method_end + 1..target_end]) };
    tracing::trace!(method, target, version, "HTTP/1 peek matched request-line");
}

#[inline]
fn trace_http1_version_match(
    buffer: &[u8],
    method_start: usize,
    method_end: usize,
    target_end: usize,
    minor: u8,
) {
    const VERSIONS: [&str; 10] = [
        "HTTP/1.0", "HTTP/1.1", "HTTP/1.2", "HTTP/1.3", "HTTP/1.4", "HTTP/1.5", "HTTP/1.6",
        "HTTP/1.7", "HTTP/1.8", "HTTP/1.9",
    ];
    let version = VERSIONS[usize::from(minor.saturating_sub(b'0')).min(9)];
    trace_http1_match(buffer, method_start, method_end, target_end, version);
}

#[inline]
fn is_http_request_target_prefix_byte(byte: u8) -> bool {
    byte != b' ' && !is_control_byte(byte)
}

/// Detect HTTP using [`HttpPeekConfig::default`] and return an input that
/// replays every byte consumed during detection.
///
/// Timeouts use [`PeekTimeoutPolicy::FailOpen`] for backward compatibility. Use
/// [`peek_http_input_with_timeout_policy`] to select an explicit policy.
pub async fn peek_http_input<PeekableInput>(
    input: PeekableInput,
    timeout: Option<Duration>,
) -> Result<
    (
        Option<HttpPeekVersion>,
        PeekableInput::Mapped<HttpPrefixedIo<PeekableInput::PeekIo>>,
    ),
    BoxError,
>
where
    PeekableInput: PeekIoProvider<PeekIo: Unpin>,
{
    peek_http_input_with_timeout_policy(input, timeout, PeekTimeoutPolicy::FailOpen).await
}

/// Detect HTTP with an explicit timeout policy and return an input that replays
/// every byte consumed during detection.
///
/// A definitive non-HTTP prefix returns `Ok((None, input))` under either policy.
/// An inconclusive timeout returns [`PeekTimeoutError`] when
/// [`PeekTimeoutPolicy::FailClosed`] is selected.
pub async fn peek_http_input_with_timeout_policy<PeekableInput>(
    input: PeekableInput,
    timeout: Option<Duration>,
    timeout_policy: PeekTimeoutPolicy,
) -> Result<
    (
        Option<HttpPeekVersion>,
        PeekableInput::Mapped<HttpPrefixedIo<PeekableInput::PeekIo>>,
    ),
    BoxError,
>
where
    PeekableInput: PeekIoProvider<PeekIo: Unpin>,
{
    peek_http_input_with_config(
        input,
        HttpPeekConfig {
            timeout,
            timeout_policy,
            ..Default::default()
        },
    )
    .await
}

/// Detect HTTP using explicit resource limits and return an input that
/// replays every byte consumed during detection.
///
/// HTTP/1.0 and HTTP/1.1 are accepted only after a complete request-line
/// containing a valid method token, request target, `HTTP/1.<digit>` version, and
/// line terminator has been read. An HTTP/0.9 simple-request is accepted as
/// HTTP/1x after `GET`, a valid request target, and a line terminator.
/// Matching lenient HTTP/1 parsers such as httparse, a bare LF is accepted
/// as line terminator and empty lines before the request-line are skipped
/// (they count toward [`HttpPeekConfig::max_http1_request_line_size`]).
/// HTTP/2 is accepted only after its complete client preface, starting at
/// the first byte.
pub async fn peek_http_input_with_config<PeekableInput>(
    mut input: PeekableInput,
    config: HttpPeekConfig,
) -> Result<
    (
        Option<HttpPeekVersion>,
        PeekableInput::Mapped<HttpPrefixedIo<PeekableInput::PeekIo>>,
    ),
    BoxError,
>
where
    PeekableInput: PeekIoProvider<PeekIo: Unpin>,
{
    let mut state = HttpPeekState::new(
        config.max_http1_request_line_size,
        config.skipped_http1_methods,
    );
    let max_peek_len = state.max_peek_len();
    let read_buffer_size = config.read_buffer_size.max(1);
    let mut next_read_buffer_size = read_buffer_size
        .min(INITIAL_HTTP_PEEK_READ_BUFFER_SIZE)
        .min(max_peek_len);
    let mut buffer = BytesMut::with_capacity(next_read_buffer_size);
    let mut total_len = 0usize;
    let mut matched_version = None;
    let deadline = config.timeout.map(|duration| Instant::now() + duration);

    'peek: loop {
        let remaining = state.max_peek_len().saturating_sub(total_len);
        if remaining == 0 {
            break;
        }

        let read_capacity = remaining.min(next_read_buffer_size);
        buffer.reserve(read_capacity);
        let read_start = buffer.len();
        let mut limited = input.peek_io_mut().take(read_capacity as u64);
        let read = limited.read_buf(&mut buffer);
        let read_size = match deadline {
            Some(deadline) => match tokio::time::timeout_at(deadline, read).await {
                Ok(Ok(size)) => size,
                Ok(Err(err)) => {
                    tracing::debug!(%err, "HTTP peek read failed");
                    break;
                }
                Err(err) => {
                    tracing::debug!(%err, "HTTP peek timed out");
                    if config.timeout_policy == PeekTimeoutPolicy::FailClosed {
                        return Err(PeekTimeoutError::new().into());
                    }
                    break;
                }
            },
            None => match read.await {
                Ok(size) => size,
                Err(err) => {
                    tracing::debug!(%err, "HTTP peek read failed");
                    break;
                }
            },
        };

        let Some(_) = core::num::NonZeroUsize::new(read_size) else {
            break;
        };

        if read_size == read_capacity {
            next_read_buffer_size = next_read_buffer_size
                .saturating_mul(2)
                .min(read_buffer_size);
        }

        for index in read_start..buffer.len() {
            total_len = index + 1;
            match state.push_byte(buffer[index], total_len, &buffer) {
                HttpPeekDecision::Continue => {}
                HttpPeekDecision::Matched(version) => {
                    matched_version = Some(version);
                    break 'peek;
                }
                HttpPeekDecision::Reject => {
                    break 'peek;
                }
            }
        }
        total_len = buffer.len();
    }

    tracing::trace!(
        version = ?matched_version,
        peek_size = buffer.len(),
        "HTTP peek read loop finished"
    );

    let peek = ReplayReader::new(buffer.freeze());
    let peek_input = input.map_peek_io(|io| PrefixedIo::new(peek, io));

    Ok((matched_version, peek_input))
}

const H2_MAGIC_PREFIX: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// [`PrefixedIo`] alias used by [`HttpPeekRouter`].
pub type HttpPrefixedIo<S> = PrefixedIo<ReplayReader, S>;

#[cfg(test)]
mod test {
    use core::convert::Infallible;
    use std::{
        io,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
    };

    use super::*;

    use parking_lot::Mutex;
    use rama_core::io::Io;
    use rama_core::{
        ServiceInput,
        bytes::Bytes,
        futures::{StreamExt as _, async_stream::stream_fn},
        service::{RejectError, service_fn},
        stream::io::StreamReader,
    };
    use tokio::io::{AsyncRead, ReadBuf};

    async fn peek_bytes(
        content: &[u8],
        config: HttpPeekConfig,
    ) -> (Option<HttpPeekVersion>, Vec<u8>) {
        let input = ServiceInput::new(std::io::Cursor::new(content.to_vec()));
        let (version, mut input) = peek_http_input_with_config(input, config).await.unwrap();
        let mut replayed = Vec::new();
        input.read_to_end(&mut replayed).await.unwrap();
        (version, replayed)
    }

    async fn peek_fragmented_bytes(content: &'static [u8]) -> (Option<HttpPeekVersion>, Vec<u8>) {
        let reader = StreamReader::new(rama_core::futures::stream::iter(
            content
                .iter()
                .map(|&byte| Ok::<_, std::io::Error>(Bytes::copy_from_slice(&[byte]))),
        ));
        let io = Box::pin(tokio::io::join(reader, tokio::io::sink()));
        let (version, mut io) = peek_http_input(io, None).await.unwrap();
        let mut replayed = Vec::new();
        io.read_to_end(&mut replayed).await.unwrap();
        (version, replayed)
    }

    fn state_decision(content: &[u8]) -> HttpPeekDecision {
        let mut state = HttpPeekState::new(DEFAULT_HTTP1_REQUEST_LINE_MAX_SIZE, &[]);
        let mut decision = HttpPeekDecision::Continue;
        for (index, &byte) in content.iter().enumerate() {
            decision = state.push_byte(byte, index + 1, &content[..=index]);
            if decision != HttpPeekDecision::Continue {
                break;
            }
        }
        decision
    }

    fn state_decision_with_skipped_methods(
        content: &[u8],
        skipped_http1_methods: &'static [&'static str],
    ) -> HttpPeekDecision {
        let mut state =
            HttpPeekState::new(DEFAULT_HTTP1_REQUEST_LINE_MAX_SIZE, skipped_http1_methods);
        let mut decision = HttpPeekDecision::Continue;
        for (index, &byte) in content.iter().enumerate() {
            decision = state.push_byte(byte, index + 1, &content[..=index]);
            if decision != HttpPeekDecision::Continue {
                break;
            }
        }
        decision
    }

    #[test]
    fn test_http1_state_rejects_at_first_impossible_byte() {
        assert_eq!(HttpPeekDecision::Reject, state_decision(b" "));
        assert_eq!(HttpPeekDecision::Reject, state_decision(b"\rG"));
        assert_eq!(HttpPeekDecision::Reject, state_decision(b"\r\r"));
        assert_eq!(HttpPeekDecision::Continue, state_decision(b"\r"));
        assert_eq!(HttpPeekDecision::Continue, state_decision(b"\r\n\nGET"));
        assert_eq!(HttpPeekDecision::Reject, state_decision(b"GE("));
        assert_eq!(HttpPeekDecision::Reject, state_decision(b"GET \t"));
        assert_eq!(HttpPeekDecision::Reject, state_decision(b"GET \x7f"));
        assert_eq!(HttpPeekDecision::Reject, state_decision(b"GET /\t"));
        assert_eq!(HttpPeekDecision::Reject, state_decision(b"CONNECT h\t"));
        assert_eq!(HttpPeekDecision::Reject, state_decision(b"GET ["));
        assert_eq!(HttpPeekDecision::Reject, state_decision(b"GET *x"));
        assert_eq!(HttpPeekDecision::Reject, state_decision(b"GET ht!"));
        assert_eq!(HttpPeekDecision::Reject, state_decision(b"GET /#"));
        assert_eq!(HttpPeekDecision::Reject, state_decision(b"GET http://x#"));
        assert_eq!(HttpPeekDecision::Reject, state_decision(b"CONNECT host/"));

        // A leading byte of a potentially valid UTF-8 target is not enough
        // information to reject; validation completes at the target delimiter.
        assert_eq!(HttpPeekDecision::Continue, state_decision(b"GET /\xc3"));
        assert_eq!(HttpPeekDecision::Continue, state_decision(b"GET http:x"));
        assert_eq!(HttpPeekDecision::Continue, state_decision(b"GET http:/x"));
        assert_eq!(HttpPeekDecision::Continue, state_decision(b"CONNECT ["));

        let mut max_scheme = b"GET ".to_vec();
        max_scheme.extend(core::iter::repeat_n(b'a', crate::proto::MAX_SCHEME_LEN));
        assert_eq!(HttpPeekDecision::Continue, state_decision(&max_scheme));
        max_scheme.push(b':');
        assert_eq!(HttpPeekDecision::Continue, state_decision(&max_scheme));

        let mut oversized_scheme = b"GET ".to_vec();
        oversized_scheme.extend(core::iter::repeat_n(b'a', crate::proto::MAX_SCHEME_LEN + 1));
        assert_eq!(HttpPeekDecision::Reject, state_decision(&oversized_scheme));
    }

    #[test]
    fn test_http1_state_rejects_configured_methods_immediately() {
        assert_eq!(HttpPeekDecision::Continue, state_decision(b"PING"));

        assert_eq!(
            KNOWN_NON_HTTP_PROTOCOL_METHODS,
            HttpPeekConfig::new()
                .with_known_non_http_protocol_methods()
                .skipped_http1_methods,
        );

        for method in KNOWN_NON_HTTP_PROTOCOL_METHODS {
            assert_eq!(
                HttpPeekDecision::Reject,
                state_decision_with_skipped_methods(
                    method.as_bytes(),
                    KNOWN_NON_HTTP_PROTOCOL_METHODS,
                ),
                "known non-HTTP method {method:?} was not rejected",
            );
        }
        assert_eq!(
            HttpPeekDecision::Reject,
            state_decision_with_skipped_methods(
                b"PINGX / HTTP/1.1\r\n",
                KNOWN_NON_HTTP_PROTOCOL_METHODS,
            )
        );
        assert_eq!(
            HttpPeekDecision::Continue,
            state_decision_with_skipped_methods(b"PIN", KNOWN_NON_HTTP_PROTOCOL_METHODS)
        );
        assert_eq!(
            HttpPeekDecision::Matched(HttpPeekVersion::Http1x),
            state_decision_with_skipped_methods(
                b"GET / HTTP/1.1\r\n",
                KNOWN_NON_HTTP_PROTOCOL_METHODS,
            )
        );
        assert_eq!(
            HttpPeekDecision::Reject,
            state_decision_with_skipped_methods(b"CUSTOM", &["CUSTOM"])
        );
        assert_eq!(
            HttpPeekDecision::Matched(HttpPeekVersion::H2),
            state_decision_with_skipped_methods(H2_MAGIC_PREFIX, &["PRI"])
        );
        assert_eq!(
            HttpPeekDecision::Continue,
            state_decision_with_skipped_methods(b"PING", &["", "PI NG", "PÉNG"])
        );
    }

    #[test]
    fn test_http1_skipped_method_configuration_is_last_call_wins() {
        let config = HttpPeekConfig::new()
            .with_known_non_http_protocol_methods()
            .with_skipped_http1_methods(&["CUSTOM"]);
        assert_eq!(&["CUSTOM"], config.skipped_http1_methods);

        let config = HttpPeekConfig::new()
            .with_skipped_http1_methods(&["CUSTOM"])
            .with_known_non_http_protocol_methods();
        assert_eq!(
            KNOWN_NON_HTTP_PROTOCOL_METHODS,
            config.skipped_http1_methods
        );

        let router = HttpPeekRouter::new(service_fn(async || Ok::<_, Infallible>("http")))
            .with_known_non_http_protocol_methods()
            .with_skipped_http1_methods(&["CUSTOM"]);
        assert_eq!(&["CUSTOM"], router.peek_config.skipped_http1_methods);
    }

    #[tokio::test]
    async fn test_peek_router() {
        let http_service = service_fn(async || Ok::<_, Infallible>("http"));
        let fallback_service = service_fn(async || Ok::<_, Infallible>("other"));

        let peek_http_svc = HttpPeekRouter::new(http_service).with_fallback(fallback_service);

        let response = peek_http_svc
            .serve(ServiceInput::new(std::io::Cursor::new(b"".to_vec())))
            .await
            .unwrap();
        assert_eq!("other", response);

        let response = peek_http_svc
            .serve(ServiceInput::new(std::io::Cursor::new(
                b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec(),
            )))
            .await
            .unwrap();
        assert_eq!("http", response);

        let response = peek_http_svc
            .serve(ServiceInput::new(std::io::Cursor::new(
                b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\nfoo".to_vec(),
            )))
            .await
            .unwrap();
        assert_eq!("http", response);

        const HTTP_METHODS: &[&str] = &[
            "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "CONNECT", "TRACE", "PATCH",
        ];
        for method in HTTP_METHODS {
            let target = if *method == "CONNECT" {
                "example.com:443"
            } else {
                "/foobar"
            };
            let response = peek_http_svc
                .serve(ServiceInput::new(std::io::Cursor::new(
                    format!("{method} {target} HTTP/1.1\r\n").into_bytes(),
                )))
                .await
                .unwrap();
            assert_eq!("http", response);
        }

        let response = peek_http_svc
            .serve(ServiceInput::new(std::io::Cursor::new(b"foo".to_vec())))
            .await
            .unwrap();
        assert_eq!("other", response);

        let response = peek_http_svc
            .serve(ServiceInput::new(std::io::Cursor::new(b"foobar".to_vec())))
            .await
            .unwrap();
        assert_eq!("other", response);
    }

    #[tokio::test]
    async fn test_peek_http1_connect() {
        for timeout in [Some(Duration::from_millis(500)), None] {
            let reader = StreamReader::new(
                stream_fn(async |mut yielder| {
                    yielder.yield_item(Bytes::from_static(b"CONN")).await;
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    yielder.yield_item(Bytes::from_static(b"EC")).await;
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    yielder
                        .yield_item(Bytes::from_static(b"T foobar.com:443 HTTP/1.1\r\n"))
                        .await;
                })
                .map(Ok::<_, std::io::Error>),
            );
            let writer = tokio::io::sink();

            let io = Box::pin(tokio::io::join(reader, writer));

            let (http_version, _) = peek_http_input(io, timeout).await.unwrap();

            assert_eq!(Some(HttpPeekVersion::Http1x), http_version);
        }
    }

    #[tokio::test]
    async fn test_peek_http1_complete_request_line_forms() {
        const CASES: &[&[u8]] = &[
            b"GET /\r\n",
            b"GET http://example.com/legacy\r\n",
            b"GET urn:legacy\r\n",
            b"GET / HTTP/1.1\r\n",
            b"GET /legacy HTTP/1.0\r\n",
            b"OPTIONS * HTTP/1.1\r\n",
            b"GET http://example.com/resource?q=1 HTTP/1.1\r\n",
            b"GET urn:opaque HTTP/1.1\r\n",
            b"GET http:/single-slash HTTP/1.1\r\n",
            b"CONNECT example.com:443 HTTP/1.1\r\n",
            b"PROPFIND /collection HTTP/1.1\r\n",
            b"QUERY /search HTTP/1.1\r\n",
            b"M-SEARCH /discovery HTTP/1.1\r\n",
            b"!#$%&'*+-.^_`|~ /extension HTTP/1.1\r\n",
            "GET /café HTTP/1.1\r\n".as_bytes(),
            b"GET / HTTP/1.1\n",
            b"GET /legacy HTTP/1.0\n",
            b"GET / HTTP/1.2\r\n",
            b"GET / HTTP/1.9\n",
            b"GET /\n",
            b"\r\nGET / HTTP/1.1\r\n",
            b"\n\n\r\nGET / HTTP/1.1\n",
            b"\nCONNECT example.com:443 HTTP/1.1\r\n",
        ];

        for &content in CASES {
            let (version, replayed) = peek_bytes(content, HttpPeekConfig::default()).await;
            assert_eq!(Some(HttpPeekVersion::Http1x), version, "{content:?}");
            assert_eq!(content, replayed, "{content:?}");
        }
    }

    #[tokio::test]
    async fn test_peek_http1_rejects_other_text_protocols_and_invalid_lines() {
        const CASES: &[&[u8]] = &[
            b"POST /\r\n",
            b"get /\r\n",
            b"GET *\r\n",
            b"GET * HTTP/1.1\r\n",
            b"POST * HTTP/1.1\r\n",
            b"OPTIONS icap://icap.example.net/service ICAP/1.0\r\n",
            b"OPTIONS * RTSP/2.0\r\n",
            b"OPTIONS sip:service@example.com SIP/2.0\r\n",
            b"GET / HTTP/1.1",
            b"GET / HTTP/1.a\r\n",
            b"GET / HTTP/1.10\r\n",
            b"GET / HTTP/2.0\r\n",
            b"GET / HTTP/1.1\r\r",
            b"\rGET / HTTP/1.1\r\n",
            b"\r\nPRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
            b"GET  / HTTP/1.1\r\n",
            b"GET /path#fragment HTTP/1.1\r\n",
            b"GE(T / HTTP/1.1\r\n",
            b"GE(/ HTTP/1.1\r\n",
            b" / HTTP/1.1\r\n",
            b"GET /bad\ttarget HTTP/1.1\r\n",
            b"GET http://[bad]/ HTTP/1.1\r\n",
            b"CONNECT /not-authority HTTP/1.1\r\n",
        ];

        for &content in CASES {
            let (version, replayed) = peek_bytes(content, HttpPeekConfig::default()).await;
            assert_eq!(None, version, "{content:?}");
            assert_eq!(content, replayed, "{content:?}");
        }
    }

    #[tokio::test]
    async fn test_peek_handles_single_byte_fragmentation() {
        const HTTP1: &[u8] = b"PROPFIND /collection HTTP/1.1\r\nbody";
        let (version, replayed) = peek_fragmented_bytes(HTTP1).await;
        assert_eq!(Some(HttpPeekVersion::Http1x), version);
        assert_eq!(HTTP1, replayed);

        const HTTP09: &[u8] = b"GET /legacy\r\n";
        let (version, replayed) = peek_fragmented_bytes(HTTP09).await;
        assert_eq!(Some(HttpPeekVersion::Http1x), version);
        assert_eq!(HTTP09, replayed);

        const HTTP1_LENIENT: &[u8] = b"\r\n\nGET /lenient HTTP/1.1\nbody";
        let (version, replayed) = peek_fragmented_bytes(HTTP1_LENIENT).await;
        assert_eq!(Some(HttpPeekVersion::Http1x), version);
        assert_eq!(HTTP1_LENIENT, replayed);

        const H2: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\nframes";
        let (version, replayed) = peek_fragmented_bytes(H2).await;
        assert_eq!(Some(HttpPeekVersion::H2), version);
        assert_eq!(H2, replayed);

        const ICAP: &[u8] = b"OPTIONS icap://icap.example.net/service ICAP/1.0\r\n";
        let (version, replayed) = peek_fragmented_bytes(ICAP).await;
        assert_eq!(None, version);
        assert_eq!(ICAP, replayed);
    }

    #[tokio::test]
    async fn test_peek_http1_configurable_buffer_limits() {
        const CONTENT: &[u8] = b"GET /configurable HTTP/1.1\r\n";

        let exact = HttpPeekConfig {
            max_http1_request_line_size: CONTENT.len(),
            read_buffer_size: 1,
            ..Default::default()
        };

        let (version, replayed) = peek_bytes(CONTENT, exact).await;
        assert_eq!(Some(HttpPeekVersion::Http1x), version);
        assert_eq!(CONTENT, replayed);

        let zero_read_size = HttpPeekConfig {
            read_buffer_size: 0,
            ..exact
        };

        let (version, replayed) = peek_bytes(CONTENT, zero_read_size).await;
        assert_eq!(Some(HttpPeekVersion::Http1x), version);
        assert_eq!(CONTENT, replayed);

        let too_small = HttpPeekConfig {
            max_http1_request_line_size: CONTENT.len() - 1,
            ..exact
        };

        let (version, replayed) = peek_bytes(CONTENT, too_small).await;
        assert_eq!(None, version);
        assert_eq!(CONTENT, replayed);

        let disabled = HttpPeekConfig {
            max_http1_request_line_size: 0,
            ..exact
        };

        let (version, replayed) = peek_bytes(CONTENT, disabled).await;
        assert_eq!(None, version);
        assert_eq!(CONTENT, replayed);

        let (version, replayed) = peek_bytes(H2_MAGIC_PREFIX, disabled).await;
        assert_eq!(Some(HttpPeekVersion::H2), version);
        assert_eq!(H2_MAGIC_PREFIX, replayed);
    }

    #[tokio::test]
    async fn test_peek_http1_starts_reasonably_and_grows_reads_on_demand() {
        let mut content = b"PROPFIND /".to_vec();
        content.extend(std::iter::repeat_n(
            b'a',
            INITIAL_HTTP_PEEK_READ_BUFFER_SIZE * 3,
        ));
        content.extend_from_slice(b" HTTP/1.1\r\nbody");
        let read_sizes = Arc::new(Mutex::new(Vec::new()));
        let reader = RecordingReader {
            inner: std::io::Cursor::new(content),
            read_sizes: Arc::clone(&read_sizes),
            max_read_size: usize::MAX,
        };
        let input = tokio::io::join(reader, tokio::io::sink());

        let (version, _input) = peek_http_input(input, None).await.unwrap();
        assert_eq!(Some(HttpPeekVersion::Http1x), version);

        let read_sizes = read_sizes.lock();
        assert_eq!(
            Some(&INITIAL_HTTP_PEEK_READ_BUFFER_SIZE),
            read_sizes.first()
        );
        assert!(read_sizes.len() >= 3, "read sizes: {read_sizes:?}");
        for sizes in read_sizes.windows(2) {
            assert!(
                sizes[1] <= sizes[0].saturating_mul(2),
                "read sizes should grow geometrically: {read_sizes:?}"
            );
            assert!(
                sizes[1] <= DEFAULT_HTTP_PEEK_READ_BUFFER_SIZE,
                "read size exceeded configured maximum: {read_sizes:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_peek_http1_does_not_grow_after_short_reads() {
        const CONTENT: &[u8] = b"PROPFIND /fragmented HTTP/1.1\r\n";
        let read_sizes = Arc::new(Mutex::new(Vec::new()));
        let reader = RecordingReader {
            inner: std::io::Cursor::new(CONTENT.to_vec()),
            read_sizes: Arc::clone(&read_sizes),
            max_read_size: 1,
        };
        let input = tokio::io::join(reader, tokio::io::sink());

        let (version, _input) = peek_http_input(input, None).await.unwrap();
        assert_eq!(Some(HttpPeekVersion::Http1x), version);

        let read_sizes = read_sizes.lock();
        assert!(read_sizes.len() > 1);
        assert!(
            read_sizes
                .iter()
                .all(|&size| size == INITIAL_HTTP_PEEK_READ_BUFFER_SIZE),
            "short reads should not grow the next read window: {read_sizes:?}"
        );
    }

    #[tokio::test]
    async fn test_peek_router_skips_configured_idle_method() {
        async fn fallback_service_fn(
            mut stream: impl Io + Unpin,
        ) -> Result<&'static str, io::Error> {
            let mut method = [0_u8; 4];
            stream.read_exact(&mut method).await?;
            assert_eq!(b"PING", &method);
            Ok("fallback")
        }

        let http_service = service_fn(async || Ok::<_, Infallible>("http"));
        let router = HttpPeekRouter::new(http_service)
            .with_known_non_http_protocol_methods()
            .with_fallback(service_fn(fallback_service_fn));
        let input = tokio::io::join(IdleAfterPrefix::new(b"PING"), tokio::io::sink());

        let result = tokio::time::timeout(Duration::from_secs(1), router.serve(input))
            .await
            .expect("configured method must fall back without waiting for a delimiter")
            .unwrap();
        assert_eq!("fallback", result);
    }

    #[tokio::test]
    async fn test_peek_http1_timeout_replays_partial_request_line() {
        const PREFIX: &[u8] = b"GET /slow ";
        const SUFFIX: &[u8] = b"HTTP/1.1\r\n";
        let reader = StreamReader::new(
            stream_fn(async |mut yielder| {
                yielder.yield_item(Bytes::from_static(PREFIX)).await;
                tokio::time::sleep(Duration::from_millis(50)).await;
                yielder.yield_item(Bytes::from_static(SUFFIX)).await;
            })
            .map(Ok::<_, std::io::Error>),
        );
        let io = Box::pin(tokio::io::join(reader, tokio::io::sink()));

        let (version, mut io) = peek_http_input(io, Some(Duration::from_millis(10)))
            .await
            .unwrap();
        assert_eq!(None, version);

        let mut replayed = Vec::new();
        io.read_to_end(&mut replayed).await.unwrap();
        assert_eq!([PREFIX, SUFFIX].concat(), replayed);
    }

    #[tokio::test]
    async fn test_http_router_default_fail_open_replays_partial_request_line_to_fallback() {
        const PREFIX: &[u8] = b"GET /slow ";

        async fn fallback_service_fn(
            mut stream: impl Io + Unpin,
        ) -> Result<&'static str, io::Error> {
            let mut prefix = [0_u8; PREFIX.len()];
            stream.read_exact(&mut prefix).await?;
            assert_eq!(PREFIX, prefix);
            Ok("fallback")
        }

        let router = HttpPeekRouter::new(service_fn(async || Ok::<_, Infallible>("http")))
            .with_peek_timeout(Duration::from_millis(10))
            .with_fallback(service_fn(fallback_service_fn));
        let input = tokio::io::join(IdleAfterPrefix::new(PREFIX), tokio::io::sink());

        let result = router.serve(input).await.unwrap();
        assert_eq!("fallback", result);
        assert_eq!(PeekTimeoutPolicy::FailOpen, PeekTimeoutPolicy::default());
    }

    #[tokio::test]
    async fn test_all_http_router_modes_fail_closed_without_invoking_fallback() {
        let fallback_calls = Arc::new(AtomicUsize::new(0));

        macro_rules! assert_fail_closed {
            ($router:expr) => {{
                let fallback_calls_for_service = Arc::clone(&fallback_calls);
                let fallback = service_fn(move || {
                    fallback_calls_for_service.fetch_add(1, Ordering::SeqCst);
                    async { Ok::<_, Infallible>("fallback") }
                });
                let router = $router
                    .with_peek_timeout(Duration::from_millis(10))
                    .with_peek_timeout_policy(PeekTimeoutPolicy::FailClosed)
                    .with_fallback(fallback);
                let input =
                    tokio::io::join(IdleAfterPrefix::new(b"GET /fragmented "), tokio::io::sink());

                let error = router.serve(input).await.unwrap_err();
                assert!(error.downcast_ref::<PeekTimeoutError>().is_some());
                assert_eq!(0, fallback_calls.load(Ordering::SeqCst));
            }};
        }

        assert_fail_closed!(HttpPeekRouter::new(service_fn(async || {
            Ok::<_, Infallible>("http")
        })));
        assert_fail_closed!(HttpPeekRouter::new_http1(service_fn(async || {
            Ok::<_, Infallible>("http1")
        })));
        assert_fail_closed!(HttpPeekRouter::new_h2(service_fn(async || {
            Ok::<_, Infallible>("h2")
        })));
        assert_fail_closed!(HttpPeekRouter::new_dual(
            service_fn(async || Ok::<_, Infallible>("http1")),
            service_fn(async || Ok::<_, Infallible>("h2")),
        ));
    }

    #[tokio::test]
    async fn test_http_definitive_mismatch_falls_back_under_both_timeout_policies() {
        for policy in [PeekTimeoutPolicy::FailOpen, PeekTimeoutPolicy::FailClosed] {
            let router = HttpPeekRouter::new(service_fn(async || Ok::<_, Infallible>("http")))
                .with_peek_timeout(Duration::from_millis(10))
                .with_peek_timeout_policy(policy)
                .with_fallback(service_fn(async || Ok::<_, Infallible>("fallback")));

            let response = router
                .serve(ServiceInput::new(std::io::Cursor::new(vec![0])))
                .await
                .unwrap();
            assert_eq!("fallback", response);
        }
    }

    #[tokio::test]
    async fn test_peek_http1_router() {
        let http_service = service_fn(async || Ok::<_, Infallible>("http1"));
        let fallback_service = service_fn(async || Ok::<_, Infallible>("other"));

        let peek_http_svc = HttpPeekRouter::new_http1(http_service).with_fallback(fallback_service);

        let response = peek_http_svc
            .serve(ServiceInput::new(std::io::Cursor::new(b"".to_vec())))
            .await
            .unwrap();
        assert_eq!("other", response);

        let response = peek_http_svc
            .serve(ServiceInput::new(std::io::Cursor::new(
                b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\nfoo".to_vec(),
            )))
            .await
            .unwrap();
        assert_eq!("other", response);

        const HTTP_METHODS: &[&str] = &[
            "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "CONNECT", "TRACE", "PATCH",
        ];
        for method in HTTP_METHODS {
            let target = if *method == "CONNECT" {
                "example.com:443"
            } else {
                "/foobar"
            };
            let response = peek_http_svc
                .serve(ServiceInput::new(std::io::Cursor::new(
                    format!("{method} {target} HTTP/1.1\r\n").into_bytes(),
                )))
                .await
                .unwrap();
            assert_eq!("http1", response);
        }

        let response = peek_http_svc
            .serve(ServiceInput::new(std::io::Cursor::new(b"foo".to_vec())))
            .await
            .unwrap();
        assert_eq!("other", response);

        let response = peek_http_svc
            .serve(ServiceInput::new(std::io::Cursor::new(b"foobar".to_vec())))
            .await
            .unwrap();
        assert_eq!("other", response);
    }

    #[tokio::test]
    async fn test_peek_h2_router() {
        let http_service = service_fn(async || Ok::<_, Infallible>("h2"));
        let fallback_service = service_fn(async || Ok::<_, Infallible>("other"));

        let peek_http_svc = HttpPeekRouter::new_h2(http_service).with_fallback(fallback_service);

        let response = peek_http_svc
            .serve(ServiceInput::new(std::io::Cursor::new(b"".to_vec())))
            .await
            .unwrap();
        assert_eq!("other", response);

        let response = peek_http_svc
            .serve(ServiceInput::new(std::io::Cursor::new(
                b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\nfoo".to_vec(),
            )))
            .await
            .unwrap();
        assert_eq!("h2", response);

        const HTTP_METHODS: &[&str] = &[
            "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "CONNECT", "TRACE", "PATCH",
        ];
        for method in HTTP_METHODS {
            let target = if *method == "CONNECT" {
                "example.com:443"
            } else {
                "/foobar"
            };
            let response = peek_http_svc
                .serve(ServiceInput::new(std::io::Cursor::new(
                    format!("{method} {target} HTTP/1.1\r\n").into_bytes(),
                )))
                .await
                .unwrap();
            assert_eq!("other", response);
        }

        let response = peek_http_svc
            .serve(ServiceInput::new(std::io::Cursor::new(b"foo".to_vec())))
            .await
            .unwrap();
        assert_eq!("other", response);

        let response = peek_http_svc
            .serve(ServiceInput::new(std::io::Cursor::new(b"foobar".to_vec())))
            .await
            .unwrap();
        assert_eq!("other", response);
    }

    #[tokio::test]
    async fn test_peek_dual_router() {
        let http1_service = service_fn(async || Ok::<_, Infallible>("http1"));
        let h2_service = service_fn(async || Ok::<_, Infallible>("h2"));
        let fallback_service = service_fn(async || Ok::<_, Infallible>("other"));

        let peek_http_svc =
            HttpPeekRouter::new_dual(http1_service, h2_service).with_fallback(fallback_service);

        let response = peek_http_svc
            .serve(ServiceInput::new(std::io::Cursor::new(b"".to_vec())))
            .await
            .unwrap();
        assert_eq!("other", response);

        let response = peek_http_svc
            .serve(ServiceInput::new(std::io::Cursor::new(
                b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\nfoo".to_vec(),
            )))
            .await
            .unwrap();
        assert_eq!("h2", response);

        const HTTP_METHODS: &[&str] = &[
            "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "CONNECT", "TRACE", "PATCH",
        ];
        for method in HTTP_METHODS {
            let target = if *method == "CONNECT" {
                "example.com:443"
            } else {
                "/foobar"
            };
            let response = peek_http_svc
                .serve(ServiceInput::new(std::io::Cursor::new(
                    format!("{method} {target} HTTP/1.1\r\n").into_bytes(),
                )))
                .await
                .unwrap();
            assert_eq!("http1", response);
        }

        let response = peek_http_svc
            .serve(ServiceInput::new(std::io::Cursor::new(b"foo".to_vec())))
            .await
            .unwrap();
        assert_eq!("other", response);

        let response = peek_http_svc
            .serve(ServiceInput::new(std::io::Cursor::new(b"foobar".to_vec())))
            .await
            .unwrap();
        assert_eq!("other", response);
    }

    #[tokio::test]
    async fn test_peek_router_read_eof() {
        const CONTENT: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\nfoobar";

        async fn http_service_fn(mut stream: impl Io + Unpin) -> Result<&'static str, BoxError> {
            let mut v = Vec::default();
            _ = stream.read_to_end(&mut v).await?;
            assert_eq!(CONTENT, v);

            Ok("ok")
        }
        let http_service = service_fn(http_service_fn);

        let peek_http_svc = HttpPeekRouter::new(http_service).with_fallback(RejectService::<
            &'static str,
            RejectError,
        >::new(
            RejectError::default(),
        ));

        let response = peek_http_svc
            .serve(ServiceInput::new(std::io::Cursor::new(CONTENT.to_vec())))
            .await
            .unwrap();
        assert_eq!("ok", response);
    }

    #[tokio::test]
    async fn test_peek_router_read_no_http_eof() {
        let cases = [
            "",
            "foo",
            "abcd",
            "abcde",
            "foobarbazbananas",
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nunc vehicula turpis nibh, eget euismod enim elementum et.",
        ];
        for content in cases {
            async fn http_service_fn() -> Result<Vec<u8>, BoxError> {
                Ok("http".as_bytes().to_vec())
            }
            let http_service = service_fn(http_service_fn);

            async fn other_service_fn(mut stream: impl Io + Unpin) -> Result<Vec<u8>, BoxError> {
                let mut v = Vec::default();
                _ = stream.read_to_end(&mut v).await?;
                Ok(v)
            }
            let other_service = service_fn(other_service_fn);

            let peek_http_svc = HttpPeekRouter::new(http_service).with_fallback(other_service);

            let response = peek_http_svc
                .serve(ServiceInput::new(std::io::Cursor::new(
                    content.as_bytes().to_vec(),
                )))
                .await
                .unwrap();

            assert_eq!(content.as_bytes(), &response[..]);
        }
    }

    struct RecordingReader {
        inner: std::io::Cursor<Vec<u8>>,
        read_sizes: Arc<Mutex<Vec<usize>>>,
        max_read_size: usize,
    }

    impl AsyncRead for RecordingReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            self.read_sizes.lock().push(buffer.remaining());
            let start = self.inner.position() as usize;
            let end = (start + buffer.remaining().min(self.max_read_size))
                .min(self.inner.get_ref().len());
            if start < end {
                buffer.put_slice(&self.inner.get_ref()[start..end]);
                self.inner.set_position(end as u64);
            }
            Poll::Ready(Ok(()))
        }
    }

    struct IdleAfterPrefix {
        prefix: Option<&'static [u8]>,
    }

    impl IdleAfterPrefix {
        fn new(prefix: &'static [u8]) -> Self {
            Self {
                prefix: Some(prefix),
            }
        }
    }

    impl AsyncRead for IdleAfterPrefix {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if let Some(prefix) = self.prefix.take() {
                buffer.put_slice(prefix);
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            }
        }
    }
}
