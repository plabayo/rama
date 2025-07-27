use crate::Request;
use crate::header::USER_AGENT;
use crate::opentelemetry::version_as_protocol_version;
use rama_core::telemetry::tracing::{self, Level, Span};

use super::DEFAULT_MESSAGE_LEVEL;

/// Trait used to generate [`Span`]s from requests. [`Trace`] wraps all request handling in this
/// span.
///
/// [`Span`]: tracing::Span
/// [`Trace`]: super::Trace
pub trait MakeSpan<B>: Send + Sync + 'static {
    /// Make a span from a request.
    fn make_span(&self, request: &Request<B>) -> Span;
}

impl<B> MakeSpan<B> for Span {
    fn make_span(&self, _request: &Request<B>) -> Span {
        self.clone()
    }
}

impl<F, B> MakeSpan<B> for F
where
    F: Fn(&Request<B>) -> Span + Send + Sync + 'static,
{
    fn make_span(&self, request: &Request<B>) -> Span {
        self(request)
    }
}

/// The default way [`Span`]s will be created for [`Trace`].
///
/// [`Span`]: tracing::Span
/// [`Trace`]: super::Trace
#[derive(Debug, Clone)]
pub struct DefaultMakeSpan {
    level: Level,
    include_headers: bool,
}

impl DefaultMakeSpan {
    /// Create a new `DefaultMakeSpan`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            level: DEFAULT_MESSAGE_LEVEL,
            include_headers: false,
        }
    }

    /// Set the [`Level`] used for the [tracing span].
    ///
    /// Defaults to [`Level::DEBUG`].
    ///
    /// [tracing span]: https://docs.rs/tracing/latest/tracing/#spans
    #[must_use]
    pub const fn level(mut self, level: Level) -> Self {
        self.level = level;
        self
    }

    /// Set the [`Level`] used for the [tracing span].
    ///
    /// Defaults to [`Level::DEBUG`].
    ///
    /// [tracing span]: https://docs.rs/tracing/latest/tracing/#spans
    pub fn set_level(&mut self, level: Level) -> &mut Self {
        self.level = level;
        self
    }

    /// Include request headers on the [`Span`].
    ///
    /// By default headers are not included.
    ///
    /// [`Span`]: tracing::Span
    #[must_use]
    pub const fn include_headers(mut self, include_headers: bool) -> Self {
        self.include_headers = include_headers;
        self
    }

    /// Include request headers on the [`Span`].
    ///
    /// By default headers are not included.
    ///
    /// [`Span`]: tracing::Span
    pub fn set_include_headers(&mut self, include_headers: bool) -> &mut Self {
        self.include_headers = include_headers;
        self
    }
}

impl Default for DefaultMakeSpan {
    fn default() -> Self {
        Self::new()
    }
}

impl<B> MakeSpan<B> for DefaultMakeSpan {
    fn make_span(&self, request: &Request<B>) -> Span {
        // This ugly macro is needed, unfortunately, because `tracing::span!`
        // required the level argument to be static. Meaning we can't just pass
        // `self.level`.
        macro_rules! make_span {
            ($level:expr) => {
                if self.include_headers {
                    tracing::span!(
                        $level,
                        "request",
                        http.request.method = %request.method(),
                        url.full = %request.uri(),
                        url.path = %request.uri().path(),
                        url.query = request.uri().query().unwrap_or_default(),
                        url.scheme = %request.uri().scheme().map(|s| s.as_str()).unwrap_or_default(),
                        network.protocol.name = "http",
                        network.protocol.version = version_as_protocol_version(request.version()),
                        user_agent.original = %request.headers().get(USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or_default(),
                        headers = ?request.headers(),
                    )
                } else {
                    tracing::span!(
                        $level,
                        "request",
                        http.request.method = %request.method(),
                        url.full = %request.uri(),
                        url.path = %request.uri().path(),
                        url.query = request.uri().query().unwrap_or_default(),
                        url.scheme = %request.uri().scheme().map(|s| s.as_str()).unwrap_or_default(),
                        network.protocol.name = "http",
                        network.protocol.version = version_as_protocol_version(request.version()),
                        user_agent.original = %request.headers().get(USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or_default(),
                    )
                }
            }
        }

        match self.level {
            Level::ERROR => make_span!(Level::ERROR),
            Level::WARN => make_span!(Level::WARN),
            Level::INFO => make_span!(Level::INFO),
            Level::DEBUG => make_span!(Level::DEBUG),
            Level::TRACE => make_span!(Level::TRACE),
        }
    }
}
