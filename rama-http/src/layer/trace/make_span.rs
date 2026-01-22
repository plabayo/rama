use crate::Request;
use crate::header::USER_AGENT;
use crate::opentelemetry::version_as_protocol_version;
use rama_core::telemetry::tracing::{self, Level, Span};
use rama_net::http::RequestContext;

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

    rama_utils::macros::generate_set_and_with! {
        /// Set the [`Level`] used for the [tracing span].
        ///
        /// Defaults to [`Level::DEBUG`].
        ///
        /// [tracing span]: https://docs.rs/tracing/latest/tracing/#spans
        pub fn level(mut self, level: Level) -> Self {
            self.level = level;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Include request headers on the [`Span`].
        ///
        /// By default headers are not included.
        ///
        /// [`Span`]: tracing::Span
        pub fn include_headers(mut self, include_headers: bool) -> Self {
            self.include_headers = include_headers;
            self
        }
    }
}

impl Default for DefaultMakeSpan {
    fn default() -> Self {
        Self::new()
    }
}

impl<B> MakeSpan<B> for DefaultMakeSpan {
    fn make_span(&self, request: &Request<B>) -> Span {
        // to ensure that we always log authority even if not included in full protocol
        // TODO: in near future this will be slightly more elegant with input extensions,
        // it is blocking on the url rework that has to be done first
        let req_ctx = RequestContext::try_from(request);
        let (found_domain, found_port, found_scheme) = match &req_ctx {
            Ok(req_ctx) => {
                // according to OTEL spec domain can be domain or IP, so host is fine
                let authority = req_ctx.host_with_port();
                let scheme = req_ctx.protocol.as_str();

                (Some(authority.host), Some(authority.port), Some(scheme))
            }
            Err(err) => {
                tracing::debug!("error extracting request context: {err:?}");
                (None, None, None)
            }
        };

        let found_domain_cow_str = found_domain.as_ref().map(|d| d.to_str());
        let found_domain_str = found_domain_cow_str.as_deref();

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
                        url.domain = found_domain_str,
                        url.port = found_port,
                        url.path = request.uri().path(),
                        url.query = request.uri().query(),
                        url.scheme = found_scheme,
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
                        url.domain = found_domain_str,
                        url.port = found_port,
                        url.path = request.uri().path(),
                        url.query = request.uri().query(),
                        url.scheme = found_scheme,
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
