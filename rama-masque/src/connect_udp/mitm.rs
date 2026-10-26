//! Relay a client's own CONNECT-UDP session to its chosen proxy.
//!
//! These adapters validate successful responses without interpreting the proxy's URI
//! template or resolving the UDP target. The chosen proxy validates requests and
//! owns their error responses. Inner payloads and unknown capsules are
//! forwarded opaquely. The carrier HTTP version is preserved.

use super::{request::request_names_connect_udp, validate_connect_udp_response};
use rama_core::{
    Layer, Service,
    error::BoxError,
    extensions::{Extensions, ExtensionsRef as _},
    matcher::{
        Matcher,
        service::{ServiceMatch, ServiceMatcher},
    },
    rt::Executor,
};
use rama_http::{
    Request, Response, StatusCode, Version,
    datagram::{HttpDatagramRelay, handshake::CapsuleHandshakeError},
    proto::ext::HttpDatagrams,
};
use std::{convert::Infallible, time::Duration};

fn selected<B: Send + 'static>(request: &Request<B>, matcher: &impl Matcher<Request<B>>) -> bool {
    // Most intercepted traffic is ordinary HTTP. Classify before allocating
    // matcher metadata, and leave request validity to the client's chosen proxy.
    if !matches!(
        request.version(),
        Version::HTTP_11 | Version::HTTP_2 | Version::HTTP_3
    ) || !request_names_connect_udp(request)
    {
        return false;
    }
    let extensions = Extensions::new();
    if !matcher.matches(Some(&extensions), request) {
        return false;
    }
    request.extensions().extend(&extensions);
    request.extensions().insert(HttpDatagrams);
    true
}

fn accepted<B>(version: Version, response: &Response<B>) -> Result<bool, CapsuleHandshakeError> {
    if !response.status().is_success() && response.status() != StatusCode::SWITCHING_PROTOCOLS {
        return Ok(false);
    }
    validate_connect_udp_response(version, response)?;
    response.extensions().insert(HttpDatagrams);
    Ok(true)
}

/// Bounded opaque forwarding, with the same two-minute idle default as a
/// CONNECT-UDP socket. A half-close allows five seconds for the other direction
/// to drain. Shutdown and errors abort both stream-local transports.
#[must_use]
pub fn relay(exec: Executor) -> HttpDatagramRelay {
    HttpDatagramRelay::new(super::session_config())
        .with_idle_timeout(Duration::from_mins(2))
        .with_close_timeout(Duration::from_secs(5))
        .with_executor(exec)
}

/// Select CONNECT-UDP upgrades for an HTTP/1.1 or HTTP/2 MITM relay.
///
/// Install in `HttpUpgradeMitmRelayLayer`, alongside WebSocket and CONNECT
/// matchers. Refused responses pass through; malformed successful handshakes
/// fail before upgrading. Use [`ConnectUdpMitmLayer`] for HTTP/3.
#[derive(Debug, Clone)]
pub struct ConnectUdpRelayRequestMatcher<S = HttpDatagramRelay, M = bool> {
    relay_svc: S,
    matcher: M,
}

impl Default for ConnectUdpRelayRequestMatcher {
    fn default() -> Self {
        Self::default_with_exec(Executor::new())
    }
}

impl ConnectUdpRelayRequestMatcher {
    /// Use bounded opaque forwarding with the supplied shutdown executor.
    #[must_use]
    pub fn default_with_exec(exec: Executor) -> Self {
        Self::new(relay(exec))
    }
}

impl<S> ConnectUdpRelayRequestMatcher<S> {
    /// Use a relay service, optionally decorated with ordinary Rama layers.
    #[must_use]
    pub fn new(relay_svc: S) -> Self {
        Self {
            relay_svc,
            matcher: true,
        }
    }
}

impl<S, M> ConnectUdpRelayRequestMatcher<S, M> {
    /// Select sessions by destination, headers or connection metadata.
    /// A non-match leaves the request to other handlers; it does not deny access.
    /// Use HTTP policy middleware to reject a request before forwarding it.
    /// Matcher metadata is attached to the request. To pass selected metadata to
    /// the relay service, use HTTP middleware to copy those values into the
    /// request's own `HttpUpgradeMitmRelayExtensions` selection.
    #[must_use]
    pub fn with_matcher<N>(self, matcher: N) -> ConnectUdpRelayRequestMatcher<S, N> {
        ConnectUdpRelayRequestMatcher {
            relay_svc: self.relay_svc,
            matcher,
        }
    }
}

impl<S, M, B> ServiceMatcher<Request<B>> for ConnectUdpRelayRequestMatcher<S, M>
where
    S: Clone + Send + Sync + 'static,
    M: Matcher<Request<B>>,
    B: Send + 'static,
{
    type Service = ConnectUdpRelayResponseMatcher<S>;
    type Error = Infallible;
    type ModifiedInput = Request<B>;

    async fn match_service(
        &self,
        request: Request<B>,
    ) -> Result<ServiceMatch<Request<B>, Self::Service>, Infallible> {
        let service = if request.version() != Version::HTTP_3 && selected(&request, &self.matcher) {
            Some(ConnectUdpRelayResponseMatcher {
                version: request.version(),
                relay_svc: self.relay_svc.clone(),
            })
        } else {
            None
        };
        Ok(ServiceMatch {
            input: request,
            service,
        })
    }
}

/// The response half of [`ConnectUdpRelayRequestMatcher`].
#[derive(Debug, Clone)]
pub struct ConnectUdpRelayResponseMatcher<S> {
    version: Version,
    relay_svc: S,
}

impl<S, B> ServiceMatcher<Response<B>> for ConnectUdpRelayResponseMatcher<S>
where
    S: Clone + Send + Sync + 'static,
    B: Send + 'static,
{
    type Service = S;
    type Error = BoxError;
    type ModifiedInput = Response<B>;

    async fn match_service(
        &self,
        response: Response<B>,
    ) -> Result<ServiceMatch<Response<B>, S>, BoxError> {
        Ok(ServiceMatch {
            service: accepted(self.version, &response)?.then(|| self.relay_svc.clone()),
            input: response,
        })
    }

    async fn into_match_service(
        self,
        response: Response<B>,
    ) -> Result<ServiceMatch<Response<B>, S>, BoxError> {
        Ok(ServiceMatch {
            service: accepted(self.version, &response)?.then_some(self.relay_svc),
            input: response,
        })
    }
}

/// Explicitly select CONNECT-UDP datagrams in an HTTP/3 MITM relay.
///
/// Configure forwarding with `Http3MitmRelay::with_datagram_relay`.
/// This layer stores only protocol metadata, never services.
/// Both QUIC transports must also enable bounded datagrams. No other upgrade
/// token acquires Capsule semantics from this middleware.
#[derive(Debug, Clone)]
pub struct ConnectUdpMitmLayer<M = bool> {
    matcher: M,
}

impl Default for ConnectUdpMitmLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectUdpMitmLayer {
    /// Select all CONNECT-UDP handshakes.
    #[must_use]
    pub const fn new() -> Self {
        Self { matcher: true }
    }
}

impl<M> ConnectUdpMitmLayer<M> {
    /// Select sessions with an ordinary Rama matcher after protocol classification.
    /// A non-match is not an access denial; use HTTP middleware to reject requests.
    /// Matcher metadata is request-local. Use HTTP middleware to copy values
    /// for the upgraded ingress into the request's own
    /// `HttpUpgradeMitmRelayExtensions` selection.
    #[must_use]
    pub fn with_matcher<N>(self, matcher: N) -> ConnectUdpMitmLayer<N> {
        ConnectUdpMitmLayer { matcher }
    }
}

impl<S, M: Clone> Layer<S> for ConnectUdpMitmLayer<M> {
    type Service = ConnectUdpMitm<S, M>;
    fn layer(&self, inner: S) -> Self::Service {
        ConnectUdpMitm {
            inner,
            matcher: self.matcher.clone(),
        }
    }
}

/// Service created by [`ConnectUdpMitmLayer`].
#[derive(Debug, Clone)]
pub struct ConnectUdpMitm<S, M = bool> {
    inner: S,
    matcher: M,
}

impl<S, M> ConnectUdpMitm<S, M> {
    rama_utils::macros::define_inner_service_accessors!();
}

impl<S, M, B, R> Service<Request<B>> for ConnectUdpMitm<S, M>
where
    B: Send + 'static,
    R: Send + 'static,
    M: Matcher<Request<B>>,
    S: Service<Request<B>, Output = Response<R>, Error: Into<BoxError>>,
{
    type Output = Response<R>;
    type Error = BoxError;

    async fn serve(&self, request: Request<B>) -> Result<Self::Output, BoxError> {
        let selected = selected(&request, &self.matcher);
        let version = request.version();
        let response = self.inner.serve(request).await.map_err(Into::into)?;
        if selected {
            accepted(version, &response)?;
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests;
