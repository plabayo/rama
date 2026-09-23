//! Learn HTTP alternative services from origin responses.
//!
//! [RFC 7838] allows an origin to advertise alternative protocols, hosts and
//! ports; the mechanism is independent of HTTP/3. [`AltSvcCache`] retains
//! all advertised protocols, and connector selection applies client capabilities.
//! Response headers are learned here; [`HttpServiceConnector`] also activates
//! connection-level learning of HTTP/2 ALTSVC frames, including idle connections.
//! DNS HTTPS/SVCB discovery is a
//! separate mechanism and must not be recorded as an Alt-Svc advertisement.
//!
//! The transport supplies the logical origin and whether it authenticated that
//! origin. The middleware records response hints and sets the typed `Alt-Used`
//! request header. Connection selection, authentication and retry policy remain
//! the transport's responsibility; a request is dispatched exactly once.
//!
//! [RFC 7838]: https://www.rfc-editor.org/rfc/rfc7838
//! [`HttpServiceConnector`]: crate::layer::http_service::HttpServiceConnector

mod cache;
mod frames;
#[doc(inline)]
pub use cache::AltSvcCache;
pub(crate) use cache::RouteContext;

use crate::{
    Body, Request, Response, StatusCode, StreamingBody,
    body::{Frame, SizeHint},
};
use pin_project_lite::pin_project;
use rama_core::{
    Layer, Service,
    error::{BoxError, error_chain},
    extensions::{Extensions, ExtensionsRef},
};
use rama_http_headers::{AltUsed, HeaderMapExt as _, TypedHeader as _};
use rama_http_types::{
    conn::{EstablishedHttpService, HttpOrigin, HttpServiceCandidates, HttpServiceSource},
    proto::h2::alt_svc::AltSvcReceivedAt,
};
use rama_net::{
    address::HostWithPort,
    client::{ConnectionError, ConnectionErrorDomain, ConnectionErrorKind, ConnectionPolicyScope},
};
use rama_utils::macros::{define_inner_service_accessors, generate_set_and_with};
use std::{
    any::Any,
    error::Error as StdError,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};

// Bound malformed/cyclic custom error chains without allocating.
const MAX_ERROR_SOURCE_DEPTH: usize = 64;

/// Learn alternatives for one logical HTTP origin over an established connection.
///
/// HTTPS learning requires [`Self::with_authenticated`] from a transport that
/// verified the origin. Plaintext HTTP may supply hints, but automatic selection
/// requires the additional origin authorization from RFC 8164. Passing no cache
/// disables learning.
#[derive(Clone, Debug)]
pub struct AltSvcLayer {
    cache: Option<AltSvcCache>,
    origin: HttpOrigin,
    authenticated: bool,
    alternative: Option<HostWithPort>,
    selection: Option<(Arc<HttpServiceCandidates>, usize)>,
    failure: Option<AlternativeFailure>,
}

/// Established endpoint and fixed connector policy, independent of whichever
/// advertisement is current when a response fails.
#[derive(Clone, Debug)]
struct AlternativeFailure {
    service: Arc<EstablishedHttpService>,
    route: Option<RouteContext>,
    network: u64,
}

impl AltSvcLayer {
    /// Create middleware scoped to the logical origin, independently of the dial target.
    pub fn new(origin: HttpOrigin) -> Self {
        Self {
            cache: None,
            origin,
            authenticated: false,
            alternative: None,
            selection: None,
            failure: None,
        }
    }

    pub(crate) fn with_connection(
        mut self,
        connection: &impl ExtensionsRef,
        route: Option<RouteContext>,
    ) -> Self {
        // A request's trust anchors must not publish hints to clients using
        // the connector's default policy, including an advertisement of clear.
        let connector_policy = connection.extensions().get_ref::<ConnectionPolicyScope>()
            == Some(&ConnectionPolicyScope::Connector);
        if self.origin.is_secure() && !connector_policy {
            self.cache = None;
            return self;
        }
        if let Some(cache) = &self.cache
            && connector_policy
            && let Some(service) = connection.extensions().get_arc::<EstablishedHttpService>()
            && service.origin == self.origin
            && service.candidate.source == HttpServiceSource::AltSvc
        {
            self.failure = Some(AlternativeFailure {
                service,
                route,
                network: cache.network_epoch(),
            });
        }
        self
    }

    fn record_failure(&self, error: &dyn Any, started: Instant) {
        if let (Some(cache), Some(failure)) = (&self.cache, &self.failure)
            && is_remote_response_failure(error)
        {
            cache.failed_service(
                &failure.service,
                failure.route.as_ref(),
                failure.network,
                started,
            );
        }
    }

    generate_set_and_with! {
        /// Share an advertisement cache; `None` disables learning.
        pub fn cache(mut self, cache: Option<AltSvcCache>) -> Self {
            self.cache = cache;
            self
        }
    }

    generate_set_and_with! {
        /// Declare whether this connection authenticated the logical HTTPS origin.
        ///
        /// This must represent successful certificate and configured peer-policy
        /// verification, not merely the presence of encryption or a peer certificate.
        pub fn authenticated(mut self, authenticated: bool) -> Self {
            self.authenticated = authenticated;
            self
        }
    }

    generate_set_and_with! {
        /// Set the selected alternative authority to report in `Alt-Used`.
        pub fn alternative(mut self, alternative: Option<HostWithPort>) -> Self {
            self.alternative = alternative;
            self.selection = None;
            self
        }
    }

    generate_set_and_with! {
        /// Identify the exact cached candidate used by this connection.
        ///
        /// Carries advertisement identity so a 421 cannot remove a newer hint for
        /// the same endpoint. Also sets `Alt-Used` from the selected candidate.
        pub fn selection(mut self, snapshot: Arc<HttpServiceCandidates>, index: usize) -> Self {
            self.alternative = None;
            self.selection = None;
            if snapshot.origin() == &self.origin
                && let Some(candidate) = snapshot.get(index)
                && candidate.source == HttpServiceSource::AltSvc
            {
                self.alternative = Some(candidate.target.clone());
                self.selection = Some((snapshot, index));
            }
            self
        }
    }
}

/// Recognize the standard classified error forms without restricting a service's
/// error type. In particular, an `Err(Response)` or opaque application error is
/// not evidence of endpoint failure. The first classification is authoritative:
/// an outer local body error must not expose a remote error nested inside it.
fn is_remote_response_failure(error: &dyn Any) -> bool {
    let error: &(dyn StdError + 'static) =
        if let Some(error) = error.downcast_ref::<ConnectionError>() {
            error
        } else if let Some(error) = error.downcast_ref::<BoxError>() {
            error.as_ref()
        } else {
            return false;
        };
    error_chain(error, MAX_ERROR_SOURCE_DEPTH)
        .find_map(|error| error.downcast_ref::<ConnectionError>())
        .is_some_and(|error| {
            matches!(
                error.domain(),
                ConnectionErrorDomain::Transport | ConnectionErrorDomain::Application
            ) && matches!(
                error.kind(),
                ConnectionErrorKind::Unavailable
                    | ConnectionErrorKind::Timeout
                    | ConnectionErrorKind::Protocol
                    | ConnectionErrorKind::Rejected
                    | ConnectionErrorKind::Authentication
            )
        })
}

impl<S> Layer<S> for AltSvcLayer {
    type Service = AltSvc<S>;
    fn layer(&self, inner: S) -> Self::Service {
        AltSvc {
            inner,
            policy: Some(self.clone()),
        }
    }
}

/// Service applying an [`AltSvcLayer`] to an established connection.
#[derive(Clone, Debug)]
pub struct AltSvc<S> {
    inner: S,
    policy: Option<AltSvcLayer>,
}

impl<S> AltSvc<S> {
    define_inner_service_accessors!();

    /// Wrap a connection without changing requests or learning advertisements.
    pub fn passthrough(inner: S) -> Self {
        Self {
            inner,
            policy: None,
        }
    }
}

impl<S: ExtensionsRef> ExtensionsRef for AltSvc<S> {
    fn extensions(&self) -> &Extensions {
        self.inner.extensions()
    }
}

pin_project! {
    /// Response body preserving the underlying frames and errors while recording
    /// complete responses and remote failures of a discovered alternative.
    /// Dropping an unread body is not evidence of success or endpoint failure.
    /// The wrapper does not allocate.
    #[derive(Debug)]
    pub struct AltSvcBody<B> {
        #[pin]
        inner: B,
        failure: Option<BodyFailure>,
    }
}

#[derive(Debug)]
struct BodyFailure {
    cache: AltSvcCache,
    alternative: AlternativeFailure,
    started: Instant,
    accepted: bool,
}

impl BodyFailure {
    fn succeeded(self) {
        if self.accepted {
            self.cache.succeeded_service(
                &self.alternative.service,
                self.alternative.route.as_ref(),
                self.alternative.network,
            );
        }
    }
}

impl<B: StreamingBody> AltSvcBody<B> {
    fn new(inner: B, policy: &AltSvcLayer, started: Instant, accepted: bool) -> Self {
        let failure =
            policy
                .failure
                .as_ref()
                .zip(policy.cache.as_ref())
                .map(|(alternative, cache)| BodyFailure {
                    cache: cache.clone(),
                    alternative: alternative.clone(),
                    started,
                    accepted,
                });
        // Empty responses are complete without ever being polled.
        let failure = if inner.is_end_stream() {
            if let Some(failure) = failure {
                failure.succeeded();
            }
            None
        } else {
            failure
        };
        Self { inner, failure }
    }
}

impl AltSvcBody<Body> {
    /// Normalize a response to Rama's common body type. Ordinary origin
    /// responses retain their existing allocation; tracked alternatives retain
    /// failure observation until their bodies complete.
    pub fn into_body(self) -> Body {
        if self.failure.is_none() || self.inner.is_end_stream() {
            if let Some(failure) = self.failure {
                failure.succeeded();
            }
            self.inner
        } else {
            Body::new(self)
        }
    }
}

impl From<AltSvcBody<Self>> for Body {
    fn from(body: AltSvcBody<Self>) -> Self {
        body.into_body()
    }
}

impl<B> StreamingBody for AltSvcBody<B>
where
    B: StreamingBody<Error: 'static>,
{
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let mut this = self.project();
        let result = this.inner.as_mut().poll_frame(cx);
        match &result {
            Poll::Ready(Some(Err(error))) => {
                if let Some(failure) = this.failure.take()
                    && is_remote_response_failure(error)
                {
                    failure.cache.failed_service(
                        &failure.alternative.service,
                        failure.alternative.route.as_ref(),
                        failure.alternative.network,
                        failure.started,
                    );
                }
            }
            Poll::Ready(None) => {
                if let Some(failure) = this.failure.take() {
                    failure.succeeded();
                }
            }
            Poll::Ready(Some(Ok(_))) if this.inner.is_end_stream() => {
                if let Some(failure) = this.failure.take() {
                    failure.succeeded();
                }
            }
            _ => {}
        }
        result
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for AltSvc<S>
where
    S: Service<Request<ReqBody>, Output = Response<ResBody>>,
    ReqBody: Send + 'static,
    ResBody: StreamingBody + Send + 'static,
{
    type Output = Response<AltSvcBody<ResBody>>;
    type Error = S::Error;

    async fn serve(&self, mut request: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        let Some(policy) = &self.policy else {
            return self.inner.serve(request).await.map(|response| {
                response.map(|inner| AltSvcBody {
                    inner,
                    failure: None,
                })
            });
        };
        if let Some(target) = &policy.alternative {
            request
                .headers_mut()
                .typed_insert(AltUsed::from(target.clone()));
        } else {
            request.headers_mut().remove(AltUsed::name());
        }
        let started = Instant::now();
        let response = self
            .inner
            .serve(request)
            .await
            .inspect_err(|error| policy.record_failure(error, started))?;
        if let Some(cache) = &policy.cache {
            if response.status() == StatusCode::MISDIRECTED_REQUEST {
                if let Some((snapshot, index)) = &policy.selection {
                    cache.misdirected(snapshot, *index);
                }
            } else if policy.authenticated || !policy.origin.is_secure() {
                if let Some(received) = response.extensions().get_ref::<AltSvcReceivedAt>() {
                    cache.record_received(
                        &policy.origin,
                        response.headers(),
                        received.instant.saturating_duration_since(started),
                        *received,
                    );
                } else {
                    cache.record(&policy.origin, response.headers(), started.elapsed());
                }
            }
        }
        let accepted = response.status() != StatusCode::MISDIRECTED_REQUEST;
        Ok(response.map(|body| AltSvcBody::new(body, policy, started, accepted)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Body;
    use rama_core::{error::BoxErrorExt as _, service::service_fn};
    use rama_net::Protocol;
    use std::{
        convert::Infallible,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    fn origin(protocol: Protocol) -> HttpOrigin {
        HttpOrigin::new(protocol, "example.com:443".parse().unwrap()).unwrap()
    }

    #[tokio::test]
    async fn remote_response_failures_suppress_the_actual_endpoint_without_replay() {
        for scope in [
            ConnectionPolicyScope::Connector,
            ConnectionPolicyScope::Request,
            ConnectionPolicyScope::Unknown,
        ] {
            let cache = AltSvcCache::default();
            let origin = origin(Protocol::HTTPS);
            let mut headers = crate::HeaderMap::new();
            headers.insert(
                "alt-svc",
                "h2=\"first.example:443\", h3=\"second.example:443\""
                    .parse()
                    .unwrap(),
            );
            cache.record(&origin, &headers, Duration::ZERO);
            let snapshot = cache.lookup(&origin).unwrap();
            let connection = Extensions::new();
            connection.insert(scope);
            connection.insert(EstablishedHttpService {
                origin: origin.clone(),
                candidate: snapshot.get(0).unwrap().clone(),
            });
            let dispatched = Arc::new(AtomicUsize::new(0));
            let service = AltSvcLayer::new(origin.clone())
                .with_cache(cache.clone())
                .with_connection(&connection, None)
                .layer(service_fn({
                    let dispatched = dispatched.clone();
                    move |_: Request| {
                        dispatched.fetch_add(1, Ordering::Relaxed);
                        async {
                            Err::<Response, BoxError>(Box::new(ConnectionError::application(
                                BoxError::from_static_str("peer reset the response stream"),
                                ConnectionErrorKind::Unavailable,
                            )))
                        }
                    }
                }));
            // The current advertisement may have a different order from the
            // one which established the still-healthy multiplexed connection.
            headers.insert(
                "alt-svc",
                "h3=\"second.example:443\", h2=\"first.example:443\""
                    .parse()
                    .unwrap(),
            );
            cache.record(&origin, &headers, Duration::ZERO);
            let current = cache.lookup(&origin).unwrap();
            let error = service
                .serve(Request::new(Body::empty()))
                .await
                .unwrap_err();
            assert!(error.to_string().contains("peer reset the response stream"));
            assert_eq!(dispatched.load(Ordering::Relaxed), 1);
            assert!(cache.is_usable(&current, 0));
            assert_eq!(
                cache.is_usable(&current, 1),
                scope != ConnectionPolicyScope::Connector
            );
        }
    }

    #[test]
    fn local_or_unclassified_response_errors_cannot_expose_nested_remote_failures() {
        let remote = || {
            ConnectionError::application(
                BoxError::from_static_str("remote reset"),
                ConnectionErrorKind::Unavailable,
            )
        };
        assert!(is_remote_response_failure(&remote()));
        let boxed: BoxError = Box::new(remote());
        assert!(is_remote_response_failure(&boxed));
        for domain in [ConnectionErrorDomain::Local, ConnectionErrorDomain::Unknown] {
            let error: BoxError = Box::new(ConnectionError::new(
                Box::new(remote()),
                domain,
                ConnectionErrorKind::Other,
            ));
            assert!(!is_remote_response_failure(&error));
        }
        assert!(!is_remote_response_failure(&Response::new(Body::empty())));
        assert!(!is_remote_response_failure(&BoxError::from_static_str(
            "application failure"
        )));
    }

    #[tokio::test]
    async fn https_learning_requires_authentication_http_hints_do_not() {
        for (protocol, authenticated, enabled, expected) in [
            (Protocol::HTTPS, false, true, false),
            (Protocol::HTTPS, true, false, false),
            (Protocol::HTTPS, true, true, true),
            (Protocol::HTTP, false, true, true),
        ] {
            let cache = AltSvcCache::default();
            let origin = origin(protocol);
            let service = AltSvcLayer::new(origin.clone())
                .maybe_with_cache(enabled.then(|| cache.clone()))
                .with_authenticated(authenticated)
                .layer(service_fn(async |request: Request| {
                    assert!(!request.headers().contains_key(AltUsed::name()));
                    Ok::<_, Infallible>(
                        Response::builder()
                            .header("alt-svc", "h2=\":8443\", h3=\":443\"")
                            .body(Body::empty())
                            .unwrap(),
                    )
                }));
            service
                .serve(
                    Request::builder()
                        .header("alt-used", "stale.example:443")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(cache.lookup(&origin).is_some(), expected);
        }
    }

    #[tokio::test]
    async fn request_authentication_cannot_replace_or_clear_shared_advertisements() {
        for scope in [
            ConnectionPolicyScope::Connector,
            ConnectionPolicyScope::Request,
            ConnectionPolicyScope::Unknown,
        ] {
            for advertisement in ["clear", "h3=\":9443\""] {
                let cache = AltSvcCache::default();
                let origin = origin(Protocol::HTTPS);
                let mut headers = crate::HeaderMap::new();
                headers.insert("alt-svc", "h2=\":8443\"".parse().unwrap());
                cache.record(&origin, &headers, Duration::ZERO);
                let before = cache.lookup(&origin).unwrap();
                let connection = Extensions::new();
                connection.insert(scope);
                let service = AltSvcLayer::new(origin.clone())
                    .with_cache(cache.clone())
                    .with_authenticated(true)
                    .with_connection(&connection, None)
                    .layer(service_fn(move |_: Request| async move {
                        Ok::<_, Infallible>(
                            Response::builder()
                                .header("alt-svc", advertisement)
                                .body(Body::empty())
                                .unwrap(),
                        )
                    }));
                service.serve(Request::new(Body::empty())).await.unwrap();
                let after = cache.lookup(&origin);
                if scope == ConnectionPolicyScope::Connector {
                    assert!(
                        after
                            .as_ref()
                            .is_none_or(|after| !Arc::ptr_eq(&before, after))
                    );
                } else {
                    assert!(Arc::ptr_eq(&before, &after.unwrap()));
                }
            }
        }
    }

    #[tokio::test]
    async fn misdirected_removes_only_selected_advertisement_without_replaying() {
        let cache = AltSvcCache::default();
        let origin = origin(Protocol::HTTPS);
        let mut headers = crate::HeaderMap::new();
        headers.insert(
            "alt-svc",
            "h2=\"alternative.example:8443\", h3=\":443\""
                .parse()
                .unwrap(),
        );
        cache.record(&origin, &headers, Duration::ZERO);
        let snapshot = cache.lookup(&origin).unwrap();
        let target = snapshot.get(0).unwrap().target.clone();
        let dispatched = Arc::new(AtomicUsize::new(0));
        let service = AltSvcLayer::new(origin.clone())
            .with_cache(cache.clone())
            .with_authenticated(true)
            .with_selection(snapshot.clone(), 0)
            .layer(service_fn({
                let dispatched = dispatched.clone();
                move |request: Request| {
                    let dispatched = dispatched.clone();
                    let target = target.clone();
                    async move {
                        dispatched.fetch_add(1, Ordering::SeqCst);
                        assert_eq!(
                            request.headers().typed_get::<AltUsed>(),
                            Some(AltUsed::from(target))
                        );
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(StatusCode::MISDIRECTED_REQUEST)
                                .header("alt-svc", "h3=\":9443\"")
                                .body(Body::empty())
                                .unwrap(),
                        )
                    }
                }
            }));
        assert_eq!(
            service
                .serve(Request::new(Body::empty()))
                .await
                .unwrap()
                .status(),
            StatusCode::MISDIRECTED_REQUEST
        );
        assert_eq!(dispatched.load(Ordering::SeqCst), 1);
        assert!(!cache.is_usable(&snapshot, 0));
        assert!(cache.is_usable(&snapshot, 1));
    }

    #[tokio::test]
    async fn late_421_cannot_remove_same_target_readvertised_during_request() {
        let cache = AltSvcCache::default();
        let origin = origin(Protocol::HTTPS);
        let mut headers = crate::HeaderMap::new();
        headers.insert("alt-svc", "h2=\":8443\"".parse().unwrap());
        cache.record(&origin, &headers, Duration::ZERO);
        let snapshot = cache.lookup(&origin).unwrap();
        let service = AltSvcLayer::new(origin.clone())
            .with_cache(cache.clone())
            .with_authenticated(true)
            .with_selection(snapshot, 0)
            .layer(service_fn({
                let cache = cache.clone();
                let origin = origin.clone();
                move |_: Request| {
                    cache.record(&origin, &headers, Duration::ZERO);
                    async {
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(StatusCode::MISDIRECTED_REQUEST)
                                .body(Body::empty())
                                .unwrap(),
                        )
                    }
                }
            }));
        service.serve(Request::new(Body::empty())).await.unwrap();
        let replacement = cache.lookup(&origin).unwrap();
        assert!(cache.is_usable(&replacement, 0));
    }

    #[tokio::test]
    async fn configured_service_does_not_manufacture_alt_used() {
        let origin = origin(Protocol::HTTPS);
        let snapshot = Arc::new(HttpServiceCandidates::new(
            origin.clone(),
            vec![rama_http_types::conn::HttpServiceCandidate::new(
                rama_net::tls::ApplicationProtocol::HTTP_2,
                "configured.example:443".parse().unwrap(),
            )],
        ));
        let service = AltSvcLayer::new(origin)
            .with_selection(snapshot, 0)
            .layer(service_fn(async |request: Request| {
                assert!(!request.headers().contains_key(AltUsed::name()));
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }));
        service.serve(Request::new(Body::empty())).await.unwrap();
    }

    #[tokio::test]
    async fn passthrough_preserves_headers() {
        let service = AltSvc::passthrough(service_fn(async |request: Request| {
            assert_eq!(
                request.headers().get(AltUsed::name()).unwrap(),
                "existing.example:443"
            );
            Ok::<_, Infallible>(Response::new(Body::empty()))
        }));
        service
            .serve(
                Request::builder()
                    .header("alt-used", "existing.example:443")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
    }
}
