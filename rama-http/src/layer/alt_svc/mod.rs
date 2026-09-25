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
//! Each request supplies its logical origin; connection metadata supplies the
//! actual endpoint, authenticated identity and policy scope. The middleware records response hints and sets the typed `Alt-Used`
//! request header. Connection selection, authentication and retry policy remain
//! the transport's responsibility; a request is dispatched exactly once.
//!
//! [RFC 7838]: https://www.rfc-editor.org/rfc/rfc7838
//! [`HttpServiceConnector`]: crate::layer::http_service::HttpServiceConnector

mod cache;
mod frames;
#[cfg(test)]
mod provenance_tests;
#[doc(inline)]
pub use cache::AltSvcCache;

use crate::layer::http_service::authenticates;
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
    conn::{EstablishedHttpService, HttpOrigin, HttpServiceSelection, HttpServiceSource},
    proto::h2::alt_svc::AltSvcReceivedAt,
};
use rama_net::{
    AuthorityInputExt as _, Protocol, ProtocolInputExt as _,
    client::{
        ConnectionAttempt, ConnectionError, ConnectionErrorDomain, ConnectionErrorKind,
        ConnectionPolicyScope, ProxyRouteContext,
    },
};
use rama_utils::macros::define_inner_service_accessors;
use std::{
    any::Any,
    error::Error as StdError,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};

/// Observe alternative services on an HTTP request service.
///
/// Configure once with a shared cache. Every call resolves its own logical origin
/// and reads the actual connection's [`EstablishedHttpService`] and authentication
/// metadata. A selector may supply [`HttpServiceSelection`] on the request; no
/// particular selector implementation is required.
///
/// HTTPS advertisements can update shared discovery only when the connection
/// authenticated this origin under [`ConnectionPolicyScope::Connector`].
/// Request-specific trust never changes the configured cache or other requests'
/// discovery state. Plaintext advertisements remain hints (RFC 8164).
///
/// Remote failures are recognized as [`ConnectionError`], directly or inside
/// [`BoxError`]. Other error types pass through without changing shared backoff;
/// custom services can box classified source chains to participate.
#[derive(Clone, Debug)]
pub struct AltSvcLayer {
    cache: AltSvcCache,
}

impl AltSvcLayer {
    /// Share discovery state with a selector or another HTTP client.
    pub fn new(cache: AltSvcCache) -> Self {
        Self { cache }
    }
}

/// Outcome context for one dispatch, never stored on a shared service.
struct Observation {
    origin: HttpOrigin,
    may_learn: bool,
    selection: Option<Arc<HttpServiceSelection>>,
    failure: Option<AlternativeFailure>,
}

/// Established endpoint and route whose body outcome updates backoff.
#[derive(Clone, Debug)]
struct AlternativeFailure {
    service: Arc<EstablishedHttpService>,
    route: Option<ProxyRouteContext>,
    network: u64,
}

impl Observation {
    fn new(
        cache: &AltSvcCache,
        origin: HttpOrigin,
        connection: &impl ExtensionsRef,
        request: &impl ExtensionsRef,
        alternative: Option<SelectedAlternative>,
    ) -> Self {
        let connector_policy = connection.extensions().get_ref::<ConnectionPolicyScope>()
            == Some(&ConnectionPolicyScope::Connector)
            && request
                .extensions()
                .get_ref::<ConnectionAttempt>()
                .is_none_or(|attempt| attempt.policy_scope() != ConnectionPolicyScope::Request);
        let (service, selection) = alternative.map_or((None, None), |(service, selection)| {
            (Some(service), selection)
        });
        let failure = connector_policy
            .then(|| {
                service.map(|service| AlternativeFailure {
                    service,
                    route: selection.as_ref().map_or_else(
                        || ProxyRouteContext::for_request(request.extensions()),
                        |selection| selection.route.clone(),
                    ),
                    network: cache.network_epoch(),
                })
            })
            .flatten();
        Self {
            may_learn: !origin.is_secure()
                || (connector_policy && authenticates(connection, &origin)),
            origin,
            selection,
            failure,
        }
    }

    fn record_failure(&self, cache: &AltSvcCache, error: &dyn Any, started: Instant) {
        if let Some(failure) = &self.failure
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
}

type SelectedAlternative = (
    Arc<EstablishedHttpService>,
    Option<Arc<HttpServiceSelection>>,
);

/// Match request-local discovery against immutable connection endpoint facts.
/// The same pooled endpoint can be selected from different discovery sources.
fn alternative_for_request(
    connection: &impl ExtensionsRef,
    request: &impl ExtensionsRef,
    origin: &HttpOrigin,
) -> Option<SelectedAlternative> {
    let established = connection
        .extensions()
        .get_arc::<EstablishedHttpService>()
        .filter(|service| &service.origin == origin)?;
    let selection = request
        .extensions()
        .get_arc::<HttpServiceSelection>()
        .filter(|selection| {
            selection.candidates.origin() == origin
                && selection
                    .candidates
                    .get(selection.index)
                    .is_some_and(|candidate| {
                        candidate.protocol == established.candidate.protocol
                            && candidate.target == established.candidate.target
                    })
        });
    if let Some(selection) = selection {
        let candidate = selection.candidates.get(selection.index)?;
        if candidate.source != HttpServiceSource::AltSvc {
            return None;
        }
        let service = if established.candidate.source == candidate.source {
            established
        } else {
            Arc::new(EstablishedHttpService::new(
                origin.clone(),
                candidate.clone(),
            ))
        };
        Some((service, Some(selection)))
    } else {
        (established.candidate.source == HttpServiceSource::AltSvc).then_some((established, None))
    }
}

/// Resolve the logical request target, never the physical alternative endpoint.
/// WebSocket opening handshakes belong to the corresponding HTTP(S) origin.
fn request_origin<B>(request: &Request<B>) -> Option<HttpOrigin> {
    let protocol = match request.protocol()? {
        protocol if protocol == &Protocol::WS => Protocol::HTTP,
        protocol if protocol == &Protocol::WSS => Protocol::HTTPS,
        protocol => protocol.clone(),
    };
    let authority = request
        .authority()?
        .into_host_with_port(protocol.default_port())?;
    HttpOrigin::new(protocol, authority).ok()
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
    error_chain(error)
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
            cache: Some(self.cache.clone()),
        }
    }
}

/// Service applying an [`AltSvcLayer`] to an established connection.
#[derive(Clone, Debug)]
pub struct AltSvc<S> {
    inner: S,
    cache: Option<AltSvcCache>,
}

impl<S> AltSvc<S> {
    define_inner_service_accessors!();

    /// Disable advertisement learning while preserving actual Alt-Used bookkeeping.
    pub fn passthrough(inner: S) -> Self {
        Self { inner, cache: None }
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
    fn new(
        inner: B,
        cache: &AltSvcCache,
        policy: &Observation,
        started: Instant,
        accepted: bool,
    ) -> Self {
        let failure = policy.failure.as_ref().map(|alternative| BodyFailure {
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
    S: Service<Request<ReqBody>, Output = Response<ResBody>> + ExtensionsRef,
    ReqBody: Send + 'static,
    ResBody: StreamingBody + Send + 'static,
{
    type Output = Response<AltSvcBody<ResBody>>;
    type Error = S::Error;

    async fn serve(&self, mut request: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        // Disabled discovery on an ordinary connection is a true passthrough:
        // do not allocate request-origin metadata or rewrite caller headers.
        if self.cache.is_none() && !self.inner.extensions().contains::<EstablishedHttpService>() {
            return self.inner.serve(request).await.map(|response| {
                response.map(|inner| AltSvcBody {
                    inner,
                    failure: None,
                })
            });
        }
        let origin = request_origin(&request);
        let alternative = origin
            .as_ref()
            .and_then(|origin| alternative_for_request(&self.inner, &request, origin));
        if let Some((service, _)) = &alternative {
            request
                .headers_mut()
                .typed_insert(AltUsed::from(service.candidate.target.clone()));
        } else if origin.is_some() {
            request.headers_mut().remove(AltUsed::name());
        }
        let observation = self.cache.as_ref().zip(origin).map(|(cache, origin)| {
            Observation::new(cache, origin, &self.inner, &request, alternative)
        });
        let started = Instant::now();
        let response = self.inner.serve(request).await.inspect_err(|error| {
            if let (Some(cache), Some(observation)) = (&self.cache, &observation) {
                observation.record_failure(cache, error, started);
            }
        })?;
        if let (Some(cache), Some(policy)) = (&self.cache, &observation) {
            if response.status() == StatusCode::MISDIRECTED_REQUEST {
                if policy.may_learn
                    && let Some(selection) = &policy.selection
                {
                    cache.misdirected(&selection.candidates, selection.index);
                }
            } else if policy.may_learn {
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
        Ok(response.map(|body| match (&self.cache, &observation) {
            (Some(cache), Some(policy)) => AltSvcBody::new(body, cache, policy, started, accepted),
            _ => AltSvcBody {
                inner: body,
                failure: None,
            },
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Body;
    use rama_core::{error::BoxErrorExt as _, service::service_fn};
    use rama_http_types::conn::{
        HttpServiceCandidate, HttpServiceCandidates, HttpServiceSelection,
    };
    use rama_net::{Protocol, address::HostWithPort, tls::ApplicationProtocol};
    #[cfg(feature = "tls")]
    use rama_tls::client::TlsServerAuthentication;

    use std::{
        convert::Infallible,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    struct Connection<S> {
        inner: S,
        extensions: Extensions,
    }

    impl<S> ExtensionsRef for Connection<S> {
        fn extensions(&self) -> &Extensions {
            &self.extensions
        }
    }

    impl<S, Input> Service<Input> for Connection<S>
    where
        S: Service<Input>,
        Input: Send + 'static,
    {
        type Output = S::Output;
        type Error = S::Error;

        async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
            self.inner.serve(input).await
        }
    }

    fn connection<S>(inner: S, extensions: Extensions) -> Connection<S> {
        Connection { inner, extensions }
    }

    fn authenticated_connection(origin: &HttpOrigin) -> Extensions {
        let extensions = Extensions::new();
        extensions.insert(ConnectionPolicyScope::Connector);
        #[cfg(feature = "tls")]
        extensions.insert(TlsServerAuthentication(Some(
            origin.authority().host.clone(),
        )));
        #[cfg(not(feature = "tls"))]
        let _ = origin;
        extensions
    }

    fn selected_connection(snapshot: &Arc<HttpServiceCandidates>) -> Extensions {
        let extensions = authenticated_connection(snapshot.origin());
        extensions.insert(EstablishedHttpService {
            origin: snapshot.origin().clone(),
            candidate: snapshot.get(0).unwrap().clone(),
        });
        extensions
    }

    fn request(origin: &HttpOrigin) -> Request {
        Request::builder()
            .uri(format!("{}://{}/", origin.protocol(), origin.authority()))
            .body(Body::empty())
            .unwrap()
    }

    fn selected_request(snapshot: Arc<HttpServiceCandidates>) -> Request {
        let request = request(snapshot.origin());
        request.extensions().insert(HttpServiceSelection {
            candidates: snapshot,
            index: 0,
            route: None,
        });
        request
    }

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
            let service = AltSvcLayer::new(cache.clone()).layer(self::connection(
                service_fn({
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
                }),
                connection,
            ));
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
            let error = service.serve(request(&origin)).await.unwrap_err();
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
            let extensions = if authenticated {
                authenticated_connection(&origin)
            } else {
                Extensions::new()
            };
            let inner = connection(
                service_fn(move |request: Request| async move {
                    assert_eq!(request.headers().contains_key(AltUsed::name()), !enabled);
                    Ok::<_, Infallible>(
                        Response::builder()
                            .header("alt-svc", "h2=\":8443\", h3=\":443\"")
                            .body(Body::empty())
                            .unwrap(),
                    )
                }),
                extensions,
            );
            let service = if enabled {
                AltSvcLayer::new(cache.clone()).layer(inner)
            } else {
                AltSvc::passthrough(inner)
            };
            service
                .serve(
                    Request::builder()
                        .uri(format!("{}://{}/", origin.protocol(), origin.authority()))
                        .header("alt-used", "stale.example:443")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                cache.lookup(&origin).is_some(),
                expected && (!origin.is_secure() || cfg!(feature = "tls"))
            );
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
                let extensions = authenticated_connection(&origin);
                extensions.insert(scope);
                let service = AltSvcLayer::new(cache.clone()).layer(connection(
                    service_fn(move |_: Request| async move {
                        Ok::<_, Infallible>(
                            Response::builder()
                                .header("alt-svc", advertisement)
                                .body(Body::empty())
                                .unwrap(),
                        )
                    }),
                    extensions,
                ));
                service.serve(request(&origin)).await.unwrap();
                let after = cache.lookup(&origin);
                if scope == ConnectionPolicyScope::Connector && cfg!(feature = "tls") {
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
        let extensions = selected_connection(&snapshot);
        let service = AltSvcLayer::new(cache.clone()).layer(connection(
            service_fn({
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
            }),
            extensions,
        ));
        assert_eq!(
            service
                .serve(selected_request(snapshot.clone()))
                .await
                .unwrap()
                .status(),
            StatusCode::MISDIRECTED_REQUEST
        );
        assert_eq!(dispatched.load(Ordering::SeqCst), 1);
        assert_eq!(cache.is_usable(&snapshot, 0), !cfg!(feature = "tls"));
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
        let extensions = selected_connection(&snapshot);
        let service = AltSvcLayer::new(cache.clone()).layer(connection(
            service_fn({
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
            }),
            extensions,
        ));
        service.serve(selected_request(snapshot)).await.unwrap();
        let replacement = cache.lookup(&origin).unwrap();
        assert!(cache.is_usable(&replacement, 0));
    }

    #[tokio::test]
    async fn configured_service_does_not_manufacture_alt_used() {
        let origin = origin(Protocol::HTTPS);
        let snapshot = Arc::new(HttpServiceCandidates::new(
            origin.clone(),
            vec![HttpServiceCandidate::new(
                ApplicationProtocol::HTTP_2,
                "configured.example:443".parse().unwrap(),
            )],
        ));
        let extensions = selected_connection(&snapshot);
        let service = AltSvcLayer::new(AltSvcCache::default()).layer(connection(
            service_fn(async |request: Request| {
                assert!(!request.headers().contains_key(AltUsed::name()));
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }),
            extensions,
        ));
        service.serve(selected_request(snapshot)).await.unwrap();
    }

    #[tokio::test]
    async fn custom_selection_is_checked_against_origin_and_established_endpoint() {
        let cache = AltSvcCache::default();
        let origin = origin(Protocol::HTTP);
        let other = HttpOrigin::new(Protocol::HTTP, "other.example:443".parse().unwrap()).unwrap();
        let mut headers = crate::HeaderMap::new();
        headers.insert(
            "alt-svc",
            "h2=\"actual.example:8443\", h3=\"other.example:9443\""
                .parse()
                .unwrap(),
        );
        cache.record(&origin, &headers, Duration::ZERO);
        cache.record(&other, &headers, Duration::ZERO);
        let snapshot = cache.lookup(&origin).unwrap();
        let other_snapshot = cache.lookup(&other).unwrap();
        let service = AltSvcLayer::new(cache.clone()).layer(connection(
            service_fn(async |request: Request| {
                assert_eq!(
                    request.headers().typed_get::<AltUsed>(),
                    Some(AltUsed::from(
                        "actual.example:8443".parse::<HostWithPort>().unwrap()
                    ))
                );
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(StatusCode::MISDIRECTED_REQUEST)
                        .body(Body::empty())
                        .unwrap(),
                )
            }),
            selected_connection(&snapshot),
        ));
        // A replacement selector may publish these extensions, but mismatched
        // origins, endpoints and indexes must not invalidate unrelated hints.
        for (candidates, index) in [
            (snapshot.clone(), 1),
            (snapshot.clone(), usize::MAX),
            (other_snapshot.clone(), 0),
        ] {
            let request = request(&origin);
            request.extensions().insert(HttpServiceSelection {
                candidates,
                index,
                route: None,
            });
            service.serve(request).await.unwrap();
            assert!(cache.is_usable(&snapshot, 0));
            assert!(cache.is_usable(&snapshot, 1));
            assert!(cache.is_usable(&other_snapshot, 0));
        }
        service
            .serve(selected_request(snapshot.clone()))
            .await
            .unwrap();
        assert!(!cache.is_usable(&snapshot, 0));
        assert!(cache.is_usable(&snapshot, 1));
        assert!(cache.is_usable(&other_snapshot, 0));
    }

    #[tokio::test]
    async fn established_endpoint_sets_alt_used_only_for_its_origin_without_a_cache() {
        let established_origin = origin(Protocol::HTTPS);
        let other_origin =
            HttpOrigin::new(Protocol::HTTPS, "other.example:443".parse().unwrap()).unwrap();
        let extensions = Extensions::new();
        extensions.insert(EstablishedHttpService {
            origin: established_origin.clone(),
            candidate: HttpServiceCandidate {
                protocol: ApplicationProtocol::HTTP_2,
                target: "alternative.example:8443".parse().unwrap(),
                source: HttpServiceSource::AltSvc,
            },
        });
        let service = AltSvc::passthrough(connection(
            service_fn(async |request: Request| {
                let expected = if request.uri().host_str().as_deref() == Some("example.com") {
                    Some(AltUsed::from(
                        "alternative.example:8443".parse::<HostWithPort>().unwrap(),
                    ))
                } else {
                    None
                };
                assert_eq!(request.headers().typed_get::<AltUsed>(), expected);
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }),
            extensions,
        ));
        for origin in [&established_origin, &other_origin, &established_origin] {
            let mut request = request(origin);
            request
                .headers_mut()
                .insert(AltUsed::name(), "stale.example:443".parse().unwrap());
            service.serve(request).await.unwrap();
        }
    }

    #[tokio::test]
    async fn passthrough_preserves_headers() {
        let service = AltSvc::passthrough(connection(
            service_fn(async |request: Request| {
                assert_eq!(
                    request.headers().get(AltUsed::name()).unwrap(),
                    "existing.example:443"
                );
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }),
            Extensions::new(),
        ));
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

    #[tokio::test]
    async fn long_lived_layer_keeps_concurrent_origins_independent() {
        let cache = AltSvcCache::default();
        let first = HttpOrigin::new(Protocol::HTTP, "first.example:80".parse().unwrap()).unwrap();
        let second = HttpOrigin::new(Protocol::HTTP, "second.example:80".parse().unwrap()).unwrap();
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let service = AltSvcLayer::new(cache.clone()).layer(connection(
            service_fn(move |request: Request| {
                let barrier = barrier.clone();
                async move {
                    let advertisement = match request.uri().host_str().as_deref() {
                        Some("first.example") => "h2=\":8443\"",
                        Some("second.example") => "h3=\":9443\"",
                        _ => panic!("unexpected request origin"),
                    };
                    barrier.wait().await;
                    Ok::<_, Infallible>(
                        Response::builder()
                            .header("alt-svc", advertisement)
                            .body(Body::empty())
                            .unwrap(),
                    )
                }
            }),
            Extensions::new(),
        ));
        for _ in 0..2 {
            let (first_response, second_response) = tokio::join!(
                service.serve(request(&first)),
                service.serve(request(&second)),
            );
            first_response.unwrap();
            second_response.unwrap();
            let first_candidates = cache.lookup(&first).unwrap();
            let second_candidates = cache.lookup(&second).unwrap();
            assert_eq!(first_candidates.origin(), &first);
            assert_eq!(first_candidates.get(0).unwrap().target.port, 8443);
            assert_eq!(second_candidates.origin(), &second);
            assert_eq!(second_candidates.get(0).unwrap().target.port, 9443);
        }
    }
}
