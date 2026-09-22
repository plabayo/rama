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

use crate::{Request, Response, StatusCode};
use rama_core::{
    Layer, Service,
    extensions::{Extensions, ExtensionsRef},
};
use rama_http_headers::{AltUsed, HeaderMapExt as _, TypedHeader as _};
use rama_http_types::conn::{HttpOrigin, HttpServiceCandidates, HttpServiceSource};
use rama_net::address::HostWithPort;
use rama_utils::macros::{define_inner_service_accessors, generate_set_and_with};
use std::{sync::Arc, time::Instant};

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
}

impl AltSvcLayer {
    /// Create middleware scoped to the logical origin, independently of the dial target.
    pub fn new(cache: Option<AltSvcCache>, origin: HttpOrigin) -> Self {
        Self {
            cache,
            origin,
            authenticated: false,
            alternative: None,
            selection: None,
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

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for AltSvc<S>
where
    S: Service<Request<ReqBody>, Output = Response<ResBody>>,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, mut request: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        let Some(policy) = &self.policy else {
            return self.inner.serve(request).await;
        };
        if let Some(target) = &policy.alternative {
            request
                .headers_mut()
                .typed_insert(AltUsed::from(target.clone()));
        } else {
            request.headers_mut().remove(AltUsed::name());
        }
        let started = Instant::now();
        let response = self.inner.serve(request).await?;
        if let Some(cache) = &policy.cache {
            if response.status() == StatusCode::MISDIRECTED_REQUEST {
                if let Some((snapshot, index)) = &policy.selection {
                    cache.misdirected(snapshot, *index);
                }
            } else if policy.authenticated || !policy.origin.is_secure() {
                cache.record(&policy.origin, response.headers(), started.elapsed());
            }
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Body;
    use rama_core::service::service_fn;
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
    async fn https_learning_requires_authentication_http_hints_do_not() {
        for (protocol, authenticated, enabled, expected) in [
            (Protocol::HTTPS, false, true, false),
            (Protocol::HTTPS, true, false, false),
            (Protocol::HTTPS, true, true, true),
            (Protocol::HTTP, false, true, true),
        ] {
            let cache = AltSvcCache::default();
            let origin = origin(protocol);
            let service = AltSvcLayer::new(enabled.then(|| cache.clone()), origin.clone())
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
        cache.record_authenticated(&origin, &headers, Duration::ZERO);
        let snapshot = cache.lookup(&origin).unwrap();
        let target = snapshot.get(0).unwrap().target.clone();
        let dispatched = Arc::new(AtomicUsize::new(0));
        let service = AltSvcLayer::new(Some(cache.clone()), origin.clone())
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
        cache.record_authenticated(&origin, &headers, Duration::ZERO);
        let snapshot = cache.lookup(&origin).unwrap();
        let service = AltSvcLayer::new(Some(cache.clone()), origin.clone())
            .with_authenticated(true)
            .with_selection(snapshot, 0)
            .layer(service_fn({
                let cache = cache.clone();
                let origin = origin.clone();
                move |_: Request| {
                    cache.record_authenticated(&origin, &headers, Duration::ZERO);
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
        let service = AltSvcLayer::new(None, origin)
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
