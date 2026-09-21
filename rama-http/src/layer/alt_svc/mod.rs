//! Learn HTTP alternative services from authenticated HTTPS responses.
//!
//! [RFC 7838] allows an origin to advertise alternative protocols, hosts and
//! ports; the mechanism is independent of HTTP/3. The current [`AltSvcCache`]
//! retains HTTP/3 alternatives for the H3-capable client.
//!
//! The transport supplies the logical origin and whether it authenticated that
//! origin. The middleware records response hints and sets the typed `Alt-Used`
//! request header. Connection selection, authentication and retry policy remain
//! the transport's responsibility; a request is dispatched exactly once.
//!
//! [RFC 7838]: https://www.rfc-editor.org/rfc/rfc7838

mod cache;
#[doc(inline)]
pub use cache::AltSvcCache;

use crate::{Request, Response, StatusCode};
use rama_core::{
    Layer, Service,
    extensions::{Extensions, ExtensionsRef},
};
use rama_http_headers::{AltUsed, HeaderMapExt as _, TypedHeader as _};
use rama_net::address::HostWithPort;
use rama_utils::macros::define_inner_service_accessors;
use std::time::Instant;

/// Learn alternatives for one logical HTTPS origin over an established connection.
///
/// Learning is disabled until [`Self::with_authenticated`] is explicitly enabled
/// by a transport that verified the origin. Passing no cache disables learning.
#[derive(Clone, Debug)]
pub struct AltSvcLayer {
    cache: Option<AltSvcCache>,
    origin: HostWithPort,
    authenticated: bool,
    alternative: Option<HostWithPort>,
}

impl AltSvcLayer {
    /// Create middleware scoped to the logical origin, independently of the dial target.
    pub fn new(cache: Option<AltSvcCache>, origin: HostWithPort) -> Self {
        Self {
            cache,
            origin,
            authenticated: false,
            alternative: None,
        }
    }

    /// Declare whether this connection authenticated the logical HTTPS origin.
    ///
    /// This must represent successful certificate and configured peer-policy
    /// verification, not merely the presence of encryption or a peer certificate.
    #[must_use]
    pub fn with_authenticated(mut self, authenticated: bool) -> Self {
        self.authenticated = authenticated;
        self
    }

    /// Set the selected alternative authority to report in `Alt-Used`.
    #[must_use]
    pub fn with_alternative(mut self, alternative: Option<HostWithPort>) -> Self {
        self.alternative = alternative;
        self
    }
}

impl<S> Layer<S> for AltSvcLayer {
    type Service = AltSvc<S>;
    fn layer(&self, inner: S) -> Self::Service {
        AltSvc {
            inner,
            policy: self.clone(),
        }
    }
}

/// Service applying an [`AltSvcLayer`] to an established connection.
#[derive(Clone, Debug)]
pub struct AltSvc<S> {
    inner: S,
    policy: AltSvcLayer,
}

impl<S> AltSvc<S> {
    define_inner_service_accessors!();
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
        if let Some(target) = &self.policy.alternative {
            request
                .headers_mut()
                .typed_insert(AltUsed::from(target.clone()));
        } else {
            request.headers_mut().remove(AltUsed::name());
        }
        let started = Instant::now();
        let response = self.inner.serve(request).await?;
        if let Some(cache) = &self.policy.cache {
            if response.status() == StatusCode::MISDIRECTED_REQUEST {
                if self.policy.alternative.is_some() {
                    cache.clear(&self.policy.origin);
                }
            } else if self.policy.authenticated {
                cache.record_authenticated(
                    &self.policy.origin,
                    response.headers(),
                    started.elapsed(),
                );
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
    use std::{
        convert::Infallible,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    #[tokio::test]
    async fn learning_requires_explicit_authentication_and_enabled_cache() {
        for (authenticated, enabled) in [(false, true), (true, false), (true, true)] {
            let cache = AltSvcCache::default();
            let origin: HostWithPort = "example.com:443".parse().unwrap();
            let service = AltSvcLayer::new(enabled.then(|| cache.clone()), origin.clone())
                .with_authenticated(authenticated)
                .layer(service_fn(async |request: Request| {
                    assert!(!request.headers().contains_key(AltUsed::name()));
                    Ok::<_, Infallible>(
                        Response::builder()
                            .header("alt-svc", "h3=\":8443\"")
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
            assert_eq!(cache.lookup(&origin).is_some(), authenticated && enabled);
        }
    }

    #[tokio::test]
    async fn misdirected_alternative_is_cleared_without_replaying_request() {
        let cache = AltSvcCache::default();
        let origin: HostWithPort = "example.com:443".parse().unwrap();
        let target: HostWithPort = "alternative.example:8443".parse().unwrap();
        let mut headers = crate::HeaderMap::new();
        headers.insert(
            "alt-svc",
            "h3=\"alternative.example:8443\"".parse().unwrap(),
        );
        cache.record_authenticated(&origin, &headers, Duration::ZERO);
        let dispatched = Arc::new(AtomicUsize::new(0));
        let service = AltSvcLayer::new(Some(cache.clone()), origin.clone())
            .with_authenticated(true)
            .with_alternative(Some(target.clone()))
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
        let response = service.serve(Request::new(Body::empty())).await.unwrap();
        assert_eq!(response.status(), StatusCode::MISDIRECTED_REQUEST);
        assert_eq!(dispatched.load(Ordering::SeqCst), 1);
        assert!(cache.lookup(&origin).is_none());
    }
}
