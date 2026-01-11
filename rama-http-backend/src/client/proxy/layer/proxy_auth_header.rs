use rama_core::extensions::ExtensionsRef;
use rama_core::telemetry::tracing;
use rama_core::{Layer, Service};
use rama_http_headers::{HeaderMapExt, ProxyAuthorization};
use rama_http_types::Request;
use rama_net::{address::ProxyAddress, http::RequestContext, user::ProxyCredential};

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// A [`Layer`] which will set the http auth header
/// in case there is a [`ProxyAddress`] in the [`Extensions`].
///
/// [`Extensions`]: rama_core::extensions::Extensions
pub struct SetProxyAuthHttpHeaderLayer;

impl SetProxyAuthHttpHeaderLayer {
    /// Create a new [`SetProxyAuthHttpHeaderLayer`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl<S> Layer<S> for SetProxyAuthHttpHeaderLayer {
    type Service = SetProxyAuthHttpHeaderService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SetProxyAuthHttpHeaderService::new(inner)
    }
}

/// A [`Service`] wwhich will set the http auth header
/// in case there is a [`ProxyAddress`] in the [`Extensions`].
///
/// [`Extensions`]: rama_core::extensions::Extensions
#[derive(Debug, Clone)]
pub struct SetProxyAuthHttpHeaderService<S> {
    inner: S,
}

impl<S> SetProxyAuthHttpHeaderService<S> {
    /// Create a new [`SetProxyAuthHttpHeaderService`].
    pub const fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S, Body> Service<Request<Body>> for SetProxyAuthHttpHeaderService<S>
where
    S: Service<Request<Body>>,
    Body: Send + 'static,
{
    type Output = S::Output;
    type Error = S::Error;

    fn serve(
        &self,
        mut req: Request<Body>,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + '_ {
        if let Some(pa) = req.extensions().get::<ProxyAddress>()
            && let Some(credential) = pa.credential.clone()
        {
            match credential {
                ProxyCredential::Basic(basic) => {
                    let maybe_request_ctx = RequestContext::try_from(&req).ok();

                    if !maybe_request_ctx
                        .map(|ctx| ctx.protocol.is_secure())
                        .unwrap_or_default()
                    {
                        tracing::trace!("inserted proxy Basic credentials into (http) request");
                        req.headers_mut().typed_insert(ProxyAuthorization(basic))
                    }
                }
                ProxyCredential::Bearer(bearer) => {
                    // Bearer tokens always need to be inserted, as there's no uri support for these
                    tracing::trace!("inserted proxy Bearer credentials into (http) request");
                    req.headers_mut().typed_insert(ProxyAuthorization(bearer))
                }
            }
        }

        self.inner.serve(req)
    }
}
