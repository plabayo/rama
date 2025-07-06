use rama_core::telemetry::tracing;
use rama_core::{Context, Layer, Service};
use rama_http_headers::{HeaderMapExt, ProxyAuthorization};
use rama_http_types::Request;
use rama_net::{address::ProxyAddress, http::RequestContext, user::ProxyCredential};
use std::fmt;

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// A [`Layer`] which will set the http auth header
/// in case there is a [`ProxyAddress`] in the [`Context`].
pub struct SetProxyAuthHttpHeaderLayer;

impl SetProxyAuthHttpHeaderLayer {
    /// Create a new [`SetProxyAuthHttpHeaderLayer`].
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
/// in case there is a [`ProxyAddress`] in the [`Context`].
pub struct SetProxyAuthHttpHeaderService<S> {
    inner: S,
}

impl<S: fmt::Debug> fmt::Debug for SetProxyAuthHttpHeaderService<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SetProxyAuthHttpHeaderService")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<S: Clone> Clone for SetProxyAuthHttpHeaderService<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<S> SetProxyAuthHttpHeaderService<S> {
    /// Create a new [`SetProxyAuthHttpHeaderService`].
    pub const fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S, State, Body> Service<State, Request<Body>> for SetProxyAuthHttpHeaderService<S>
where
    S: Service<State, Request<Body>>,
    State: Clone + Send + Sync + 'static,
    Body: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;

    fn serve(
        &self,
        mut ctx: Context<State>,
        mut req: Request<Body>,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        if let Some(pa) = ctx.get::<ProxyAddress>() {
            if let Some(credential) = pa.credential.clone() {
                match credential {
                    ProxyCredential::Basic(basic) => {
                        let maybe_request_ctx = ctx
                            .get_or_try_insert_with_ctx::<RequestContext, _>(|ctx| {
                                (ctx, &req).try_into()
                            })
                            .ok();
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
        }

        self.inner.serve(ctx, req)
    }
}
