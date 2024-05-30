//! Set required headers on the request, if they are missing.
//!
//! For now this only sets `Host` header on http/1.1,
//! as well as always a User-Agent for all versions.

use http::HeaderValue;

use crate::http::{
    header::HeaderName,
    headers::{Header, HeaderExt},
    Request, Response,
};
use crate::service::{Context, Layer, Service};
use std::fmt;

/// Layer that applies [`RequiredRequestHeader`] which adds a request header.
///
/// See [`RequiredRequestHeader`] for more details.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct RequiredRequestHeaderLayer;

impl RequiredRequestHeaderLayer {
    /// Create a new [`RequiredRequestHeaderLayer`].
    pub fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for RequiredRequestHeaderLayer {
    type Service = RequiredRequestHeader<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequiredRequestHeader { inner }
    }
}

/// Middleware that sets a header on the request.
#[derive(Clone)]
pub struct RequiredRequestHeader<S> {
    inner: S,
}

impl<S> RequiredRequestHeader<S> {
    /// Create a new [`RequiredRequestHeader`].
    pub fn new(inner: S) -> Self {
        Self { inner }
    }

    define_inner_service_accessors!();
}

impl<S> fmt::Debug for RequiredRequestHeader<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequiredRequestHeader")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<ReqBody, ResBody, State, S> Service<State, Request<ReqBody>> for RequiredRequestHeader<S>
where
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
    State: Send + Sync + 'static,
    S: Service<State, Request<ReqBody>, Response = Response<ResBody>>,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn serve(
        &self,
        mut ctx: Context<State>,
        req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        
        req.headers_mut().entry(HOST).or_try_insert_with(|| {
            let request_info = 
            HeaderValue::from_str("localhost").expect("failed to create header value")
        });
        let (ctx, req) = self
            .mode
            .apply(&self.header_name, ctx, req, &self.make)
            .await;
        self.inner.serve(ctx, req).await
    }
}
