//! Set required headers on the request, if they are missing.
//!
//! For now this only sets `Host` header on http/1.1,
//! as well as always a User-Agent for all versions.

use http::header::{HOST, USER_AGENT};

use crate::service::{Context, Layer, Service};
use crate::{
    error::{BoxError, ErrorContext},
    http::{
        header::{self, RAMA_ID_HEADER_VALUE},
        Request, RequestContext, Response,
    },
};
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
    S::Error: Into<BoxError>,
{
    type Response = S::Response;
    type Error = BoxError;

    async fn serve(
        &self,
        mut ctx: Context<State>,
        mut req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        if !req.headers().contains_key(HOST) {
            let host = match ctx
                .get_or_insert_with(|| RequestContext::from(&req))
                .host
                .as_deref()
            {
                Some(host) => host,
                None => {
                    return Err("error extracting required host".into());
                }
            };

            req.headers_mut().insert(
                HOST,
                host.parse().context("create required host header value")?,
            );
        }

        if let header::Entry::Vacant(header) = req.headers_mut().entry(USER_AGENT) {
            header.insert(RAMA_ID_HEADER_VALUE.clone());
        }

        self.inner.serve(ctx, req).await.map_err(Into::into)
    }
}
