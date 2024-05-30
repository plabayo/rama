//! Set required headers on the response, if they are missing.
//!
//! For now this only sets `Server` and `Date` heades.

use crate::http::{
    header::{self, RAMA_ID_HEADER_VALUE},
    Request, Response,
};
use crate::http::{
    header::{DATE, SERVER},
    headers::{Date, HeaderMapExt},
};
use crate::service::{Context, Layer, Service};
use std::{fmt, time::SystemTime};

/// Layer that applies [`AddRequiredResponseHeaders`] which adds a request header.
///
/// See [`AddRequiredResponseHeaders`] for more details.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct AddRequiredResponseHeadersLayer;

impl AddRequiredResponseHeadersLayer {
    /// Create a new [`AddRequiredResponseHeadersLayer`].
    pub fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for AddRequiredResponseHeadersLayer {
    type Service = AddRequiredResponseHeaders<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AddRequiredResponseHeaders { inner }
    }
}

/// Middleware that sets a header on the request.
#[derive(Clone)]
pub struct AddRequiredResponseHeaders<S> {
    inner: S,
}

impl<S> AddRequiredResponseHeaders<S> {
    /// Create a new [`AddRequiredResponseHeaders`].
    pub fn new(inner: S) -> Self {
        Self { inner }
    }

    define_inner_service_accessors!();
}

impl<S> fmt::Debug for AddRequiredResponseHeaders<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AddRequiredResponseHeaders")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<ReqBody, ResBody, State, S> Service<State, Request<ReqBody>> for AddRequiredResponseHeaders<S>
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
        ctx: Context<State>,
        req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        let mut resp = self.inner.serve(ctx, req).await?;

        if let header::Entry::Vacant(header) = resp.headers_mut().entry(SERVER) {
            header.insert(RAMA_ID_HEADER_VALUE.clone());
        }

        if !resp.headers().contains_key(DATE) {
            resp.headers_mut()
                .typed_insert(Date::from(SystemTime::now()));
        }

        Ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{http::Body, service::ServiceBuilder};
    use std::convert::Infallible;

    #[tokio::test]
    async fn add_required_response_headers() {
        let svc = ServiceBuilder::new()
            .layer(AddRequiredResponseHeadersLayer::default())
            .service_fn(|_ctx: Context<()>, req: Request| async move {
                assert!(!req.headers().contains_key(SERVER));
                assert!(!req.headers().contains_key(DATE));
                Ok::<_, Infallible>(Response::new(Body::empty()))
            });

        let req = Request::new(Body::empty());
        let resp = svc.serve(Context::default(), req).await.unwrap();

        assert_eq!(
            resp.headers().get(SERVER).unwrap(),
            RAMA_ID_HEADER_VALUE.as_ref()
        );
        assert!(resp.headers().contains_key(DATE));
    }
}
