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
pub struct AddRequiredResponseHeadersLayer {
    overwrite: bool,
}

impl AddRequiredResponseHeadersLayer {
    /// Create a new [`AddRequiredResponseHeadersLayer`].
    pub fn new() -> Self {
        Self { overwrite: false }
    }

    /// Set whether to overwrite the existing headers.
    /// If set to `true`, the headers will be overwritten.
    ///
    /// Default is `false`.
    pub fn overwrite(mut self, overwrite: bool) -> Self {
        self.overwrite = overwrite;
        self
    }
}

impl<S> Layer<S> for AddRequiredResponseHeadersLayer {
    type Service = AddRequiredResponseHeaders<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AddRequiredResponseHeaders {
            inner,
            overwrite: self.overwrite,
        }
    }
}

/// Middleware that sets a header on the request.
#[derive(Clone)]
pub struct AddRequiredResponseHeaders<S> {
    inner: S,
    overwrite: bool,
}

impl<S> AddRequiredResponseHeaders<S> {
    /// Create a new [`AddRequiredResponseHeaders`].
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            overwrite: false,
        }
    }

    /// Set whether to overwrite the existing headers.
    /// If set to `true`, the headers will be overwritten.
    ///
    /// Default is `false`.
    pub fn overwrite(mut self, overwrite: bool) -> Self {
        self.overwrite = overwrite;
        self
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

        if self.overwrite {
            resp.headers_mut()
                .insert(SERVER, RAMA_ID_HEADER_VALUE.clone());
        } else if let header::Entry::Vacant(header) = resp.headers_mut().entry(SERVER) {
            header.insert(RAMA_ID_HEADER_VALUE.clone());
        }

        if self.overwrite || !resp.headers().contains_key(DATE) {
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

    #[tokio::test]
    async fn add_required_response_headers_overwrite() {
        let svc = ServiceBuilder::new()
            .layer(AddRequiredResponseHeadersLayer::new().overwrite(true))
            .service_fn(|_ctx: Context<()>, req: Request| async move {
                assert!(!req.headers().contains_key(SERVER));
                assert!(!req.headers().contains_key(DATE));
                Ok::<_, Infallible>(
                    Response::builder()
                        .header(SERVER, "foo")
                        .header(DATE, "bar")
                        .body(Body::empty())
                        .unwrap(),
                )
            });

        let req = Request::new(Body::empty());
        let resp = svc.serve(Context::default(), req).await.unwrap();

        assert_eq!(
            resp.headers().get(SERVER).unwrap(),
            RAMA_ID_HEADER_VALUE.to_str().unwrap()
        );
        assert_ne!(resp.headers().get(DATE).unwrap(), "bar");
    }
}
