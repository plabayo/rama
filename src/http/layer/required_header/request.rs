//! Set required headers on the request, if they are missing.
//!
//! For now this only sets `Host` header on http/1.1,
//! as well as always a User-Agent for all versions.

use crate::error::ErrorContext;
use crate::http::RequestContext;
use crate::service::{Context, Layer, Service};
use crate::{
    error::BoxError,
    http::{
        header::{self, RAMA_ID_HEADER_VALUE},
        Request, Response,
    },
};
use headers::HeaderMapExt;
use http::header::{HOST, USER_AGENT};
use std::fmt;

/// Layer that applies [`AddRequiredRequestHeaders`] which adds a request header.
///
/// See [`AddRequiredRequestHeaders`] for more details.
#[derive(Debug, Clone, Default)]
pub struct AddRequiredRequestHeadersLayer {
    overwrite: bool,
}

impl AddRequiredRequestHeadersLayer {
    /// Create a new [`AddRequiredRequestHeadersLayer`].
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

    /// Set whether to overwrite the existing headers.
    /// If set to `true`, the headers will be overwritten.
    ///
    /// Default is `false`.
    pub fn set_overwrite(&mut self, overwrite: bool) -> &mut Self {
        self.overwrite = overwrite;
        self
    }
}

impl<S> Layer<S> for AddRequiredRequestHeadersLayer {
    type Service = AddRequiredRequestHeaders<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AddRequiredRequestHeaders {
            inner,
            overwrite: self.overwrite,
        }
    }
}

/// Middleware that sets a header on the request.
#[derive(Clone)]
pub struct AddRequiredRequestHeaders<S> {
    inner: S,
    overwrite: bool,
}

impl<S> AddRequiredRequestHeaders<S> {
    /// Create a new [`AddRequiredRequestHeaders`].
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

    /// Set whether to overwrite the existing headers.
    /// If set to `true`, the headers will be overwritten.
    ///
    /// Default is `false`.
    pub fn set_overwrite(&mut self, overwrite: bool) -> &mut Self {
        self.overwrite = overwrite;
        self
    }

    define_inner_service_accessors!();
}

impl<S> fmt::Debug for AddRequiredRequestHeaders<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AddRequiredRequestHeaders")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<ReqBody, ResBody, State, S> Service<State, Request<ReqBody>> for AddRequiredRequestHeaders<S>
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
        if self.overwrite || !req.headers().contains_key(HOST) {
            let request_ctx: &mut RequestContext = ctx
                .get_or_try_insert_with_ctx(|ctx| (ctx, &req).try_into())
                .context(
                    "AddRequiredRequestHeaders: get/compute RequestContext to set authority",
                )?;
            let host = crate::http::dep::http::uri::Authority::from_maybe_shared(
                request_ctx.authority.to_string(),
            )
            .map(crate::http::headers::Host::from)
            .context("AddRequiredRequestHeaders: set authority")?;
            req.headers_mut().typed_insert(host);
        }

        if self.overwrite {
            req.headers_mut()
                .insert(USER_AGENT, RAMA_ID_HEADER_VALUE.clone());
        } else if let header::Entry::Vacant(header) = req.headers_mut().entry(USER_AGENT) {
            header.insert(RAMA_ID_HEADER_VALUE.clone());
        }

        self.inner.serve(ctx, req).await.map_err(Into::into)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::http::{Body, Request};
    use crate::service::{Context, Service, ServiceBuilder};
    use std::convert::Infallible;

    #[tokio::test]
    async fn add_required_request_headers() {
        let svc = ServiceBuilder::new()
            .layer(AddRequiredRequestHeadersLayer::default())
            .service_fn(|_ctx: Context<()>, req: Request| async move {
                assert!(req.headers().contains_key(HOST));
                assert!(req.headers().contains_key(USER_AGENT));
                Ok::<_, Infallible>(http::Response::new(Body::empty()))
            });

        let req = Request::builder()
            .uri("http://www.example.com/")
            .body(Body::empty())
            .unwrap();
        let resp = svc.serve(Context::default(), req).await.unwrap();

        assert!(!resp.headers().contains_key(HOST));
        assert!(!resp.headers().contains_key(USER_AGENT));
    }

    #[tokio::test]
    async fn add_required_request_headers_overwrite() {
        let svc = ServiceBuilder::new()
            .layer(AddRequiredRequestHeadersLayer::new().overwrite(true))
            .service_fn(|_ctx: Context<()>, req: Request| async move {
                assert_eq!(req.headers().get(HOST).unwrap(), "example.com:80");
                assert_eq!(
                    req.headers().get(USER_AGENT).unwrap(),
                    RAMA_ID_HEADER_VALUE.to_str().unwrap()
                );
                Ok::<_, Infallible>(http::Response::new(Body::empty()))
            });

        let req = Request::builder()
            .uri("http://127.0.0.1/")
            .header(HOST, "example.com")
            .header(USER_AGENT, "test")
            .body(Body::empty())
            .unwrap();

        let resp = svc.serve(Context::default(), req).await.unwrap();

        assert!(!resp.headers().contains_key(HOST));
        assert!(!resp.headers().contains_key(USER_AGENT));
    }
}
