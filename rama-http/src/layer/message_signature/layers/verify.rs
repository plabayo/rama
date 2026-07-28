//! Request/response verification layers.

use std::fmt;

use rama_core::error::BoxError;
use rama_core::{Layer, Service};
use rama_http_types::{Request, Response};
use rama_utils::macros::define_inner_service_accessors;

use super::config::VerifyConfig;
use super::util::{request_context, response_context, verify_from_headers};

/// Layer that verifies inbound HTTP request signatures.
#[derive(Clone)]
pub struct VerifyRequestLayer {
    config: VerifyConfig,
}

impl VerifyRequestLayer {
    #[must_use]
    pub fn new(config: VerifyConfig) -> Self {
        Self { config }
    }
}

impl fmt::Debug for VerifyRequestLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifyRequestLayer")
            .field("label", &self.config.label)
            .finish()
    }
}

impl<S> Layer<S> for VerifyRequestLayer {
    type Service = VerifyRequest<S>;

    fn layer(&self, inner: S) -> Self::Service {
        VerifyRequest {
            inner,
            config: self.config.clone(),
        }
    }
}

/// Service that verifies inbound HTTP request signatures.
#[derive(Clone)]
pub struct VerifyRequest<S> {
    inner: S,
    config: VerifyConfig,
}

impl<S> VerifyRequest<S> {
    define_inner_service_accessors!();
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for VerifyRequest<S>
where
    S: Service<Request<ReqBody>, Output = Response<ResBody>, Error: Into<BoxError>>,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Output = Response<ResBody>;
    type Error = BoxError;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        {
            let ctx = request_context(&req);
            verify_from_headers(&ctx, req.headers(), &self.config)?;
        }
        self.inner.serve(req).await.map_err(Into::into)
    }
}

/// Layer that verifies inbound HTTP response signatures.
#[derive(Clone)]
pub struct VerifyResponseLayer {
    config: VerifyConfig,
}

impl VerifyResponseLayer {
    #[must_use]
    pub fn new(config: VerifyConfig) -> Self {
        Self { config }
    }
}

impl fmt::Debug for VerifyResponseLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifyResponseLayer")
            .field("label", &self.config.label)
            .finish()
    }
}

impl<S> Layer<S> for VerifyResponseLayer {
    type Service = VerifyResponse<S>;

    fn layer(&self, inner: S) -> Self::Service {
        VerifyResponse {
            inner,
            config: self.config.clone(),
        }
    }
}

/// Service that verifies inbound HTTP response signatures.
#[derive(Clone)]
pub struct VerifyResponse<S> {
    inner: S,
    config: VerifyConfig,
}

impl<S> VerifyResponse<S> {
    define_inner_service_accessors!();
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for VerifyResponse<S>
where
    S: Service<Request<ReqBody>, Output = Response<ResBody>, Error: Into<BoxError>>,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Output = Response<ResBody>;
    type Error = BoxError;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        let res = self.inner.serve(req).await.map_err(Into::into)?;
        {
            let ctx = response_context(&res, None);
            verify_from_headers(&ctx, res.headers(), &self.config)?;
        }
        Ok(res)
    }
}
