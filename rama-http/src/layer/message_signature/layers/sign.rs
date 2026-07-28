//! Request/response signing layers.

use std::fmt;

use rama_core::error::BoxError;
use rama_core::{Layer, Service};
use rama_http_types::{Request, Response};
use rama_utils::macros::define_inner_service_accessors;

use super::config::SignConfig;
use super::util::{request_context, response_context};

/// Layer that signs outbound HTTP requests.
#[derive(Clone)]
pub struct SignRequestLayer {
    config: SignConfig,
}

impl SignRequestLayer {
    #[must_use]
    pub fn new(config: SignConfig) -> Self {
        Self { config }
    }
}

impl fmt::Debug for SignRequestLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignRequestLayer")
            .field("label", &self.config.label)
            .finish()
    }
}

impl<S> Layer<S> for SignRequestLayer {
    type Service = SignRequest<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SignRequest {
            inner,
            config: self.config.clone(),
        }
    }
}

/// Service that signs outbound HTTP requests.
#[derive(Clone)]
pub struct SignRequest<S> {
    inner: S,
    config: SignConfig,
}

impl<S> SignRequest<S> {
    define_inner_service_accessors!();
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for SignRequest<S>
where
    S: Service<Request<ReqBody>, Output = Response<ResBody>, Error: Into<BoxError>>,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Output = Response<ResBody>;
    type Error = BoxError;

    async fn serve(&self, mut req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        let (signature, params) = {
            let ctx = request_context(&req);
            super::util::compute_signature(&ctx, &self.config)?
        };
        super::util::apply_signature(req.headers_mut(), &self.config.label, signature, params);
        self.inner.serve(req).await.map_err(Into::into)
    }
}

/// Layer that signs outbound HTTP responses.
#[derive(Clone)]
pub struct SignResponseLayer {
    config: SignConfig,
}

impl SignResponseLayer {
    #[must_use]
    pub fn new(config: SignConfig) -> Self {
        Self { config }
    }
}

impl fmt::Debug for SignResponseLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignResponseLayer")
            .field("label", &self.config.label)
            .finish()
    }
}

impl<S> Layer<S> for SignResponseLayer {
    type Service = SignResponse<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SignResponse {
            inner,
            config: self.config.clone(),
        }
    }
}

/// Service that signs outbound HTTP responses.
#[derive(Clone)]
pub struct SignResponse<S> {
    inner: S,
    config: SignConfig,
}

impl<S> SignResponse<S> {
    define_inner_service_accessors!();
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for SignResponse<S>
where
    S: Service<Request<ReqBody>, Output = Response<ResBody>, Error: Into<BoxError>>,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Output = Response<ResBody>;
    type Error = BoxError;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        let mut res = self.inner.serve(req).await.map_err(Into::into)?;
        let (signature, params) = {
            let ctx = response_context(&res, None);
            super::util::compute_signature(&ctx, &self.config)?
        };
        super::util::apply_signature(res.headers_mut(), &self.config.label, signature, params);
        Ok(res)
    }
}
