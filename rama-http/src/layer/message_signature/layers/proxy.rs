//! Proxy / intermediary signature layers (RFC 9421 §4.3).

use std::fmt;

use rama_core::error::BoxError;
use rama_core::{Layer, Service};
use rama_http_types::{Request, Response};
use rama_utils::macros::define_inner_service_accessors;

use super::config::{SignConfig, VerifyConfig};
use super::util::{
    RelatedRequestSnapshot, apply_signature_unique, request_context, response_context,
    verify_from_headers,
};

/// What to do when optional inbound verification is configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProxyVerifyAction {
    /// Reject the message if verification fails.
    #[default]
    Reject,
    /// Continue even if verification fails (still append proxy signature).
    Continue,
}

/// Policy for [`AddProxySignatureLayer`].
#[derive(Clone)]
pub struct ProxySignaturePolicy {
    pub sign: SignConfig,
    /// If set, verify this inbound label / config before appending.
    pub verify: Option<VerifyConfig>,
    pub on_verify_failure: ProxyVerifyAction,
}

impl ProxySignaturePolicy {
    #[must_use]
    pub fn new(sign: SignConfig) -> Self {
        Self {
            sign,
            verify: None,
            on_verify_failure: ProxyVerifyAction::Reject,
        }
    }

    #[must_use]
    pub fn with_verify(mut self, verify: VerifyConfig) -> Self {
        self.verify = Some(verify);
        self
    }

    #[must_use]
    pub fn on_verify_failure(mut self, action: ProxyVerifyAction) -> Self {
        self.on_verify_failure = action;
        self
    }
}

/// Layer that optionally verifies an inbound signature and appends a proxy signature
/// on requests (typical MITM / reverse-proxy use).
#[derive(Clone)]
pub struct AddProxySignatureLayer {
    policy: ProxySignaturePolicy,
}

impl AddProxySignatureLayer {
    #[must_use]
    pub fn new(policy: ProxySignaturePolicy) -> Self {
        Self { policy }
    }
}

impl fmt::Debug for AddProxySignatureLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AddProxySignatureLayer")
            .field("label", &self.policy.sign.label)
            .finish()
    }
}

impl<S> Layer<S> for AddProxySignatureLayer {
    type Service = AddProxySignature<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AddProxySignature {
            inner,
            policy: self.policy.clone(),
        }
    }
}

/// Service companion for [`AddProxySignatureLayer`].
#[derive(Clone)]
pub struct AddProxySignature<S> {
    inner: S,
    policy: ProxySignaturePolicy,
}

impl<S> AddProxySignature<S> {
    define_inner_service_accessors!();
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for AddProxySignature<S>
where
    S: Service<Request<ReqBody>, Output = Response<ResBody>, Error: Into<BoxError>>,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Output = Response<ResBody>;
    type Error = BoxError;

    async fn serve(&self, mut req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        {
            let ctx = request_context(&req);
            if let Some(ref verify) = self.policy.verify {
                match verify_from_headers(&ctx, req.headers(), verify) {
                    Ok(_) => {}
                    Err(err) => match self.policy.on_verify_failure {
                        ProxyVerifyAction::Reject => return Err(err),
                        ProxyVerifyAction::Continue => {
                            rama_core::telemetry::tracing::debug!(
                                "proxy inbound signature verification failed (continuing): {err}"
                            );
                        }
                    },
                }
            }
        }

        let (signature, params) = {
            let ctx = request_context(&req);
            super::util::compute_signature(&ctx, &self.policy.sign)?
        };
        apply_signature_unique(
            req.headers_mut(),
            &self.policy.sign.label,
            signature,
            params,
        )?;

        self.inner.serve(req).await.map_err(Into::into)
    }
}

/// Layer that appends a proxy signature on outbound responses.
#[derive(Clone)]
pub struct AddProxyResponseSignatureLayer {
    policy: ProxySignaturePolicy,
}

impl AddProxyResponseSignatureLayer {
    #[must_use]
    pub fn new(policy: ProxySignaturePolicy) -> Self {
        Self { policy }
    }
}

impl fmt::Debug for AddProxyResponseSignatureLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AddProxyResponseSignatureLayer")
            .field("label", &self.policy.sign.label)
            .finish()
    }
}

impl<S> Layer<S> for AddProxyResponseSignatureLayer {
    type Service = AddProxyResponseSignature<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AddProxyResponseSignature {
            inner,
            policy: self.policy.clone(),
        }
    }
}

/// Service companion for [`AddProxyResponseSignatureLayer`].
#[derive(Clone)]
pub struct AddProxyResponseSignature<S> {
    inner: S,
    policy: ProxySignaturePolicy,
}

impl<S> AddProxyResponseSignature<S> {
    define_inner_service_accessors!();
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for AddProxyResponseSignature<S>
where
    S: Service<Request<ReqBody>, Output = Response<ResBody>, Error: Into<BoxError>>,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Output = Response<ResBody>;
    type Error = BoxError;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        let related = RelatedRequestSnapshot::from_request(&req);
        let mut res = self.inner.serve(req).await.map_err(Into::into)?;

        if let Some(ref verify) = self.policy.verify {
            let related_ctx = related.context();
            let ctx = response_context(&res, Some(related_ctx));
            match verify_from_headers(&ctx, res.headers(), verify) {
                Ok(_) => {}
                Err(err) => match self.policy.on_verify_failure {
                    ProxyVerifyAction::Reject => return Err(err),
                    ProxyVerifyAction::Continue => {
                        rama_core::telemetry::tracing::debug!(
                            "proxy response signature verification failed (continuing): {err}"
                        );
                    }
                },
            }
        }

        let (signature, params) = {
            let related_ctx = related.context();
            let ctx = response_context(&res, Some(related_ctx));
            super::util::compute_signature(&ctx, &self.policy.sign)?
        };
        apply_signature_unique(
            res.headers_mut(),
            &self.policy.sign.label,
            signature,
            params,
        )?;

        Ok(res)
    }
}
