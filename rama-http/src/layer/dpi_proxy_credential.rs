//! Middleware that extracts credentials for an egress proxy
//! found in the Proxy-Authorization header of a passthrough request.
//!
//! See for more information: [`DpiProxyCredentialExtractor`]

use crate::Request;
use crate::headers::{HeaderMapExt, ProxyAuthorization};
use rama_core::extensions::ExtensionsMut;
use rama_core::telemetry::tracing;
use rama_core::{Layer, Service};
use rama_net::user::credentials::DpiProxyCredential;
use rama_net::user::{Basic, Bearer, ProxyCredential};
use rama_utils::macros::define_inner_service_accessors;

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// Layer that applies the [`DpiProxyCredentialExtractor`] middleware.
pub struct DpiProxyCredentialExtractorLayer;

impl DpiProxyCredentialExtractorLayer {
    #[inline(always)]
    /// Creates a new [`DpiProxyCredentialExtractorLayer`].
    pub const fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for DpiProxyCredentialExtractorLayer {
    type Service = DpiProxyCredentialExtractor<S>;

    #[inline(always)]
    fn layer(&self, inner: S) -> Self::Service {
        DpiProxyCredentialExtractor::new(inner)
    }
}

#[derive(Debug, Clone)]
/// Middleware that extracts credentials for an egress proxy
/// found in the Proxy-Authorization header of a passthrough request.
///
/// This is useful for MITM proxies such as transparent (L4) proxies, to keep track of used
/// proxy credentials for meta purposes.
pub struct DpiProxyCredentialExtractor<S> {
    inner: S,
}

impl<S> DpiProxyCredentialExtractor<S> {
    #[inline(always)]
    /// Creates a new [`DpiProxyCredentialExtractor`].
    pub const fn new(inner: S) -> Self {
        Self { inner }
    }

    define_inner_service_accessors!();
}

impl<S, ReqBody> Service<Request<ReqBody>> for DpiProxyCredentialExtractor<S>
where
    S: Service<Request<ReqBody>>,
    ReqBody: Send + 'static,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, mut req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        if let Some(ProxyAuthorization::<Basic>(credentials)) = req.headers().typed_get() {
            tracing::trace!(
                "DpiProxyCredentialExtractor: extracted Basic proxy auth: inserted in req extensions"
            );
            req.extensions_mut()
                .insert(DpiProxyCredential(ProxyCredential::Basic(credentials)));
        } else if let Some(ProxyAuthorization::<Bearer>(token)) = req.headers().typed_get() {
            tracing::trace!(
                "DpiProxyCredentialExtractor: extracted Bearer proxy auth: inserted in req extensions"
            );
            req.extensions_mut()
                .insert(DpiProxyCredential(ProxyCredential::Bearer(token)));
        }

        self.inner.serve(req).await
    }
}
