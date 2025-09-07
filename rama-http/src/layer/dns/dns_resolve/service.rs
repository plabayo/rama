use super::DnsResolveMode;
use crate::{HeaderName, Request};
use rama_core::{Context, Service, error::OpaqueError};
use rama_utils::macros::define_inner_service_accessors;
use std::fmt;

/// Service to support configuring the DNS resolve mode.
///
/// By default DNS resolving is expected to only be done
/// if it is needed (e.g. because we need to know the IP).
/// Configuring this to be used as eager (when requested) is
/// a way to have requested the intent
/// to reoslve DNS even if it is not needed.
///
/// See `Dns` (`rama_core`) and [`DnsResolveMode`] for more information.
pub struct DnsResolveModeService<S> {
    inner: S,
    header_name: HeaderName,
}

impl<S> DnsResolveModeService<S> {
    /// Create a new instance of the [`DnsResolveModeService`].
    pub const fn new(inner: S, header_name: HeaderName) -> Self {
        Self { inner, header_name }
    }

    define_inner_service_accessors!();
}

impl<S: fmt::Debug> fmt::Debug for DnsResolveModeService<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsResolveModeService")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<S: Clone> Clone for DnsResolveModeService<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            header_name: self.header_name.clone(),
        }
    }
}

impl<Body, S> Service<Request<Body>> for DnsResolveModeService<S>
where
    Body: Send + Sync + 'static,
    S: Service<Request<Body>, Error: Into<rama_core::error::BoxError> + Send + Sync + 'static>,
{
    type Response = S::Response;
    type Error = OpaqueError;

    async fn serve(
        &self,
        mut ctx: Context,
        request: Request<Body>,
    ) -> Result<Self::Response, Self::Error> {
        if let Some(header_value) = request.headers().get(&self.header_name) {
            let dns_resolve_mode: DnsResolveMode = header_value.try_into()?;
            ctx.insert(dns_resolve_mode);
        }

        self.inner
            .serve(ctx, request)
            .await
            .map_err(|err| OpaqueError::from_boxed(err.into()))
    }
}
