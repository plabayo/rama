use super::DnsResolveMode;
use crate::{HeaderName, Request};
use rama_core::error::ErrorContext;
use rama_core::{Service, error::BoxError, extensions::ExtensionsMut};
use rama_utils::macros::define_inner_service_accessors;

/// Service to support configuring the DNS resolve mode.
///
/// By default DNS resolving is expected to only be done
/// if it is needed (e.g. because we need to know the IP).
/// Configuring this to be used as eager (when requested) is
/// a way to have requested the intent
/// to reoslve DNS even if it is not needed.
///
/// See `Dns` (`rama_core`) and [`DnsResolveMode`] for more information.
#[derive(Debug, Clone)]
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

impl<Body, S> Service<Request<Body>> for DnsResolveModeService<S>
where
    Body: Send + Sync + 'static,
    S: Service<Request<Body>, Error: Into<rama_core::error::BoxError> + Send + Sync + 'static>,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, mut request: Request<Body>) -> Result<Self::Output, Self::Error> {
        if let Some(header_value) = request.headers().get(&self.header_name) {
            let dns_resolve_mode: DnsResolveMode = header_value.try_into()?;
            request.extensions_mut().insert(dns_resolve_mode);
        }

        self.inner.serve(request).await.into_box_error()
    }
}
