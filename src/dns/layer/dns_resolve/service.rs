use super::DnsResolveMode;
use crate::{
    error::OpaqueError,
    http::{HeaderName, Request},
    service::{Context, Service},
};

/// Service to support configuring the DNS resolve mode.
///
/// By default DNS resolving is expected to only be done
/// if it is needed (e.g. because we need to know the IP).
/// Configuring this to be used as eager (when requested) is
/// a way to have requested the intent
/// to reoslve DNS even if it is not needed.
///
/// See [`Dns`] and [`DnsResolveMode`] for more information.
///
/// [`Dns`]: crate::dns::Dns
#[derive(Debug, Clone)]
pub struct DnsResolveModeService<S> {
    inner: S,
    header_name: HeaderName,
}

impl<S> DnsResolveModeService<S> {
    /// Create a new instance of the [`DnsResolveModeService`].
    pub fn new(inner: S, header_name: HeaderName) -> Self {
        Self { inner, header_name }
    }

    define_inner_service_accessors!();
}

impl<State, Body, E, S> Service<State, Request<Body>> for DnsResolveModeService<S>
where
    State: Send + Sync + 'static,
    Body: Send + Sync + 'static,
    E: Into<crate::error::BoxError> + Send + Sync + 'static,
    S: Service<State, Request<Body>, Error = E>,
{
    type Response = S::Response;
    type Error = OpaqueError;

    async fn serve(
        &self,
        mut ctx: Context<State>,
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
