use super::{dns_map::DnsMap, DnsError, DynamicDnsResolver};
use crate::{
    http::{
        headers::{HeaderMapExt, Host},
        layer::extract_header_config,
        utils::{HeaderValueErr, HeaderValueGetter},
        HeaderName, Request,
    },
    service::{Context, Service},
};
use std::net::SocketAddr;

/// State that is added to the [`Extensions`] of a request when a [`DnsService`] is used,
/// and which has resolved the hostname of the request.
///
/// The (Http) request itself is not modified, and the resolved addresses are not added to the
/// request headers.
///
/// [`Extensions`]: crate::service::context::Extensions
#[derive(Debug, Clone)]
pub struct DnsResolvedSocketAddresses {
    addresses: Vec<SocketAddr>,
}

impl DnsResolvedSocketAddresses {
    pub(crate) fn new(addresses: Vec<SocketAddr>) -> Self {
        Self { addresses }
    }

    /// Get the resolved addresses, if any.
    pub fn resolved_addresses(&self) -> &[SocketAddr] {
        self.addresses.as_slice()
    }

    /// Take the resolved addresses, if any.
    pub fn into_resolved_addresses(self) -> Vec<SocketAddr> {
        self.addresses
    }
}

/// [`Service`] which resolves the hostname of the request and adds the resolved addresses
/// to the [`Extensions`] of the request.
///
/// The (Http) request itself is not modified, and the resolved addresses are not added to the
/// request headers. The addresses are resolved by using the [`Host`] header of the request
/// in the following order:
///
/// 1. If the defined Dns Map header is present, and enabled by defining an opt-in header name, use it to resolve the hostname.
/// 2. If the [`DynamicDnsResolver`] is enabled it will be:
///   - always used in case no opt-in header is defined for these purposes;
///   - used if the opt-in header is present and its value is `1`.
///
/// [`Service`]: crate::service::Service
/// [`Extensions`]: crate::service::context::Extensions
/// [`Host`]: crate::http::headers::Host
/// [`DynamicDnsResolver`]: crate::http::layer::DynamicDnsResolver
#[derive(Debug, Clone)]
pub struct DnsService<S, R> {
    inner: S,
    resolver: R,
    resolver_header: Option<HeaderName>,
    dns_map_header: Option<HeaderName>,
}

impl<S, R> DnsService<S, R> {
    pub(crate) fn new(
        inner: S,
        resolver: R,
        resolver_header: Option<HeaderName>,
        dns_map_header: Option<HeaderName>,
    ) -> Self {
        Self {
            inner,
            resolver,
            resolver_header,
            dns_map_header,
        }
    }
}

impl<State, Body, E, S> Service<State, Request<Body>> for DnsService<S, ()>
where
    State: Send + Sync + 'static,
    Body: Send + Sync + 'static,
    E: Into<crate::error::Error> + Send + Sync + 'static,
    S: Service<State, Request<Body>, Error = E>,
{
    type Response = S::Response;
    type Error = DnsError<E>;

    async fn serve(
        &self,
        mut ctx: Context<State>,
        request: Request<Body>,
    ) -> Result<Self::Response, Self::Error> {
        if let Some(addresses) = self.lookup_host(&request).await? {
            ctx.extensions_mut()
                .insert(DnsResolvedSocketAddresses::new(addresses));
        }
        self.inner
            .serve(ctx, request)
            .await
            .map_err(DnsError::ServiceError)
    }
}

impl<S, R> DnsService<S, R>
where
    R: DynamicDnsResolver,
{
    async fn lookup_host<Body, E>(
        &self,
        request: &Request<Body>,
    ) -> Result<Option<Vec<SocketAddr>>, DnsError<E>> {
        let maybe_host = request
            .headers()
            .typed_get::<Host>()
            .map(|host| host.to_string());

        // opt-in callee-defined dns map, only if allowed by the service
        if let Some(dns_map_header) = &self.dns_map_header {
            match extract_header_config::<_, DnsMap, _>(request, dns_map_header) {
                Err(HeaderValueErr::HeaderInvalid(_)) => {
                    return Err(DnsError::MappingNotFound(maybe_host.unwrap_or_default()));
                }
                Err(HeaderValueErr::HeaderMissing(_)) => (), // ignore if missing, it's opt-in
                Ok(dns_map) => {
                    return match maybe_host {
                        None => Err(DnsError::HostnameNotFound),
                        Some(host) => {
                            let addr = dns_map
                                .lookup_host(host.clone())
                                .ok_or_else(|| DnsError::MappingNotFound(host))?;
                            Ok(Some(vec![addr]))
                        }
                    };
                }
            }
        }

        // opt-in resolver, only if allowed by the service
        if let Some(resolver_header) = &self.resolver_header {
            match request.header_str(resolver_header) {
                Err(HeaderValueErr::HeaderInvalid(_)) => {
                    return Err(DnsError::InvalidHeader(resolver_header.to_string()));
                }
                Err(HeaderValueErr::HeaderMissing(_)) => return Ok(None), // take it as `0`
                Ok(raw_value) => match raw_value.trim() {
                    "" | "0" => return Ok(None),
                    "1" => (),
                    _ => return Err(DnsError::InvalidHeader(resolver_header.to_string())),
                },
            }
        }

        let host = maybe_host.ok_or_else(|| DnsError::HostnameNotFound)?;
        Ok(Some(
            self.resolver.lookup_host(host.to_string()).await?.collect(),
        ))
    }
}
