use super::{dns_map::DnsMap, DnsError, DynamicDnsResolver};
use crate::{
    http::{
        layer::header_config::extract_header_config,
        utils::{HeaderValueErr, HeaderValueGetter},
        HeaderName, Request, RequestContext,
    },
    service::{Context, Service},
    stream::ServerSocketAddr,
};
use std::net::SocketAddr;

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
/// [`DynamicDnsResolver`]: crate::dns::layer::DynamicDnsResolver
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

impl<State, Body, E, S, R> Service<State, Request<Body>> for DnsService<S, R>
where
    State: Send + Sync + 'static,
    Body: Send + Sync + 'static,
    E: Into<crate::error::BoxError> + Send + Sync + 'static,
    S: Service<State, Request<Body>, Error = E>,
    R: DynamicDnsResolver,
{
    type Response = S::Response;
    type Error = DnsError<E>;

    async fn serve(
        &self,
        mut ctx: Context<State>,
        request: Request<Body>,
    ) -> Result<Self::Response, Self::Error> {
        let host = ctx
            .get_or_insert_with::<RequestContext>(|| RequestContext::from(&request))
            .host
            .clone();

        if let Some(addresses) = self.lookup_host(&request, host).await? {
            let mut addresses_it = addresses.into_iter();
            match addresses_it.next() {
                Some(address) => {
                    ctx.insert(ServerSocketAddr::new(address));
                }
                None => {
                    return Err(DnsError::HostnameNotFound);
                }
            }
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
        maybe_host: Option<String>,
    ) -> Result<Option<Vec<SocketAddr>>, DnsError<E>> {
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
                                .lookup_host(&host)
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
