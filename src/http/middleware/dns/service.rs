use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
};

use crate::{
    http::{
        headers::{HeaderMapExt, Host},
        middleware::extract_header_config,
        HeaderName, Request,
    },
    service::Service,
    BoxError,
};

use super::{DnsError, DnsResolver, DnsResolverFn, NoDnsResolver, ResolvedSocketAddr};

#[derive(Debug, Clone)]
pub struct DnsService<S, R> {
    pub(super) inner: S,
    pub(super) resolver: R,
    pub(super) header_name: Option<HeaderName>,
}

impl<S> DnsService<S, NoDnsResolver> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            resolver: NoDnsResolver,
            header_name: None,
        }
    }
}

impl<S, R> DnsService<S, R> {
    pub fn resolver<I, T>(self, resolver: I) -> DnsService<S, T>
    where
        T: DnsResolver,
        I: Into<T>,
    {
        DnsService {
            inner: self.inner,
            resolver: resolver.into(),
            header_name: self.header_name,
        }
    }

    pub fn resolver_fn<F, T>(self, resolver: F) -> DnsService<S, DnsResolverFn<F>>
    where
        T: DnsResolver,
        F: Fn(&str) -> T + Send + Sync + 'static,
    {
        DnsService {
            inner: self.inner,
            resolver: DnsResolverFn::new(resolver),
            header_name: self.header_name,
        }
    }

    pub fn header_name<T>(mut self, header_name: T) -> Self
    where
        T: Into<HeaderName>,
    {
        self.header_name = Some(header_name.into());
        self
    }
}

impl<Body, E, S, R> Service<Request<Body>> for DnsService<S, R>
where
    S: Service<Request<Body>, Error = E>,
    R: DnsResolver,
    E: Into<BoxError>,
{
    type Response = S::Response;
    type Error = BoxError;

    async fn call(&self, mut request: Request<Body>) -> Result<Self::Response, Self::Error> {
        let addr = self.lookup_host(&request).await?;
        request.extensions_mut().insert(ResolvedSocketAddr(addr));
        self.inner.call(request).await.map_err(Into::into)
    }
}

impl<S, R> DnsService<S, R>
where
    R: DnsResolver,
{
    async fn lookup_host<Body>(&self, request: &Request<Body>) -> Result<SocketAddr, BoxError> {
        let host = request
            .headers()
            .typed_get::<Host>()
            .ok_or_else(|| DnsError::HostnameNotFound)?;

        let hostname = host.hostname().to_lowercase();
        let port = host.port().unwrap_or_else(|| {
            let scheme = request.uri().scheme_str();
            if scheme
                .map(|s| s == "https" || s == "wss")
                .unwrap_or_default()
            {
                443
            } else {
                80
            }
        });

        // if a dns mapping was defined, try to use it
        if let Some(header_name) = &self.header_name {
            let dns_table =
                extract_header_config::<_, _, HashMap<String, IpAddr>>(request, header_name)
                    .await?;
            for (key, value) in dns_table.into_iter() {
                if hostname == key.to_lowercase() {
                    let addr: SocketAddr = (value, port).into();
                    return Ok(addr);
                }
            }
        }

        // use internal dns resolver if still no dns mapping found
        let addr = self
            .resolver
            .lookup_host(format!("{}:{}", hostname, port).as_str())
            .await?;
        Ok(addr)
    }
}
