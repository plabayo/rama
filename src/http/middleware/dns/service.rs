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

use super::{DefaultDnsResolver, DnsResolver, ResolvedSocketAddr};

#[derive(Debug, Clone)]
pub struct DnsService<S, R> {
    pub(super) inner: S,
    pub(super) resolver: R,
    pub(super) header_name: Option<HeaderName>,
}

impl<S> DnsService<S, DefaultDnsResolver> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            resolver: DefaultDnsResolver,
            header_name: None,
        }
    }
}

impl<S, R> DnsService<S, R> {
    pub fn resolver<T>(self, resolver: T) -> DnsService<S, T> {
        DnsService {
            inner: self.inner,
            resolver,
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
        let host = request
            .headers()
            .typed_get::<Host>()
            .ok_or("Host header is required for DNS resolution")?;

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
                extract_header_config::<_, _, HashMap<String, IpAddr>>(&request, header_name)
                    .await?;
            for (key, value) in dns_table.into_iter() {
                if hostname == key.to_lowercase() {
                    let addr: SocketAddr = (value, port).into();
                    request.extensions_mut().insert(ResolvedSocketAddr(addr));

                    // early return with header-based dns mapping
                    return self.inner.call(request).await.map_err(Into::into);
                }
            }
        }

        // use internal dns resolver if still no dns mapping found
        let addr = self.resolver.lookup_host((hostname.as_str(), port)).await?;
        request.extensions_mut().insert(ResolvedSocketAddr(addr));

        // call inner service in default path
        self.inner.call(request).await.map_err(Into::into)
    }
}
