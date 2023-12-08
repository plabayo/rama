use std::{future::Future, net::SocketAddr};

use crate::rt::net::lookup_host;

use super::{DnsError, DnsResult};

pub trait DnsResolver {
    fn lookup_host(&self, host: &str) -> impl Future<Output = DnsResult<SocketAddr>>;
}

#[derive(Debug, Clone)]
pub struct ResolvedSocketAddr(pub(super) SocketAddr);

impl ResolvedSocketAddr {
    pub fn addr(&self) -> &SocketAddr {
        &self.0
    }

    pub fn into_addr(self) -> SocketAddr {
        self.0
    }
}

impl AsRef<SocketAddr> for ResolvedSocketAddr {
    fn as_ref(&self) -> &SocketAddr {
        &self.0
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DefaultDnsResolver;

impl DnsResolver for DefaultDnsResolver {
    async fn lookup_host(&self, host: &str) -> DnsResult<SocketAddr> {
        lookup_host(host)
            .await?
            .next()
            .ok_or_else(|| DnsError::MappingNotFound(String::from(host)))
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct NoDnsResolver;

impl DnsResolver for NoDnsResolver {
    async fn lookup_host(&self, host: &str) -> DnsResult<SocketAddr> {
        Err(DnsError::MappingNotFound(String::from(host)))
    }
}

#[derive(Debug, Clone)]
pub struct DnsResolverFn<F> {
    inner: F,
}

impl<F> DnsResolverFn<F> {
    pub fn new(inner: F) -> Self {
        Self { inner }
    }
}

impl<F, Fut> DnsResolver for DnsResolverFn<F>
where
    F: Fn(&str) -> Fut + Send + 'static,
    Fut: Future<Output = DnsResult<SocketAddr>> + Send,
{
    fn lookup_host(&self, host: &str) -> impl Future<Output = DnsResult<SocketAddr>> {
        (self.inner)(host)
    }
}
