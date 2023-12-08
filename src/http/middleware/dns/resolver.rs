use std::{future::Future, net::SocketAddr};

use crate::rt::net::{lookup_host, ToSocketAddrs};

pub trait DnsResolver {
    fn lookup_host<T: ToSocketAddrs>(
        &self,
        addr: T,
    ) -> impl Future<Output = std::io::Result<SocketAddr>>;
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
    async fn lookup_host<T: ToSocketAddrs>(&self, addr: T) -> std::io::Result<SocketAddr> {
        lookup_host(addr).await?.next().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::Other, "DNS address failed to resolve")
        })
    }
}
