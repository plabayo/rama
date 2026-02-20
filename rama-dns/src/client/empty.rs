use rama_core::{
    bytes::Bytes,
    futures::{Stream, stream},
};
use rama_net::address::Domain;

use std::{
    convert::Infallible,
    net::{Ipv4Addr, Ipv6Addr},
};

use super::resolver::{DnsAddressResolver, DnsResolver, DnsTxtResolver};

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// a [`DnsResolver`] implementation which
/// returns an empty stream for any DNS resolve call.
pub struct EmptyDnsResolver;

impl EmptyDnsResolver {
    #[inline(always)]
    /// Create a new [`Default`] [`EmptyDnsResolver`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl DnsAddressResolver for EmptyDnsResolver {
    type Error = Infallible;

    #[inline(always)]
    fn lookup_ipv4(
        &self,
        _: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
        stream::empty()
    }

    #[inline(always)]
    fn lookup_ipv4_first(
        &self,
        _: Domain,
    ) -> impl Future<Output = Option<Result<Ipv4Addr, Self::Error>>> + Send + '_ {
        std::future::ready(None)
    }

    #[inline(always)]
    fn lookup_ipv4_rand(
        &self,
        _: Domain,
    ) -> impl Future<Output = Option<Result<Ipv4Addr, Self::Error>>> + Send + '_ {
        std::future::ready(None)
    }

    #[inline(always)]
    fn lookup_ipv6(
        &self,
        _: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
        stream::empty()
    }

    #[inline(always)]
    fn lookup_ipv6_first(
        &self,
        _: Domain,
    ) -> impl Future<Output = Option<Result<Ipv6Addr, Self::Error>>> + Send + '_ {
        std::future::ready(None)
    }

    #[inline(always)]
    fn lookup_ipv6_rand(
        &self,
        _: Domain,
    ) -> impl Future<Output = Option<Result<Ipv6Addr, Self::Error>>> + Send + '_ {
        std::future::ready(None)
    }
}

impl DnsTxtResolver for EmptyDnsResolver {
    type Error = Infallible;

    #[inline(always)]
    fn lookup_txt(
        &self,
        _domain: Domain,
    ) -> impl Stream<Item = Result<Bytes, Self::Error>> + Send + '_ {
        stream::empty()
    }
}

impl DnsResolver for EmptyDnsResolver {}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::futures::StreamExt;

    macro_rules! impl_empty_test_body {
        ($fn:ident) => {
            let resolver = EmptyDnsResolver;

            let item = std::pin::pin!(resolver.$fn(Domain::example())).next().await;
            assert!(item.is_none());
        };
    }

    macro_rules! impl_empty_single {
        ($fn:ident) => {
            let resolver = EmptyDnsResolver;

            let item = resolver.$fn(Domain::example()).await;
            assert!(item.is_none());
        };
    }

    #[tokio::test]
    async fn test_empty_lookup_ipv4() {
        impl_empty_test_body!(lookup_ipv4);
    }

    #[tokio::test]
    async fn test_empty_lookup_ipv4_first() {
        impl_empty_single!(lookup_ipv4_first);
    }

    #[tokio::test]
    async fn test_empty_lookup_ipv4_rand() {
        impl_empty_single!(lookup_ipv4_rand);
    }

    #[tokio::test]
    async fn test_empty_lookup_ipv6() {
        impl_empty_test_body!(lookup_ipv6);
    }

    #[tokio::test]
    async fn test_empty_lookup_txt() {
        impl_empty_test_body!(lookup_txt);
    }

    #[tokio::test]
    async fn test_empty_lookup_ipv6_first() {
        impl_empty_single!(lookup_ipv6_first);
    }

    #[tokio::test]
    async fn test_empty_lookup_ipv6_rand() {
        impl_empty_single!(lookup_ipv6_rand);
    }
}
