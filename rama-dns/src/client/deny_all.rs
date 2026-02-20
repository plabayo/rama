use rama_core::{
    bytes::Bytes,
    futures::{Stream, stream},
};
use rama_net::address::Domain;
use rama_utils::macros::error::static_str_error;

use std::net::{Ipv4Addr, Ipv6Addr};

use super::resolver::{DnsAddressResolver, DnsResolver, DnsTxtResolver};

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
/// a [`DnsResolver`] implementation which
/// denies all incoming DNS requests with a [`DnsDeniedError`].
pub struct DenyAllDnsResolver;

impl DenyAllDnsResolver {
    #[inline(always)]
    /// Create a new [`Default`] [`DenyAllDnsResolver`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

static_str_error! {
    #[doc = "Dns resolve denied"]
    pub struct DnsDeniedError;
}

impl DnsAddressResolver for DenyAllDnsResolver {
    type Error = DnsDeniedError;

    #[inline(always)]
    fn lookup_ipv4(
        &self,
        _: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
        stream::once(std::future::ready(Err(DnsDeniedError)))
    }

    #[inline(always)]
    fn lookup_ipv4_first(
        &self,
        _: Domain,
    ) -> impl Future<Output = Option<Result<Ipv4Addr, Self::Error>>> + Send + '_ {
        std::future::ready(Some(Err(DnsDeniedError)))
    }

    #[inline(always)]
    fn lookup_ipv4_rand(
        &self,
        _: Domain,
    ) -> impl Future<Output = Option<Result<Ipv4Addr, Self::Error>>> + Send + '_ {
        std::future::ready(Some(Err(DnsDeniedError)))
    }

    #[inline(always)]
    fn lookup_ipv6(
        &self,
        _: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
        stream::once(std::future::ready(Err(DnsDeniedError)))
    }

    #[inline(always)]
    fn lookup_ipv6_first(
        &self,
        _: Domain,
    ) -> impl Future<Output = Option<Result<Ipv6Addr, Self::Error>>> + Send + '_ {
        std::future::ready(Some(Err(DnsDeniedError)))
    }

    #[inline(always)]
    fn lookup_ipv6_rand(
        &self,
        _: Domain,
    ) -> impl Future<Output = Option<Result<Ipv6Addr, Self::Error>>> + Send + '_ {
        std::future::ready(Some(Err(DnsDeniedError)))
    }
}

impl DnsTxtResolver for DenyAllDnsResolver {
    type Error = DnsDeniedError;

    fn lookup_txt(&self, _: Domain) -> impl Stream<Item = Result<Bytes, Self::Error>> + Send + '_ {
        stream::once(std::future::ready(Err(DnsDeniedError)))
    }
}

impl DnsResolver for DenyAllDnsResolver {}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::futures::StreamExt;

    macro_rules! impl_deny_test_body {
        ($fn:ident) => {
            let resolver = DenyAllDnsResolver;

            let mut stream = std::pin::pin!(resolver.$fn(Domain::example()));

            let item = stream.next().await.unwrap();
            assert_eq!(DnsDeniedError, item.unwrap_err());

            let item = stream.next().await;
            assert!(item.is_none());
        };
    }

    macro_rules! impl_deny_test_single_item {
        ($fn:ident) => {
            let resolver = DenyAllDnsResolver;
            let result = resolver.$fn(Domain::example()).await.unwrap();
            assert_eq!(DnsDeniedError, result.unwrap_err());
        };
    }

    #[tokio::test]
    async fn test_deny_all_lookup_ipv4() {
        impl_deny_test_body!(lookup_ipv4);
    }

    #[tokio::test]
    async fn test_deny_all_lookup_ipv4_first() {
        impl_deny_test_single_item!(lookup_ipv4_first);
    }

    #[tokio::test]
    async fn test_deny_all_lookup_ipv4_rand() {
        impl_deny_test_single_item!(lookup_ipv4_rand);
    }

    #[tokio::test]
    async fn test_deny_all_lookup_ipv6() {
        impl_deny_test_body!(lookup_ipv6);
    }

    #[tokio::test]
    async fn test_deny_all_lookup_ipv6_first() {
        impl_deny_test_single_item!(lookup_ipv6_first);
    }

    #[tokio::test]
    async fn test_deny_all_lookup_ipv6_rand() {
        impl_deny_test_single_item!(lookup_ipv6_rand);
    }

    #[tokio::test]
    async fn test_deny_all_lookup_txt() {
        impl_deny_test_body!(lookup_txt);
    }
}
