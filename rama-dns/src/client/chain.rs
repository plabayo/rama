use std::net::{Ipv4Addr, Ipv6Addr};

use rama_core::{
    bytes::Bytes,
    error::BoxError,
    futures::{Stream, StreamExt, stream},
};
use rama_net::address::Domain;
use rama_utils::collections::NonEmptyVec;

use super::resolver::{DnsAddressResolver, DnsResolver, DnsTxtResolver};

macro_rules! impl_chain_dns_address_resolver {
    () => {
        type Error = BoxError;

        fn lookup_ipv4(
            &self,
            domain: Domain,
        ) -> impl Stream<Item = Result<Ipv4Addr, BoxError>> + Send + '_ {
            stream::iter(self.iter())
                .flat_map(move |resolver| resolver.lookup_ipv4(domain.clone()))
                .map(|result| result.map_err(Into::into))
        }

        fn lookup_ipv6(
            &self,
            domain: Domain,
        ) -> impl Stream<Item = Result<Ipv6Addr, BoxError>> + Send + '_ {
            stream::iter(self.iter())
                .flat_map(move |resolver| resolver.lookup_ipv6(domain.clone()))
                .map(|result| result.map_err(Into::into))
        }
    };
}

macro_rules! impl_chain_dns_txt_resolver {
    () => {
        type Error = BoxError;

        fn lookup_txt(
            &self,
            domain: Domain,
        ) -> impl Stream<Item = Result<Bytes, Self::Error>> + Send + '_ {
            stream::iter(self.iter())
                .flat_map(move |resolver| resolver.lookup_txt(domain.clone()))
                .map(|result| result.map_err(Into::into))
        }
    };
}

impl<R: DnsAddressResolver> DnsAddressResolver for Vec<R> {
    impl_chain_dns_address_resolver!();
}
impl<R: DnsTxtResolver> DnsTxtResolver for Vec<R> {
    impl_chain_dns_txt_resolver!();
}
impl<R: DnsResolver> DnsResolver for Vec<R> {}

impl<R: DnsAddressResolver> DnsAddressResolver for NonEmptyVec<R> {
    impl_chain_dns_address_resolver!();
}
impl<R: DnsTxtResolver> DnsTxtResolver for NonEmptyVec<R> {
    impl_chain_dns_txt_resolver!();
}
impl<R: DnsResolver> DnsResolver for NonEmptyVec<R> {}

impl<R: DnsAddressResolver, const N: usize> DnsAddressResolver for [R; N] {
    impl_chain_dns_address_resolver!();
}
impl<R: DnsTxtResolver, const N: usize> DnsTxtResolver for [R; N] {
    impl_chain_dns_txt_resolver!();
}
impl<R: DnsResolver, const N: usize> DnsResolver for [R; N] {}
