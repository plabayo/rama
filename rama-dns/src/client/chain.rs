use std::net::{Ipv4Addr, Ipv6Addr};

use rama_core::{
    bytes::Bytes,
    error::{ErrorExt, extra::OpaqueError},
    futures::{Stream, StreamExt, stream},
};
use rama_net::address::Domain;
use rama_utils::collections::NonEmptyVec;
use rand::RngExt;

use super::resolver::{DnsAddressResolver, DnsResolver, DnsTxtResolver};

fn gcd(mut a: usize, mut b: usize) -> usize {
    while b != 0 {
        let r = a % b;
        a = b;
        b = r;
    }
    a
}

fn random_cycle_indices(n: usize) -> Option<(usize, usize)> {
    if n == 0 {
        return None;
    }
    if n == 1 {
        return Some((0, 1));
    }

    let mut rng = rand::rng();
    let start = rng.random_range(0..n);

    let step = loop {
        let k = rng.random_range(1..n);
        if gcd(k, n) == 1 {
            break k;
        }
    };

    Some((start, step))
}

macro_rules! impl_chain_dns_address_resolver {
    () => {
        type Error = OpaqueError;

        fn lookup_ipv4(
            &self,
            domain: Domain,
        ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
            stream::iter(self.iter())
                .flat_map(move |resolver| resolver.lookup_ipv4(domain.clone()))
                .map(|result| result.map_err(ErrorExt::into_opaque_error))
        }

        async fn lookup_ipv4_first(&self, domain: Domain) -> Option<Result<Ipv4Addr, Self::Error>> {
            let mut last_err = None;
            for resolver in self {
                match resolver.lookup_ipv4_first(domain.clone()).await {
                    None => (),
                    Some(Ok(addr)) => return Some(Ok(addr)),
                    Some(Err(err)) => last_err = Some(Err(err.into_opaque_error())),
                }
            }
            last_err
        }

        async fn lookup_ipv4_rand(&self, domain: Domain) -> Option<Result<Ipv4Addr, Self::Error>> {
            let mut last_err = None;
            let n = self.len();

            let (start, step) = random_cycle_indices(n)?;

            for t in 0..n {
                let i = (start + t * step) % n;
                let resolver = &self[i];

                match resolver.lookup_ipv4_rand(domain.clone()).await {
                    None => {}
                    Some(Ok(addr)) => return Some(Ok(addr)),
                    Some(Err(err)) => last_err = Some(Err(err.into_opaque_error())),
                }
            }

            last_err
        }

        fn lookup_ipv6(
            &self,
            domain: Domain,
        ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
            stream::iter(self.iter())
                .flat_map(move |resolver| resolver.lookup_ipv6(domain.clone()))
                .map(|result| result.map_err(ErrorExt::into_opaque_error))
        }

        async fn lookup_ipv6_first(&self, domain: Domain) -> Option<Result<Ipv6Addr, Self::Error>> {
            let mut last_err = None;
            for resolver in self {
                match resolver.lookup_ipv6_first(domain.clone()).await {
                    None => (),
                    Some(Ok(addr)) => return Some(Ok(addr)),
                    Some(Err(err)) => last_err = Some(Err(err.into_opaque_error())),
                }
            }
            last_err
        }

        async fn lookup_ipv6_rand(&self, domain: Domain) -> Option<Result<Ipv6Addr, Self::Error>> {
            let mut last_err = None;
            let n = self.len();

            let (start, step) = random_cycle_indices(n)?;

            for t in 0..n {
                let i = (start + t * step) % n;
                let resolver = &self[i];

                match resolver.lookup_ipv6_rand(domain.clone()).await {
                    None => {}
                    Some(Ok(addr)) => return Some(Ok(addr)),
                    Some(Err(err)) => last_err = Some(Err(err.into_opaque_error())),
                }
            }

            last_err
        }
    };
}

macro_rules! impl_chain_dns_txt_resolver {
    () => {
        type Error = OpaqueError;

        fn lookup_txt(
            &self,
            domain: Domain,
        ) -> impl Stream<Item = Result<Bytes, Self::Error>> + Send + '_ {
            stream::iter(self.iter())
                .flat_map(move |resolver| resolver.lookup_txt(domain.clone()))
                .map(|result| result.map_err(ErrorExt::into_opaque_error))
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

#[cfg(test)]
mod tests {
    use ahash::{HashSet, HashSetExt as _};

    use super::*;

    #[tokio::test]
    async fn test_rand_ipv4() {
        let mut addresses = Vec::new();
        for i in 0..=u8::MAX {
            addresses.push(Ipv4Addr::new(i, i, i, i));

            let mut results = HashSet::new();

            for _ in 0..=((i as usize) * 100) {
                results.insert(
                    addresses
                        .lookup_ipv4_rand(Domain::example())
                        .await
                        .unwrap()
                        .unwrap(),
                );
            }

            assert_eq!((i as usize) + 1, results.len());
        }
    }

    #[tokio::test]
    async fn test_rand_ipv6() {
        let mut addresses = Vec::new();
        for i in 0..=512 {
            addresses.push(Ipv6Addr::new(
                i as u16, i as u16, i as u16, i as u16, i as u16, i as u16, i as u16, i as u16,
            ));

            let mut results = HashSet::new();

            for _ in 0..=((i as usize) * 100) {
                results.insert(
                    addresses
                        .lookup_ipv6_rand(Domain::example())
                        .await
                        .unwrap()
                        .unwrap(),
                );
            }

            assert_eq!((i as usize) + 1, results.len());
        }
    }
}
