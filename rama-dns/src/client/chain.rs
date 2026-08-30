use std::net::{Ipv4Addr, Ipv6Addr};

use rama_core::{
    bytes::Bytes,
    error::{ErrorExt, extra::OpaqueError},
    futures::{Stream, StreamExt, async_stream::stream_fn, stream},
};
use rama_net::address::Domain;
use rama_utils::collections::NonEmptyVec;
use rand::RngExt;

use super::resolver::{DnsAddressResolver, DnsResolver, DnsServiceBindingResolver, DnsTxtResolver};
use crate::wire::ServiceBinding;

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

macro_rules! impl_chain_dns_service_binding_resolver {
    () => {
        type Error = OpaqueError;

        fn lookup_svcb(
            &self,
            domain: Domain,
        ) -> impl Stream<Item = Result<ServiceBinding, Self::Error>> + Send + '_ {
            stream_fn(async move |mut yielder| {
                let mut bindings = Vec::new();
                for resolver in self {
                    let mut stream = std::pin::pin!(resolver.lookup_svcb(domain.clone()));
                    while let Some(result) = stream.next().await {
                        match result {
                            Ok(binding) => bindings.push(binding),
                            Err(err) => {
                                yielder.yield_item(Err(err.into_opaque_error())).await;
                                return;
                            }
                        }
                    }
                }
                for binding in bindings {
                    yielder.yield_item(Ok(binding)).await;
                }
            })
        }

        fn lookup_https(
            &self,
            domain: Domain,
        ) -> impl Stream<Item = Result<ServiceBinding, Self::Error>> + Send + '_ {
            stream_fn(async move |mut yielder| {
                let mut bindings = Vec::new();
                for resolver in self {
                    let mut stream = std::pin::pin!(resolver.lookup_https(domain.clone()));
                    while let Some(result) = stream.next().await {
                        match result {
                            Ok(binding) => bindings.push(binding),
                            Err(err) => {
                                yielder.yield_item(Err(err.into_opaque_error())).await;
                                return;
                            }
                        }
                    }
                }
                for binding in bindings {
                    yielder.yield_item(Ok(binding)).await;
                }
            })
        }
    };
}

impl<R: DnsAddressResolver> DnsAddressResolver for Vec<R> {
    impl_chain_dns_address_resolver!();
}
impl<R: DnsTxtResolver> DnsTxtResolver for Vec<R> {
    impl_chain_dns_txt_resolver!();
}
impl<R: DnsServiceBindingResolver> DnsServiceBindingResolver for Vec<R> {
    impl_chain_dns_service_binding_resolver!();
}
impl<R: DnsResolver> DnsResolver for Vec<R> {}

impl<R: DnsAddressResolver> DnsAddressResolver for NonEmptyVec<R> {
    impl_chain_dns_address_resolver!();
}
impl<R: DnsTxtResolver> DnsTxtResolver for NonEmptyVec<R> {
    impl_chain_dns_txt_resolver!();
}
impl<R: DnsServiceBindingResolver> DnsServiceBindingResolver for NonEmptyVec<R> {
    impl_chain_dns_service_binding_resolver!();
}
impl<R: DnsResolver> DnsResolver for NonEmptyVec<R> {}

impl<R: DnsAddressResolver, const N: usize> DnsAddressResolver for [R; N] {
    impl_chain_dns_address_resolver!();
}
impl<R: DnsTxtResolver, const N: usize> DnsTxtResolver for [R; N] {
    impl_chain_dns_txt_resolver!();
}
impl<R: DnsServiceBindingResolver, const N: usize> DnsServiceBindingResolver for [R; N] {
    impl_chain_dns_service_binding_resolver!();
}
impl<R: DnsResolver, const N: usize> DnsResolver for [R; N] {}

#[cfg(test)]
mod tests {
    use ahash::{HashSet, HashSetExt as _};
    use rama_core::bytes::Bytes;
    use rama_core::error::{BoxError, BoxErrorExt as _};

    use super::*;

    #[derive(Debug, Clone)]
    struct BindingResolver {
        svcb_port: u16,
        https_port: u16,
        fail: bool,
    }

    impl DnsServiceBindingResolver for BindingResolver {
        type Error = BoxError;

        fn lookup_svcb(
            &self,
            _: Domain,
        ) -> impl Stream<Item = Result<ServiceBinding, Self::Error>> + Send + '_ {
            stream::once(std::future::ready(if self.fail {
                Err(BoxError::from_static_str("malformed RRset"))
            } else {
                Ok(binding(self.svcb_port))
            }))
        }

        fn lookup_https(
            &self,
            _: Domain,
        ) -> impl Stream<Item = Result<ServiceBinding, Self::Error>> + Send + '_ {
            stream::once(std::future::ready(if self.fail {
                Err(BoxError::from_static_str("malformed RRset"))
            } else {
                Ok(binding(self.https_port))
            }))
        }
    }

    fn binding(port: u16) -> ServiceBinding {
        let mut rdata = vec![0, 1, 0, 0, 3, 0, 2];
        rdata.extend_from_slice(&port.to_be_bytes());
        ServiceBinding::parse_rdata_bytes(&Bytes::from(rdata)).expect("valid service binding")
    }

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

    #[tokio::test]
    async fn service_binding_chain_flattens_every_resolver() {
        let resolvers = vec![
            BindingResolver {
                svcb_port: 8443,
                https_port: 443,
                fail: false,
            },
            BindingResolver {
                svcb_port: 9443,
                https_port: 444,
                fail: false,
            },
        ];
        let svcb: Vec<_> = resolvers
            .lookup_svcb(Domain::example())
            .map(|result| result.expect("success").port().expect("port"))
            .collect()
            .await;
        assert_eq!(svcb, [8443, 9443]);

        let array: [_; 2] = resolvers.try_into().expect("two resolvers");
        let https: Vec<_> = array
            .lookup_https(Domain::example())
            .map(|result| result.expect("success").port().expect("port"))
            .collect()
            .await;
        assert_eq!(https, [443, 444]);
    }

    #[tokio::test]
    async fn service_binding_chain_discards_values_before_an_error() {
        let resolvers = vec![
            BindingResolver {
                svcb_port: 8443,
                https_port: 443,
                fail: false,
            },
            BindingResolver {
                svcb_port: 0,
                https_port: 0,
                fail: true,
            },
        ];

        let items: Vec<_> = resolvers.lookup_svcb(Domain::example()).collect().await;
        assert_eq!(items.len(), 1);
        items[0]
            .as_ref()
            .expect_err("malformed RRset must yield an error");
    }
}
