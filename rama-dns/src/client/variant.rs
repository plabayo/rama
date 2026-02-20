use std::net::{Ipv4Addr, Ipv6Addr};

use rama_core::{
    bytes::Bytes,
    error::{ErrorExt, extra::OpaqueError},
    futures::{Stream, StreamExt as _, async_stream::stream_fn},
};
use rama_net::address::Domain;

use super::resolver::{DnsAddressResolver, DnsResolver, DnsTxtResolver};

macro_rules! impl_dns_resolver_either {
    ($id:ident, $($param:ident),+ $(,)?) => {
        impl<$($param),+> DnsAddressResolver for ::rama_core::combinators::$id<$($param),+>
        where
            $($param: DnsAddressResolver),+,
        {
            type Error = OpaqueError;

            fn lookup_ipv4(
                &self,
                domain: Domain,
            ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
                stream_fn(async move |mut yielder| {
                    match self {
                        $(
                            ::rama_core::combinators::$id::$param(d) => {
                                let mut stream = std::pin::pin!(d.lookup_ipv4(domain));
                                while let Some(result) = stream.next().await {
                                    yielder.yield_item(result.map_err(ErrorExt::into_opaque_error)).await;
                                }
                            },
                        )+
                    }
                })
            }

            async fn lookup_ipv4_first(
                &self,
                domain: Domain,
            ) -> Option<Result<Ipv4Addr, Self::Error>> {
                match self {
                    $(
                        ::rama_core::combinators::$id::$param(d) =>
                            d.lookup_ipv4_first(domain).await.map(|result|
                                result.map_err(ErrorExt::into_opaque_error)),
                    )+
                }
            }

            async fn lookup_ipv4_rand(
                &self,
                domain: Domain,
            ) -> Option<Result<Ipv4Addr, Self::Error>> {
                match self {
                    $(
                        ::rama_core::combinators::$id::$param(d) =>
                            d.lookup_ipv4_rand(domain).await.map(|result|
                                result.map_err(ErrorExt::into_opaque_error)),
                    )+
                }
            }

            fn lookup_ipv6(
                &self,
                domain: Domain,
            ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
                stream_fn(async move |mut yielder| {
                    match self {
                        $(
                            ::rama_core::combinators::$id::$param(d) => {
                                let mut stream = std::pin::pin!(d.lookup_ipv6(domain));
                                while let Some(result) = stream.next().await {
                                    yielder.yield_item(result.map_err(ErrorExt::into_opaque_error)).await;
                                }
                            },
                        )+
                    }
                })
            }

            async fn lookup_ipv6_first(
                &self,
                domain: Domain,
            ) -> Option<Result<Ipv6Addr, Self::Error>> {
                match self {
                    $(
                        ::rama_core::combinators::$id::$param(d) =>
                            d.lookup_ipv6_first(domain).await.map(|result|
                                result.map_err(ErrorExt::into_opaque_error)),
                    )+
                }
            }

            async fn lookup_ipv6_rand(
                &self,
                domain: Domain,
            ) -> Option<Result<Ipv6Addr, Self::Error>> {
                match self {
                    $(
                        ::rama_core::combinators::$id::$param(d) =>
                            d.lookup_ipv6_rand(domain).await.map(|result|
                                result.map_err(ErrorExt::into_opaque_error)),
                    )+
                }
            }
        }

        impl<$($param),+> DnsTxtResolver for ::rama_core::combinators::$id<$($param),+>
        where
            $($param: DnsTxtResolver),+,
        {
            type Error = OpaqueError;

            fn lookup_txt(
                &self,
                domain: Domain,
            ) -> impl Stream<Item = Result<Bytes, Self::Error>> + Send + '_ {
                stream_fn(async move |mut yielder| {
                    match self {
                        $(
                            ::rama_core::combinators::$id::$param(d) => {
                                let mut stream = std::pin::pin!(d.lookup_txt(domain));
                                while let Some(result) = stream.next().await {
                                    yielder.yield_item(result.map_err(ErrorExt::into_opaque_error)).await;
                                }
                            },
                        )+
                    }
                })
            }
        }

        impl<$($param),+> DnsResolver for ::rama_core::combinators::$id<$($param),+>
        where
            $($param: DnsResolver),+,
        {}
    };
}

rama_core::combinators::impl_either!(impl_dns_resolver_either);

#[cfg(test)]
mod tests {
    use rama_core::{
        bytes::Bytes,
        combinators::Either,
        futures::{Stream, stream},
        stream::StreamExt as _,
    };
    use rama_net::address::Domain;

    use std::convert::Infallible;
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::client::resolver::{DnsAddressResolver, DnsResolver, DnsTxtResolver};

    // Mock DNS resolvers for testing
    struct MockResolver1;
    struct MockResolver2;

    macro_rules! impl_mock_dns_resolver {
        (
            $resolver:ident,
            $ipv4:expr,
            $ipv6:expr,
            $txt_map:expr
        ) => {
            impl DnsAddressResolver for $resolver {
                type Error = Infallible;

                fn lookup_ipv4(
                    &self,
                    _domain: Domain,
                ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
                    stream::once(std::future::ready(Ok::<_, Infallible>($ipv4)))
                }

                fn lookup_ipv6(
                    &self,
                    _domain: Domain,
                ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
                    stream::once(std::future::ready(Ok::<_, Infallible>($ipv6)))
                }
            }

            impl DnsTxtResolver for $resolver {
                type Error = Infallible;

                fn lookup_txt(
                    &self,
                    domain: Domain,
                ) -> impl Stream<Item = Result<Bytes, Self::Error>> + Send + '_ {
                    stream::once(std::future::ready(Ok::<_, Infallible>($txt_map(domain))))
                }
            }

            impl DnsResolver for $resolver {}
        };
    }

    impl_mock_dns_resolver!(
        MockResolver1,
        Ipv4Addr::LOCALHOST,
        Ipv6Addr::LOCALHOST,
        |domain: Domain| Bytes::from(domain.as_str().to_lowercase())
    );

    impl_mock_dns_resolver!(
        MockResolver2,
        Ipv4Addr::new(192, 168, 1, 1),
        Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2),
        |domain: Domain| Bytes::from(domain.as_str().to_uppercase())
    );

    #[tokio::test]
    async fn test_either_lookup_txt() {
        let resolver1 = Either::<MockResolver1, MockResolver2>::A(MockResolver1);
        let resolver2 = Either::<MockResolver1, MockResolver2>::B(MockResolver2);

        let result1 = std::pin::pin!(resolver1.lookup_txt(Domain::from_static("abc")))
            .next()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result1, Bytes::from("abc"));

        let result2 = std::pin::pin!(resolver2.lookup_txt(Domain::from_static("abc")))
            .next()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result2, Bytes::from("ABC"));
    }

    #[tokio::test]
    async fn test_either_lookup_ipv4() {
        let resolver1 = Either::<MockResolver1, MockResolver2>::A(MockResolver1);
        let resolver2 = Either::<MockResolver1, MockResolver2>::B(MockResolver2);

        let ip_1 = std::pin::pin!(resolver1.lookup_ipv4(Domain::example()))
            .next()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ip_1, Ipv4Addr::LOCALHOST);

        let ip_2 = std::pin::pin!(resolver2.lookup_ipv4(Domain::example()))
            .next()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ip_2, Ipv4Addr::new(192, 168, 1, 1));
    }

    #[tokio::test]
    async fn test_either_lookup_ipv6() {
        let resolver1 = Either::<MockResolver1, MockResolver2>::A(MockResolver1);
        let resolver2 = Either::<MockResolver1, MockResolver2>::B(MockResolver2);

        let ip_1 = std::pin::pin!(resolver1.lookup_ipv6(Domain::example()))
            .next()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ip_1, Ipv6Addr::LOCALHOST);

        let ip_2 = std::pin::pin!(resolver2.lookup_ipv6(Domain::example()))
            .next()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ip_2, Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2));
    }
}
