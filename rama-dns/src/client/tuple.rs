use std::net::{Ipv4Addr, Ipv6Addr};

use rama_core::{
    bytes::Bytes,
    error::{ErrorExt, extra::OpaqueError},
    futures::{Stream, StreamExt as _, async_stream::stream_fn},
};
use rama_net::address::Domain;
use rama_utils::macros::all_the_tuples_no_last_special_case;

use super::resolver::{DnsAddressResolver, DnsResolver, DnsServiceBindingResolver, DnsTxtResolver};
use crate::wire::ServiceBinding;

macro_rules! dns_resolve_tuple_impl {
    ($($ty:ident),+ $(,)?) => {
        impl<$($ty,)+> DnsAddressResolver for ($($ty,)+)where
            $(
                $ty: DnsAddressResolver,
            )+
        {
            type Error = OpaqueError;

            fn lookup_ipv4(
                &self,
                domain: Domain,
            ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
                stream_fn(async move |mut yielder| {
                    let ($($ty,)+) = self;

                    $(
                        let mut stream = std::pin::pin!($ty.lookup_ipv4(domain.clone()));
                        while let Some(result) = stream.next().await {
                            yielder.yield_item(result.map_err(ErrorExt::into_opaque_error)).await;
                        }
                    )+
                })
            }

            async fn lookup_ipv4_first(
                &self,
                domain: Domain,
            ) -> Option<Result<Ipv4Addr, Self::Error>> {
                let ($($ty,)+) = self;
                let mut last_err = None;

                $(
                    if let Some(result) = $ty.lookup_ipv4_first(domain.clone()).await {
                        match result {
                            Ok(addr) => return Some(Ok(addr)),
                            Err(err) => last_err = Some(Err(err.into_opaque_error())),
                        }
                    }
                )+

                last_err
            }

            async fn lookup_ipv4_rand(
                &self,
                domain: Domain,
            ) -> Option<Result<Ipv4Addr, Self::Error>> {
                let ($($ty,)+) = self;
                let mut last_err = None;

                $(
                    if let Some(result) = $ty.lookup_ipv4_rand(domain.clone()).await {
                        match result {
                            Ok(addr) => return Some(Ok(addr)),
                            Err(err) => last_err = Some(Err(err.into_opaque_error())),
                        }
                    }
                )+

                last_err
            }

            fn lookup_ipv6(
                &self,
                domain: Domain,
            ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
                stream_fn(async move |mut yielder| {
                    let ($($ty,)+) = self;

                    $(
                        let mut stream = std::pin::pin!($ty.lookup_ipv6(domain.clone()));
                        while let Some(result) = stream.next().await {
                            yielder.yield_item(result.map_err(ErrorExt::into_opaque_error)).await;
                        }
                    )+
                })
            }

            async fn lookup_ipv6_first(
                &self,
                domain: Domain,
            ) -> Option<Result<Ipv6Addr, Self::Error>> {
                let ($($ty,)+) = self;
                let mut last_err = None;

                $(
                    if let Some(result) = $ty.lookup_ipv6_first(domain.clone()).await {
                        match result {
                            Ok(addr) => return Some(Ok(addr)),
                            Err(err) => last_err = Some(Err(err.into_opaque_error())),
                        }
                    }
                )+

                last_err
            }

            async fn lookup_ipv6_rand(
                &self,
                domain: Domain,
            ) -> Option<Result<Ipv6Addr, Self::Error>> {
                let ($($ty,)+) = self;
                let mut last_err = None;

                $(
                    if let Some(result) = $ty.lookup_ipv6_rand(domain.clone()).await {
                        match result {
                            Ok(addr) => return Some(Ok(addr)),
                            Err(err) => last_err = Some(Err(err.into_opaque_error())),
                        }
                    }
                )+

                last_err
            }
        }

        impl<$($ty,)+> DnsTxtResolver for ($($ty,)+)
        where
            $(
                $ty: DnsTxtResolver,
            )+
        {
            type Error = OpaqueError;

            fn lookup_txt(
                &self,
                domain: Domain,
            ) -> impl Stream<Item = Result<Bytes, Self::Error>> + Send + '_ {
                stream_fn(async move |mut yielder| {
                    let ($($ty,)+) = self;

                    $(
                        let mut stream = std::pin::pin!($ty.lookup_txt(domain.clone()));
                        while let Some(result) = stream.next().await {
                            yielder.yield_item(result.map_err(ErrorExt::into_opaque_error)).await;
                        }
                    )+
                })
            }
        }

        impl<$($ty,)+> DnsServiceBindingResolver for ($($ty,)+)
        where
            $(
                $ty: DnsServiceBindingResolver,
            )+
        {
            type Error = OpaqueError;

            fn lookup_svcb(
                &self,
                domain: Domain,
            ) -> impl Stream<Item = Result<ServiceBinding, Self::Error>> + Send + '_ {
                stream_fn(async move |mut yielder| {
                    let ($($ty,)+) = self;
                    let mut bindings = Vec::new();

                    $(
                        let mut stream = std::pin::pin!($ty.lookup_svcb(domain.clone()));
                        while let Some(result) = stream.next().await {
                            match result {
                                Ok(binding) => bindings.push(binding),
                                Err(err) => {
                                    yielder.yield_item(Err(err.into_opaque_error())).await;
                                    return;
                                }
                            }
                        }
                    )+
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
                    let ($($ty,)+) = self;
                    let mut bindings = Vec::new();

                    $(
                        let mut stream = std::pin::pin!($ty.lookup_https(domain.clone()));
                        while let Some(result) = stream.next().await {
                            match result {
                                Ok(binding) => bindings.push(binding),
                                Err(err) => {
                                    yielder.yield_item(Err(err.into_opaque_error())).await;
                                    return;
                                }
                            }
                        }
                    )+
                    for binding in bindings {
                        yielder.yield_item(Ok(binding)).await;
                    }
                })
            }
        }

        impl<$($ty,)+> DnsResolver for ($($ty,)+)
        where
            $(
                $ty: DnsResolver,
            )+
        {}
    };
}

all_the_tuples_no_last_special_case!(dns_resolve_tuple_impl);

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use rama_core::{
        bytes::Bytes,
        error::{BoxError, BoxErrorExt as _},
        futures::stream,
    };

    use super::*;

    struct BindingResolver(u16, u16);

    impl DnsServiceBindingResolver for BindingResolver {
        type Error = Infallible;

        fn lookup_svcb(
            &self,
            _: Domain,
        ) -> impl Stream<Item = Result<ServiceBinding, Self::Error>> + Send + '_ {
            stream::once(std::future::ready(Ok(binding(self.0))))
        }

        fn lookup_https(
            &self,
            _: Domain,
        ) -> impl Stream<Item = Result<ServiceBinding, Self::Error>> + Send + '_ {
            stream::once(std::future::ready(Ok(binding(self.1))))
        }
    }

    struct FailingResolver;

    impl DnsServiceBindingResolver for FailingResolver {
        type Error = BoxError;

        fn lookup_svcb(
            &self,
            _: Domain,
        ) -> impl Stream<Item = Result<ServiceBinding, Self::Error>> + Send + '_ {
            stream::once(std::future::ready(Err(BoxError::from_static_str(
                "malformed RRset",
            ))))
        }

        fn lookup_https(
            &self,
            _: Domain,
        ) -> impl Stream<Item = Result<ServiceBinding, Self::Error>> + Send + '_ {
            stream::once(std::future::ready(Err(BoxError::from_static_str(
                "malformed RRset",
            ))))
        }
    }

    fn binding(port: u16) -> ServiceBinding {
        let mut rdata = vec![0, 1, 0, 0, 3, 0, 2];
        rdata.extend_from_slice(&port.to_be_bytes());
        ServiceBinding::parse_rdata_bytes(&Bytes::from(rdata)).expect("valid service binding")
    }

    #[tokio::test]
    async fn tuple_flattens_both_service_binding_record_families() {
        let resolvers = (BindingResolver(8443, 443), BindingResolver(9443, 444));
        let svcb: Vec<_> = resolvers
            .lookup_svcb(Domain::example())
            .map(|result| result.expect("success").port().expect("port"))
            .collect()
            .await;
        assert_eq!(svcb, [8443, 9443]);

        let https: Vec<_> = resolvers
            .lookup_https(Domain::example())
            .map(|result| result.expect("success").port().expect("port"))
            .collect()
            .await;
        assert_eq!(https, [443, 444]);
    }

    #[tokio::test]
    async fn tuple_discards_service_bindings_before_an_error() {
        let resolvers = (BindingResolver(8443, 443), FailingResolver);
        let items: Vec<_> = resolvers.lookup_https(Domain::example()).collect().await;
        assert_eq!(items.len(), 1);
        items[0]
            .as_ref()
            .expect_err("malformed RRset must yield an error");
    }
}
