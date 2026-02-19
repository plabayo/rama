use std::net::{Ipv4Addr, Ipv6Addr};

use rama_core::{
    bytes::Bytes,
    error::BoxError,
    futures::{Stream, StreamExt as _, async_stream::stream_fn},
};
use rama_net::address::Domain;
use rama_utils::macros::all_the_tuples_no_last_special_case;

use super::resolver::{DnsAddressResolver, DnsResolver, DnsTxtResolver};

macro_rules! dns_resolve_tuple_impl {
    ($($ty:ident),+ $(,)?) => {
        #[allow(non_snake_case)]
        impl<$($ty,)+> DnsAddressResolver for ($($ty,)+)where
            $(
                $ty: DnsAddressResolver,
            )+
        {
            type Error = BoxError;

            fn lookup_ipv4(
                &self,
                domain: Domain,
            ) -> impl Stream<Item = Result<Ipv4Addr, BoxError>> + Send + '_ {
                stream_fn(async move |mut yielder| {
                    let ($($ty,)+) = self;

                    $(
                        let mut stream = std::pin::pin!($ty.lookup_ipv4(domain.clone()));
                        while let Some(result) = stream.next().await {
                            yielder.yield_item(result.map_err(Into::into)).await;
                        }
                    )+
                })
            }

            fn lookup_ipv6(
                &self,
                domain: Domain,
            ) -> impl Stream<Item = Result<Ipv6Addr, BoxError>> + Send + '_ {
                stream_fn(async move |mut yielder| {
                    let ($($ty,)+) = self;

                    $(
                        let mut stream = std::pin::pin!($ty.lookup_ipv6(domain.clone()));
                        while let Some(result) = stream.next().await {
                            yielder.yield_item(result.map_err(Into::into)).await;
                        }
                    )+
                })
            }
        }

        #[allow(non_snake_case)]
        impl<$($ty,)+> DnsTxtResolver for ($($ty,)+)
        where
            $(
                $ty: DnsTxtResolver,
            )+
        {
            type Error = BoxError;

            fn lookup_txt(
                &self,
                domain: Domain,
            ) -> impl Stream<Item = Result<Bytes, BoxError>> + Send + '_ {
                stream_fn(async move |mut yielder| {
                    let ($($ty,)+) = self;

                    $(
                        let mut stream = std::pin::pin!($ty.lookup_txt(domain.clone()));
                        while let Some(result) = stream.next().await {
                            yielder.yield_item(result.map_err(Into::into)).await;
                        }
                    )+
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
