use std::net::{Ipv4Addr, Ipv6Addr};

use rama_core::{
    bytes::Bytes,
    error::{ErrorExt, extra::OpaqueError},
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

        #[allow(non_snake_case)]
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

        impl<$($ty,)+> DnsResolver for ($($ty,)+)
        where
            $(
                $ty: DnsResolver,
            )+
        {}
    };
}

all_the_tuples_no_last_special_case!(dns_resolve_tuple_impl);
