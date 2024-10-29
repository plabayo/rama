use crate::DnsResolver;
use rama_net::address::Domain;
use std::net::{Ipv4Addr, Ipv6Addr};
macro_rules! impl_dns_resolver_either_either {
    ($id:ident, $($param:ident),+ $(,)?) => {
        impl<$($param),+> DnsResolver for ::rama_core::combinators::$id<$($param),+>
        where
            $($param: DnsResolver<Error: Into<::rama_core::error::BoxError>>),+,
        {
            type Error = ::rama_core::error::BoxError;

            async fn ipv4_lookup(
                &self,
                domain: Domain,
            ) -> Result<Vec<Ipv4Addr>, Self::Error>{
                match self {
                    $(
                        ::rama_core::combinators::$id::$param(d) => d.ipv4_lookup(domain)
                            .await
                            .map_err(Into::into),
                    )+
                }
            }

            async fn ipv6_lookup(
                &self,
                domain: Domain,
            ) -> Result<Vec<Ipv6Addr>, Self::Error> {
                match self {
                    $(
                        ::rama_core::combinators::$id::$param(d) => d.ipv6_lookup(domain)
                            .await
                            .map_err(Into::into),
                    )+
                }
            }
        }
    };
}

rama_core::combinators::impl_either!(impl_dns_resolver_either_either);
