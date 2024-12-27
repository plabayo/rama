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

#[cfg(test)]
mod tests {
    use crate::DnsResolver;
    use rama_core::combinators::Either;
    use rama_net::address::Domain;
    use std::future::Future;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // Mock DNS resolvers for testing
    struct MockResolver1;
    struct MockResolver2;

    impl DnsResolver for MockResolver1 {
        type Error = Box<dyn std::error::Error + Send + Sync>;

        fn ipv4_lookup(
            &self,
            _domain: Domain,
        ) -> impl Future<Output = Result<Vec<Ipv4Addr>, Self::Error>> {
            std::future::ready(Ok(vec![Ipv4Addr::new(127, 0, 0, 1)]))
        }

        fn ipv6_lookup(
            &self,
            _domain: Domain,
        ) -> impl Future<Output = Result<Vec<Ipv6Addr>, Self::Error>> {
            std::future::ready(Ok(vec![Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)]))
        }
    }

    impl DnsResolver for MockResolver2 {
        type Error = Box<dyn std::error::Error + Send + Sync>;

        fn ipv4_lookup(
            &self,
            _domain: Domain,
        ) -> impl Future<Output = Result<Vec<Ipv4Addr>, Self::Error>> + Send + '_ {
            std::future::ready(Ok(vec![Ipv4Addr::new(192, 168, 1, 1)]))
        }

        fn ipv6_lookup(
            &self,
            _domain: Domain,
        ) -> impl Future<Output = Result<Vec<Ipv6Addr>, Self::Error>> + Send + '_ {
            std::future::ready(Ok(vec![Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2)]))
        }
    }

    #[tokio::test]
    async fn test_either_ipv4_lookup() {
        let resolver1 = Either::<MockResolver1, MockResolver2>::A(MockResolver1);
        let resolver2 = Either::<MockResolver1, MockResolver2>::B(MockResolver2);

        let domain = "example.com".parse::<Domain>().unwrap();

        let result1 = resolver1.ipv4_lookup(domain.clone()).await.unwrap();
        assert_eq!(result1, vec![Ipv4Addr::new(127, 0, 0, 1)]);

        let result2 = resolver2.ipv4_lookup(domain).await.unwrap();
        assert_eq!(result2, vec![Ipv4Addr::new(192, 168, 1, 1)]);
    }

    #[tokio::test]
    async fn test_either_ipv6_lookup() {
        let resolver1 = Either::<MockResolver1, MockResolver2>::A(MockResolver1);
        let resolver2 = Either::<MockResolver1, MockResolver2>::B(MockResolver2);

        let domain = "example.com".parse::<Domain>().unwrap();

        let result1 = resolver1.ipv6_lookup(domain.clone()).await.unwrap();
        assert_eq!(result1, vec![Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)]);

        let result2 = resolver2.ipv6_lookup(domain).await.unwrap();
        assert_eq!(result2, vec![Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2)]);
    }
}
