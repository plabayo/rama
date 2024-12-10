use std::net::{Ipv4Addr, Ipv6Addr};

use rama_net::address::Domain;

use crate::DnsResolver;

#[derive(Debug)]
pub struct DnsChainDomainResolveErr<E: 'static> {
    errors: Vec<E>,
}

impl<E: std::fmt::Debug> std::fmt::Display for DnsChainDomainResolveErr<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "domain resolver chain resulted in errors: {:?}",
            self.errors
        )
    }
}

impl<E: std::error::Error + 'static> std::error::Error for DnsChainDomainResolveErr<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.errors.last()
    }
}

macro_rules! dns_resolver_chain_impl {
    () => {
        async fn ipv4_lookup(&self, domain: Domain) -> Result<Vec<Ipv4Addr>, Self::Error> {
            let mut errors = Vec::new();
            for resolver in self {
                match resolver.ipv4_lookup(domain.clone()).await {
                    Ok(ipv4s) => return Ok(ipv4s),
                    Err(err) => errors.push(err),
                }
            }
            Err(DnsChainDomainResolveErr { errors })
        }

        async fn ipv6_lookup(&self, domain: Domain) -> Result<Vec<Ipv6Addr>, Self::Error> {
            let mut errors = Vec::new();
            for resolver in self {
                match resolver.ipv6_lookup(domain.clone()).await {
                    Ok(ipv6s) => return Ok(ipv6s),
                    Err(err) => errors.push(err),
                }
            }
            Err(DnsChainDomainResolveErr { errors })
        }
    };
}

impl<R, E> DnsResolver for Vec<R>
where
    R: DnsResolver<Error = E> + Send,
    E: Send + 'static,
{
    type Error = DnsChainDomainResolveErr<E>;

    dns_resolver_chain_impl!();
}

impl<R, E, const N: usize> DnsResolver for [R; N]
where
    R: DnsResolver<Error = E> + Send,
    E: Send + 'static,
{
    type Error = DnsChainDomainResolveErr<E>;
    dns_resolver_chain_impl!();
}

#[cfg(test)]
mod tests {
    use crate::{DenyAllDns, DnsOverwrite, InMemoryDns};
    use rama_core::combinators::Either;
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[tokio::test]
    async fn test_empty_chain_vec() {
        let v = Vec::<InMemoryDns>::new();
        assert!(v
            .ipv4_lookup(Domain::from_static("plabayo.tech"))
            .await
            .is_err());
        assert!(v
            .ipv6_lookup(Domain::from_static("plabayo.tech"))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_empty_chain_array() {
        let a: [InMemoryDns; 0] = [];
        assert!(a
            .ipv4_lookup(Domain::from_static("plabayo.tech"))
            .await
            .is_err());
        assert!(a
            .ipv6_lookup(Domain::from_static("plabayo.tech"))
            .await
            .is_err());
    }

    // #[tokio::test]
    // async fn test_chain_ok_err_ipv4() {
    //     let v: Vec<Either<_, DenyAllDns>> = vec![
    //         Either::A(serde_html_form::from_str("example.com=127.0.0.1").unwrap()),
    //         Either::B(DenyAllDns::new()),
    //     ];
    //     assert_eq!(
    //         v.ipv4_lookup(Domain::from_static("example.com"))
    //             .await
    //             .unwrap()
    //             .into_iter()
    //             .next()
    //             .unwrap(),
    //         Ipv4Addr::new(127, 0, 0, 1)
    //     );
    //     assert!(v
    //         .ipv6_lookup(Domain::from_static("example.com"))
    //         .await
    //         .is_err());
    // }
}
