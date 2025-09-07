use std::net::{Ipv4Addr, Ipv6Addr};

use rama_core::error::{BoxError, OpaqueError};
use rama_net::address::Domain;

use crate::DnsResolver;

macro_rules! dns_resolver_chain_impl {
    () => {
        async fn ipv4_lookup(&self, domain: Domain) -> Result<Vec<Ipv4Addr>, Self::Error> {
            let mut last_err = None;
            for resolver in self {
                match resolver.ipv4_lookup(domain.clone()).await {
                    Ok(ipv4s) => return Ok(ipv4s),
                    Err(err) => last_err = Some(err.into()),
                }
            }
            Err(last_err.unwrap_or_else(|| {
                OpaqueError::from_display("unknown dns error (erorr missing)").into_boxed()
            }))
        }

        async fn ipv6_lookup(&self, domain: Domain) -> Result<Vec<Ipv6Addr>, Self::Error> {
            let mut last_err = None;
            for resolver in self {
                match resolver.ipv6_lookup(domain.clone()).await {
                    Ok(ipv6s) => return Ok(ipv6s),
                    Err(err) => last_err = Some(err.into()),
                }
            }
            Err(last_err.unwrap_or_else(|| {
                OpaqueError::from_display("unknown dns error (erorr missing)").into_boxed()
            }))
        }
    };
}

impl<R> DnsResolver for Vec<R>
where
    R: DnsResolver + Send,
{
    type Error = BoxError;

    dns_resolver_chain_impl!();
}

impl<R, const N: usize> DnsResolver for [R; N]
where
    R: DnsResolver + Send,
{
    type Error = BoxError;

    dns_resolver_chain_impl!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DenyAllDns, InMemoryDns};
    use rama_core::combinators::Either;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[tokio::test]
    async fn test_empty_chain_vec() {
        let v = Vec::<InMemoryDns>::new();
        assert!(
            v.ipv4_lookup(Domain::from_static("plabayo.tech"))
                .await
                .is_err()
        );
        assert!(
            v.ipv6_lookup(Domain::from_static("plabayo.tech"))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_empty_chain_array() {
        let a: [InMemoryDns; 0] = [];
        assert!(
            a.ipv4_lookup(Domain::from_static("plabayo.tech"))
                .await
                .is_err()
        );
        assert!(
            a.ipv6_lookup(Domain::from_static("plabayo.tech"))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_chain_ok_err_ipv4() {
        let mut dns = InMemoryDns::new();
        dns.insert_address(
            &Domain::from_static("example.com"),
            Ipv4Addr::new(127, 0, 0, 1),
        );
        let v = vec![Either::A(dns), Either::B(DenyAllDns::new())];

        let result = v
            .ipv4_lookup(Domain::from_static("example.com"))
            .await
            .unwrap();
        assert_eq!(result[0], Ipv4Addr::new(127, 0, 0, 1));
    }

    #[tokio::test]
    async fn test_chain_err_ok_ipv6() {
        let mut dns = InMemoryDns::new();
        dns.insert_address(
            &Domain::from_static("example.com"),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
        );
        let v = vec![Either::B(DenyAllDns::new()), Either::A(dns)];

        let result = v
            .ipv6_lookup(Domain::from_static("example.com"))
            .await
            .unwrap();
        assert_eq!(result[0], Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
    }

    #[tokio::test]
    async fn test_chain_ok_ok_ipv6() {
        let mut dns1 = InMemoryDns::new();
        let mut dns2 = InMemoryDns::new();
        dns1.insert_address(
            &Domain::from_static("example.com"),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
        );
        dns2.insert_address(
            &Domain::from_static("example.com"),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2),
        );

        let v = vec![dns1, dns2];
        let result = v
            .ipv6_lookup(Domain::from_static("example.com"))
            .await
            .unwrap();
        // Should return the first successful result
        assert_eq!(result[0], Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
    }

    #[tokio::test]
    async fn test_chain_err_err_ok_ipv4() {
        let mut dns = InMemoryDns::new();
        dns.insert_address(
            &Domain::from_static("example.com"),
            Ipv4Addr::new(127, 0, 0, 1),
        );

        let v = vec![
            Either::B(DenyAllDns::new()),
            Either::B(DenyAllDns::new()),
            Either::A(dns),
        ];
        let result = v
            .ipv4_lookup(Domain::from_static("example.com"))
            .await
            .unwrap();
        assert_eq!(result[0], Ipv4Addr::new(127, 0, 0, 1));
    }

    #[tokio::test]
    async fn test_chain_err_err_ipv4() {
        let v = vec![DenyAllDns::new(), DenyAllDns::new()];
        assert!(
            v.ipv4_lookup(Domain::from_static("example.com"))
                .await
                .is_err()
        );
    }
}
