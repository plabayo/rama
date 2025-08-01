use crate::DnsResolver;
use rama_net::address::{Domain, DomainTrie};
use rama_utils::macros::error::static_str_error;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::Deref,
    sync::Arc,
};

#[derive(Debug, Clone)]
/// Wrapper struct that can be used to add
/// dns overwrites to a service Context.
///
/// This is supported by the official `rama`
/// consumers such as [`TcpConnector`].
pub struct DnsOverwrite(Arc<InMemoryDns>);

impl<'de> Deserialize<'de> for DnsOverwrite {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let map = HashMap::<Domain, Vec<IpAddr>>::deserialize(deserializer)?;
        Ok(Self(Arc::new(InMemoryDns {
            trie: map.into_iter().collect(),
        })))
    }
}

impl Serialize for DnsOverwrite {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = HashMap::new();
        for (domain, value) in self.trie.iter() {
            map.insert(domain, value);
        }
        map.serialize(serializer)
    }
}

impl From<InMemoryDns> for DnsOverwrite {
    fn from(value: InMemoryDns) -> Self {
        Self(Arc::new(value))
    }
}

impl AsRef<InMemoryDns> for DnsOverwrite {
    fn as_ref(&self) -> &InMemoryDns {
        self.0.as_ref()
    }
}

impl Deref for DnsOverwrite {
    type Target = InMemoryDns;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

#[derive(Debug, Clone, Default)]
/// in-memory Dns that can be used as a simplistic cache,
/// or wrapped in [`DnsOverwrite`] to indicate dns overwrites.
pub struct InMemoryDns {
    trie: DomainTrie<Vec<IpAddr>>,
}

impl InMemoryDns {
    /// Creates a new empty [`InMemoryDns`] instance.
    #[must_use]
    pub fn new() -> Self {
        Default::default()
    }

    /// Inserts a domain to IP address mapping to the [`InMemoryDns`].
    ///
    /// Existing mappings will be overwritten.
    pub fn insert(&mut self, name: &Domain, addresses: Vec<IpAddr>) -> &mut Self {
        self.trie.insert_domain(name.as_str(), addresses);
        self
    }

    /// Insert an IP address for a domain.
    ///
    /// This method accepts any type that can be converted into an `IpAddr`,
    /// such as `Ipv4Addr` or `Ipv6Addr`.
    pub fn insert_address<A: Into<IpAddr>>(&mut self, name: &Domain, addr: A) -> &mut Self {
        self.insert(name, vec![addr.into()])
    }

    /// Insert multiple IP addresses for a domain.
    ///
    /// This method accepts any iterator which item type can be converted into an `IpAddr`,
    /// such as `Ipv4Addr` or `Ipv6Addr`.
    pub fn insert_addresses<I: IntoIterator<Item: Into<IpAddr>>>(
        &mut self,
        name: &Domain,
        addresses: I,
    ) -> &mut Self {
        self.insert(name, addresses.into_iter().map(Into::into).collect())
    }

    /// Extend the [`InMemoryDns`] with the given mappings.
    ///
    /// Existing mappings will be overwritten.
    pub fn extend(
        &mut self,
        overwrites: impl IntoIterator<Item = (Domain, Vec<IpAddr>)>,
    ) -> &mut Self {
        self.trie.extend(overwrites);
        self
    }
}

static_str_error! {
    #[doc = "domain not mapped in memory"]
    pub struct DomainNotMappedErr;
}

impl DnsResolver for InMemoryDns {
    type Error = DomainNotMappedErr;

    async fn ipv4_lookup(&self, domain: Domain) -> Result<Vec<Ipv4Addr>, Self::Error> {
        self.trie
            .match_exact(domain.as_str())
            .and_then(|ips| {
                let ips: Vec<_> = ips
                    .iter()
                    .filter_map(|ip| match ip {
                        IpAddr::V4(ip) => Some(*ip),
                        IpAddr::V6(_) => None,
                    })
                    .collect();
                (!ips.is_empty()).then_some(ips)
            })
            .ok_or(DomainNotMappedErr)
    }

    async fn ipv6_lookup(&self, domain: Domain) -> Result<Vec<Ipv6Addr>, Self::Error> {
        self.trie
            .match_exact(domain.as_str())
            .and_then(|ips| {
                let ips: Vec<_> = ips
                    .iter()
                    .filter_map(|ip| match ip {
                        IpAddr::V4(_) => None,
                        IpAddr::V6(ip) => Some(*ip),
                    })
                    .collect();
                (!ips.is_empty()).then_some(ips)
            })
            .ok_or(DomainNotMappedErr)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[tokio::test]
    async fn test_dns_overwrite_deserialize() {
        let dns_overwrite: DnsOverwrite =
            serde_html_form::from_str("example.com=127.0.0.1").unwrap();
        assert_eq!(
            dns_overwrite
                .ipv4_lookup(Domain::from_static("example.com"))
                .await
                .unwrap()
                .into_iter()
                .next()
                .unwrap(),
            Ipv4Addr::new(127, 0, 0, 1)
        );
        assert!(
            dns_overwrite
                .ipv6_lookup(Domain::from_static("example.com"))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_dns_overwrite_deserialize_ipv6() {
        let dns_overwrite: DnsOverwrite = serde_html_form::from_str("example.com=::1").unwrap();
        assert!(
            dns_overwrite
                .ipv4_lookup(Domain::from_static("example.com"))
                .await
                .is_err()
        );
        assert_eq!(
            dns_overwrite
                .ipv6_lookup(Domain::from_static("example.com"))
                .await
                .unwrap()
                .into_iter()
                .next()
                .unwrap(),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)
        );
    }

    #[tokio::test]
    async fn test_dns_overwrite_deserialize_multi() {
        let dns_overwrite: DnsOverwrite =
            serde_html_form::from_str("example.com=127.0.0.1&example.com=127.0.0.2").unwrap();
        let mut ipv4_it = dns_overwrite
            .ipv4_lookup(Domain::from_static("example.com"))
            .await
            .unwrap()
            .into_iter();
        assert_eq!(ipv4_it.next().unwrap(), Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(ipv4_it.next().unwrap(), Ipv4Addr::new(127, 0, 0, 2));
        assert!(ipv4_it.next().is_none());
        assert!(
            dns_overwrite
                .ipv6_lookup(Domain::from_static("example.com"))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_dns_overwrite_deserialize_multi_combo() {
        let dns_overwrite: DnsOverwrite =
            serde_html_form::from_str("example.com=127.0.0.1&example.com=::1").unwrap();
        assert_eq!(
            dns_overwrite
                .ipv4_lookup(Domain::from_static("example.com"))
                .await
                .unwrap()
                .into_iter()
                .next()
                .unwrap(),
            Ipv4Addr::new(127, 0, 0, 1)
        );
        assert_eq!(
            dns_overwrite
                .ipv6_lookup(Domain::from_static("example.com"))
                .await
                .unwrap()
                .into_iter()
                .next()
                .unwrap(),
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)
        );
    }

    #[tokio::test]
    async fn test_dns_overwrite_deserialize_not_found() {
        let dns_overwrite: DnsOverwrite =
            serde_html_form::from_str("example.com=127.0.0.1").unwrap();
        assert!(
            dns_overwrite
                .ipv4_lookup(Domain::from_static("plabayo.tech"))
                .await
                .is_err()
        );
        assert!(
            dns_overwrite
                .ipv6_lookup(Domain::from_static("plabayo.tech"))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_dns_overwrite_deserialize_empty() {
        let dns_overwrite: DnsOverwrite = serde_html_form::from_str("").unwrap();
        assert!(
            dns_overwrite
                .ipv4_lookup(Domain::from_static("example.com"))
                .await
                .is_err()
        );
        assert!(
            dns_overwrite
                .ipv6_lookup(Domain::from_static("example.com"))
                .await
                .is_err()
        );
    }
}
