use crate::DnsResolver;
use rama_net::address::Domain;
use rama_utils::macros::{error::static_str_error, impl_deref};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

#[derive(Debug, Clone)]
/// Wrapper struct that can be used to add
/// dns overwrites to a service Context.
///
/// This is supported by the official `rama`
/// consumers such as [`TcpConnector`].
pub struct DnsOverwrite(InMemoryDns);

impl_deref! {DnsOverwrite: InMemoryDns}

impl<'de> Deserialize<'de> for DnsOverwrite {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let map = HashMap::<Domain, Vec<IpAddr>>::deserialize(deserializer)?;
        Ok(DnsOverwrite(InMemoryDns {
            map: (!map.is_empty()).then_some(map),
        }))
    }
}

impl Serialize for DnsOverwrite {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self.0.map.as_ref() {
            Some(map) => map.serialize(serializer),
            None => HashMap::<Domain, Vec<IpAddr>>::default().serialize(serializer),
        }
    }
}

#[derive(Debug, Clone)]
/// in-memory Dns that can be used as a simplistic cache,
/// or wrapped in [`DnsOverwrite`] to indicate dns overwrites.
pub struct InMemoryDns {
    map: Option<HashMap<Domain, Vec<IpAddr>>>,
}

impl InMemoryDns {
    /// Inserts a domain to IP address mapping to the [`InMemoryDns`].
    ///
    /// Existing mappings will be overwritten.
    pub fn insert(&mut self, name: Domain, addresses: Vec<IpAddr>) -> &mut Self {
        self.map
            .get_or_insert_with(HashMap::new)
            .insert(name, addresses);
        self
    }

    /// Extend the [`InMemoryDns`] with the given mappings.
    ///
    /// Existing mappings will be overwritten.
    pub fn extend(
        &mut self,
        overwrites: impl IntoIterator<Item = (Domain, Vec<IpAddr>)>,
    ) -> &mut Self {
        self.map.get_or_insert_with(HashMap::new).extend(overwrites);
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
        self.map
            .as_ref()
            .and_then(|m| m.get(&domain))
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
        self.map
            .as_ref()
            .and_then(|m| m.get(&domain))
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
        assert!(dns_overwrite
            .ipv6_lookup(Domain::from_static("example.com"))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_dns_overwrite_deserialize_ipv6() {
        let dns_overwrite: DnsOverwrite = serde_html_form::from_str("example.com=::1").unwrap();
        assert!(dns_overwrite
            .ipv4_lookup(Domain::from_static("example.com"))
            .await
            .is_err());
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
        assert!(dns_overwrite
            .ipv6_lookup(Domain::from_static("example.com"))
            .await
            .is_err());
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
        assert!(dns_overwrite
            .ipv4_lookup(Domain::from_static("plabayo.tech"))
            .await
            .is_err());
        assert!(dns_overwrite
            .ipv6_lookup(Domain::from_static("plabayo.tech"))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_dns_overwrite_deserialize_empty() {
        let dns_overwrite: DnsOverwrite = serde_html_form::from_str("").unwrap();
        assert!(dns_overwrite
            .ipv4_lookup(Domain::from_static("example.com"))
            .await
            .is_err());
        assert!(dns_overwrite
            .ipv6_lookup(Domain::from_static("example.com"))
            .await
            .is_err());
    }
}
