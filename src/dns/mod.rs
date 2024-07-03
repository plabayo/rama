//! DNS module for Rama.
//!
//! The star of the show is the [`Dns`] struct, which is a DNS resolver for all your lookup needs.
//! It is made available as [`Context::dns`] for your convenience.
//!
//! [`Context::dns`]: crate::service::Context::dns

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use hickory_resolver::{
    config::{ResolverConfig, ResolverOpts},
    proto::rr::rdata::{A, AAAA},
    IntoName, Name, TokioAsyncResolver,
};

use crate::{
    error::{ErrorContext, OpaqueError},
    net::address::Domain,
    utils::combinators::Either,
};

pub mod layer;

#[derive(Debug, Clone)]
/// Dns Resolver for all your lookup needs.
///
/// We try to keep this module as minimal as possible, and only expose the
/// necessary functions to perform DNS lookups in function of Rama.
///
/// Please [open an issue](https://github.com/plabayo/rama/issues/new)
/// with clear goals and motivation if you need more functionality.
pub struct Dns {
    resolver: Arc<TokioAsyncResolver>,
    overwrites: Option<HashMap<Domain, Vec<IpAddr>>>,
}

impl Default for Dns {
    fn default() -> Self {
        Self {
            resolver: Arc::new(TokioAsyncResolver::tokio(
                // TODO: make this configurable in a `DnsBuilder`,
                // if we ever get a feature request for this
                ResolverConfig::cloudflare(),
                // TODO: make this configurable in a `DnsBuilder`,
                // if we ever get a feature request for this
                ResolverOpts::default(),
            )),
            overwrites: None,
        }
    }
}

impl Dns {
    /// Inserts a domain to IP address mapping to overwrite the DNS lookup.
    ///
    /// Existing mappings will be overwritten.
    ///
    /// Note that this impacts both [`Self::ipv4_lookup`] and [`Self::ipv6_lookup`],
    /// meaning that no Ipv6 addresses will be returned for the domain.
    pub fn insert_overwrite(&mut self, domain: Domain, addresses: Vec<IpAddr>) -> &mut Self {
        self.overwrites
            .get_or_insert_with(HashMap::new)
            .insert(domain, addresses);
        self
    }

    /// Extend the overwrites with a new mapping.
    ///
    /// Existing mappings will be overwritten.
    ///
    /// See [`Self::insert_overwrite`] for more information.
    pub fn extend_overwrites(&mut self, overwrites: HashMap<Domain, Vec<IpAddr>>) -> &mut Self {
        self.overwrites
            .get_or_insert_with(HashMap::new)
            .extend(overwrites);
        self
    }

    /// Performs a 'A' DNS record lookup.
    pub async fn ipv4_lookup(
        &self,
        domain: Domain,
    ) -> Result<impl Iterator<Item = Ipv4Addr>, OpaqueError> {
        if let Some(addresses) = self
            .overwrites
            .as_ref()
            .and_then(|cache| cache.get(&domain))
        {
            return Ok(Either::A(addresses.clone().into_iter().filter_map(
                |ip| match ip {
                    IpAddr::V4(ip) => Some(ip),
                    IpAddr::V6(_) => None,
                },
            )));
        }
        Ok(Either::B(self.ipv4_lookup_trusted(domain).await?))
    }

    /// Performs a 'A' DNS record lookup.
    ///
    /// Same as [`Self::ipv4_lookup`] but without consulting
    /// the overwrites first.
    pub async fn ipv4_lookup_trusted(
        &self,
        domain: Domain,
    ) -> Result<impl Iterator<Item = Ipv4Addr>, OpaqueError> {
        Ok(self
            .resolver
            .ipv4_lookup(domain_str_as_fqdn(domain)?)
            .await
            .context("lookup IPv4 address(es)")?
            .into_iter()
            .map(|A(ip)| ip))
    }

    /// Performs a 'AAAA' DNS record lookup.
    pub async fn ipv6_lookup(
        &self,
        domain: Domain,
    ) -> Result<impl Iterator<Item = Ipv6Addr>, OpaqueError> {
        if let Some(addresses) = self
            .overwrites
            .as_ref()
            .and_then(|cache| cache.get(&domain))
        {
            return Ok(Either::A(addresses.clone().into_iter().filter_map(
                |ip| match ip {
                    IpAddr::V4(_) => None,
                    IpAddr::V6(ip) => Some(ip),
                },
            )));
        }
        Ok(Either::B(self.ipv6_lookup_trusted(domain).await?))
    }

    /// Performs a 'AAAA' DNS record lookup.
    ///
    /// Same as [`Self::ipv6_lookup`] but without
    /// consulting the overwrites first.
    pub async fn ipv6_lookup_trusted(
        &self,
        domain: Domain,
    ) -> Result<impl Iterator<Item = Ipv6Addr>, OpaqueError> {
        Ok(self
            .resolver
            .ipv6_lookup(domain_str_as_fqdn(domain)?)
            .await
            .context("lookup IPv6 address(es)")?
            .into_iter()
            .map(|AAAA(ip)| ip))
    }
}

fn domain_str_as_fqdn(domain: Domain) -> Result<Name, OpaqueError> {
    let mut name = domain
        .to_string()
        .into_name()
        .context("turn domain into FQDN")?;
    name.set_fqdn(true);
    Ok(name)
}
