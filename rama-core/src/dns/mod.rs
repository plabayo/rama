//! DNS module for Rama.
//!
//! The star of the show is the [`Dns`] struct, which is a DNS resolver for all your lookup needs.
//! It is made available as [`Context::dns`] for your convenience.
//!
//! [`Context::dns`]: crate::Context::dns

use crate::{
    combinators::Either,
    error::{ErrorContext, OpaqueError},
};
use hickory_resolver::{
    config::{ResolverConfig, ResolverOpts},
    proto::rr::rdata::{A, AAAA},
    Name as DnsName, TokioAsyncResolver,
};
use std::{
    collections::HashMap,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// A domain name
pub struct Name(DnsName);

impl Name {
    fn fqdn_from_domain(domain: impl TryIntoName) -> Result<Self, OpaqueError> {
        let mut domain = domain.try_into_name()?;
        domain.0.set_fqdn(true);
        Ok(domain)
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Conversion into a Name
pub trait TryIntoName: Sized {
    /// Convert this into [`Name`]
    fn try_into_name(self) -> Result<Name, OpaqueError>;
}

impl TryIntoName for Name {
    fn try_into_name(self) -> Result<Name, OpaqueError> {
        Ok(self)
    }
}

impl<T> TryIntoName for T
where
    T: TryInto<Name, Error = OpaqueError>,
{
    fn try_into_name(self) -> Result<Name, OpaqueError> {
        self.try_into()
    }
}

impl<'a> TryIntoName for &'a str {
    /// Performs a utf8, IDNA or punycode, translation of the `str` into `Name`
    fn try_into_name(self) -> Result<Name, OpaqueError> {
        DnsName::from_utf8(self)
            .map(Name)
            .context("try to convert &'a str into domain")
    }
}

impl TryIntoName for String {
    /// Performs a utf8, IDNA or punycode, translation of the `String` into `Name`
    fn try_into_name(self) -> Result<Name, OpaqueError> {
        DnsName::from_utf8(self)
            .map(Name)
            .context("try to convert String into domain")
    }
}

impl TryIntoName for &String {
    /// Performs a utf8, IDNA or punycode, translation of the `&String` into `Name`
    fn try_into_name(self) -> Result<Name, OpaqueError> {
        DnsName::from_utf8(self)
            .map(Name)
            .context("try to convert &String into domain")
    }
}

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
    overwrites: Option<HashMap<Name, Vec<IpAddr>>>,
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
    pub fn insert_overwrite(&mut self, name: Name, addresses: Vec<IpAddr>) -> &mut Self {
        self.overwrites
            .get_or_insert_with(HashMap::new)
            .insert(name, addresses);
        self
    }

    /// Extend the overwrites with a new mapping.
    ///
    /// Existing mappings will be overwritten.
    ///
    /// See [`Self::insert_overwrite`] for more information.
    pub fn extend_overwrites(&mut self, overwrites: HashMap<Name, Vec<IpAddr>>) -> &mut Self {
        self.overwrites
            .get_or_insert_with(HashMap::new)
            .extend(overwrites);
        self
    }

    /// Performs a 'A' DNS record lookup.
    pub async fn ipv4_lookup(
        &self,
        name: impl TryIntoName,
    ) -> Result<impl Iterator<Item = Ipv4Addr>, OpaqueError> {
        let name = Name::fqdn_from_domain(name)?;

        if let Some(addresses) = self.overwrites.as_ref().and_then(|cache| cache.get(&name)) {
            return Ok(Either::A(addresses.clone().into_iter().filter_map(
                |ip| match ip {
                    IpAddr::V4(ip) => Some(ip),
                    IpAddr::V6(_) => None,
                },
            )));
        }

        Ok(Either::B(self.ipv4_lookup_trusted(name).await?))
    }

    /// Performs a 'A' DNS record lookup.
    ///
    /// Same as [`Self::ipv4_lookup`] but without consulting
    /// the overwrites first.
    pub async fn ipv4_lookup_trusted(
        &self,
        name: impl TryIntoName,
    ) -> Result<impl Iterator<Item = Ipv4Addr>, OpaqueError> {
        let name = Name::fqdn_from_domain(name)?;

        Ok(self
            .resolver
            .ipv4_lookup(name.0)
            .await
            .context("lookup IPv4 address(es)")?
            .into_iter()
            .map(|A(ip)| ip))
    }

    /// Performs a 'AAAA' DNS record lookup.
    pub async fn ipv6_lookup(
        &self,
        name: impl TryIntoName,
    ) -> Result<impl Iterator<Item = Ipv6Addr>, OpaqueError> {
        let name = Name::fqdn_from_domain(name)?;

        if let Some(addresses) = self.overwrites.as_ref().and_then(|cache| cache.get(&name)) {
            return Ok(Either::A(addresses.clone().into_iter().filter_map(
                |ip| match ip {
                    IpAddr::V4(_) => None,
                    IpAddr::V6(ip) => Some(ip),
                },
            )));
        }

        Ok(Either::B(self.ipv6_lookup_trusted(name).await?))
    }

    /// Performs a 'AAAA' DNS record lookup.
    ///
    /// Same as [`Self::ipv6_lookup`] but without
    /// consulting the overwrites first.
    pub async fn ipv6_lookup_trusted(
        &self,
        name: impl TryIntoName,
    ) -> Result<impl Iterator<Item = Ipv6Addr>, OpaqueError> {
        let name = Name::fqdn_from_domain(name)?;

        Ok(self
            .resolver
            .ipv6_lookup(name.0)
            .await
            .context("lookup IPv6 address(es)")?
            .into_iter()
            .map(|AAAA(ip)| ip))
    }
}
