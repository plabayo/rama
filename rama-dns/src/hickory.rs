//! dns using the [`hickory_resolver`] crate

use crate::DnsResolver;
use hickory_resolver::{
    proto::rr::rdata::{A, AAAA},
    Name, TokioAsyncResolver,
};
use rama_core::error::{ErrorContext, OpaqueError};
use rama_net::address::Domain;
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

pub use hickory_resolver::config;

#[derive(Debug, Clone)]
/// [`DnsResolver`] using the [`hickory_resolver`] crate
pub struct HickoryDns(Arc<TokioAsyncResolver>);

impl Default for HickoryDns {
    fn default() -> Self {
        Self::builder().build()
    }
}

impl HickoryDns {
    #[inline]
    /// Construct a [`HickoryDnsBuilder`] used to build
    /// a custom [`HickoryDns`] instead of the default [`HickoryDns::new`].
    pub fn builder() -> HickoryDnsBuilder {
        HickoryDnsBuilder::default()
    }

    #[inline]
    /// Construct a new [`HickoryDns`] instance with the [`Default`] setup.
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone, Default)]
/// A [`Builder`] to [`build`][`Self::build`] a [`HickoryDns`] instance.
pub struct HickoryDnsBuilder {
    config: Option<config::ResolverConfig>,
    options: Option<config::ResolverOpts>,
}

impl HickoryDnsBuilder {
    /// Replace `self` with a hickory [`ResolverConfig`][`config::ResolverConfig`] defined.
    pub fn with_config(mut self, config: config::ResolverConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Replace `self` with an [`Option`]al hickory [`ResolverConfig`][`config::ResolverConfig`] defined.
    pub fn maybe_with_config(mut self, config: Option<config::ResolverConfig>) -> Self {
        self.config = config;
        self
    }

    /// Set a hickory [`ResolverConfig`][`config::ResolverConfig`].
    pub fn set_config(&mut self, config: config::ResolverConfig) -> &mut Self {
        self.config = Some(config);
        self
    }

    /// Replace `self` with a hickory [`ResolverOpts`][`config::ResolverOpts`] defined.
    pub fn with_options(mut self, options: config::ResolverOpts) -> Self {
        self.options = Some(options);
        self
    }

    /// Replace `self` with an [`Option`]al hickory [`ResolverOpts`][`config::ResolverOpts`] defined.
    pub fn maybe_with_options(mut self, options: Option<config::ResolverOpts>) -> Self {
        self.options = options;
        self
    }

    /// Set a hickory [`ResolverOpts`][`config::ResolverOpts`].
    pub fn set_options(&mut self, options: config::ResolverOpts) -> &mut Self {
        self.options = Some(options);
        self
    }

    /// Build a [`HickoryDns`] instance, consuming [`self`].
    ///
    /// [`Clone`] the [`HickoryDnsBuilder`] prior to calling this method in case you
    /// still need the builder afterwards.
    pub fn build(self) -> HickoryDns {
        HickoryDns(Arc::new(TokioAsyncResolver::tokio(
            self.config
                .unwrap_or_else(config::ResolverConfig::cloudflare),
            self.options.unwrap_or_default(),
        )))
    }
}

impl DnsResolver for HickoryDns {
    type Error = OpaqueError;

    async fn ipv4_lookup(&self, domain: Domain) -> Result<Vec<Ipv4Addr>, Self::Error> {
        let name = fqdn_from_domain(domain)?;
        Ok(self
            .0
            .ipv4_lookup(name)
            .await
            .context("lookup IPv4 address(es)")?
            .into_iter()
            .map(|A(ip)| ip)
            .collect())
    }

    async fn ipv6_lookup(&self, domain: Domain) -> Result<Vec<Ipv6Addr>, Self::Error> {
        let name = fqdn_from_domain(domain)?;
        Ok(self
            .0
            .ipv6_lookup(name)
            .await
            .context("lookup IPv6 address(es)")?
            .into_iter()
            .map(|AAAA(ip)| ip)
            .collect())
    }
}

fn fqdn_from_domain(domain: Domain) -> Result<Name, OpaqueError> {
    let mut name = Name::from_utf8(domain).context("try to consume a Domain as a Dns Name")?;
    name.set_fqdn(true);
    Ok(name)
}
