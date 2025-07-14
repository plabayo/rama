//! dns using the [`hickory_resolver`] crate

use crate::DnsResolver;
use hickory_resolver::{
    Name, TokioResolver,
    config::ResolverConfig,
    name_server::TokioConnectionProvider,
    proto::rr::rdata::{A, AAAA},
};
use rama_core::error::{ErrorContext, OpaqueError};
use rama_core::telemetry::tracing;
use rama_net::address::Domain;
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

pub use hickory_resolver::config;

#[derive(Debug, Clone)]
/// [`DnsResolver`] using the [`hickory_resolver`] crate
pub struct HickoryDns(Arc<TokioResolver>);

impl Default for HickoryDns {
    #[cfg(any(unix, target_os = "windows"))]
    fn default() -> Self {
        Self::try_new_system().unwrap_or_else(|_| Self::new_cloudflare())
    }

    #[cfg(not(any(unix, target_os = "windows")))]
    fn default() -> Self {
        Self::new_cloudflare()
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

    #[inline]
    /// Construct a new non-shared [`HickoryDns`] instance using Google's nameservers.
    ///
    /// Creates a default configuration, using `8.8.8.8`, `8.8.4.4` and `2001:4860:4860::8888`,
    /// `2001:4860:4860::8844` (thank you, Google).
    ///
    /// Please see Google's [privacy
    /// statement](https://developers.google.com/speed/public-dns/privacy) for important information
    /// about what they track, many ISP's track similar information in DNS.
    ///
    /// To use the system configuration see: [`Self::new_system`].
    pub fn new_google() -> Self {
        tracing::trace!("create HickoryDns resolver using default google config");
        Self::builder()
            .with_config(ResolverConfig::google())
            .build()
    }

    #[inline]
    /// Construct a new non-shared [`HickoryDns`] instance using Cloudflare's nameservers.
    ///
    /// Creates a default configuration, using `1.1.1.1`, `1.0.0.1` and `2606:4700:4700::1111`, `2606:4700:4700::1001` (thank you, Cloudflare).
    ///
    /// Please see: <https://www.cloudflare.com/dns/>
    ///
    /// To use the system configuration see: [`Self::new_system`].
    pub fn new_cloudflare() -> Self {
        tracing::trace!("create HickoryDns resolver using default cloudflare config");
        Self::builder()
            .with_config(ResolverConfig::cloudflare())
            .build()
    }

    #[inline]
    /// Construct a new non-shared [`HickoryDns`] instance using Quad9's nameservers.
    ///
    /// Creates a configuration, using `9.9.9.9`, `149.112.112.112` and `2620:fe::fe`, `2620:fe::fe:9`,
    /// the "secure" variants of the quad9 settings (thank you, Quad9).
    ///
    /// Please see: <https://www.quad9.net/faq/>
    ///
    /// To use the system configuration see: [`Self::new_system`].
    pub fn new_quad9() -> Self {
        tracing::trace!("create HickoryDns resolver using default quad9 config");
        Self::builder().with_config(ResolverConfig::quad9()).build()
    }

    #[cfg(any(unix, target_os = "windows"))]
    /// Construct a new [`HickoryDns`] with the system configuration.
    ///
    /// This will use `/etc/resolv.conf` on Unix OSes and the registry on Windows.
    pub fn try_new_system() -> Result<Self, OpaqueError> {
        tracing::trace!("try to create HickoryDns resolver using system config");
        Ok(TokioResolver::builder_tokio()
            .context("build async dns resolver with system conf")
            .inspect_err(|err| {
                tracing::debug!("failed to create HickoryDns resolver using system config: {err:?}")
            })?
            .build()
            .into())
    }
}

impl From<TokioResolver> for HickoryDns {
    fn from(value: TokioResolver) -> Self {
        Self(Arc::new(value))
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
        let mut resolver_builder = TokioResolver::builder_with_config(
            self.config
                .unwrap_or_else(config::ResolverConfig::cloudflare),
            TokioConnectionProvider::default(),
        );
        if let Some(options) = self.options {
            *resolver_builder.options_mut() = options;
        }
        HickoryDns(Arc::new(resolver_builder.build()))
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
