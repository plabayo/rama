//! dns using the [`hickory_resolver`] crate

use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

pub use hickory_resolver as resolver;
use hickory_resolver::{
    Name, TokioResolver,
    config::ResolverConfig,
    name_server::TokioConnectionProvider,
    proto::rr::rdata::{A, AAAA},
};

use rama_core::{
    bytes::Bytes,
    error::{BoxError, ErrorContext},
    futures::Stream,
};
use rama_core::{futures::async_stream::stream_fn, telemetry::tracing};
use rama_net::address::Domain;
use rama_utils::macros::generate_set_and_with;

use super::resolver::{DnsAddressResolver, DnsResolver, DnsTxtResolver};

#[derive(Debug, Clone)]
/// DNS Resolver using the [`hickory_resolver`] crate
pub struct HickoryDnsResolver(Arc<TokioResolver>);

impl Default for HickoryDnsResolver {
    #[cfg(any(target_family = "unix", target_os = "windows"))]
    fn default() -> Self {
        Self::try_new_system().unwrap_or_else(|err| {
            tracing::warn!(
                "fail to create system HickoryDnsResolver client: fallback to cloudflare: {err}"
            );
            Self::new_cloudflare()
        })
    }

    #[cfg(not(any(target_family = "unix", target_os = "windows")))]
    fn default() -> Self {
        Self::new_cloudflare()
    }
}

impl HickoryDnsResolver {
    #[inline]
    /// Construct a [`HickoryDnsBuilder`] used to build
    /// a custom [`HickoryDnsResolver`] instead of the default [`HickoryDnsResolver::new`].
    #[must_use]
    pub fn builder() -> HickoryDnsBuilder {
        HickoryDnsBuilder::default()
    }

    #[inline]
    /// Construct a new [`HickoryDnsResolver`] instance with the [`Default`] setup.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    /// Construct a new non-shared [`HickoryDnsResolver`] instance using Google's nameservers.
    ///
    /// Creates a default configuration, using `8.8.8.8`, `8.8.4.4` and `2001:4860:4860::8888`,
    /// `2001:4860:4860::8844` (thank you, Google).
    ///
    /// Please see Google's [privacy
    /// statement](https://developers.google.com/speed/public-dns/privacy) for important information
    /// about what they track, many ISP's track similar information in DNS.
    ///
    /// To use the system configuration see: [`Self::try_new_system`].
    pub fn new_google() -> Self {
        tracing::trace!("create HickoryDnsResolver resolver using default google config");
        Self::builder()
            .with_config(ResolverConfig::google())
            .build()
    }

    #[inline]
    /// Construct a new non-shared [`HickoryDnsResolver`] instance using Cloudflare's nameservers.
    ///
    /// Creates a default configuration, using `1.1.1.1`, `1.0.0.1` and `2606:4700:4700::1111`, `2606:4700:4700::1001` (thank you, Cloudflare).
    ///
    /// Please see: <https://www.cloudflare.com/dns/>
    ///
    /// To use the system configuration see: [`Self::try_new_system`].
    pub fn new_cloudflare() -> Self {
        tracing::trace!("create HickoryDnsResolver resolver using default cloudflare config");
        Self::builder()
            .with_config(ResolverConfig::cloudflare())
            .build()
    }

    #[inline]
    /// Construct a new non-shared [`HickoryDnsResolver`] instance using Quad9's nameservers.
    ///
    /// Creates a configuration, using `9.9.9.9`, `149.112.112.112` and `2620:fe::fe`, `2620:fe::fe:9`,
    /// the "secure" variants of the quad9 settings (thank you, Quad9).
    ///
    /// Please see: <https://www.quad9.net/faq/>
    ///
    /// To use the system configuration see: [`Self::try_new_system`].
    pub fn new_quad9() -> Self {
        tracing::trace!("create HickoryDnsResolver resolver using default quad9 config");
        Self::builder().with_config(ResolverConfig::quad9()).build()
    }

    #[cfg(any(target_family = "unix", target_os = "windows"))]
    /// Construct a new [`HickoryDnsResolver`] with the system configuration.
    ///
    /// This will use `/etc/resolv.conf` on Unix OSes and the registry on Windows.
    pub fn try_new_system() -> Result<Self, BoxError> {
        tracing::trace!("try to create HickoryDnsResolver resolver using system config");
        Ok(TokioResolver::builder_tokio()
            .context("build async dns resolver with system conf")
            .inspect_err(|err| {
                tracing::debug!(
                    "failed to create HickoryDnsResolver resolver using system config: {err:?}"
                )
            })?
            .build()
            .into())
    }
}

impl From<TokioResolver> for HickoryDnsResolver {
    fn from(value: TokioResolver) -> Self {
        Self(Arc::new(value))
    }
}

#[derive(Debug, Clone, Default)]
/// Used to [`build`][`Self::build`] a [`HickoryDnsResolver`] instance.
pub struct HickoryDnsBuilder {
    config: Option<self::resolver::config::ResolverConfig>,
    options: Option<self::resolver::config::ResolverOpts>,
}

impl HickoryDnsBuilder {
    generate_set_and_with! {
        /// Define the [`ResolverConfig`][`config::ResolverConfig`] used.
        pub fn config(mut self, config: Option<self::resolver::config::ResolverConfig>) -> Self {
            self.config = config;
            self
        }
    }

    generate_set_and_with! {
        /// Define the [`ResolverOpts`][`config::ResolverOpts`] used.
        #[must_use]
        pub fn options(mut self, options: Option<self::resolver::config::ResolverOpts>) -> Self {
            self.options = options;
            self
        }
    }

    /// Build a [`HickoryDnsResolver`] instance, consuming [`self`].
    ///
    /// [`Clone`] the [`HickoryDnsBuilder`] prior to calling this method in case you
    /// still need the builder afterwards.
    pub fn build(self) -> HickoryDnsResolver {
        let mut resolver_builder = TokioResolver::builder_with_config(
            self.config
                .unwrap_or_else(self::resolver::config::ResolverConfig::cloudflare),
            TokioConnectionProvider::default(),
        );
        if let Some(options) = self.options {
            *resolver_builder.options_mut() = options;
        }
        HickoryDnsResolver(Arc::new(resolver_builder.build()))
    }
}

macro_rules! try_or_yield {
    ($yielder:ident, $expr:expr, $ctx:literal $(,$field_name:literal = $field_value:ident)*) => {
        match $expr {
            Ok(v) => v,
            Err(err) => {
                $yielder.yield_item(Err(err).context($ctx)$(.context_debug_field($field_name, $field_value))*).await;
                return;
            }
        }
    };
}

impl DnsAddressResolver for HickoryDnsResolver {
    type Error = BoxError;

    fn lookup_ipv4(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, BoxError>> + Send + '_ {
        stream_fn(async |mut yielder| {
            let name = try_or_yield!(
                yielder,
                name_from_domain(domain),
                "lookup_ipv4: create name from domain"
            );
            let lookup = try_or_yield!(
                yielder,
                self.0.ipv4_lookup(name.clone()).await,
                "resolve A record(s) for name",
                "name" = name
            );
            for A(ip) in lookup {
                yielder.yield_item(Ok(ip)).await;
            }
        })
    }

    fn lookup_ipv6(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, BoxError>> + Send + '_ {
        stream_fn(async |mut yielder| {
            let name = try_or_yield!(
                yielder,
                name_from_domain(domain),
                "lookup_ipv6: reate name from domain"
            );
            let lookup = try_or_yield!(
                yielder,
                self.0.ipv6_lookup(name.clone()).await,
                "resolve AAAA record(s) for name",
                "name" = name
            );
            for AAAA(ip) in lookup {
                yielder.yield_item(Ok(ip)).await;
            }
        })
    }
}

impl DnsTxtResolver for HickoryDnsResolver {
    type Error = BoxError;

    fn lookup_txt(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<rama_core::bytes::Bytes, Self::Error>> + Send + '_ {
        stream_fn(async |mut yielder| {
            let name = try_or_yield!(
                yielder,
                name_from_domain(domain),
                "lookup_txt: create name from domain"
            );
            let lookup = try_or_yield!(
                yielder,
                self.0.txt_lookup(name.clone()).await,
                "resolve TXT record(s) for name",
                "name" = name
            );
            for txt in lookup {
                for part in txt.txt_data() {
                    yielder.yield_item(Ok(Bytes::from(part.clone()))).await;
                }
            }
        })
    }
}

impl DnsResolver for HickoryDnsResolver {}

fn name_from_domain(domain: Domain) -> Result<Name, BoxError> {
    let is_fqdn = domain.is_fqdn();
    let mut name = Name::from_utf8(domain).context("try to consume a Domain as a Dns Name")?;
    name.set_fqdn(is_fqdn);
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_box_hickory_dns_resolver() {
        let _ = HickoryDnsResolver::default().into_box_dns_resolver();
    }
}
