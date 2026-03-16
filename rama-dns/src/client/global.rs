use rama_core::{bytes::Bytes, error::extra::OpaqueError, futures::Stream, telemetry::tracing};
use rama_net::address::Domain;

use crate::client::{
    HickoryDnsResolver,
    resolver::{BoxDnsResolver, DnsAddressResolver, DnsResolver, DnsTxtResolver},
};
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::OnceLock,
};

static GLOBAL_DNS_RESOLVER: OnceLock<BoxDnsResolver> = OnceLock::new();

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct GlobalDnsResolver;

impl GlobalDnsResolver {
    #[inline(always)]
    /// Create a new [`GlobalDnsResolver`].
    ///
    /// This has no cost.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl DnsAddressResolver for GlobalDnsResolver {
    type Error = OpaqueError;

    #[inline(always)]
    fn lookup_ipv4(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
        let resolver = global_dns_resolver();
        resolver.lookup_ipv4(domain)
    }

    fn lookup_ipv4_first(
        &self,
        domain: Domain,
    ) -> impl Future<Output = Option<Result<Ipv4Addr, Self::Error>>> + Send + '_ {
        let resolver = global_dns_resolver();
        resolver.lookup_ipv4_first(domain)
    }

    fn lookup_ipv4_rand(
        &self,
        domain: Domain,
    ) -> impl Future<Output = Option<Result<Ipv4Addr, Self::Error>>> + Send + '_ {
        let resolver = global_dns_resolver();
        resolver.lookup_ipv4_rand(domain)
    }

    #[inline(always)]
    fn lookup_ipv6(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
        let resolver = global_dns_resolver();
        resolver.lookup_ipv6(domain)
    }

    fn lookup_ipv6_first(
        &self,
        domain: Domain,
    ) -> impl Future<Output = Option<Result<Ipv6Addr, Self::Error>>> + Send + '_ {
        let resolver = global_dns_resolver();
        resolver.lookup_ipv6_first(domain)
    }

    fn lookup_ipv6_rand(
        &self,
        domain: Domain,
    ) -> impl Future<Output = Option<Result<Ipv6Addr, Self::Error>>> + Send + '_ {
        let resolver = global_dns_resolver();
        resolver.lookup_ipv6_rand(domain)
    }
}

impl DnsTxtResolver for GlobalDnsResolver {
    type Error = OpaqueError;

    #[inline(always)]
    fn lookup_txt(
        &self,
        domain: Domain,
    ) -> impl Stream<Item = Result<Bytes, Self::Error>> + Send + '_ {
        let resolver = global_dns_resolver();
        resolver.lookup_txt(domain)
    }
}

impl DnsResolver for GlobalDnsResolver {
    fn into_box_dns_resolver(self) -> BoxDnsResolver
    where
        Self: Sized,
    {
        global_dns_resolver().clone()
    }
}

/// Get the global [`DnsResolver`].
///
/// This is a shared once-time init dns resolver used by default in rama.
/// By default it is created in a lazy fashion using [`HickoryDns::default`].
///
/// Use [`init_global_dns_resolver`] or [`try_init_global_dns_resolver`] to overwrite
/// the global [`DnsResolver`]. This has to be done as early as possible,
/// as it fails if the global resolver was already initialised (e.g. using the default).
fn global_dns_resolver() -> &'static BoxDnsResolver {
    GLOBAL_DNS_RESOLVER.get_or_init(|| {
        tracing::debug!("no global dns resolver configured by user: init (default) global (hickory) DNS resolver");
        let resolver = HickoryDnsResolver::default();

        if let Ok(path) = std::env::var(ENV_NAME_RAMA_DEBUG_HICKORY_DNS_RESOLVER_CONFIG) {
            tracing::debug!("spawn background task to write auto-init global (hickory) DNS resolver config to: {path}");
            tokio::task::spawn(try_to_write_hickory_dns_resolver_config_for_diagnostics(resolver.clone(), path));
        }

        resolver.into_box_dns_resolver()
    })
}

async fn try_to_write_hickory_dns_resolver_config_for_diagnostics(
    resolver: HickoryDnsResolver,
    path: String,
) {
    let config = resolver.config();
    let v = match serde_json::to_vec_pretty(&config) {
        Ok(v) => v,
        Err(err) => {
            tracing::error!(
                "failed to encode (HickoryDns global) config with (json) serde (report bug please): {err}"
            );
            return;
        }
    };
    if let Err(err) = tokio::fs::write(&path, v).await {
        tracing::error!("failed to write json-encoded (HickoryDns global) config to {path}: {err}");
    } else {
        tracing::debug!("wrote json-encoded (HickoryDns global) config to {path}");
    }
}

/// Environment name that can be set by user of software built with Rama to write
/// the used hickory DNS resolver config/opts to the given file as json.
///
/// This can be useful to inspect why DNS might not be resolved correctly.
///
/// It is only used if the global dns resolver is used as the global dns resolver,
/// with none set by the user explicitly.
///
/// Use [`HickoryDnsResolver::config`] if you wish to write or use
/// that same config for your own created HickoryDnsResolver's.
pub const ENV_NAME_RAMA_DEBUG_HICKORY_DNS_RESOLVER_CONFIG: &str =
    "RAMA_DEBUG_HICKORY_DNS_RESOLVER_CONFIG";

#[inline(always)]
/// Initialises the global [`DnsResolver`].
///
/// # Panics
///
/// Panics in case the global [`DnsResolver`] was already set.
/// Use [`try_init_global_dns_resolver`] in case you wish to handle this more gracefully.
pub fn init_global_dns_resolver(resolver: impl DnsResolver) {
    if try_init_global_dns_resolver(resolver).is_err() {
        panic!("global DNS resolver already set");
    }
}

/// Tries to initialise the global [`DnsResolver`].
///
/// This returns the input [`DnsResolver`] boxed but useless back,
/// in case the global [`DnsResolver`] was already set.
///
/// You can use [`init_global_dns_resolver`] should you want to panic on failure instead.
pub fn try_init_global_dns_resolver(resolver: impl DnsResolver) -> Result<(), BoxDnsResolver> {
    GLOBAL_DNS_RESOLVER.set(resolver.into_box_dns_resolver())
}
