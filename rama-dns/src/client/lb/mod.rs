//! DNS-based client-side load balancer.
//!
//! [`DnsLoadBalancer`] resolves a request's target domain, caches the result,
//! refreshes it in the background, and selects one resolved IP per request via
//! a [`DnsIpPicker`] strategy. The selected endpoint is published on
//! the request as a [`ConnectorTarget`] extension so a downstream
//! connectors (tcp, pool...) connects straight to that IP, the original authority
//! stays intact (needed for things like TLS sni).
//!
//! Example use case: rotating GPRC requests between different IPs of
//! a headless service.

use std::{net::IpAddr, sync::Arc, time::Duration};

use crate::client::{GlobalDnsResolver, resolver::DnsAddressResolver};
use rama_core::{
    Layer, Service,
    error::{BoxError, ErrorContext},
    extensions::{Extensions, ExtensionsRef},
    telemetry::tracing,
};
use rama_net::{
    address::{Host, HostWithPort, ProxyAddress},
    client::ConnectorTarget,
    mode::DnsResolveIpMode,
    transport::TryRefIntoTransportContext,
};
use rama_utils::collections::NonEmptyVec;
use tokio::time::Instant;

mod cache;
mod picker;

use self::cache::DnsLbCache;
pub use self::picker::{DnsIpPicker, RandomPicker, RoundRobinPicker};

pub const DEFAULT_LB_REFRESH_AFTER: Duration = Duration::from_secs(30);
pub const DEFAULT_LB_EVICT_AFTER_IDLE: Duration = Duration::from_secs(300);
pub const DEFAULT_LB_EVICT_AFTER_STALE: Duration = Duration::from_secs(300);
pub const DEFAULT_LB_MAX_ENTRIES: u64 = 1024;

/// DNS loadbalancer config used by [`DnsLoadBalancerLayer`] and [`DnsLoadBalancer`].
pub struct DnsLoadBalancerConfig<R = GlobalDnsResolver, P = RoundRobinPicker> {
    /// [`DnsAddressResolver`] that will resolve IPs for the given host
    ///
    /// WARNING: it is possible that the underlying resolver also has caching
    /// of its own. So definetely check the docs and tweak the config if needed
    /// so it works together with the caching logic in this loadbalancer.
    pub resolver: R,
    /// [`DnsIpPicker`] that will decide which IP to use
    pub picker: P,
    /// A cached resolution older than this triggers a background
    /// refresh (the stale value is still served while it refreshes)
    pub refresh_after: Duration,
    /// A cache entry that hasn't been accessed for this long
    /// is dropped from the cache.
    pub evict_after_idle: Duration,
    /// A cache entry whose last successful refresh was longer than this ago is dropped
    ///
    /// Protects against serving stale data when refreshes keep failing.
    pub evict_after_stale: Duration,
    /// Ip resolve mode that will be used by resolver
    pub mode: DnsResolveIpMode,
    /// Max amount of entries that will be stored in cache
    pub max_entries: u64,
}

impl<R: Clone, P: Clone> Clone for DnsLoadBalancerConfig<R, P> {
    fn clone(&self) -> Self {
        Self {
            resolver: self.resolver.clone(),
            picker: self.picker.clone(),
            refresh_after: self.refresh_after,
            evict_after_idle: self.evict_after_idle,
            evict_after_stale: self.evict_after_stale,
            mode: self.mode,
            max_entries: self.max_entries,
        }
    }
}

impl DnsLoadBalancerConfig {
    /// Default config: global DNS resolver, round-robin picker,
    /// [`DEFAULT_LB_REFRESH_AFTER`], [`DEFAULT_LB_EVICT_AFTER_IDLE`],
    /// [`DEFAULT_LB_EVICT_AFTER_STALE`], [`DEFAULT_LB_MAX_ENTRIES`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            resolver: GlobalDnsResolver::new(),
            picker: RoundRobinPicker::new(),
            refresh_after: DEFAULT_LB_REFRESH_AFTER,
            evict_after_idle: DEFAULT_LB_EVICT_AFTER_IDLE,
            evict_after_stale: DEFAULT_LB_EVICT_AFTER_STALE,
            mode: DnsResolveIpMode::default(),
            max_entries: DEFAULT_LB_MAX_ENTRIES,
        }
    }
}

impl Default for DnsLoadBalancerConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl<R, P> DnsLoadBalancerConfig<R, P>
where
    R: DnsAddressResolver + Clone,
    P: DnsIpPicker,
{
    /// Build a config with a custom resolver and picker, defaults for
    /// everything else.
    ///
    /// Combine with struct update syntax to tweak individual fields:
    /// ```ignore
    /// DnsLoadBalancerConfig {
    ///     refresh_after: Duration::from_secs(60),
    ///     ..DnsLoadBalancerConfig::from_parts(my_resolver, my_picker)
    /// }
    /// ```
    pub fn from_parts(resolver: R, picker: P) -> Self {
        Self {
            resolver,
            picker,
            refresh_after: DEFAULT_LB_REFRESH_AFTER,
            evict_after_idle: DEFAULT_LB_EVICT_AFTER_IDLE,
            evict_after_stale: DEFAULT_LB_EVICT_AFTER_STALE,
            mode: DnsResolveIpMode::default(),
            max_entries: DEFAULT_LB_MAX_ENTRIES,
        }
    }
}

// TODO: replace `Arc<NonEmptyVec<_>>` with a dedicated `NonEmptyArcSlice<_>`
// once added to `rama-utils::collections`

#[derive(Clone)]
#[non_exhaustive]
/// The data a [`DnsIpPicker`] sees for a single host
pub struct HostResolution {
    /// Resolved IPs for the host. Guaranteed non-empty by construction
    /// (the cache only stores resolutions that produced at least one IP).
    pub ips: Arc<NonEmptyVec<IpAddr>>,
    /// When the resolution was last fetched
    pub fetched_at: Instant,
    /// Per-host state
    ///
    /// Pickers can stash their own state here, e.g. a round-robin cursor
    pub state: Extensions,
}

/// [`Layer`] producing a [`DnsLoadBalancer`] service from a [`DnsLoadBalancerConfig`].
pub struct DnsLoadBalancerLayer<R = GlobalDnsResolver, P = RoundRobinPicker> {
    config: DnsLoadBalancerConfig<R, P>,
}

impl<R, P> DnsLoadBalancerLayer<R, P> {
    pub fn new(config: DnsLoadBalancerConfig<R, P>) -> Self {
        Self { config }
    }
}

impl Default for DnsLoadBalancerLayer {
    fn default() -> Self {
        Self::new(DnsLoadBalancerConfig::new())
    }
}

impl<S, R, P> Layer<S> for DnsLoadBalancerLayer<R, P>
where
    P: Clone,
    R: DnsAddressResolver + Clone,
{
    type Service = DnsLoadBalancer<S, R, P>;

    fn layer(&self, inner: S) -> Self::Service {
        DnsLoadBalancer::new(inner, self.config.clone())
    }

    fn into_layer(self, inner: S) -> Self::Service {
        DnsLoadBalancer::new(inner, self.config)
    }
}

#[derive(Clone, Debug)]
/// Service that pins each request to an IP picked from the
/// resolved DNS entries
pub struct DnsLoadBalancer<S, R, P> {
    inner: S,
    cache: Arc<DnsLbCache<R>>,
    picker: P,
}

impl<S, R, P> DnsLoadBalancer<S, R, P>
where
    R: DnsAddressResolver + Clone,
{
    pub fn new(inner: S, config: DnsLoadBalancerConfig<R, P>) -> Self {
        Self {
            inner,
            cache: Arc::new(DnsLbCache::new(
                config.resolver,
                config.refresh_after,
                config.evict_after_idle,
                config.evict_after_stale,
                config.mode,
                config.max_entries,
            )),
            picker: config.picker,
        }
    }
}

impl<S, R, P, Input> Service<Input> for DnsLoadBalancer<S, R, P>
where
    S: Service<Input>,
    S::Error: Into<BoxError> + Send + Sync + 'static,
    Input: TryRefIntoTransportContext<Error: Into<BoxError> + Send + Sync + 'static>
        + ExtensionsRef
        + Send
        + 'static,
    R: DnsAddressResolver + Clone,
    P: DnsIpPicker,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        // TODO maybe if a ProxyAddress is configured with dns we want to choose
        // an IP for this. Since this might complicate things I'll keep this open
        // for the future, if a need would arise.
        if input.extensions().get_ref::<ProxyAddress>().is_some() {
            tracing::trace!("dns lb: ProxyAddress set, skipping");
            return self.inner.serve(input).await.map_err(Into::into);
        }

        if input.extensions().get_ref::<ConnectorTarget>().is_some() {
            tracing::trace!("dns lb: ConnectorTarget already set, skipping");
            return self.inner.serve(input).await.map_err(Into::into);
        }

        let ctx = input
            .try_ref_into_transport_ctx()
            .context("dns lb: extract transport context")?;

        let Some(authority) = ctx.host_with_port() else {
            tracing::trace!("dns lb: no authority/port resolvable, skipping");
            return self.inner.serve(input).await.map_err(Into::into);
        };

        match authority.host {
            Host::Name(domain) => {
                let entry = self.cache.lookup(&domain).await?;
                let picked = self.picker.pick(&domain, &entry).context("pick ip")?;
                if let Some(picked) = picked {
                    tracing::trace!(%picked, port = authority.port, %domain, "dns lb: picked ip");
                    input.extensions().insert(ConnectorTarget(HostWithPort::new(
                        Host::Address(picked),
                        authority.port,
                    )));
                } else {
                    tracing::debug!("dns lb: picker returned no address for {domain}");
                }
            }
            Host::Address(_) => {
                tracing::trace!("dns lb, address already configured, skipping");
            }
            Host::Uninterpreted(_) => {
                tracing::trace!("dns lb, uninterpreted host, skipping");
            }
            _ => {
                tracing::trace!("dns lb, unrecognized host, skipping");
            }
        }

        self.inner.serve(input).await.map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    use rama_core::{
        extensions::Extensions,
        futures::{Stream, stream},
    };
    use rama_net::{
        Protocol,
        address::Domain,
        transport::{TransportContext, TransportProtocol},
    };
    use std::{
        convert::Infallible,
        net::{Ipv4Addr, Ipv6Addr},
    };

    #[derive(Clone)]
    struct StaticResolver {
        ips: Vec<Ipv4Addr>,
    }

    impl DnsAddressResolver for StaticResolver {
        type Error = Infallible;

        fn lookup_ipv4(
            &self,
            _: Domain,
        ) -> impl Stream<Item = Result<Ipv4Addr, Self::Error>> + Send + '_ {
            stream::iter(self.ips.clone().into_iter().map(Ok))
        }

        fn lookup_ipv6(
            &self,
            _: Domain,
        ) -> impl Stream<Item = Result<Ipv6Addr, Self::Error>> + Send + '_ {
            stream::empty()
        }
    }

    #[derive(Default)]
    struct FakeRequest {
        extensions: Extensions,
        authority: Option<HostWithPort>,
    }

    impl ExtensionsRef for FakeRequest {
        fn extensions(&self) -> &Extensions {
            &self.extensions
        }
    }

    impl TryRefIntoTransportContext for FakeRequest {
        type Error = BoxError;

        fn try_ref_into_transport_ctx(&self) -> Result<TransportContext, Self::Error> {
            let Some(authority) = self.authority.clone() else {
                return Err("no authority".into());
            };
            Ok(TransportContext {
                protocol: TransportProtocol::Tcp,
                app_protocol: Some(Protocol::HTTPS),
                http_version: None,
                authority: authority.into(),
            })
        }
    }

    #[derive(Default, Clone)]
    struct CapturingInner {
        captured: Arc<Mutex<Vec<Option<HostWithPort>>>>,
    }

    impl Service<FakeRequest> for CapturingInner {
        type Output = ();
        type Error = Infallible;

        async fn serve(&self, input: FakeRequest) -> Result<Self::Output, Self::Error> {
            let target = input
                .extensions()
                .get_ref::<ConnectorTarget>()
                .map(|t| t.0.clone());
            self.captured.lock().push(target);
            Ok(())
        }
    }

    fn req(host: &'static str, port: u16) -> FakeRequest {
        FakeRequest {
            extensions: Extensions::default(),
            authority: Some(HostWithPort::new(
                Host::Name(Domain::from_static(host)),
                port,
            )),
        }
    }

    #[tokio::test]
    async fn round_robin_pins_distinct_ips_across_calls() {
        let resolver = StaticResolver {
            ips: vec![
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 0, 0, 2),
                Ipv4Addr::new(10, 0, 0, 3),
            ],
        };
        let inner = CapturingInner::default();
        let config = DnsLoadBalancerConfig {
            mode: DnsResolveIpMode::SingleIpV4,
            ..DnsLoadBalancerConfig::from_parts(resolver, RoundRobinPicker::new())
        };
        let svc = DnsLoadBalancer::new(inner.clone(), config);

        for _ in 0..6 {
            svc.serve(req("example.com", 443)).await.unwrap();
        }

        let picks: Vec<_> = inner
            .captured
            .lock()
            .iter()
            .map(|hp| hp.as_ref().map(|hp| hp.to_string()))
            .collect();
        assert_eq!(
            picks,
            vec![
                Some("10.0.0.1:443".to_owned()),
                Some("10.0.0.2:443".to_owned()),
                Some("10.0.0.3:443".to_owned()),
                Some("10.0.0.1:443".to_owned()),
                Some("10.0.0.2:443".to_owned()),
                Some("10.0.0.3:443".to_owned()),
            ]
        );
    }

    #[tokio::test]
    async fn existing_connector_target_is_preserved() {
        let resolver = StaticResolver {
            ips: vec![Ipv4Addr::new(10, 0, 0, 1)],
        };
        let inner = CapturingInner::default();
        let config = DnsLoadBalancerConfig {
            mode: DnsResolveIpMode::SingleIpV4,
            ..DnsLoadBalancerConfig::from_parts(resolver, RoundRobinPicker::new())
        };
        let svc = DnsLoadBalancer::new(inner.clone(), config);

        let request = req("example.com", 443);
        let manual = HostWithPort::new(Host::Address(Ipv4Addr::new(192, 168, 1, 1).into()), 8443);
        request.extensions.insert(ConnectorTarget(manual.clone()));

        svc.serve(request).await.unwrap();

        let captured = inner.captured.lock();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].as_ref().unwrap(), &manual);
    }

    #[tokio::test]
    async fn ip_authority_is_skipped() {
        let resolver = StaticResolver {
            ips: vec![Ipv4Addr::new(10, 0, 0, 1)],
        };
        let inner = CapturingInner::default();
        let config = DnsLoadBalancerConfig {
            mode: DnsResolveIpMode::SingleIpV4,
            ..DnsLoadBalancerConfig::from_parts(resolver, RoundRobinPicker::new())
        };
        let svc = DnsLoadBalancer::new(inner.clone(), config);

        let request = FakeRequest {
            extensions: Extensions::default(),
            authority: Some(HostWithPort::new(
                Host::Address(Ipv4Addr::new(127, 0, 0, 1).into()),
                443,
            )),
        };
        svc.serve(request).await.unwrap();

        let captured = inner.captured.lock();
        assert_eq!(captured.len(), 1);
        assert!(captured[0].is_none(), "no ConnectorTarget should be set");
    }
}
