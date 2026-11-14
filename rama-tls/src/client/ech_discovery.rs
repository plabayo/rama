//! Optional ECH discovery for a fixed destination, before opening its transport.
//!
//! This adapter never changes the endpoint or negotiates an HTTP service. It
//! consumes compatible records for the selected target, including a root
//! ServiceMode target at its CNAME owner when no HTTPS AliasMode was followed
//! and the port is unchanged. This binds the service's configuration to the
//! existing endpoint; it does not claim that address and HTTPS CNAME chains match. Stacks selecting
//! among HTTPS endpoints should use the shared lookup directly or the HTTP
//! discovery layer, then supply `TargetEchConfig` to their TLS backend.
use super::{EchRequirement, TlsClientConfig, TlsEncryptedClientHello, target_ech_config};
use rama_core::{
    Layer, Service,
    error::{BoxError, BoxErrorExt as _},
};
use rama_dns::client::{
    GlobalDnsResolver, HttpsServiceBindingLookup, resolver::DnsServiceBindingResolver,
};
use rama_net::{
    ConnectorTargetInputExt,
    client::ProxyRouteContext,
    tls::{ApplicationProtocol, TargetEchConfig, TargetEchServiceBinding, TlsAlpn},
};
use rama_utils::macros::generate_set_and_with;
use std::time::Duration;

/// Discover ECH for an already selected physical endpoint without adding a cache.
#[derive(Debug, Clone)]
pub struct TargetEchConfigLayer<R = GlobalDnsResolver> {
    lookup: HttpsServiceBindingLookup<R>,
    tls: TlsClientConfig,
    capable: bool,
    proxy_discovery: bool,
    timeout: Duration,
}

impl Default for TargetEchConfigLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl TargetEchConfigLayer {
    /// Use the global resolver. Declare backend support with `with_capable`.
    pub fn new() -> Self {
        Self {
            lookup: HttpsServiceBindingLookup::new(),
            tls: TlsClientConfig::default(),
            capable: false,
            proxy_discovery: false,
            timeout: Duration::from_secs(5),
        }
    }
}

impl<R> TargetEchConfigLayer<R> {
    /// Use a custom HTTPS resolver. Address resolution remains with the transport.
    pub fn with_resolver<T>(self, resolver: T) -> TargetEchConfigLayer<T> {
        TargetEchConfigLayer {
            lookup: self.lookup.with_resolver(resolver),
            tls: self.tls,
            capable: self.capable,
            proxy_discovery: self.proxy_discovery,
            timeout: self.timeout,
        }
    }

    generate_set_and_with! {
        /// Connector defaults used when resolving request ECH intent and ALPN.
        pub fn tls(mut self, tls: TlsClientConfig) -> Self {
            self.tls = tls;
            self
        }
    }

    generate_set_and_with! {
        /// Declare real ECH support in the inner TLS backend (default false).
        pub fn capable(mut self, capable: bool) -> Self {
            self.capable = capable;
            self
        }
    }

    generate_set_and_with! {
        /// Permit this resolver to learn names delegated to a proxy (default false).
        pub fn proxy_discovery(mut self, allowed: bool) -> Self {
            self.proxy_discovery = allowed;
            self
        }
    }

    generate_set_and_with! {
        /// Bound HTTPS discovery before invoking the inner service.
        pub fn timeout(mut self, timeout: Duration) -> Self {
            self.timeout = timeout;
            self
        }
    }
}

impl<S, R: Clone> Layer<S> for TargetEchConfigLayer<R> {
    type Service = TargetEchConfigService<S, R>;

    fn layer(&self, inner: S) -> Self::Service {
        TargetEchConfigService {
            inner,
            config: self.clone(),
        }
    }
}

/// Fixed-endpoint ECH discovery followed by an ordinary TLS connector service.
#[derive(Debug, Clone)]
pub struct TargetEchConfigService<S, R = GlobalDnsResolver> {
    inner: S,
    config: TargetEchConfigLayer<R>,
}

impl<R: DnsServiceBindingResolver> TargetEchConfigLayer<R> {
    /// Prepare a selected endpoint. Explicit matching preknowledge takes precedence.
    /// Backend capability gates DNS; final intent may be installed later by a profile.
    pub async fn prepare<T: ConnectorTargetInputExt>(&self, input: &T) -> Result<(), BoxError> {
        let effective = input
            .extensions()
            .fork()
            .with_base(self.tls.as_extensions());
        let requirement = effective
            .get_ref::<EchRequirement>()
            .copied()
            .unwrap_or_default();
        requirement.intent(effective.get_ref::<TlsEncryptedClientHello>())?;
        let Some(target) = input.connector_target() else {
            return if requirement == EchRequirement::Required {
                Err(BoxError::from_static_str(
                    "required ECH needs a selected target",
                ))
            } else {
                Ok(())
            };
        };
        if !self.capable {
            target_ech_config(&effective, &target, self.capable)?;
            return Ok(());
        }
        if effective
            .get_ref::<TargetEchConfig>()
            .is_some_and(|config| config.matches_target(&target))
        {
            return Ok(());
        }
        if ProxyRouteContext::for_request(input.extensions()).is_some() && !self.proxy_discovery {
            target_ech_config(&effective, &target, self.capable)?;
            return Ok(());
        }
        let protocols = effective.get_ref::<TlsAlpn>().map_or_else(
            || vec![ApplicationProtocol::HTTP_11],
            |alpn| alpn.0.to_vec(),
        );
        let result = match tokio::time::timeout(
            self.timeout,
            self.lookup.lookup(&target, &protocols, self.capable),
        )
        .await
        {
            Ok(result) => result,
            Err(_) if requirement == EchRequirement::Optional => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        let binding = result.bindings().iter().find(|binding| {
            binding.target == target
                || (!result.followed_alias()
                    && binding.record.binding.target().is_root()
                    && binding.target.port == target.port)
        });
        if let Some(config) = binding.and_then(|binding| binding.record.binding.ech_config_list()) {
            input
                .extensions()
                .insert(TargetEchConfig::new(target.clone(), config.clone()));
        }
        input.extensions().insert(TargetEchServiceBinding {
            target: target.clone(),
            reliant: result.ech_reliant(),
            mandatory: binding.is_some_and(|binding| {
                binding
                    .record
                    .binding
                    .mandatory_keys()
                    .is_some_and(|keys| keys.contains(&rama_dns::wire::SvcParamKey::Ech))
            }),
        });
        let effective = input
            .extensions()
            .fork()
            .with_base(self.tls.as_extensions());
        target_ech_config(&effective, &target, self.capable)?;
        Ok(())
    }
}

impl<S, R, T> Service<T> for TargetEchConfigService<S, R>
where
    T: ConnectorTargetInputExt + Send + Sync + 'static,
    S: Service<T>,
    S::Error: Into<BoxError>,
    R: DnsServiceBindingResolver,
{
    type Output = S::Output;
    type Error = BoxError;
    async fn serve(&self, input: T) -> Result<Self::Output, Self::Error> {
        self.config.prepare(&input).await?;
        self.inner.serve(input).await.map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::{
        extensions::ExtensionsRef,
        futures::{Stream, stream},
    };
    use rama_dns::{
        client::resolver::ServiceBindingRecord,
        wire::{Name, ServiceBinding},
    };
    use rama_net::{
        address::Domain,
        client::{ConnectRequest, ProxyRoute},
    };
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    #[derive(Clone, Default)]
    struct Resolver(Arc<AtomicUsize>, bool);
    impl DnsServiceBindingResolver for Resolver {
        type Error = BoxError;
        fn lookup_https(
            &self,
            _: Domain,
        ) -> impl Stream<Item = Result<ServiceBindingRecord, BoxError>> + Send + '_ {
            self.0.fetch_add(1, Ordering::SeqCst);
            let wire = [0, 1, 0, 0, 5, 0, 7, 0, 5, 0xfe, 0x0d, 0, 1, 0];
            stream::iter([Ok(ServiceBindingRecord {
                owner: Name::from_presentation(if self.1 {
                    "cdn.example"
                } else {
                    "origin.example"
                })
                .unwrap(),
                binding: ServiceBinding::parse_rdata(&wire).unwrap(),
            })])
        }
        fn lookup_svcb(
            &self,
            _: Domain,
        ) -> impl Stream<Item = Result<ServiceBindingRecord, BoxError>> + Send + '_ {
            stream::empty()
        }
    }

    #[tokio::test]
    async fn fixed_endpoint_discovers_real_configuration_and_reliance() {
        let resolver = Resolver::default();
        let layer = TargetEchConfigLayer::new()
            .with_resolver(resolver.clone())
            .with_capable(true);
        let input = ConnectRequest::new("origin.example:443".parse().unwrap());
        input.extensions().insert(TlsEncryptedClientHello(true));
        layer.prepare(&input).await.unwrap();
        assert!(
            input
                .extensions()
                .get_ref::<TargetEchConfig>()
                .unwrap()
                .matches_target(&input.authority)
        );
        assert_eq!(
            input
                .extensions()
                .get_ref::<TargetEchServiceBinding>()
                .map(|fact| fact.reliant),
            Some(true)
        );
        layer.prepare(&input).await.unwrap();
        assert_eq!(resolver.0.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn no_capability_or_proxy_permission_means_no_dns() {
        for proxy in [false, true] {
            let resolver = Resolver::default();
            let layer = TargetEchConfigLayer::new()
                .with_resolver(resolver.clone())
                .with_capable(proxy);
            let input = ConnectRequest::new("origin.example:443".parse().unwrap());
            if proxy {
                input.extensions().insert(TlsEncryptedClientHello(true));
                input.extensions().insert(ProxyRoute::Proxy(
                    "socks5h://proxy.example:1080".parse().unwrap(),
                ));
            }
            layer.prepare(&input).await.unwrap();
            assert_eq!(resolver.0.load(Ordering::SeqCst), 0);
            input.extensions().insert(EchRequirement::Required);
            layer.prepare(&input).await.unwrap_err();
        }
    }

    #[tokio::test]
    async fn explicit_required_preknowledge_works_without_proxy_discovery() {
        let resolver = Resolver::default();
        let layer = TargetEchConfigLayer::new()
            .with_resolver(resolver.clone())
            .with_capable(true);
        let input = ConnectRequest::new("origin.example:443".parse().unwrap());
        input.extensions().insert(EchRequirement::Required);
        input.extensions().insert(ProxyRoute::Proxy(
            "http://proxy.example:3128".parse().unwrap(),
        ));
        input
            .extensions()
            .insert(TargetEchConfig::new(input.authority.clone(), vec![0, 1, 2]));
        layer.prepare(&input).await.unwrap();
        assert_eq!(resolver.0.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn cname_owner_root_target_uses_the_original_address_resolution() {
        let resolver = Resolver(Arc::default(), true);
        let layer = TargetEchConfigLayer::new()
            .with_resolver(resolver)
            .with_capable(true);
        let input = ConnectRequest::new("origin.example:443".parse().unwrap());
        input.extensions().insert(TlsEncryptedClientHello(true));
        layer.prepare(&input).await.unwrap();
        assert!(
            input
                .extensions()
                .get_ref::<TargetEchConfig>()
                .unwrap()
                .matches_target(&input.authority)
        );
        assert_eq!(
            input
                .extensions()
                .get_ref::<TargetEchServiceBinding>()
                .map(|fact| fact.reliant),
            Some(true)
        );
    }
}
