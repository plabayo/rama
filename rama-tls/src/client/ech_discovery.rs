//! Optional ECH discovery for a fixed destination before a TLS handshake.
//!
//! This adapter never changes the endpoint or negotiates an HTTP service. It
//! consumes compatible records for the selected target, including a root
//! ServiceMode target at its CNAME owner when no HTTPS AliasMode was followed
//! and the port is unchanged. This binds the service's configuration to the
//! existing endpoint; it does not claim that address and HTTPS CNAME chains match. Stacks selecting
//! among HTTPS endpoints should use the shared lookup directly or the HTTP
//! discovery layer, then supply `TargetEchConfig` to their TLS backend.
use super::{
    ClientHello, EchRequirement, TlsClientConfig, TlsEncryptedClientHello, target_ech_config,
};
use crate::server::InputWithClientHello;
use rama_core::{
    Layer, Service,
    error::{BoxError, BoxErrorExt as _},
    extensions::{Extensions, ExtensionsRef},
};
use rama_dns::client::{
    DEFAULT_HTTPS_ALIAS_LIMIT, GlobalDnsResolver, lookup_https_service_bindings,
    resolver::DnsServiceBindingResolver,
};
use rama_net::{
    ConnectorTargetInputExt,
    address::HostWithPort,
    client::{ConnectorTarget, ProxyRouteContext},
    tls::{ApplicationProtocol, TargetEchConfig, TargetEchServiceBinding, TlsAlpn},
};
use rama_utils::macros::generate_set_and_with;
use std::time::Duration;

/// Discover ECH for an already selected physical endpoint without adding a cache.
#[derive(Debug, Clone)]
pub struct TargetEchConfigLayer<R = GlobalDnsResolver> {
    resolver: R,
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
            resolver: GlobalDnsResolver::new(),
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
            resolver,
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

/// Fixed-endpoint ECH discovery followed by a TLS connector or peeked relay service.
#[derive(Debug, Clone)]
pub struct TargetEchConfigService<S, R = GlobalDnsResolver> {
    inner: S,
    config: TargetEchConfigLayer<R>,
}

impl<R: DnsServiceBindingResolver> TargetEchConfigLayer<R> {
    /// Prepare a selected endpoint. Explicit matching preknowledge takes precedence.
    /// Backend capability gates DNS; final intent may be installed later by a profile.
    pub async fn prepare<T: ConnectorTargetInputExt>(&self, input: &T) -> Result<(), BoxError> {
        let Some(target) = input.connector_target() else {
            let effective = input
                .extensions()
                .fork()
                .with_base(self.tls.as_extensions());
            let requirement = effective
                .get_ref::<EchRequirement>()
                .copied()
                .unwrap_or_default();
            requirement.intent(effective.get_ref::<TlsEncryptedClientHello>())?;
            return if requirement == EchRequirement::Required {
                Err(BoxError::from_static_str(
                    "required ECH needs a selected target",
                ))
            } else {
                Ok(())
            };
        };
        if input
            .target_protocol()
            .is_some_and(|protocol| !protocol.is_secure())
        {
            return Ok(());
        }
        self.prepare_target(input.extensions(), &target, &target, None)
            .await
    }

    /// Discover for a mirrored TLS flow, querying SNI even for an IP dial target.
    /// The resulting configuration stays bound to the already connected endpoint.
    /// An explicit `ConnectorTarget` is required; this adapter never guesses a port.
    pub async fn prepare_client_hello<I: ExtensionsRef>(
        &self,
        input: &InputWithClientHello<I>,
    ) -> Result<(), BoxError> {
        let Some(server_name) = input.client_hello.ext_server_name() else {
            return Ok(());
        };
        let extensions = input.input.extensions();
        // The stream is already connected: never guess its physical port or
        // attach knowledge that the relay cannot correlate with that endpoint.
        let Some(ConnectorTarget(target)) = extensions.get_ref::<ConnectorTarget>() else {
            return Ok(());
        };
        let sni_target = target
            .host
            .is_ip()
            .then(|| HostWithPort::new(server_name.clone().into(), target.port));
        self.prepare_target(
            extensions,
            target,
            sni_target.as_ref().unwrap_or(target),
            Some(&input.client_hello),
        )
        .await
    }

    async fn prepare_target(
        &self,
        extensions: &Extensions,
        target: &HostWithPort,
        query_target: &HostWithPort,
        mirrored_hello: Option<&ClientHello>,
    ) -> Result<(), BoxError> {
        let effective_config = || {
            let effective = extensions.fork().with_base(self.tls.as_extensions());
            if let Some(hello) = mirrored_hello
                && !effective.contains::<TlsEncryptedClientHello>()
            {
                effective.insert(TlsEncryptedClientHello(hello.has_encrypted_client_hello()));
            }
            effective
        };
        let effective = effective_config();
        let requirement = effective
            .get_ref::<EchRequirement>()
            .copied()
            .unwrap_or_default();
        let intent = requirement.intent(effective.get_ref::<TlsEncryptedClientHello>())?;
        // A peeked hello supplies final mirror intent; ordinary connectors may
        // still install a profile after this layer has prepared endpoint facts.
        if mirrored_hello.is_some() && !intent {
            target_ech_config(&effective, target, self.capable)?;
            return Ok(());
        }
        if !self.capable {
            target_ech_config(&effective, target, self.capable)?;
            return Ok(());
        }
        if effective
            .get_ref::<TargetEchConfig>()
            .is_some_and(|config| config.matches_target(target))
            || effective
                .get_ref::<TargetEchServiceBinding>()
                .is_some_and(|binding| binding.target == *target)
        {
            target_ech_config(&effective, target, self.capable)?;
            return Ok(());
        }
        if ProxyRouteContext::for_request(extensions).is_some() && !self.proxy_discovery {
            target_ech_config(&effective, target, self.capable)?;
            return Ok(());
        }
        let default_protocols = [ApplicationProtocol::HTTP_11];
        let protocols = effective
            .get_ref::<TlsAlpn>()
            .map(|alpn| alpn.0.as_slice())
            .or_else(|| mirrored_hello.and_then(ClientHello::ext_alpn))
            .unwrap_or(&default_protocols);
        let result = match tokio::time::timeout(
            self.timeout,
            lookup_https_service_bindings(
                &self.resolver,
                query_target,
                protocols,
                self.capable,
                DEFAULT_HTTPS_ALIAS_LIMIT,
            ),
        )
        .await
        {
            Ok(result) => result,
            Err(_) if requirement == EchRequirement::Optional => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        let binding = result.bindings().iter().find(|binding| {
            binding.target == *query_target
                || (!result.followed_alias()
                    && binding.record.binding.target().is_root()
                    && binding.target.port == query_target.port)
        });
        if let Some(config) = binding.and_then(|binding| binding.record.binding.ech_config_list()) {
            extensions.insert(TargetEchConfig::new(target.clone(), config.clone()));
        }
        extensions.insert(TargetEchServiceBinding {
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
        let effective = effective_config();
        target_ech_config(&effective, target, self.capable)?;
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

impl<S, R, I> Service<InputWithClientHello<I>> for TargetEchConfigService<S, R>
where
    I: ExtensionsRef + Send + Sync + 'static,
    S: Service<InputWithClientHello<I>>,
    S::Error: Into<BoxError>,
    R: DnsServiceBindingResolver,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, input: InputWithClientHello<I>) -> Result<Self::Output, Self::Error> {
        self.config.prepare_client_hello(&input).await?;
        self.inner.serve(input).await.map_err(Into::into)
    }
}

#[cfg(test)]
mod tests;
