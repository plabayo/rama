//! HTTPS DNS knowledge for the existing HTTP service selector.
//!
//! Compose this before `HttpServiceConnector`, proxy selection and pooling.
//! Discovery changes connection candidates, never the logical origin. DNS
//! caching belongs to the supplied resolver. Named-proxy discovery is opt-in;
//! even when enabled it never starts local destination address lookups.
//!
//! ```text
//! HTTPS DNS + Alt-Svc -> candidates + per-candidate extensions
//!                              |
//!                         select candidate <---+ failure, if allowed
//!                              |               |
//!                         proxy route          |
//!                              |               |
//!                         pool lookup          |
//!                         /         \          |
//!                       hit        miss        |
//!                        |          |          |
//!                        |    connect + TLS ---+
//!                        |          | success
//!                        +----> use connection
//! ```
//!
//! Pool lookup uses the selected candidate's endpoint and policy. Custom
//! preknowledge producers can supply the same candidates and extensions.
//!
//! Use the same TLS defaults and Alt-Svc cache in discovery and selection.
//! WebSocket (`wss`) service selection and HTTP-to-HTTPS upgrades are not
//! implemented by this layer. Each Alt-Svc authority has independent ECH
//! reliance, as specified by RFC 9848 section 6: an origin's ECH advertisement
//! does not itself require its separately advertised alternatives to offer ECH.
//!
//! Custom resolvers reuse the same interpretation and extension contracts. See
//! the `http_https_discovery_custom_resolver` and `http_ech_preknowledge` examples.
//! DNS-free producers can supply candidate-local facts directly. Apply caller
//! ECH intent and `EchRequirement::Required` separately on the request; the
//! backend checks acceptance on new connections and pooled reuse.

use crate::layer::{alt_svc::AltSvcCache, http_service::dials_another_endpoint};
use rama_core::{
    Layer, Service,
    error::{BoxError, BoxErrorExt as _},
    extensions::{Extensions, ExtensionsRef},
};
use rama_dns::{
    client::{
        DEFAULT_HTTPS_ALIAS_LIMIT, DnsAddressSource, GlobalDnsResolver, HttpsServiceBindings,
        lookup_https_service_bindings,
        resolver::{DnsAddressResolver, DnsServiceBindingResolver},
    },
    wire::SvcParamKey,
};
use rama_http_types::conn::{
    HttpOrigin, HttpServiceCandidate, HttpServiceCandidates, HttpServiceSelection,
    HttpServiceSource,
};
use rama_net::{
    Protocol,
    address::HostWithPort,
    client::{
        ConnectRequest, ConnectionError, ConnectionErrorKind, ConnectorTarget,
        ConnectorTargetStream, ProxyRouteContext,
    },
    tls::{ApplicationProtocol, TargetEchConfig, TargetEchServiceBinding, TlsAlpn},
};
use rama_tls::client::{EchRequirement, TlsClientConfig};
use rama_utils::macros::{define_inner_service_accessors, generate_set_and_with};
use std::{net::IpAddr, sync::Arc, time::Duration};

/// Reusable HTTPS discovery configuration, independent of an easy client.
#[derive(Debug, Clone)]
pub struct HttpsServiceLayer<R = GlobalDnsResolver> {
    resolver: R,
    enabled: bool,
    cache: Option<AltSvcCache>,
    tls: TlsClientConfig,
    protocols: Vec<ApplicationProtocol>,
    ech_capable: bool,
    proxy_discovery: bool,
    fail_on_discovery_error: bool,
    timeout: Duration,
    max_candidates: usize,
}

impl Default for HttpsServiceLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpsServiceLayer {
    /// Use the global resolver. ECH capability must be declared by the stack.
    pub fn new() -> Self {
        Self {
            resolver: GlobalDnsResolver::new(),
            enabled: true,
            cache: None,
            tls: TlsClientConfig::default(),
            protocols: vec![
                ApplicationProtocol::HTTP_3,
                ApplicationProtocol::HTTP_2,
                ApplicationProtocol::HTTP_11,
            ],
            ech_capable: false,
            proxy_discovery: false,
            fail_on_discovery_error: false,
            timeout: Duration::from_secs(5),
            max_candidates: 64,
        }
    }
}

impl<R> HttpsServiceLayer<R> {
    /// Whether this stack has declared a backend capable of real ECH.
    pub fn is_ech_capable(&self) -> bool {
        self.ech_capable
    }

    generate_set_and_with! {
        /// Enable discovery (default true); disabled layers pass requests through.
        pub fn enabled(mut self, enabled: bool) -> Self {
            self.enabled = enabled;
            self
        }
    }

    generate_set_and_with! {
        /// Reject HTTPS resolver/record errors and discovery timeouts (default false).
        /// Applies to the origin and each consulted Alt-Svc authority. Successful
        /// empty or incompatible answers still permit ordinary optional fallback.
        /// Enable this when resolver failures must not permit DNS fallback; this
        /// setting does not infer whether a resolver authenticates its answers.
        pub fn fail_on_discovery_error(mut self, enabled: bool) -> Self {
            self.fail_on_discovery_error = enabled;
            self
        }
    }

    /// Resolve both HTTPS and address records with this resolver.
    pub fn with_resolver<T>(self, resolver: T) -> HttpsServiceLayer<T> {
        HttpsServiceLayer {
            resolver,
            enabled: self.enabled,
            cache: self.cache,
            tls: self.tls,
            protocols: self.protocols,
            ech_capable: self.ech_capable,
            proxy_discovery: self.proxy_discovery,
            fail_on_discovery_error: self.fail_on_discovery_error,
            timeout: self.timeout,
            max_candidates: self.max_candidates,
        }
    }

    generate_set_and_with! {
        /// Compose fresh Alt-Svc advertisements from the selector's cache.
        /// Supply the same cache to both layers. When DNS supplies candidates,
        /// this layer owns composition; an unrelated inner cache is not merged.
        pub fn cache(mut self, cache: Option<AltSvcCache>) -> Self {
            self.cache = cache;
            self
        }
    }

    generate_set_and_with! {
        /// Connector defaults used to compute effective ECH intent.
        /// Keep these identical to the TLS connector's defaults.
        pub fn tls(mut self, tls: TlsClientConfig) -> Self {
            self.tls = tls;
            self
        }
    }

    generate_set_and_with! {
        /// Supported HTTP ALPNs, in preference order.
        pub fn protocols(mut self, protocols: Vec<ApplicationProtocol>) -> Self {
            self.protocols = protocols;
            self
        }
    }

    generate_set_and_with! {
        /// Whether the selected TLS backend supports real ECH (default false).
        pub fn ech_capable(mut self, supported: bool) -> Self {
            self.ech_capable = supported;
            self
        }
    }

    generate_set_and_with! {
        /// Authorize HTTPS queries through this resolver for named proxy routes.
        pub fn proxy_discovery(mut self, allowed: bool) -> Self {
            self.proxy_discovery = allowed;
            self
        }
    }

    generate_set_and_with! {
        /// Bound the complete discovery operation, including Alt-Svc authorities.
        pub fn timeout(mut self, timeout: Duration) -> Self {
            self.timeout = timeout;
            self
        }
    }

    generate_set_and_with! {
        /// Bound produced candidates and consulted advertisements (default 64).
        pub fn max_candidates(mut self, limit: usize) -> Self {
            self.max_candidates = limit;
            self
        }
    }
}

impl<S, R: Clone> Layer<S> for HttpsServiceLayer<R> {
    type Service = HttpsService<S, R>;

    fn layer(&self, inner: S) -> Self::Service {
        HttpsService {
            inner,
            config: self.clone(),
        }
    }
}

/// Inject DNS-derived candidate knowledge before invoking the inner connector.
#[derive(Debug, Clone)]
pub struct HttpsService<S, R = GlobalDnsResolver> {
    inner: S,
    config: HttpsServiceLayer<R>,
}

impl<S, R> HttpsService<S, R> {
    define_inner_service_accessors!();
    /// Mutably access the inner connector.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Discovery policy for this reusable connector wrapper.
    pub fn config_mut(&mut self) -> &mut HttpsServiceLayer<R> {
        &mut self.config
    }
}

fn invalid(message: &'static str) -> ConnectionError {
    ConnectionError::local(
        BoxError::from_static_str(message),
        ConnectionErrorKind::InvalidInput,
    )
}

impl<R: DnsServiceBindingResolver + DnsAddressResolver + Clone> HttpsServiceLayer<R> {
    fn check_discovery(
        &self,
        result: HttpsServiceBindings,
    ) -> Result<HttpsServiceBindings, ConnectionError> {
        if self.fail_on_discovery_error {
            result
                .into_result()
                .map_err(|error| ConnectionError::local(error, ConnectionErrorKind::Unavailable))
        } else {
            Ok(result)
        }
    }

    async fn discover(&self, input: &ConnectRequest) -> Result<(), ConnectionError> {
        let effective = self.tls.overlay(input.extensions());
        let required =
            effective.get_ref::<EchRequirement>().copied() == Some(EchRequirement::Required);
        let mut reliant = required;
        match tokio::time::timeout(self.timeout, self.prepare(input, &mut reliant)).await {
            Ok(result) => result,
            Err(error) if self.fail_on_discovery_error => {
                Err(ConnectionError::local(error, ConnectionErrorKind::Timeout))
            }
            // A slow alternative must not discard completed primary discovery.
            Err(_)
                if input
                    .extensions()
                    .get_ref::<HttpServiceCandidates>()
                    .is_some_and(|candidates| !candidates.is_empty()) =>
            {
                Ok(())
            }
            Err(error) if required => {
                Err(ConnectionError::local(error, ConnectionErrorKind::Timeout))
            }
            Err(_) => {
                if reliant {
                    // Suppress cached bare alternatives after learning reliance.
                    // Keep the origin's endpoint fact, so its final TLS intent
                    // decides whether that fallback is usable without I/O.
                    let origin = HttpOrigin::new(Protocol::HTTPS, input.authority.clone())
                        .map_err(|error| {
                            ConnectionError::local(error, ConnectionErrorKind::InvalidInput)
                        })?;
                    input
                        .extensions()
                        .insert(HttpServiceCandidates::new(origin, []));
                }
                Ok(())
            }
        }
    }

    async fn prepare(
        &self,
        input: &ConnectRequest,
        reliant: &mut bool,
    ) -> Result<(), ConnectionError> {
        if !self.enabled
            || input.application_protocol.as_ref() != Some(&Protocol::HTTPS)
            || input.extensions().contains::<HttpServiceCandidates>()
            || dials_another_endpoint(input)
        {
            return Ok(());
        }

        let effective = self.tls.overlay(input.extensions());
        let (required, _) = EchRequirement::effective(&effective)
            .map_err(|error| ConnectionError::local(error, ConnectionErrorKind::InvalidInput))?;
        if required == EchRequirement::Required && !self.ech_capable {
            return Err(invalid("required ECH needs a capable TLS backend"));
        }
        // Explicit endpoint knowledge remains a DNS-free composition option.
        if effective
            .get_ref::<TargetEchConfig>()
            .is_some_and(|config| config.matches_target(&input.authority))
        {
            return Ok(());
        }
        // Capability admits record facts. Final intent and verification may be
        // installed by a profile compiler after service selection.
        let capable = self.ech_capable;

        let version = super::http_service::required_version(input);
        let protocols: Vec<_> = self
            .protocols
            .iter()
            .filter(|protocol| {
                version.is_none_or(|version| {
                    rama_http_types::Version::try_from(*protocol).ok() == Some(version)
                    // A stream connector's default ALPN is not a constraint on
                    // a separately configured QUIC connector. Request ALPN is.
                }) && input
                    .extensions()
                    .get_ref::<TlsAlpn>()
                    .is_none_or(|alpn| alpn.0.contains(protocol))
            })
            .cloned()
            .collect();
        let proxy = ProxyRouteContext::for_request(input.extensions()).is_some();
        if proxy && !self.proxy_discovery {
            return Ok(());
        }
        let origin = HttpOrigin::new(Protocol::HTTPS, input.authority.clone())
            .map_err(|error| ConnectionError::local(error, ConnectionErrorKind::InvalidInput))?;
        // Install only a lazy source: timeout fallback keeps the same DNS policy.
        if required != EchRequirement::Required {
            self.insert_address_source(input.extensions(), &input.authority, proxy, []);
        }
        // Complete primary discovery before selecting any transport endpoint.
        let primary = lookup_https_service_bindings(
            &self.resolver,
            &input.authority,
            &protocols,
            capable,
            DEFAULT_HTTPS_ALIAS_LIMIT,
        )
        .await;
        let primary = self.check_discovery(primary)?;
        let fallback = required != EchRequirement::Required;
        *reliant |= primary.ech_reliant();
        if primary.ech_reliant() {
            input.extensions().insert(TargetEchServiceBinding {
                target: input.authority.clone(),
                reliant: true,
                mandatory: false,
            });
        }

        let mut primary_candidates = Vec::new();
        self.append(
            &mut primary_candidates,
            &primary,
            None,
            &effective,
            &protocols,
            proxy,
            required,
        )?;

        // Publish a safe checkpoint before querying optional advertisements.
        // A cancelled lookup retains these endpoint-local configs and lazy sources.
        if !primary_candidates.is_empty() {
            input.extensions().insert(
                HttpServiceCandidates::new_with_extensions(
                    origin.clone(),
                    primary_candidates.clone(),
                )
                .with_origin_fallback(fallback),
            );
        }

        let mut candidates = Vec::new();

        // Resolve each advertised authority independently, retaining the original
        // immutable advertisement for freshness, backoff and Alt-Used/421.
        if let Some(advertised) = self
            .cache
            .as_ref()
            .and_then(|cache| cache.lookup_fresh(&origin))
        {
            for (index, candidate) in advertised.iter().enumerate().take(self.max_candidates) {
                if candidates.len() >= self.max_candidates {
                    break;
                }
                if !protocols.contains(&candidate.protocol) {
                    continue;
                }
                // The origin's own answer already covers an advertisement of itself.
                let result = if candidate.target == input.authority {
                    primary.restricted_to(&candidate.protocol)
                } else {
                    self.check_discovery(
                        lookup_https_service_bindings(
                            &self.resolver,
                            &candidate.target,
                            std::slice::from_ref(&candidate.protocol),
                            capable,
                            DEFAULT_HTTPS_ALIAS_LIMIT,
                        )
                        .await,
                    )?
                };
                // A later timeout must suppress cached bare authorities whose
                // records already established conditional ECH reliance.
                *reliant |= result.ech_reliant();
                self.append(
                    &mut candidates,
                    &result,
                    Some((&advertised, index)),
                    &effective,
                    &protocols,
                    proxy,
                    required,
                )?;
                if required != EchRequirement::Required && candidates.len() < self.max_candidates {
                    let extensions = Extensions::new();
                    self.insert_address_source(&extensions, &candidate.target, proxy, []);
                    extensions.insert(TargetEchServiceBinding {
                        target: candidate.target.clone(),
                        reliant: result.ech_reliant(),
                        mandatory: false,
                    });
                    extensions.insert(HttpServiceSelection {
                        candidates: advertised.clone(),
                        index,
                        route: None,
                    });
                    candidates.push((candidate.clone(), extensions));
                }
            }
        }
        candidates.extend(
            primary_candidates
                .into_iter()
                .take(self.max_candidates.saturating_sub(candidates.len())),
        );
        if !candidates.is_empty() || !fallback {
            input.extensions().insert(
                HttpServiceCandidates::new_with_extensions(origin, candidates)
                    .with_origin_fallback(fallback),
            );
        }
        Ok(())
    }

    /// Keep every discovered endpoint on this resolver without starting A/AAAA work.
    fn insert_address_source(
        &self,
        extensions: &Extensions,
        target: &HostWithPort,
        proxy: bool,
        hints: impl IntoIterator<Item = IpAddr>,
    ) {
        if proxy
            || extensions
                .get_ref::<ConnectorTargetStream>()
                .is_some_and(|source| source.matches_target(target))
        {
            return;
        }
        if let Ok(domain) = target.host.try_as_domain() {
            let mut source = DnsAddressSource::new(self.resolver.clone(), domain.into_owned());
            let mut hints = hints.into_iter().peekable();
            if hints.peek().is_some() {
                source.set_hints(hints.collect::<Arc<[IpAddr]>>());
            }
            extensions.insert(ConnectorTargetStream::new(target.clone(), source));
        }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "all arguments belong to this bounded discovery operation"
    )]
    fn append(
        &self,
        output: &mut Vec<(HttpServiceCandidate, Extensions)>,
        result: &HttpsServiceBindings,
        advertised: Option<(&Arc<HttpServiceCandidates>, usize)>,
        request: &Extensions,
        protocols: &[ApplicationProtocol],
        proxy: bool,
        required: EchRequirement,
    ) -> Result<(), ConnectionError> {
        for binding in result.bindings() {
            let mut stream_added = false;
            for protocol in &binding.protocols {
                let protocol = if advertised.is_none()
                    && matches!(
                        protocol,
                        ApplicationProtocol::HTTP_2 | ApplicationProtocol::HTTP_11
                    ) {
                    if stream_added {
                        continue;
                    }
                    stream_added = true;
                    // DNS gates transport compatibility; retain the client's stream preference.
                    protocols
                        .iter()
                        .find(|p| {
                            matches!(
                                p,
                                ApplicationProtocol::HTTP_2 | ApplicationProtocol::HTTP_11
                            )
                        })
                        .unwrap_or(protocol)
                } else {
                    protocol
                };
                if output.len() >= self.max_candidates {
                    return Ok(());
                }
                let extensions = Extensions::new();
                extensions.insert(ConnectorTarget(binding.target.clone()));
                if let Some(config) = request
                    .get_ref::<TargetEchConfig>()
                    .filter(|config| config.matches_target(&binding.target))
                {
                    extensions.insert(config.clone());
                } else if let Some(config) = binding.record.binding.ech_config_list() {
                    extensions.insert(TargetEchConfig::new(binding.target.clone(), config.clone()));
                }
                extensions.insert(TargetEchServiceBinding {
                    target: binding.target.clone(),
                    reliant: result.ech_reliant(),
                    mandatory: binding.record.binding.is_mandatory(SvcParamKey::Ech),
                });
                self.insert_address_source(
                    &extensions,
                    &binding.target,
                    proxy,
                    binding.record.binding.ip_hints(),
                );
                let candidate = if let Some((snapshot, index)) = advertised {
                    extensions.insert(HttpServiceSelection {
                        candidates: snapshot.clone(),
                        index,
                        route: None,
                    });
                    snapshot
                        .get(index)
                        .ok_or_else(|| invalid("invalid advertisement index"))?
                        .clone()
                } else {
                    HttpServiceCandidate::new(protocol.clone(), binding.target.clone())
                        .with_source(HttpServiceSource::Https)
                };
                output.push((candidate, extensions));
            }
        }
        // AliasMode's bare endpoint is allowed only for SVCB-optional callers.
        if required != EchRequirement::Required
            && let Some(target) = result.alias_target()
        {
            let mut stream_added = false;
            for protocol in protocols {
                if advertised.is_none()
                    && matches!(
                        protocol,
                        ApplicationProtocol::HTTP_2 | ApplicationProtocol::HTTP_11
                    )
                {
                    if stream_added {
                        continue;
                    }
                    stream_added = true;
                }
                if output.len() >= self.max_candidates {
                    break;
                }
                let extensions = Extensions::new();
                extensions.insert(ConnectorTarget(target.clone()));
                self.insert_address_source(&extensions, target, proxy, []);
                extensions.insert(TargetEchServiceBinding {
                    target: target.clone(),
                    reliant: result.ech_reliant(),
                    mandatory: false,
                });
                let candidate = if let Some((snapshot, index)) = advertised {
                    let candidate = snapshot
                        .get(index)
                        .ok_or_else(|| invalid("invalid advertisement index"))?;
                    if &candidate.protocol != protocol {
                        continue;
                    }
                    extensions.insert(HttpServiceSelection {
                        candidates: snapshot.clone(),
                        index,
                        route: None,
                    });
                    candidate.clone()
                } else {
                    HttpServiceCandidate::new(protocol.clone(), target.clone())
                        .with_source(HttpServiceSource::Https)
                };
                output.push((candidate, extensions));
            }
        }
        Ok(())
    }
}

impl<S, R> Service<ConnectRequest> for HttpsService<S, R>
where
    S: Service<ConnectRequest, Error = ConnectionError>,
    R: DnsServiceBindingResolver + DnsAddressResolver + Clone,
{
    type Output = S::Output;
    type Error = ConnectionError;
    async fn serve(&self, input: ConnectRequest) -> Result<Self::Output, Self::Error> {
        self.config.discover(&input).await?;
        self.inner.serve(input).await
    }
}

#[cfg(test)]
mod tests;
