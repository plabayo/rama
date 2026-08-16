//! Route client requests through the operating system's proxy settings.

use std::net::IpAddr;
use std::{fmt, sync::Arc};

use ipnet::IpNet;
use rama_core::{
    Layer, Service,
    error::{BoxError, BoxErrorExt as _, ErrorContext, extra::OpaqueError},
    extensions::{Extensions, ExtensionsRef},
    layer::MapErr,
    service::BoxService,
};
use rama_utils::macros::generate_set_and_with;

#[cfg(any(
    test,
    target_vendor = "apple",
    target_os = "android",
    target_os = "linux",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
use crate::address::{Host, HostWithPort};
use crate::{
    Protocol,
    address::{Authority, ProxyAddress},
    input_ext::{AuthorityInputExt, ProtocolInputExt, UriInputExt},
    uri::Uri,
};

use super::{ProxyRoute, ProxyRoutes};

mod system_proxy_platform;

/// The request information passed to a system PAC resolver.
///
/// The URI is absolute and the extension store is a cheap clone of the input's
/// store. This keeps caller metadata available to custom PAC implementations
/// without borrowing the request across an await point.
#[derive(Debug, Clone)]
pub struct SystemProxyPacRequest {
    extensions: Extensions,
    uri: Uri,
}

impl SystemProxyPacRequest {
    /// Create a PAC request from an absolute request URI and its extensions.
    pub fn new(extensions: Extensions, uri: Uri) -> Result<Self, BoxError> {
        if !uri.is_absolute() || uri.host().is_none() {
            return Err(BoxError::from_static_str(
                "system proxy PAC request URI must be absolute and have a host",
            ));
        }
        Ok(Self { extensions, uri })
    }

    /// The absolute request URI for which proxy routes are needed.
    #[must_use]
    pub const fn uri(&self) -> &Uri {
        &self.uri
    }

    /// Consume the request into its extension store and URI.
    #[must_use]
    pub fn into_parts(self) -> (Extensions, Uri) {
        (self.extensions, self.uri)
    }
}

impl ExtensionsRef for SystemProxyPacRequest {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl UriInputExt for SystemProxyPacRequest {
    fn uri(&self) -> &Uri {
        &self.uri
    }
}

/// A type-erased resolver for one system PAC URI.
pub type BoxSystemProxyPacResolver =
    BoxService<SystemProxyPacRequest, Option<ProxyRoutes>, OpaqueError>;

/// A PAC resolver accepted by [`SystemProxyLayer`].
///
/// Implementations return `None` when the script deliberately makes no routing
/// decision and [`ProxyRoutes`] when it does. `rama-pac` provides an adapter
/// backed by its cached fetcher and JavaScript evaluator.
pub trait SystemProxyPacResolver:
    Service<SystemProxyPacRequest, Output = Option<ProxyRoutes>, Error = OpaqueError>
{
}

impl<T> SystemProxyPacResolver for T where
    T: Service<SystemProxyPacRequest, Output = Option<ProxyRoutes>, Error = OpaqueError>
{
}

/// A service that supplies a resolver for a system-configured PAC URI.
pub trait SystemProxyPacService:
    Service<Uri, Output = BoxSystemProxyPacResolver, Error = OpaqueError>
{
}

impl<T> SystemProxyPacService for T where
    T: Service<Uri, Output = BoxSystemProxyPacResolver, Error = OpaqueError>
{
}

/// Box a PAC resolver while normalising its error to [`OpaqueError`].
pub fn box_system_proxy_pac_resolver<S>(service: S) -> BoxSystemProxyPacResolver
where
    S: Service<SystemProxyPacRequest, Output = Option<ProxyRoutes>>,
    S::Error: Into<BoxError> + Send + Sync + 'static,
{
    MapErr::into_opaque_error(service).boxed()
}

/// A snapshot of the operating system's proxy configuration.
///
/// HTTP and HTTPS identify the destination scheme, not necessarily the
/// transport protocol used to reach the proxy. A SOCKS5 proxy is used as a
/// fallback when no scheme-specific proxy is configured. A PAC URI takes
/// precedence over fixed proxies because it can make a per-request decision.
#[derive(Debug, Clone, Default)]
pub struct SystemProxyConfig {
    http: Option<ProxyAddress>,
    https: Option<ProxyAddress>,
    socks5: Option<ProxyAddress>,
    pac_uri: Option<Uri>,
    bypass: Arc<[String]>,
    exclude_simple_hostnames: bool,
    reversed_bypass: bool,
}

impl SystemProxyConfig {
    /// Read the current platform proxy snapshot.
    ///
    /// - Windows uses the active user's WinHTTP/Internet Options settings;
    /// - macOS and iOS use CFNetwork's system proxy dictionary;
    /// - Android uses `ConnectivityManager.getDefaultProxy()`, with the legacy
    ///   `Proxy` API on Android versions before API 23;
    /// - Linux and BSD read GNOME `gsettings`, falling back to KDE's
    ///   `kioslaverc`.
    ///
    /// This deliberately does not inspect `HTTP_PROXY` or related environment
    /// variables. Those are application configuration and are handled by the
    /// HTTP proxy environment layer instead.
    pub fn try_from_system() -> Result<Self, BoxError> {
        system_proxy_platform::read().context("read system proxy configuration")
    }

    /// Return whether this snapshot contains no PAC or fixed proxy settings.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.http.is_none()
            && self.https.is_none()
            && self.socks5.is_none()
            && self.pac_uri.is_none()
    }

    /// The proxy for HTTP destinations.
    #[must_use]
    pub const fn http_proxy(&self) -> Option<&ProxyAddress> {
        self.http.as_ref()
    }

    /// The proxy for HTTPS destinations.
    #[must_use]
    pub const fn https_proxy(&self) -> Option<&ProxyAddress> {
        self.https.as_ref()
    }

    /// The SOCKS5 fallback proxy.
    #[must_use]
    pub const fn socks5_proxy(&self) -> Option<&ProxyAddress> {
        self.socks5.as_ref()
    }

    /// The configured PAC script URI.
    #[must_use]
    pub const fn pac_uri(&self) -> Option<&Uri> {
        self.pac_uri.as_ref()
    }

    /// Host patterns that bypass fixed proxies.
    pub fn bypass(&self) -> impl Iterator<Item = &str> {
        self.bypass.iter().map(String::as_str)
    }

    /// Whether names without a dot bypass fixed proxies.
    #[must_use]
    pub const fn exclude_simple_hostnames(&self) -> bool {
        self.exclude_simple_hostnames
    }

    /// Whether fixed proxies are used only for hosts matching [`bypass`][Self::bypass].
    ///
    /// KDE exposes this uncommon inverted exception-list mode. The default is
    /// `false`, where matching hosts bypass the proxy in the usual way.
    #[must_use]
    pub const fn reversed_bypass(&self) -> bool {
        self.reversed_bypass
    }

    generate_set_and_with! {
        /// Set the proxy used for HTTP destinations.
        pub fn http_proxy(mut self, proxy: Option<ProxyAddress>) -> Self {
            self.http = proxy;
            self
        }
    }

    generate_set_and_with! {
        /// Set the proxy used for HTTPS destinations.
        pub fn https_proxy(mut self, proxy: Option<ProxyAddress>) -> Self {
            self.https = proxy;
            self
        }
    }

    generate_set_and_with! {
        /// Set the SOCKS5 fallback proxy.
        pub fn socks5_proxy(mut self, proxy: Option<ProxyAddress>) -> Self {
            self.socks5 = proxy;
            self
        }
    }

    generate_set_and_with! {
        /// Set the PAC script URI.
        pub fn pac_uri(mut self, pac_uri: Option<Uri>) -> Self {
            self.pac_uri = pac_uri;
            self
        }
    }

    /// Replace the fixed-proxy bypass patterns.
    pub fn set_bypass<I, T>(&mut self, bypass: I)
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        self.bypass = bypass.into_iter().map(Into::into).collect();
    }

    /// Replace the fixed-proxy bypass patterns.
    #[must_use]
    pub fn with_bypass<I, T>(mut self, bypass: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<String>,
    {
        self.set_bypass(bypass);
        self
    }

    generate_set_and_with! {
        /// Configure whether names without a dot bypass fixed proxies.
        pub fn exclude_simple_hostnames(mut self, exclude: bool) -> Self {
            self.exclude_simple_hostnames = exclude;
            self
        }
    }

    generate_set_and_with! {
        /// Invert the meaning of fixed-proxy bypass patterns.
        pub fn reversed_bypass(mut self, reversed: bool) -> Self {
            self.reversed_bypass = reversed;
            self
        }
    }

    fn decision(&self, uri: &Uri) -> SystemProxyDecision {
        if let Some(pac_uri) = &self.pac_uri {
            return SystemProxyDecision::Pac(pac_uri.clone());
        }

        let Some(host) = uri.host() else {
            return SystemProxyDecision::None;
        };
        let proxy = match uri.scheme() {
            Some(protocol) if *protocol == Protocol::HTTPS || *protocol == Protocol::WSS => {
                self.https.as_ref()
            }
            Some(protocol) if *protocol == Protocol::HTTP || *protocol == Protocol::WS => {
                self.http.as_ref()
            }
            _ => None,
        }
        .or(self.socks5.as_ref());
        let Some(proxy) = proxy else {
            return SystemProxyDecision::None;
        };

        let port = uri
            .port_u16()
            .or_else(|| uri.scheme().and_then(Protocol::default_port));
        if self.bypasses(host.to_str().as_ref(), port) {
            return SystemProxyDecision::Routes(ProxyRoutes::from(ProxyRoute::Direct));
        }
        SystemProxyDecision::Routes(ProxyRoutes::from(proxy.clone()))
    }

    fn bypasses(&self, host: &str, port: Option<u16>) -> bool {
        let matches = (self.exclude_simple_hostnames && !host.contains('.'))
            || self
                .bypass
                .iter()
                .any(|pattern| bypass_pattern_matches(pattern, host, port));
        if self.reversed_bypass {
            !matches
        } else {
            matches
        }
    }
}

enum SystemProxyDecision {
    None,
    Routes(ProxyRoutes),
    Pac(Uri),
}

/// Apply the operating system's proxy settings to client service inputs.
///
/// Existing [`ProxyRoute`] or [`ProxyRoutes`] extensions win by default. This
/// makes the layer safe to place below explicit CLI/application proxy layers:
/// a common priority chain is explicit option, `HTTP_PROXY` environment layer,
/// then this system layer. Use [`with_overwrite`][Self::with_overwrite] only
/// when the system policy must replace a route already chosen by the caller.
///
/// Environment proxy variables are intentionally out of scope. The
/// `rama-http-backend` `HttpProxyAddressLayer::try_from_env_default` layer is
/// the corresponding mechanism for `HTTP_PROXY`.
///
/// A configured PAC URI is used only after a service is supplied through
/// [`with_pac_service`][Self::with_pac_service]. Without one the layer leaves
/// the request unchanged. Factory, fetch, or evaluation errors fail the
/// request instead of silently bypassing the system proxy.
#[derive(Clone)]
pub struct SystemProxyLayer {
    config: Arc<SystemProxyConfig>,
    pac: Option<BoxService<Uri, BoxSystemProxyPacResolver, OpaqueError>>,
    overwrite: bool,
}

impl fmt::Debug for SystemProxyLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SystemProxyLayer")
            .field("config", &self.config)
            .field("pac", &self.pac)
            .field("overwrite", &self.overwrite)
            .finish()
    }
}

impl SystemProxyLayer {
    /// Create a layer from a proxy configuration snapshot.
    #[must_use]
    pub fn new(config: SystemProxyConfig) -> Self {
        Self {
            config: Arc::new(config),
            pac: None,
            overwrite: false,
        }
    }

    /// Create a layer from the current operating system proxy settings.
    pub fn try_from_system() -> Result<Self, BoxError> {
        SystemProxyConfig::try_from_system().map(Self::new)
    }

    /// The captured operating system proxy configuration.
    #[must_use]
    pub fn config(&self) -> &SystemProxyConfig {
        self.config.as_ref()
    }

    /// Supply a PAC resolver factory.
    #[must_use]
    pub fn with_pac_service<P>(mut self, pac: P) -> Self
    where
        P: Service<Uri, Output = BoxSystemProxyPacResolver>,
        P::Error: Into<BoxError> + Send + Sync + 'static,
    {
        self.pac = Some(MapErr::into_opaque_error(pac).boxed());
        self
    }

    generate_set_and_with! {
        /// Replace an existing route decision (defaults to `false`).
        pub fn overwrite(mut self, overwrite: bool) -> Self {
            self.overwrite = overwrite;
            self
        }
    }
}

impl<S> Layer<S> for SystemProxyLayer {
    type Service = SystemProxyService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SystemProxyService {
            inner,
            layer: self.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        SystemProxyService { inner, layer: self }
    }
}

/// See [`SystemProxyLayer`].
#[derive(Debug, Clone)]
pub struct SystemProxyService<S> {
    inner: S,
    layer: SystemProxyLayer,
}

impl<S> SystemProxyService<S> {
    /// Borrow the wrapped service.
    #[must_use]
    pub const fn inner(&self) -> &S {
        &self.inner
    }

    /// Mutably borrow the wrapped service.
    #[must_use]
    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Consume this service and return the wrapped service.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S, Input> Service<Input> for SystemProxyService<S>
where
    S: Service<Input>,
    S::Error: Into<BoxError>,
    Input: UriInputExt + AuthorityInputExt + ProtocolInputExt + ExtensionsRef + Send + 'static,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let inactive = self.layer.config.is_empty()
            || (self.layer.config.pac_uri().is_some() && self.layer.pac.is_none());
        if inactive || (!self.layer.overwrite && is_already_routed(&input)) {
            return self.inner.serve(input).await.map_err(Into::into);
        }

        let uri = absolute_uri(&input)?;
        let routes = match self.layer.config.decision(&uri) {
            SystemProxyDecision::None => None,
            SystemProxyDecision::Routes(routes) => Some(routes),
            SystemProxyDecision::Pac(pac_uri) => {
                if let Some(factory) = &self.layer.pac {
                    let resolver = factory
                        .serve(pac_uri)
                        .await
                        .context("create system PAC resolver")?;
                    resolver
                        .serve(SystemProxyPacRequest::new(input.extensions().clone(), uri)?)
                        .await
                        .context("resolve system PAC routes")?
                } else {
                    rama_core::telemetry::tracing::debug!(
                        "system PAC URI configured without a PAC resolver service"
                    );
                    None
                }
            }
        };

        if let Some(routes) = routes {
            input
                .extensions()
                .insert(routes.with_overwrite(self.layer.overwrite));
        }
        self.inner.serve(input).await.map_err(Into::into)
    }
}

fn absolute_uri<I>(input: &I) -> Result<Uri, BoxError>
where
    I: UriInputExt + AuthorityInputExt + ProtocolInputExt,
{
    let mut uri = input.uri().clone();
    if uri.scheme().is_none() {
        let protocol = input
            .protocol()
            .ok_or_else(|| BoxError::from_static_str("request has no resolvable protocol"))?;
        uri.set_scheme(protocol.clone());
    }
    if uri.host().is_none() {
        let authority = input
            .authority()
            .ok_or_else(|| BoxError::from_static_str("request has no resolvable authority"))?;
        uri = uri.with_authority(Authority::from(authority));
    }
    uri.ensure_path_or_root();
    Ok(uri)
}

fn is_already_routed(input: &impl ExtensionsRef) -> bool {
    input.extensions().contains::<ProxyRoute>() || input.extensions().contains::<ProxyRoutes>()
}

fn bypass_pattern_matches(raw_pattern: &str, host: &str, port: Option<u16>) -> bool {
    let mut pattern = raw_pattern.trim();
    if pattern.is_empty() {
        return false;
    }
    if pattern == "*" {
        return true;
    }
    if pattern.eq_ignore_ascii_case("<local>") {
        return !host.contains('.');
    }

    let mut expected_port = None;
    if let Some(bracketed) = pattern.strip_prefix('[') {
        if let Some((candidate, suffix)) = bracketed.rsplit_once("]:")
            && let Ok(parsed_port) = suffix.parse::<u16>()
        {
            pattern = candidate;
            expected_port = Some(parsed_port);
        }
    } else if pattern.bytes().filter(|byte| *byte == b':').count() == 1
        && let Some((candidate, suffix)) = pattern.rsplit_once(':')
        && let Ok(parsed_port) = suffix.parse::<u16>()
    {
        pattern = candidate;
        expected_port = Some(parsed_port);
    }
    if expected_port.is_some_and(|expected| port != Some(expected)) {
        return false;
    }

    let host_without_brackets = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(network) = pattern.parse::<IpNet>()
        && let Ok(address) = host_without_brackets.parse::<IpAddr>()
    {
        return network.contains(&address);
    }

    let pattern = pattern.trim_matches(['[', ']']).to_ascii_lowercase();
    let host = host_without_brackets.to_ascii_lowercase();
    let pattern = pattern.trim_end_matches('.');
    let host = host.trim_end_matches('.');
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return host == suffix || host.ends_with(&format!(".{suffix}"));
    }
    if let Some(suffix) = pattern.strip_prefix('.') {
        return host == suffix || host.ends_with(&format!(".{suffix}"));
    }
    host == pattern
}

#[cfg(any(
    test,
    target_vendor = "apple",
    target_os = "android",
    target_os = "linux",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
pub(super) fn proxy_address(
    protocol: Protocol,
    host: impl AsRef<str>,
    port: u16,
) -> Result<ProxyAddress, BoxError> {
    let host = Host::try_from(host.as_ref()).context("parse system proxy host")?;
    Ok(ProxyAddress {
        protocol: Some(protocol),
        address: HostWithPort::new(host, port),
        credential: None,
    })
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use parking_lot::Mutex;
    use rama_core::{extensions::Extension, service::service_fn};

    use super::*;

    #[derive(Debug, Clone, Extension)]
    struct Marker(&'static str);

    #[derive(Debug, Clone)]
    struct TestInput {
        uri: Uri,
        protocol: Option<Protocol>,
        authority: Option<crate::address::HostWithOptPort>,
        extensions: Extensions,
    }

    impl TestInput {
        fn new(uri: &str) -> Self {
            Self {
                uri: uri.parse().unwrap(),
                protocol: None,
                authority: None,
                extensions: Extensions::new(),
            }
        }

        fn origin_form(uri: &str, protocol: Protocol, authority: &str) -> Self {
            Self {
                uri: uri.parse().unwrap(),
                protocol: Some(protocol),
                authority: Some(authority.parse().unwrap()),
                extensions: Extensions::new(),
            }
        }
    }

    impl UriInputExt for TestInput {
        fn uri(&self) -> &Uri {
            &self.uri
        }
    }

    impl AuthorityInputExt for TestInput {
        fn authority(&self) -> Option<crate::address::HostWithOptPort> {
            self.authority.clone().or_else(|| {
                self.uri
                    .authority()
                    .map(|authority| authority.into_owned().address)
            })
        }
    }

    impl ProtocolInputExt for TestInput {
        fn protocol(&self) -> Option<&Protocol> {
            self.protocol.as_ref().or_else(|| self.uri.scheme())
        }
    }

    impl ExtensionsRef for TestInput {
        fn extensions(&self) -> &Extensions {
            &self.extensions
        }
    }

    fn proxy(protocol: Protocol, host: &'static str, port: u16) -> ProxyAddress {
        proxy_address(protocol, host, port).unwrap()
    }

    fn recorder() -> (
        impl Service<TestInput, Output = (), Error = Infallible> + Clone,
        Arc<Mutex<Vec<Option<ProxyRoutes>>>>,
    ) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let service = service_fn({
            let seen = seen.clone();
            move |input: TestInput| {
                seen.lock()
                    .push(input.extensions.get_ref::<ProxyRoutes>().cloned());
                async { Ok::<_, Infallible>(()) }
            }
        });
        (service, seen)
    }

    #[tokio::test]
    async fn fixed_proxies_are_selected_by_destination_scheme() {
        let config = SystemProxyConfig::default()
            .with_http_proxy(proxy(Protocol::HTTP, "http.proxy", 8080))
            .with_https_proxy(proxy(Protocol::HTTP, "https.proxy", 8443));
        let (inner, seen) = recorder();
        let service = SystemProxyLayer::new(config).into_layer(inner);

        service
            .serve(TestInput::new("http://example.com/"))
            .await
            .unwrap();
        service
            .serve(TestInput::new("https://example.com/"))
            .await
            .unwrap();
        service
            .serve(TestInput::new("ws://example.com/"))
            .await
            .unwrap();
        service
            .serve(TestInput::new("wss://example.com/"))
            .await
            .unwrap();

        let seen = seen.lock();
        assert_eq!(
            seen[0].as_ref().unwrap().as_slice()[0]
                .proxy_address()
                .unwrap()
                .address
                .host
                .to_str(),
            "http.proxy"
        );
        assert_eq!(
            seen[1].as_ref().unwrap().as_slice()[0]
                .proxy_address()
                .unwrap()
                .address
                .host
                .to_str(),
            "https.proxy"
        );
        assert_eq!(
            seen[2].as_ref().unwrap().as_slice()[0]
                .proxy_address()
                .unwrap()
                .address
                .host
                .to_str(),
            "http.proxy"
        );
        assert_eq!(
            seen[3].as_ref().unwrap().as_slice()[0]
                .proxy_address()
                .unwrap()
                .address
                .host
                .to_str(),
            "https.proxy"
        );
    }

    #[tokio::test]
    async fn socks_is_the_scheme_independent_fallback() {
        let config = SystemProxyConfig::default().with_socks5_proxy(proxy(
            Protocol::SOCKS5,
            "socks.proxy",
            1080,
        ));
        let (inner, seen) = recorder();
        let service = SystemProxyLayer::new(config).into_layer(inner);

        service
            .serve(TestInput::new("https://example.com/"))
            .await
            .unwrap();

        let seen = seen.lock();
        let address = seen[0].as_ref().unwrap().as_slice()[0]
            .proxy_address()
            .unwrap();
        assert_eq!(address.protocol, Some(Protocol::SOCKS5));
    }

    #[tokio::test]
    async fn scheme_specific_proxy_does_not_capture_other_protocols() {
        let config = SystemProxyConfig::default()
            .with_http_proxy(proxy(Protocol::HTTP, "http.proxy", 8080))
            .with_bypass(["example.com"]);
        let (inner, seen) = recorder();

        SystemProxyLayer::new(config)
            .into_layer(inner)
            .serve(TestInput::new("ftp://example.com/file"))
            .await
            .unwrap();

        assert!(seen.lock()[0].is_none());
    }

    #[tokio::test]
    async fn empty_config_does_not_require_routing_metadata() {
        let (inner, seen) = recorder();

        SystemProxyLayer::new(SystemProxyConfig::default())
            .into_layer(inner)
            .serve(TestInput::new("/relative"))
            .await
            .unwrap();

        assert!(seen.lock()[0].is_none());
    }

    #[tokio::test]
    async fn existing_route_wins_unless_overwrite_is_enabled() {
        let config = SystemProxyConfig::default().with_http_proxy(proxy(
            Protocol::HTTP,
            "system.proxy",
            8080,
        ));
        let (inner, seen) = recorder();
        let request = TestInput::new("http://example.com/");
        request.extensions.insert(ProxyRoutes::from(proxy(
            Protocol::HTTP,
            "explicit.proxy",
            9000,
        )));

        SystemProxyLayer::new(config.clone())
            .into_layer(inner.clone())
            .serve(request.clone())
            .await
            .unwrap();
        SystemProxyLayer::new(config)
            .with_overwrite(true)
            .into_layer(inner)
            .serve(request)
            .await
            .unwrap();

        let seen = seen.lock();
        let hosts: Vec<_> = seen
            .iter()
            .map(|routes| {
                routes.as_ref().unwrap().as_slice()[0]
                    .proxy_address()
                    .unwrap()
                    .address
                    .host
                    .to_str()
                    .into_owned()
            })
            .collect();
        assert_eq!(hosts, ["explicit.proxy", "system.proxy"]);
    }

    #[tokio::test]
    async fn overwrite_routes_take_priority_over_a_singular_route() {
        let config = SystemProxyConfig::default().with_http_proxy(proxy(
            Protocol::HTTP,
            "system.proxy",
            8080,
        ));
        let request = TestInput::new("http://example.com/");
        request.extensions.insert(ProxyRoute::Direct);
        let (inner, seen) = recorder();

        SystemProxyLayer::new(config)
            .with_overwrite(true)
            .into_layer(inner)
            .serve(request)
            .await
            .unwrap();

        let seen = seen.lock();
        let routes = seen[0].as_ref().unwrap();
        assert!(routes.overwrite());
        assert_eq!(
            routes.as_slice()[0]
                .proxy_address()
                .unwrap()
                .address
                .host
                .to_str(),
            "system.proxy"
        );
    }

    #[tokio::test]
    async fn pac_receives_full_uri_and_cloned_extensions() {
        let pac_uri: Uri = "http://config.example/proxy.pac".parse().unwrap();
        let factory_seen = Arc::new(Mutex::new(Vec::new()));
        let resolver_seen = Arc::new(Mutex::new(Vec::new()));
        let factory = service_fn({
            let factory_seen = factory_seen.clone();
            let resolver_seen = resolver_seen.clone();
            move |uri: Uri| {
                factory_seen.lock().push(uri);
                let resolver_seen = resolver_seen.clone();
                async move {
                    Ok::<_, OpaqueError>(box_system_proxy_pac_resolver(service_fn(
                        move |request: SystemProxyPacRequest| {
                            resolver_seen.lock().push((
                                request.uri().clone(),
                                request.extensions().get_ref::<Marker>().cloned(),
                            ));
                            async move {
                                Ok::<_, Infallible>(Some(ProxyRoutes::from(proxy(
                                    Protocol::HTTP,
                                    "pac.proxy",
                                    8080,
                                ))))
                            }
                        },
                    )))
                }
            }
        });
        let config = SystemProxyConfig::default().with_pac_uri(pac_uri.clone());
        let request = TestInput::new("https://example.com/private?q=1");
        request.extensions.insert(Marker("kept"));
        let (inner, seen) = recorder();

        SystemProxyLayer::new(config)
            .with_pac_service(factory)
            .into_layer(inner)
            .serve(request)
            .await
            .unwrap();

        assert_eq!(factory_seen.lock().as_slice(), [pac_uri]);
        let resolved = resolver_seen.lock();
        assert_eq!(resolved[0].0.to_string(), "https://example.com/private?q=1");
        assert_eq!(resolved[0].1.as_ref().unwrap().0, "kept");
        assert_eq!(
            seen.lock()[0].as_ref().unwrap().as_slice()[0]
                .proxy_address()
                .unwrap()
                .address
                .host
                .to_str(),
            "pac.proxy"
        );
    }

    #[tokio::test]
    async fn pac_receives_an_absolute_uri_for_origin_form_input() {
        let received = Arc::new(Mutex::new(None));
        let factory = service_fn({
            let received = received.clone();
            move |_uri: Uri| {
                let received = received.clone();
                async move {
                    Ok::<_, OpaqueError>(box_system_proxy_pac_resolver(service_fn(
                        move |request: SystemProxyPacRequest| {
                            *received.lock() = Some(request.uri().clone());
                            async { Ok::<_, Infallible>(None) }
                        },
                    )))
                }
            }
        });
        let config = SystemProxyConfig::default()
            .with_pac_uri("https://config.example/proxy.pac".parse().unwrap());
        let (inner, _) = recorder();

        SystemProxyLayer::new(config)
            .with_pac_service(factory)
            .into_layer(inner)
            .serve(TestInput::origin_form(
                "/private?q=1",
                Protocol::HTTPS,
                "example.com:8443",
            ))
            .await
            .unwrap();

        assert_eq!(
            received.lock().as_ref().unwrap().to_string(),
            "https://example.com:8443/private?q=1"
        );
    }

    #[tokio::test]
    async fn pac_without_a_service_leaves_the_request_undecided() {
        let config = SystemProxyConfig::default()
            .with_pac_uri("http://config.example/proxy.pac".parse().unwrap());
        let (inner, seen) = recorder();

        SystemProxyLayer::new(config)
            .into_layer(inner)
            .serve(TestInput::new("/relative"))
            .await
            .unwrap();

        assert!(seen.lock()[0].is_none());
    }

    #[tokio::test]
    async fn singular_route_also_prevents_pac_lookup() {
        let factory_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let factory = service_fn({
            let factory_calls = factory_calls.clone();
            move |_uri: Uri| {
                factory_calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                async move {
                    Ok::<_, OpaqueError>(box_system_proxy_pac_resolver(service_fn(
                        |_request| async { Ok::<_, Infallible>(None) },
                    )))
                }
            }
        });
        let config = SystemProxyConfig::default()
            .with_pac_uri("https://config.example/proxy.pac".parse().unwrap());
        let request = TestInput::new("https://example.com/");
        request.extensions.insert(ProxyRoute::Direct);
        let (inner, _) = recorder();

        SystemProxyLayer::new(config)
            .with_pac_service(factory)
            .into_layer(inner)
            .serve(request)
            .await
            .unwrap();

        assert_eq!(factory_calls.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn bypass_and_inverted_bypass_select_direct_routes() {
        let base = SystemProxyConfig::default()
            .with_http_proxy(proxy(Protocol::HTTP, "system.proxy", 8080))
            .with_bypass([".example.com", "default-port.test:80"]);
        let (inner, seen) = recorder();
        let service = SystemProxyLayer::new(base.clone()).into_layer(inner.clone());
        service
            .serve(TestInput::new("http://api.example.com/"))
            .await
            .unwrap();
        service
            .serve(TestInput::new("http://elsewhere.test/"))
            .await
            .unwrap();
        service
            .serve(TestInput::new("http://default-port.test/"))
            .await
            .unwrap();

        let inverted = SystemProxyLayer::new(base.with_reversed_bypass(true)).into_layer(inner);
        inverted
            .serve(TestInput::new("http://api.example.com/"))
            .await
            .unwrap();
        inverted
            .serve(TestInput::new("http://elsewhere.test/"))
            .await
            .unwrap();

        let seen = seen.lock();
        assert!(matches!(
            seen[0].as_ref().unwrap().as_slice(),
            [ProxyRoute::Direct]
        ));
        assert!(matches!(
            seen[1].as_ref().unwrap().as_slice(),
            [ProxyRoute::Proxy(_)]
        ));
        assert!(matches!(
            seen[2].as_ref().unwrap().as_slice(),
            [ProxyRoute::Direct]
        ));
        assert!(matches!(
            seen[3].as_ref().unwrap().as_slice(),
            [ProxyRoute::Proxy(_)]
        ));
        assert!(matches!(
            seen[4].as_ref().unwrap().as_slice(),
            [ProxyRoute::Direct]
        ));
    }

    #[tokio::test]
    async fn simple_hostname_bypass_is_opt_in() {
        let config = SystemProxyConfig::default()
            .with_http_proxy(proxy(Protocol::HTTP, "system.proxy", 8080))
            .with_exclude_simple_hostnames(true);
        let (inner, seen) = recorder();
        let service = SystemProxyLayer::new(config).into_layer(inner);

        service
            .serve(TestInput::new("http://printer/"))
            .await
            .unwrap();
        service
            .serve(TestInput::new("http://printer.example/"))
            .await
            .unwrap();

        let seen = seen.lock();
        assert!(matches!(
            seen[0].as_ref().unwrap().as_slice(),
            [ProxyRoute::Direct]
        ));
        assert!(matches!(
            seen[1].as_ref().unwrap().as_slice(),
            [ProxyRoute::Proxy(_)]
        ));
    }

    #[test]
    fn config_accessors_and_pac_request_parts_round_trip() {
        let http = proxy(Protocol::HTTP, "http.proxy", 8080);
        let https = proxy(Protocol::HTTP, "https.proxy", 8443);
        let socks = proxy(Protocol::SOCKS5, "socks.proxy", 1080);
        let pac: Uri = "https://config.example/proxy.pac".parse().unwrap();
        let config = SystemProxyConfig::default()
            .with_http_proxy(http.clone())
            .with_https_proxy(https.clone())
            .with_socks5_proxy(socks.clone())
            .with_pac_uri(pac.clone())
            .with_bypass(["localhost"])
            .with_exclude_simple_hostnames(true)
            .with_reversed_bypass(true);

        assert!(!config.is_empty());
        assert_eq!(config.http_proxy(), Some(&http));
        assert_eq!(config.https_proxy(), Some(&https));
        assert_eq!(config.socks5_proxy(), Some(&socks));
        assert_eq!(config.pac_uri(), Some(&pac));
        assert_eq!(config.bypass().collect::<Vec<_>>(), ["localhost"]);
        assert!(config.exclude_simple_hostnames());
        assert!(config.reversed_bypass());

        let extensions = Extensions::new();
        extensions.insert(Marker("parts"));
        let request =
            SystemProxyPacRequest::new(extensions, "http://example.com/path".parse().unwrap())
                .unwrap();
        assert_eq!(
            UriInputExt::uri(&request).to_string(),
            "http://example.com/path"
        );
        assert_eq!(
            ExtensionsRef::extensions(&request)
                .get_ref::<Marker>()
                .unwrap()
                .0,
            "parts"
        );
        let (extensions, uri) = request.into_parts();
        assert_eq!(extensions.get_ref::<Marker>().unwrap().0, "parts");
        assert_eq!(uri.to_string(), "http://example.com/path");
    }

    #[test]
    fn every_proxy_source_independently_makes_config_non_empty() {
        assert!(SystemProxyConfig::default().is_empty());
        for config in [
            SystemProxyConfig::default().with_http_proxy(proxy(Protocol::HTTP, "http.proxy", 8080)),
            SystemProxyConfig::default().with_https_proxy(proxy(
                Protocol::HTTP,
                "https.proxy",
                8443,
            )),
            SystemProxyConfig::default().with_socks5_proxy(proxy(
                Protocol::SOCKS5,
                "socks.proxy",
                1080,
            )),
            SystemProxyConfig::default()
                .with_pac_uri("https://config.example/proxy.pac".parse().unwrap()),
        ] {
            assert!(!config.is_empty());
        }
    }

    #[test]
    fn pac_request_rejects_non_absolute_or_hostless_uri() {
        SystemProxyPacRequest::new(Extensions::new(), "/path".parse().unwrap()).unwrap_err();
        SystemProxyPacRequest::new(Extensions::new(), "data:text/plain,x".parse().unwrap())
            .unwrap_err();
    }

    #[test]
    fn bypass_patterns_cover_domains_ports_ip_ranges_and_local_names() {
        for (pattern, host, port, expected) in [
            ("*", "anything.example", None, true),
            ("<local>", "printer", None, true),
            ("<local>", "printer.example", None, false),
            ("*.example.com", "api.example.com", None, true),
            ("*.example.com", "example.com", None, true),
            (".example.com", "api.example.com.", None, true),
            (".example.com", "notexample.com", None, false),
            ("api.example.com:8443", "api.example.com", Some(8443), true),
            ("api.example.com:8443", "api.example.com", Some(443), false),
            ("10.0.0.0/8", "10.2.3.4", None, true),
            ("10.0.0.0/8", "11.2.3.4", None, false),
            ("[::1]", "::1", None, true),
            ("::1", "::1", None, true),
            ("[::1]:8443", "::1", Some(8443), true),
            ("[::1]:8443", "::1", Some(443), false),
            ("2001:db8::/32", "2001:db8::1", None, true),
        ] {
            assert_eq!(
                bypass_pattern_matches(pattern, host, port),
                expected,
                "{pattern} {host:?} {port:?}"
            );
        }
    }
}
