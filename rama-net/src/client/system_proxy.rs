//! Route client requests through the operating system's proxy settings.

use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;
use parking_lot::Mutex;
use rama_core::{
    Layer, Service,
    error::{BoxError, BoxErrorExt as _, ErrorContext},
    extensions::{Extensions, ExtensionsRef},
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
    address::{Authority, HostRef, HostWithOptPort, ProxyAddress},
    input_ext::{AuthorityInputExt, ProtocolInputExt, UriInputExt},
    uri::Uri,
};

use super::{ProxyRoute, ProxyRoutes};

mod bypass;
mod system_proxy_platform;

use bypass::{BypassRule, is_simple_hostname};

/// How long a layer created with [`SystemProxyLayer::try_from_system`] keeps a
/// system proxy snapshot before lazily checking for changes.
///
/// The ten-second default follows the polling interval used by
/// [Chromium's Windows proxy configuration service][chromium] where change
/// notifications alone are insufficient. Use
/// [`SystemProxyLayer::try_from_system_with_ttl`] to select a different value.
///
/// [chromium]: https://chromium.googlesource.com/chromium/src/+/refs/heads/main/net/proxy_resolution/win/proxy_config_service_win.cc
pub const DEFAULT_SYSTEM_PROXY_CONFIG_TTL: Duration = Duration::from_secs(10);

/// The request information passed to a system PAC resolver.
///
/// When produced by [`SystemProxyLayer`], the URI is absolute, has a root path
/// when the original target omitted one, and omits the scheme's default port.
/// The extension store is a cheap clone of the input's store. This keeps caller
/// metadata available to custom PAC implementations without borrowing the
/// request across an await point.
#[derive(Debug, Clone)]
pub struct SystemProxyPacRequest {
    /// Metadata cloned from the routed service input.
    pub extensions: Extensions,
    /// The normalized absolute URI for which routes are requested.
    pub uri: Uri,
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

/// Resolves proxy routes for a request using one system-configured PAC script.
///
/// Returning `None` asks the system layer to try the fixed proxy settings from
/// the same snapshot, if any, and otherwise leave the request unchanged.
/// The blanket implementation accepts any resolver error that converts into
/// [`BoxError`]. Implementations may return a concrete service; no allocation
/// or type erasure is required.
pub trait SystemProxyPacResolver:
    Service<SystemProxyPacRequest, Output = Option<ProxyRoutes>>
{
}

impl<T> SystemProxyPacResolver for T
where
    T: Service<SystemProxyPacRequest, Output = Option<ProxyRoutes>>,
    T::Error: Into<BoxError>,
{
}

/// Supplies a resolver for a system-configured PAC URI.
///
/// The blanket implementation accepts any factory and resolver errors that
/// convert into [`BoxError`]. The resolver output remains concrete so
/// implementations can choose their own caching and sharing strategy.
pub trait SystemProxyPacService: Service<Uri> {}

impl<T> SystemProxyPacService for T
where
    T: Service<Uri>,
    T::Error: Into<BoxError>,
    T::Output: SystemProxyPacResolver,
    <T::Output as Service<SystemProxyPacRequest>>::Error: Into<BoxError>,
{
}

/// A snapshot of the operating system's proxy configuration.
///
/// HTTP and HTTPS identify the destination scheme, not necessarily the
/// transport protocol used to reach the proxy. A SOCKS5 proxy is used as a
/// fallback when no scheme-specific proxy is configured. A PAC URI takes
/// precedence over fixed proxies because it can make a per-request decision;
/// platform bypass entries are left to the PAC script in that case.
#[derive(Debug, Clone, Default)]
pub struct SystemProxyConfig {
    http: Option<ProxyAddress>,
    https: Option<ProxyAddress>,
    socks5: Option<ProxyAddress>,
    pac_uri: Option<Uri>,
    bypass: Arc<[BypassRule]>,
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
    /// - Linux and BSD prefer KDE's `kioslaverc` on KDE desktops, otherwise
    ///   reading GNOME `gsettings` before falling back to KDE.
    ///
    /// This deliberately does not inspect `HTTP_PROXY` or related environment
    /// variables. Those are application configuration and are handled by the
    /// HTTP proxy environment layer instead.
    ///
    /// Automatic discovery such as WPAD is not attempted when the platform
    /// does not provide a concrete PAC URI. Malformed non-empty proxy values
    /// are reported as errors rather than silently bypassing a configured
    /// system policy.
    ///
    /// This function performs blocking platform I/O and returns a snapshot;
    /// call it from an appropriate blocking thread. Applications that want a
    /// lazily refreshed cache should use [`SystemProxyLayer::try_from_system`]
    /// instead.
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
        self.bypass.iter().map(BypassRule::raw)
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
        self.bypass = bypass.into_iter().map(BypassRule::compile).collect();
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

        self.fixed_decision(uri)
    }

    fn fixed_decision(&self, uri: &Uri) -> SystemProxyDecision {
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
        if self.bypasses(host, port) {
            return SystemProxyDecision::Routes(ProxyRoutes::from(ProxyRoute::Direct));
        }
        SystemProxyDecision::Routes(ProxyRoutes::from(proxy.clone()))
    }

    fn bypasses(&self, host: HostRef<'_>, port: Option<u16>) -> bool {
        let host_text = host.to_str();
        let matches = (self.exclude_simple_hostnames && is_simple_hostname(host))
            || self
                .bypass
                .iter()
                .any(|rule| rule.matches(host, &host_text, port));
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

type SystemProxyConfigReader =
    dyn Fn() -> Result<SystemProxyConfig, BoxError> + Send + Sync + 'static;

#[derive(Clone)]
enum SystemProxyConfigSource {
    Static(Arc<SystemProxyConfig>),
    System(Arc<SystemProxyConfigCache>),
}

impl fmt::Debug for SystemProxyConfigSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Static(config) => f.debug_tuple("Static").field(config).finish(),
            Self::System(cache) => f.debug_tuple("System").field(cache).finish(),
        }
    }
}

impl SystemProxyConfigSource {
    fn snapshot(&self) -> Arc<SystemProxyConfig> {
        match self {
            Self::Static(config) => config.clone(),
            Self::System(cache) => cache.snapshot(),
        }
    }
}

struct SystemProxyConfigCache {
    current: ArcSwap<SystemProxyConfig>,
    ttl: Duration,
    last_refresh: Mutex<Instant>,
    refreshing: AtomicBool,
    reader: Arc<SystemProxyConfigReader>,
}

impl fmt::Debug for SystemProxyConfigCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SystemProxyConfigCache")
            .field("current", &self.current.load())
            .field("ttl", &self.ttl)
            .field("refreshing", &self.refreshing.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl SystemProxyConfigCache {
    fn new(
        current: SystemProxyConfig,
        ttl: Duration,
        reader: Arc<SystemProxyConfigReader>,
    ) -> Self {
        Self {
            current: ArcSwap::from_pointee(current),
            ttl,
            last_refresh: Mutex::new(Instant::now()),
            refreshing: AtomicBool::new(false),
            reader,
        }
    }

    fn snapshot(self: &Arc<Self>) -> Arc<SystemProxyConfig> {
        let current = self.current.load_full();
        if self.last_refresh.lock().elapsed() < self.ttl {
            return current;
        }
        if self
            .refreshing
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return current;
        }

        *self.last_refresh.lock() = Instant::now();
        let cache = self.clone();
        if let Err(error) = std::thread::Builder::new()
            .name("rama-system-proxy-refresh".to_owned())
            .spawn(move || {
                struct RefreshGuard<'a>(&'a AtomicBool);

                impl Drop for RefreshGuard<'_> {
                    fn drop(&mut self) {
                        self.0.store(false, Ordering::Release);
                    }
                }

                let _guard = RefreshGuard(&cache.refreshing);
                match (cache.reader)() {
                    Ok(config) => cache.current.store(Arc::new(config)),
                    Err(error) => rama_core::telemetry::tracing::warn!(
                        error = %error,
                        "failed to refresh system proxy configuration; retaining prior snapshot"
                    ),
                }
            })
        {
            self.refreshing.store(false, Ordering::Release);
            rama_core::telemetry::tracing::warn!(
                error = %error,
                "failed to start system proxy configuration refresh"
            );
        }
        current
    }
}

#[doc(hidden)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemProxyPacDisabled;

#[doc(hidden)]
#[derive(Debug, Clone, Copy)]
pub struct SystemProxyPacDisabledResolver;

impl Service<Uri> for SystemProxyPacDisabled {
    type Output = SystemProxyPacDisabledResolver;
    type Error = std::convert::Infallible;

    async fn serve(&self, _uri: Uri) -> Result<Self::Output, Self::Error> {
        Ok(SystemProxyPacDisabledResolver)
    }
}

impl Service<SystemProxyPacRequest> for SystemProxyPacDisabledResolver {
    type Output = Option<ProxyRoutes>;
    type Error = std::convert::Infallible;

    async fn serve(&self, _request: SystemProxyPacRequest) -> Result<Self::Output, Self::Error> {
        Ok(None)
    }
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
/// [`with_pac_service`][Self::with_pac_service]. Without one the layer uses a
/// fixed proxy from the same system snapshot when available, or leaves the
/// request unchanged. Factory, fetch, or evaluation errors fail the request
/// instead of silently bypassing the system proxy.
#[derive(Clone)]
pub struct SystemProxyLayer<P = SystemProxyPacDisabled> {
    config: SystemProxyConfigSource,
    pac: P,
    pac_enabled: bool,
    overwrite: bool,
}

impl<P: fmt::Debug> fmt::Debug for SystemProxyLayer<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SystemProxyLayer")
            .field("config", &self.config)
            .field("pac", &self.pac)
            .field("pac_enabled", &self.pac_enabled)
            .field("overwrite", &self.overwrite)
            .finish()
    }
}

impl SystemProxyLayer {
    /// Create a layer from a proxy configuration snapshot.
    #[must_use]
    pub fn new(config: SystemProxyConfig) -> Self {
        Self {
            config: SystemProxyConfigSource::Static(Arc::new(config)),
            pac: SystemProxyPacDisabled,
            pac_enabled: false,
            overwrite: false,
        }
    }

    /// Create a layer from the current operating system proxy settings.
    pub fn try_from_system() -> Result<Self, BoxError> {
        Self::try_from_system_with_ttl(DEFAULT_SYSTEM_PROXY_CONFIG_TTL)
    }

    /// Create a refreshing layer from the current operating system settings.
    ///
    /// The initial read happens synchronously. Each request thereafter gets
    /// the latest cached snapshot immediately. Once `ttl` has elapsed, a
    /// single background thread refreshes the cache while requests continue
    /// using the previous snapshot. A failed refresh retains that snapshot
    /// and is retried after another `ttl` interval.
    pub fn try_from_system_with_ttl(ttl: Duration) -> Result<Self, BoxError> {
        Self::try_from_system_with_reader(ttl, Arc::new(SystemProxyConfig::try_from_system))
    }

    fn try_from_system_with_reader(
        ttl: Duration,
        reader: Arc<SystemProxyConfigReader>,
    ) -> Result<Self, BoxError> {
        let config = reader()?;
        Ok(Self {
            config: SystemProxyConfigSource::System(Arc::new(SystemProxyConfigCache::new(
                config, ttl, reader,
            ))),
            pac: SystemProxyPacDisabled,
            pac_enabled: false,
            overwrite: false,
        })
    }
}

impl<P> SystemProxyLayer<P> {
    /// The latest cached operating system proxy configuration.
    ///
    /// For a refreshing layer, this returns the current snapshot and may
    /// start a non-blocking refresh when the configured TTL has expired.
    #[must_use]
    pub fn config(&self) -> Arc<SystemProxyConfig> {
        self.config.snapshot()
    }

    /// Supply a PAC resolver factory.
    #[must_use]
    pub fn with_pac_service<Q>(self, pac: Q) -> SystemProxyLayer<Q> {
        SystemProxyLayer {
            config: self.config,
            pac,
            pac_enabled: true,
            overwrite: self.overwrite,
        }
    }

    generate_set_and_with! {
        /// Replace an existing route decision (defaults to `false`).
        pub fn overwrite(mut self, overwrite: bool) -> Self {
            self.overwrite = overwrite;
            self
        }
    }
}

impl<S, P> Layer<S> for SystemProxyLayer<P>
where
    P: Clone,
{
    type Service = SystemProxyService<S, P>;

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
pub struct SystemProxyService<S, P = SystemProxyPacDisabled> {
    inner: S,
    layer: SystemProxyLayer<P>,
}

impl<S, P> SystemProxyService<S, P> {
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

impl<S, P, Input> Service<Input> for SystemProxyService<S, P>
where
    S: Service<Input>,
    S::Error: Into<BoxError>,
    P: Service<Uri>,
    P::Error: Into<BoxError>,
    P::Output: Service<SystemProxyPacRequest, Output = Option<ProxyRoutes>>,
    <P::Output as Service<SystemProxyPacRequest>>::Error: Into<BoxError>,
    Input: UriInputExt + AuthorityInputExt + ProtocolInputExt + ExtensionsRef + Send + 'static,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let config = self.layer.config.snapshot();
        if config.is_empty() || (!self.layer.overwrite && is_already_routed(&input)) {
            return self.inner.serve(input).await.map_err(Into::into);
        }

        let uri = match absolute_uri(&input) {
            Ok(uri) => uri,
            Err(error) if self.layer.pac_enabled && config.pac_uri().is_some() => {
                return Err(error);
            }
            Err(_) => {
                rama_core::telemetry::tracing::debug!(
                    "fixed system proxy cannot route an input without an authority"
                );
                return self.inner.serve(input).await.map_err(Into::into);
            }
        };
        let decision = if self.layer.pac_enabled {
            config.decision(&uri)
        } else {
            config.fixed_decision(&uri)
        };
        let routes = match decision {
            SystemProxyDecision::None => None,
            SystemProxyDecision::Routes(routes) => Some(routes),
            SystemProxyDecision::Pac(pac_uri) => {
                let resolver = self
                    .layer
                    .pac
                    .serve(pac_uri)
                    .await
                    .map_err(Into::into)
                    .context("create system PAC resolver")?;
                match resolver
                    .serve(SystemProxyPacRequest::new(
                        input.extensions().clone(),
                        uri.clone(),
                    )?)
                    .await
                    .map_err(Into::into)
                    .context("resolve system PAC routes")?
                {
                    Some(routes) => Some(routes),
                    None => match config.fixed_decision(&uri) {
                        SystemProxyDecision::Routes(routes) => Some(routes),
                        SystemProxyDecision::None | SystemProxyDecision::Pac(_) => None,
                    },
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
    let uri = input.uri();
    let protocol = uri
        .scheme()
        .cloned()
        // Authority-form is the request-target form of CONNECT. The tunnel is
        // opaque and overwhelmingly TLS, so match the HTTP PAC layer and show
        // it as HTTPS regardless of the named port.
        .or_else(|| uri.authority().map(|_| Protocol::HTTPS))
        .or_else(|| input.protocol().cloned())
        .unwrap_or(Protocol::HTTP);
    proxy_request_uri(uri, input.authority(), protocol)
}

/// Normalize a request target for fixed-proxy selection and PAC evaluation.
///
/// The result is absolute, has a root path when no path was supplied, and
/// omits the protocol's default port. The URI's own authority wins over the
/// fallback authority supplied by request metadata.
pub fn proxy_request_uri(
    uri: &Uri,
    fallback_authority: Option<HostWithOptPort>,
    protocol: Protocol,
) -> Result<Uri, BoxError> {
    let authority = uri
        .authority()
        .map(|authority| authority.into_owned().address)
        .or(fallback_authority)
        .ok_or_else(|| BoxError::from_static_str("request has no resolvable authority"))?
        .without_default_port_for(Some(&protocol));

    let mut uri = if uri.is_asterisk() {
        Uri::from_authority(protocol, authority)
    } else {
        uri.clone()
            .with_authority(Authority::from(authority))
            .with_scheme(protocol)
    };
    uri.ensure_path_or_root();
    Ok(uri)
}

fn is_already_routed(input: &impl ExtensionsRef) -> bool {
    input.extensions().contains::<ProxyRoute>() || input.extensions().contains::<ProxyRoutes>()
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
    let value = host.as_ref().trim();
    let host = match Host::try_from(value) {
        Ok(host) => host,
        Err(error) if value.contains("://") => value
            .parse::<Uri>()
            .context("parse system proxy host URI")?
            .host()
            .map(|host| host.into_owned())
            .ok_or(error)
            .context("parse system proxy host")?,
        Err(error) => return Err(error).context("parse system proxy host"),
    };
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

        fn authority_form(authority: &str) -> Self {
            Self {
                uri: Uri::parse_authority_form(authority).unwrap(),
                protocol: None,
                authority: None,
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
        service
            .serve(TestInput::new("ftp://example.com/file"))
            .await
            .unwrap();

        let seen = seen.lock();
        for routes in seen.iter() {
            let address = routes.as_ref().unwrap().as_slice()[0]
                .proxy_address()
                .unwrap();
            assert_eq!(address.protocol, Some(Protocol::SOCKS5));
        }
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
    async fn active_fixed_config_passes_input_without_an_authority() {
        let config = SystemProxyConfig::default().with_http_proxy(proxy(
            Protocol::HTTP,
            "system.proxy",
            8080,
        ));
        let (inner, seen) = recorder();

        SystemProxyLayer::new(config)
            .into_layer(inner)
            .serve(TestInput::new("/relative"))
            .await
            .unwrap();

        assert!(seen.lock()[0].is_none());
    }

    #[tokio::test]
    async fn input_without_a_protocol_defaults_to_http() {
        let config = SystemProxyConfig::default().with_http_proxy(proxy(
            Protocol::HTTP,
            "system.proxy",
            8080,
        ));
        let (inner, seen) = recorder();
        let mut input = TestInput::new("/relative");
        input.authority = Some("example.com".parse().unwrap());

        SystemProxyLayer::new(config)
            .into_layer(inner)
            .serve(input)
            .await
            .unwrap();

        assert!(matches!(
            seen.lock()[0].as_ref().unwrap().as_slice(),
            [ProxyRoute::Proxy(_)]
        ));
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
                    Ok::<_, Infallible>(service_fn(move |request: SystemProxyPacRequest| {
                        resolver_seen.lock().push((
                            request.uri.clone(),
                            request.extensions().get_ref::<Marker>().cloned(),
                        ));
                        async move {
                            Ok::<_, Infallible>(Some(ProxyRoutes::from(proxy(
                                Protocol::HTTP,
                                "pac.proxy",
                                8080,
                            ))))
                        }
                    }))
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
                    Ok::<_, Infallible>(service_fn(move |request: SystemProxyPacRequest| {
                        *received.lock() = Some(request.uri);
                        async { Ok::<_, Infallible>(None) }
                    }))
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
    async fn pac_normalizes_default_ports_with_an_unboxed_resolver() {
        let factory_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let received = Arc::new(Mutex::new(Vec::new()));
        let factory = service_fn({
            let factory_calls = factory_calls.clone();
            let received = received.clone();
            move |_uri: Uri| {
                factory_calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let received = received.clone();
                async move {
                    Ok::<_, Infallible>(service_fn(move |request: SystemProxyPacRequest| {
                        received.lock().push(request.uri);
                        async { Ok::<_, Infallible>(None) }
                    }))
                }
            }
        });
        let config = SystemProxyConfig::default()
            .with_pac_uri("https://config.example/proxy.pac".parse().unwrap());
        let (inner, _) = recorder();
        let service = SystemProxyLayer::new(config)
            .with_pac_service(factory)
            .into_layer(inner);

        for input in [
            TestInput::new("http://example.com:80/path"),
            TestInput::new("https://example.com:443/"),
            TestInput::new("http://example.com:8080/"),
            TestInput::authority_form("example.com:443"),
        ] {
            service.serve(input).await.unwrap();
        }

        assert_eq!(factory_calls.load(std::sync::atomic::Ordering::Relaxed), 4);
        assert_eq!(
            received
                .lock()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            [
                "http://example.com/path",
                "https://example.com/",
                "http://example.com:8080/",
                "https://example.com/",
            ]
        );
    }

    #[tokio::test]
    async fn authority_form_selects_the_https_proxy() {
        let config = SystemProxyConfig::default().with_https_proxy(proxy(
            Protocol::HTTP,
            "https.proxy",
            8443,
        ));
        let (inner, seen) = recorder();

        SystemProxyLayer::new(config)
            .into_layer(inner)
            .serve(TestInput::authority_form("example.com:443"))
            .await
            .unwrap();

        let routes = seen.lock();
        assert_eq!(
            routes[0].as_ref().unwrap().as_slice()[0]
                .proxy_address()
                .unwrap()
                .address
                .host
                .to_str(),
            "https.proxy"
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
    async fn pac_without_a_service_uses_a_fixed_proxy_fallback() {
        let config = SystemProxyConfig::default()
            .with_http_proxy(proxy(Protocol::HTTP, "fixed.proxy", 8080))
            .with_pac_uri("http://config.example/proxy.pac".parse().unwrap());
        let (inner, seen) = recorder();

        SystemProxyLayer::new(config)
            .into_layer(inner)
            .serve(TestInput::new("http://example.com/"))
            .await
            .unwrap();

        assert_eq!(
            seen.lock()[0].as_ref().unwrap().as_slice()[0]
                .proxy_address()
                .unwrap()
                .address
                .host
                .to_str(),
            "fixed.proxy"
        );
    }

    #[tokio::test]
    async fn active_pac_requires_a_resolvable_authority() {
        let factory = service_fn(|_uri: Uri| async {
            Ok::<_, Infallible>(service_fn(|_request| async { Ok::<_, Infallible>(None) }))
        });
        let config = SystemProxyConfig::default()
            .with_pac_uri("http://config.example/proxy.pac".parse().unwrap());
        let (inner, _) = recorder();

        SystemProxyLayer::new(config)
            .with_pac_service(factory)
            .into_layer(inner)
            .serve(TestInput::new("/relative"))
            .await
            .unwrap_err();
    }

    #[tokio::test]
    async fn singular_route_also_prevents_pac_lookup() {
        let factory_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let factory = service_fn({
            let factory_calls = factory_calls.clone();
            move |_uri: Uri| {
                factory_calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                async move {
                    Ok::<_, Infallible>(service_fn(|_request| async { Ok::<_, Infallible>(None) }))
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
        service
            .serve(TestInput::new("http://[2001:db8::1]/"))
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
            [ProxyRoute::Proxy(_)]
        ));
    }

    #[tokio::test]
    async fn inverted_simple_hostname_bypass_uses_only_simple_names() {
        let config = SystemProxyConfig::default()
            .with_http_proxy(proxy(Protocol::HTTP, "system.proxy", 8080))
            .with_exclude_simple_hostnames(true)
            .with_reversed_bypass(true);
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
            [ProxyRoute::Proxy(_)]
        ));
        assert!(matches!(
            seen[1].as_ref().unwrap().as_slice(),
            [ProxyRoute::Direct]
        ));
    }

    #[test]
    fn config_accessors_and_public_pac_request_fields_round_trip() {
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
        assert_eq!(request.extensions.get_ref::<Marker>().unwrap().0, "parts");
        assert_eq!(request.uri.to_string(), "http://example.com/path");
    }

    #[test]
    fn platform_proxy_host_accepts_a_scheme_prefix() {
        let proxy = proxy_address(Protocol::HTTP, "http://proxy.corp", 8080).unwrap();
        assert_eq!(proxy.to_string(), "http://proxy.corp:8080");
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
            ("<local>", "2001:db8::1", None, false),
            ("192.168.*", "192.168.10.20", None, true),
            ("*corp*", "api.corp.example", None, true),
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
            let host = Host::try_from(host).unwrap();
            let host_text = host.to_string();
            assert_eq!(
                BypassRule::compile(pattern).matches((&host).into(), &host_text, port),
                expected,
                "{pattern} {host_text:?} {port:?}"
            );
        }
    }

    #[tokio::test]
    async fn system_config_cache_refreshes_lazily_after_its_ttl() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let reader: Arc<SystemProxyConfigReader> = Arc::new({
            let calls = calls.clone();
            move || {
                let call = calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let host = match call {
                    0 => "old.proxy",
                    1 => "new.proxy",
                    _ => "newest.proxy",
                };
                Ok(SystemProxyConfig::default().with_http_proxy(proxy(Protocol::HTTP, host, 8080)))
            }
        });
        let layer = SystemProxyLayer::try_from_system_with_reader(Duration::ZERO, reader).unwrap();

        let first = layer.config();
        assert_eq!(
            first.http_proxy().unwrap().address.host.to_str(),
            "old.proxy"
        );

        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if layer
                    .config()
                    .http_proxy()
                    .is_some_and(|proxy| proxy.address.host.to_str() == "newest.proxy")
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(calls.load(std::sync::atomic::Ordering::Relaxed) >= 3);
    }

    #[test]
    fn system_config_cache_honors_a_custom_ttl() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (unexpected_refresh, refreshed) = std::sync::mpsc::channel();
        let reader: Arc<SystemProxyConfigReader> = Arc::new({
            let calls = calls.clone();
            move || {
                let call = calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if call > 0 {
                    unexpected_refresh.send(()).unwrap();
                }
                Ok(SystemProxyConfig::default())
            }
        });
        let layer =
            SystemProxyLayer::try_from_system_with_reader(Duration::from_secs(60), reader).unwrap();

        for _ in 0..10 {
            drop(layer.config());
        }
        assert!(refreshed.recv_timeout(Duration::from_millis(100)).is_err());
        assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 1);
    }
}
