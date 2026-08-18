use std::{
    env::VarError,
    fmt,
    sync::{Arc, OnceLock},
};

use crate::{
    address::ProxyAddress,
    client::{ProxyRoute, ProxyRoutes},
};
use rama_core::{
    Layer, Service,
    error::{BoxError, BoxErrorExt as _, ErrorContext, ErrorExt as _},
    error_sink::ErrorSink,
    extensions::ExtensionsRef,
    telemetry::tracing,
};

fn proxy_address_from_env(key: &str) -> Result<Option<ProxyAddress>, BoxError> {
    let value = read_proxy_environment_variable(key)?;
    parse_proxy_address_env_value(value.as_deref())
}

pub(super) fn read_proxy_environment_variable(key: &str) -> Result<Option<String>, BoxError> {
    if key.is_empty() || key.bytes().any(|byte| byte == b'\0' || byte == b'=') {
        return Err(
            BoxError::from_static_str("invalid environment variable name")
                .context_str_field("environment_variable", key),
        );
    }
    match std::env::var(key) {
        Ok(value) => Ok(Some(value)),
        Err(VarError::NotPresent) => Ok(None),
        Err(error @ VarError::NotUnicode(_)) => Err(error
            .context("read proxy environment variable")
            .context_str_field("environment_variable", key)),
    }
}

fn parse_proxy_address_env_value(value: Option<&str>) -> Result<Option<ProxyAddress>, BoxError> {
    let value = value.map(str::trim).filter(|value| !value.is_empty());
    value
        .map(|value| value.try_into().context("parse std env proxy info"))
        .transpose()
}

#[derive(Debug, Clone, Default)]
/// Apply one fixed proxy address to any service input with extensions.
///
/// This layer reads application environment variables only when constructed
/// with [`try_from_env`][Self::try_from_env]. It does not inspect operating
/// system proxy settings; use [`SystemProxyLayer`] for those. When the layers
/// are chained, set this layer to preserve routes or place it outside the
/// system layer so environment configuration has priority. Use
/// [`LazyProxyAddressLayer`] when environment lookup should happen only if
/// no higher-priority route has already been selected.
///
/// See [`ProxyAddressService`] for more information.
///
/// [`Extensions`]: rama_core::extensions::Extensions
/// [`SystemProxyLayer`]: crate::client::SystemProxyLayer
pub struct ProxyAddressLayer {
    address: Option<ProxyAddress>,
    preserve: bool,
}

impl ProxyAddressLayer {
    /// Create a new [`ProxyAddressLayer`] that will create
    /// a service to set the given [`ProxyAddress`] as a proxied [`ProxyRoute`].
    #[must_use]
    pub fn new(address: ProxyAddress) -> Self {
        Self::maybe(Some(address))
    }

    /// Create a new [`ProxyAddressLayer`] which will create
    /// a service that will set the given [`ProxyAddress`] as a proxied [`ProxyRoute`] if it is not
    /// `None`.
    #[must_use]
    pub fn maybe(address: Option<ProxyAddress>) -> Self {
        Self {
            address,
            ..Default::default()
        }
    }

    /// Return the configured proxy address, when this layer has one.
    #[must_use]
    pub const fn proxy_address(&self) -> Option<&ProxyAddress> {
        self.address.as_ref()
    }

    /// Try to create a new [`ProxyAddressLayer`] which will establish
    /// a proxy connection over the environment variable `http_proxy`.
    ///
    /// Uppercase `HTTP_PROXY` is deliberately not accepted by default because
    /// CGI derives it from an incoming `Proxy` header. Use
    /// [`ProxyEnvLayer`] for curl-compatible HTTP, HTTPS, and all-protocol
    /// environment selection.
    ///
    /// [`ProxyEnvLayer`]: crate::client::ProxyEnvLayer
    pub fn try_from_env_default() -> Result<Self, BoxError> {
        Self::try_from_env("http_proxy")
    }

    /// Try to create a new [`ProxyAddressLayer`] which will establish
    /// a proxy connection over the given environment variable.
    pub fn try_from_env(key: impl AsRef<str>) -> Result<Self, BoxError> {
        proxy_address_from_env(key.as_ref()).map(Self::maybe)
    }

    rama_utils::macros::generate_set_and_with! {
    /// Preserve an existing [`ProxyRoute`] or [`ProxyRoutes`] decision in the
    /// context if one already exists.
        pub fn preserve(mut self, preserve: bool) -> Self {
            self.preserve = preserve;
            self
        }
    }
}

impl<S> Layer<S> for ProxyAddressLayer {
    type Service = ProxyAddressService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ProxyAddressService::maybe(inner, self.address.clone()).with_preserve(self.preserve)
    }

    fn into_layer(self, inner: S) -> Self::Service {
        ProxyAddressService::maybe(inner, self.address).with_preserve(self.preserve)
    }
}

/// Service produced by [`ProxyAddressLayer`].
///
/// [`Extensions`]: rama_core::extensions::Extensions
#[derive(Debug, Clone)]
pub struct ProxyAddressService<S> {
    inner: S,
    proxy_info: Option<ProxyAddress>,
    preserve: bool,
}

impl<S> ProxyAddressService<S> {
    /// Create a new [`ProxyAddressService`] that will create
    /// a service to set the given [`ProxyAddress`] as a proxied [`ProxyRoute`].
    pub const fn new(inner: S, address: ProxyAddress) -> Self {
        Self::maybe(inner, Some(address))
    }

    /// Create a new [`ProxyAddressService`] which will create
    /// a service that will set the given [`ProxyAddress`] as a proxied [`ProxyRoute`] if it is not
    /// `None`.
    pub const fn maybe(inner: S, address: Option<ProxyAddress>) -> Self {
        Self {
            inner,
            proxy_info: address,
            preserve: false,
        }
    }

    /// Try to create a new [`ProxyAddressService`] which will establish
    /// a proxy connection over the environment variable `http_proxy`.
    ///
    /// Uppercase `HTTP_PROXY` is deliberately not accepted by default because
    /// CGI derives it from an incoming `Proxy` header. Use
    /// [`ProxyEnvLayer`] for curl-compatible HTTP, HTTPS, and all-protocol
    /// environment selection.
    ///
    /// [`ProxyEnvLayer`]: crate::client::ProxyEnvLayer
    pub fn try_from_env_default(inner: S) -> Result<Self, BoxError> {
        Self::try_from_env(inner, "http_proxy")
    }

    /// Try to create a new [`ProxyAddressService`] which will establish
    /// a proxy connection over the given environment variable.
    pub fn try_from_env(inner: S, key: impl AsRef<str>) -> Result<Self, BoxError> {
        proxy_address_from_env(key.as_ref()).map(|address| Self::maybe(inner, address))
    }

    rama_utils::macros::generate_set_and_with! {
        /// Preserve an existing [`ProxyRoute`] or [`ProxyRoutes`] decision in the
        /// context if one already exists.
        pub fn preserve(mut self, preserve: bool) -> Self {
            self.preserve = preserve;
            self
        }
    }
}

type ProxyAddressLoader =
    dyn Fn() -> Result<Option<ProxyAddress>, BoxError> + Send + Sync + 'static;

#[derive(Clone)]
struct CachedProxyAddressError(Arc<BoxError>);

impl fmt::Debug for CachedProxyAddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for CachedProxyAddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl core::error::Error for CachedProxyAddressError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(self.0.as_ref().as_ref())
    }
}

type CachedProxyAddress = Result<Option<ProxyAddress>, CachedProxyAddressError>;

#[derive(Clone)]
enum ProxyAddressLoadErrorPolicy {
    Reject,
    Handle(Arc<dyn ErrorSink>),
}

impl fmt::Debug for ProxyAddressLoadErrorPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reject => f.write_str("Reject"),
            Self::Handle(_) => f.write_str("Handle(_)"),
        }
    }
}

/// Lazily resolve and apply a proxy address to any input with extensions.
///
/// When configured to preserve existing routes, the loader is not consulted
/// if a [`ProxyRoute`] or [`ProxyRoutes`] decision already exists. Otherwise,
/// its result is cached and shared by every clone of the layer and service.
/// This is useful for environment configuration that may never be needed.
#[derive(Clone)]
pub struct LazyProxyAddressLayer {
    loader: Arc<ProxyAddressLoader>,
    cached: Arc<OnceLock<CachedProxyAddress>>,
    load_error_policy: ProxyAddressLoadErrorPolicy,
    preserve: bool,
}

impl fmt::Debug for LazyProxyAddressLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LazyProxyAddressLayer")
            .field("cached", &self.cached.get())
            .field("load_error_policy", &self.load_error_policy)
            .field("preserve", &self.preserve)
            .finish_non_exhaustive()
    }
}

impl LazyProxyAddressLayer {
    /// Create a lazy layer backed by a synchronous, non-blocking loader.
    ///
    /// The loader runs at most once, on the first request that does not already
    /// have a preserved route decision. Both success and failure are cached.
    #[must_use]
    pub fn new<F>(loader: F) -> Self
    where
        F: Fn() -> Result<Option<ProxyAddress>, BoxError> + Send + Sync + 'static,
    {
        Self {
            loader: Arc::new(loader),
            cached: Arc::new(OnceLock::new()),
            load_error_policy: ProxyAddressLoadErrorPolicy::Reject,
            preserve: false,
        }
    }

    /// Lazily read and parse the `http_proxy` environment variable on the
    /// first request without a preserved route.
    ///
    /// Uppercase `HTTP_PROXY` is deliberately not accepted by default because
    /// CGI derives it from an incoming `Proxy` header. Use
    /// [`ProxyEnvLayer`] for curl-compatible HTTP, HTTPS, and all-protocol
    /// environment selection.
    ///
    /// [`ProxyEnvLayer`]: crate::client::ProxyEnvLayer
    #[must_use]
    pub fn from_env_default() -> Self {
        Self::from_env("http_proxy")
    }

    /// Lazily read and parse a proxy address from the named environment
    /// variable on the first request without a preserved route.
    #[must_use]
    pub fn from_env(key: impl Into<String>) -> Self {
        let key = key.into();
        Self::new(move || proxy_address_from_env(&key))
    }

    rama_utils::macros::generate_set_and_with! {
        /// Handle a loader error through an [`ErrorSink`] and continue without
        /// selecting a proxy. By default loader errors reject the request.
        ///
        /// The sink is invoked at most once because the handled result is
        /// cached and shared by every clone of this layer and its service.
        pub fn load_error_sink(
            mut self,
            sink: impl ErrorSink,
        ) -> Self {
            self.load_error_policy = ProxyAddressLoadErrorPolicy::Handle(Arc::new(sink));
            self.cached = Arc::new(OnceLock::new());
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Preserve an existing [`ProxyRoute`] or [`ProxyRoutes`] decision.
        pub fn preserve(mut self, preserve: bool) -> Self {
            self.preserve = preserve;
            self
        }
    }
}

impl<S> Layer<S> for LazyProxyAddressLayer {
    type Service = LazyProxyAddressService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        LazyProxyAddressService {
            inner,
            loader: self.loader.clone(),
            cached: self.cached.clone(),
            load_error_policy: self.load_error_policy.clone(),
            preserve: self.preserve,
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        LazyProxyAddressService {
            inner,
            loader: self.loader,
            cached: self.cached,
            load_error_policy: self.load_error_policy,
            preserve: self.preserve,
        }
    }
}

/// Service produced by [`LazyProxyAddressLayer`].
#[derive(Clone)]
pub struct LazyProxyAddressService<S> {
    inner: S,
    loader: Arc<ProxyAddressLoader>,
    cached: Arc<OnceLock<CachedProxyAddress>>,
    load_error_policy: ProxyAddressLoadErrorPolicy,
    preserve: bool,
}

impl<S: fmt::Debug> fmt::Debug for LazyProxyAddressService<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LazyProxyAddressService")
            .field("inner", &self.inner)
            .field("cached", &self.cached.get())
            .field("load_error_policy", &self.load_error_policy)
            .field("preserve", &self.preserve)
            .finish_non_exhaustive()
    }
}

impl<S, Input> Service<Input> for LazyProxyAddressService<S>
where
    S: Service<Input, Error: Into<BoxError>>,
    Input: ExtensionsRef + Send + 'static,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        if self.preserve
            && (input.extensions().contains::<ProxyRoute>()
                || input.extensions().contains::<ProxyRoutes>())
        {
            return self.inner.serve(input).await.map_err(Into::into);
        }

        let proxy_info = self.cached.get_or_init(|| match (self.loader)() {
            Ok(proxy_info) => Ok(proxy_info),
            Err(error) => match &self.load_error_policy {
                ProxyAddressLoadErrorPolicy::Reject => {
                    Err(CachedProxyAddressError(Arc::new(error)))
                }
                ProxyAddressLoadErrorPolicy::Handle(sink) => {
                    sink.sink_error(error);
                    Ok(None)
                }
            },
        });
        let proxy_info = match proxy_info {
            Ok(proxy_info) => proxy_info,
            Err(error) => return Err(Box::new(error.clone())),
        };

        if let Some(proxy_info) = proxy_info {
            tracing::trace!(
                server.address = %proxy_info.address.host,
                server.port = proxy_info.address.port,
                "setting lazily resolved proxy address",
            );
            input
                .extensions()
                .insert(ProxyRoute::Proxy(proxy_info.clone()));
        }

        self.inner.serve(input).await.map_err(Into::into)
    }
}

impl<S, Input> Service<Input> for ProxyAddressService<S>
where
    S: Service<Input>,
    Input: ExtensionsRef + Send + 'static,
{
    type Output = S::Output;
    type Error = S::Error;

    fn serve(
        &self,
        input: Input,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send + '_ {
        if let Some(ref proxy_info) = self.proxy_info
            && (!self.preserve
                || (!input.extensions().contains::<ProxyRoute>()
                    && !input.extensions().contains::<ProxyRoutes>()))
        {
            tracing::trace!(
                server.address = %proxy_info.address.host,
                server.port = proxy_info.address.port,
                "setting proxy address",
            );
            input
                .extensions()
                .insert(ProxyRoute::Proxy(proxy_info.clone()));
        }
        self.inner.serve(input)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use parking_lot::Mutex;
    use rama_core::{Layer as _, Service as _, extensions::Extensions, service::service_fn};

    use super::*;

    #[derive(Debug, Clone)]
    struct TestInput {
        extensions: Extensions,
    }

    impl TestInput {
        fn new() -> Self {
            Self {
                extensions: Extensions::new(),
            }
        }
    }

    impl ExtensionsRef for TestInput {
        fn extensions(&self) -> &Extensions {
            &self.extensions
        }
    }

    #[test]
    fn proxy_environment_helpers_validate_names_and_values() {
        for name in ["", "RAMA=PROXY", "RAMA\0PROXY"] {
            read_proxy_environment_variable(name).unwrap_err();
        }
        assert_eq!(
            read_proxy_environment_variable("RAMA_PROXY_ADDRESS_ENV_TEST_DEFINITELY_ABSENT_2B6E19")
                .unwrap(),
            None,
        );
        assert_eq!(parse_proxy_address_env_value(None).unwrap(), None);
        assert_eq!(parse_proxy_address_env_value(Some("  ")).unwrap(), None);
        assert_eq!(
            parse_proxy_address_env_value(Some(" http://proxy.example:8080 "))
                .unwrap()
                .unwrap()
                .address
                .host
                .to_str(),
            "proxy.example"
        );
        parse_proxy_address_env_value(Some("http://")).unwrap_err();
    }

    #[tokio::test]
    async fn preserve_respects_singular_and_collected_route_decisions() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let inner = service_fn({
            let seen = seen.clone();
            move |request: TestInput| {
                seen.lock().push((
                    request.extensions().contains::<ProxyRoute>(),
                    request.extensions().contains::<ProxyRoutes>(),
                ));
                async { Ok::<_, Infallible>(()) }
            }
        });
        let layer = ProxyAddressLayer::new("http://proxy.example:8080".parse().unwrap())
            .with_preserve(true);
        let service = layer.into_layer(inner);

        let singular = TestInput::new();
        singular.extensions().insert(ProxyRoute::Direct);
        service.serve(singular).await.unwrap();

        let collected = TestInput::new();
        collected
            .extensions()
            .insert(ProxyRoutes::from(ProxyRoute::Direct));
        service.serve(collected).await.unwrap();

        let undecided = TestInput::new();
        service.serve(undecided).await.unwrap();

        assert_eq!(
            seen.lock().as_slice(),
            [(true, false), (false, true), (true, false)]
        );
    }

    #[tokio::test]
    async fn lazy_loader_skips_preserved_routes_and_shares_cached_result() {
        let calls = Arc::new(AtomicUsize::new(0));
        let proxy: ProxyAddress = "http://proxy.example:8080".parse().unwrap();
        let layer = LazyProxyAddressLayer::new({
            let calls = calls.clone();
            let proxy = proxy.clone();
            move || {
                calls.fetch_add(1, Ordering::AcqRel);
                Ok(Some(proxy.clone()))
            }
        })
        .with_preserve(true);

        let seen = Arc::new(Mutex::new(Vec::new()));
        let service = layer.into_layer(service_fn({
            let seen = seen.clone();
            move |request: TestInput| {
                seen.lock().push((
                    request.extensions().get_ref::<ProxyRoute>().cloned(),
                    request.extensions().contains::<ProxyRoutes>(),
                ));
                async { Ok::<_, Infallible>(()) }
            }
        }));
        let cloned_service = service.clone();

        let singular = TestInput::new();
        singular.extensions().insert(ProxyRoute::Direct);
        service.serve(singular).await.unwrap();

        let collected = TestInput::new();
        collected
            .extensions()
            .insert(ProxyRoutes::from(ProxyRoute::Direct));
        service.serve(collected).await.unwrap();
        assert_eq!(calls.load(Ordering::Acquire), 0);

        service.serve(TestInput::new()).await.unwrap();
        cloned_service.serve(TestInput::new()).await.unwrap();

        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(
            seen.lock().as_slice(),
            [
                (Some(ProxyRoute::Direct), false),
                (None, true),
                (Some(ProxyRoute::Proxy(proxy.clone())), false),
                (Some(ProxyRoute::Proxy(proxy)), false),
            ]
        );
    }

    #[tokio::test]
    async fn lazy_loader_caches_absence_and_failure() {
        let absent_calls = Arc::new(AtomicUsize::new(0));
        let absent_service = LazyProxyAddressLayer::new({
            let absent_calls = absent_calls.clone();
            move || {
                absent_calls.fetch_add(1, Ordering::AcqRel);
                Ok(None)
            }
        })
        .into_layer(service_fn(|request: TestInput| async move {
            Ok::<_, Infallible>(request.extensions().contains::<ProxyRoute>())
        }));

        assert!(!absent_service.serve(TestInput::new()).await.unwrap());
        assert!(!absent_service.serve(TestInput::new()).await.unwrap());
        assert_eq!(absent_calls.load(Ordering::Acquire), 1);

        let error_calls = Arc::new(AtomicUsize::new(0));
        let error_service = LazyProxyAddressLayer::new({
            let error_calls = error_calls.clone();
            move || {
                error_calls.fetch_add(1, Ordering::AcqRel);
                Err(std::io::Error::other("invalid proxy environment").into())
            }
        })
        .into_layer(service_fn(|_request: TestInput| async move {
            Ok::<_, Infallible>(())
        }));

        for _ in 0..2 {
            let error = error_service.serve(TestInput::new()).await.unwrap_err();
            assert_eq!(error.to_string(), "invalid proxy environment");
        }
        assert_eq!(error_calls.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn handled_lazy_loader_error_is_sunk_once_and_treated_as_absent() {
        let loader_calls = Arc::new(AtomicUsize::new(0));
        let sink_calls = Arc::new(AtomicUsize::new(0));
        let service = LazyProxyAddressLayer::new({
            let loader_calls = loader_calls.clone();
            move || {
                loader_calls.fetch_add(1, Ordering::AcqRel);
                Err(std::io::Error::other("invalid proxy environment").into())
            }
        })
        .with_load_error_sink({
            let sink_calls = sink_calls.clone();
            move |error: BoxError| {
                assert_eq!(error.to_string(), "invalid proxy environment");
                sink_calls.fetch_add(1, Ordering::AcqRel);
            }
        })
        .into_layer(service_fn(|request: TestInput| async move {
            Ok::<_, Infallible>(request.extensions().contains::<ProxyRoute>())
        }));

        for _ in 0..2 {
            assert!(!service.serve(TestInput::new()).await.unwrap());
        }
        assert_eq!(loader_calls.load(Ordering::Acquire), 1);
        assert_eq!(sink_calls.load(Ordering::Acquire), 1);
    }
}
