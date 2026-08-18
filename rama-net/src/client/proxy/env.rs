use std::{
    fmt,
    sync::{Arc, OnceLock},
};

use parking_lot::Mutex;
use rama_core::{
    Layer, Service,
    error::{BoxError, ErrorContext as _, ErrorExt as _},
    error_sink::ErrorSink,
    extensions::ExtensionsRef,
};
use rama_utils::macros::generate_set_and_with;

use crate::{
    Protocol,
    address::ProxyAddress,
    input_ext::{AuthorityInputExt, ProtocolInputExt, UriInputExt},
};

use super::{
    ProxyRoute, ProxyRoutes,
    address::read_proxy_environment_variable,
    bypass::{BypassRule, BypassRuleDialect},
    system::{absolute_uri, is_already_routed, request_protocol},
};

const ALL_PROXY_ENV: &[&str] = &["all_proxy", "ALL_PROXY"];
const NO_PROXY_ENV: &[&str] = &["no_proxy", "NO_PROXY"];

type EnvironmentReader = dyn Fn(&str) -> Result<Option<String>, BoxError> + Send + Sync + 'static;

#[derive(Clone)]
struct CachedLoadError(Arc<BoxError>);

impl fmt::Debug for CachedLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for CachedLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl core::error::Error for CachedLoadError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(self.0.as_ref().as_ref())
    }
}

#[derive(Clone)]
enum LoadErrorPolicy {
    Reject,
    Handle(Arc<dyn ErrorSink>),
}

impl fmt::Debug for LoadErrorPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reject => f.write_str("Reject"),
            Self::Handle(_) => f.write_str("Handle(_)"),
        }
    }
}

fn env_names(names: impl IntoIterator<Item = impl Into<String>>) -> Arc<[Box<str>]> {
    names
        .into_iter()
        .map(|name| name.into().into_boxed_str())
        .collect()
}

fn default_env_names(names: &'static [&'static str]) -> Arc<[Box<str>]> {
    env_names(names.iter().copied())
}

fn first_non_empty_value<'a>(
    names: &'a [Box<str>],
    reader: &EnvironmentReader,
) -> Result<Option<(&'a str, String)>, BoxError> {
    for name in names {
        let Some(value) = reader(name)? else {
            continue;
        };
        if !value.trim().is_empty() {
            return Ok(Some((name, value)));
        }
    }
    Ok(None)
}

#[derive(Clone)]
struct LazyProxyAddress {
    names: Arc<[Box<str>]>,
    reader: Arc<EnvironmentReader>,
    cached: Arc<OnceLock<Result<Option<ProxyAddress>, CachedLoadError>>>,
}

impl fmt::Debug for LazyProxyAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LazyProxyAddress")
            .field("names", &self.names)
            .field("cached", &self.cached.get())
            .finish_non_exhaustive()
    }
}

impl LazyProxyAddress {
    fn new(names: &'static [&'static str], reader: Arc<EnvironmentReader>) -> Self {
        Self::with_names(default_env_names(names), reader)
    }

    fn with_names(names: Arc<[Box<str>]>, reader: Arc<EnvironmentReader>) -> Self {
        Self {
            names,
            reader,
            cached: Arc::new(OnceLock::new()),
        }
    }

    fn set_names(&mut self, names: impl IntoIterator<Item = impl Into<String>>) {
        self.names = env_names(names);
        self.cached = Arc::new(OnceLock::new());
    }

    fn reset(&mut self) {
        self.cached = Arc::new(OnceLock::new());
    }

    fn load(&self, policy: &LoadErrorPolicy) -> Result<Option<ProxyAddress>, BoxError> {
        match self.cached.get_or_init(|| match self.load_uncached() {
            Ok(address) => Ok(address),
            Err(error) => match policy {
                LoadErrorPolicy::Reject => Err(CachedLoadError(Arc::new(error))),
                LoadErrorPolicy::Handle(sink) => {
                    sink.sink_error(error);
                    Ok(None)
                }
            },
        }) {
            Ok(address) => Ok(address.clone()),
            Err(error) => Err(Box::new(error.clone())),
        }
    }

    fn load_uncached(&self) -> Result<Option<ProxyAddress>, BoxError> {
        let Some((name, value)) = first_non_empty_value(&self.names, self.reader.as_ref())? else {
            return Ok(None);
        };
        value
            .trim()
            .parse::<ProxyAddress>()
            .map(Some)
            .context("parse proxy environment variable")
            .context_str_field("environment_variable", name)
    }
}

#[derive(Clone)]
struct LazySchemeProxyAddresses {
    reader: Arc<EnvironmentReader>,
    overrides: Arc<ahash::HashMap<Protocol, Arc<[Box<str>]>>>,
    cached: Arc<Mutex<ahash::HashMap<Protocol, LazyProxyAddress>>>,
}

impl fmt::Debug for LazySchemeProxyAddresses {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LazySchemeProxyAddresses")
            .field("overrides", &self.overrides)
            .field("cached_protocols", &self.cached.lock().keys())
            .finish_non_exhaustive()
    }
}

impl LazySchemeProxyAddresses {
    fn new(reader: Arc<EnvironmentReader>) -> Self {
        Self {
            reader,
            overrides: Arc::new(ahash::HashMap::default()),
            cached: Arc::new(Mutex::new(ahash::HashMap::default())),
        }
    }

    fn set_names(
        &mut self,
        protocol: Protocol,
        names: impl IntoIterator<Item = impl Into<String>>,
    ) {
        let mut overrides = self.overrides.as_ref().clone();
        overrides.insert(protocol, env_names(names));
        self.overrides = Arc::new(overrides);
        self.cached = Arc::new(Mutex::new(ahash::HashMap::default()));
    }

    fn reset(&mut self) {
        self.cached = Arc::new(Mutex::new(ahash::HashMap::default()));
    }

    fn load(
        &self,
        protocol: &Protocol,
        policy: &LoadErrorPolicy,
    ) -> Result<Option<ProxyAddress>, BoxError> {
        let loader = {
            let mut cached = self.cached.lock();
            cached
                .entry(protocol.clone())
                .or_insert_with(|| {
                    let names = self
                        .overrides
                        .get(protocol)
                        .cloned()
                        .unwrap_or_else(|| default_scheme_env_names(protocol));
                    LazyProxyAddress::with_names(names, self.reader.clone())
                })
                .clone()
        };
        loader.load(policy)
    }
}

fn default_scheme_env_names(protocol: &Protocol) -> Arc<[Box<str>]> {
    let scheme = protocol.as_str();
    if *protocol == Protocol::HTTP {
        return env_names([format!("{scheme}_proxy")]);
    }
    env_names([
        format!("{scheme}_proxy"),
        format!("{}_PROXY", scheme.to_ascii_uppercase()),
    ])
}

/// Lazily select a proxy from curl-compatible environment variables.
///
/// HTTP requests use lowercase `http_proxy`; uppercase `HTTP_PROXY` is never
/// read because CGI turns an incoming `Proxy` header into that variable.
/// Every request first tries its URL scheme's lowercase and uppercase proxy
/// variables, then `all_proxy` and `ALL_PROXY`. HTTP is the security-sensitive
/// exception: only lowercase `http_proxy` is accepted. For example, WebSocket
/// requests use `ws_proxy` / `WS_PROXY`, not `http_proxy`.
///
/// Every variable group has an independent, shared cache. A request only reads
/// the group it needs, and `ALL_PROXY` is not read when a scheme-specific proxy
/// exists. Empty name lists disable the corresponding group.
///
/// See curl's [proxy environment variable documentation][curl-env] for the
/// interoperability rules this layer follows.
///
/// [curl-env]: https://everything.curl.dev/usingcurl/proxies/env.html
#[derive(Clone)]
pub struct ProxyEnvLayer {
    schemes: LazySchemeProxyAddresses,
    all: LazyProxyAddress,
    load_error_policy: LoadErrorPolicy,
    overwrite: bool,
}

impl fmt::Debug for ProxyEnvLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyEnvLayer")
            .field("schemes", &self.schemes)
            .field("all", &self.all)
            .field("load_error_policy", &self.load_error_policy)
            .field("overwrite", &self.overwrite)
            .finish()
    }
}

impl ProxyEnvLayer {
    /// Create a lazy layer backed by the process environment.
    #[must_use]
    pub fn new() -> Self {
        Self::new_with_reader(read_proxy_environment_variable)
    }

    /// Create a lazy layer backed by a custom environment reader.
    ///
    /// This is useful for applications which virtualize their environment and
    /// for deterministic tests. `Ok(None)` means that the name is not defined.
    #[must_use]
    pub fn new_with_reader<F>(reader: F) -> Self
    where
        F: Fn(&str) -> Result<Option<String>, BoxError> + Send + Sync + 'static,
    {
        let reader: Arc<EnvironmentReader> = Arc::new(reader);
        Self {
            schemes: LazySchemeProxyAddresses::new(reader.clone()),
            all: LazyProxyAddress::new(ALL_PROXY_ENV, reader),
            load_error_policy: LoadErrorPolicy::Reject,
            overwrite: false,
        }
    }

    generate_set_and_with! {
        /// Replace the ordered HTTP proxy environment-variable names.
        ///
        /// The default is only `http_proxy`. Supplying no names disables this
        /// scheme-specific lookup.
        pub fn http_proxy_env_vars(
            mut self,
            names: impl IntoIterator<Item = impl Into<String>>,
        ) -> Self {
            self.schemes.set_names(Protocol::HTTP, names);
            self
        }
    }

    generate_set_and_with! {
        /// Replace the ordered HTTPS proxy environment-variable names.
        ///
        /// The default is `https_proxy`, then `HTTPS_PROXY`. Supplying no names
        /// disables this scheme-specific lookup.
        pub fn https_proxy_env_vars(
            mut self,
            names: impl IntoIterator<Item = impl Into<String>>,
        ) -> Self {
            self.schemes.set_names(Protocol::HTTPS, names);
            self
        }
    }

    generate_set_and_with! {
        /// Replace the ordered proxy environment-variable names for one URL
        /// protocol. Supplying no names disables its scheme-specific lookup.
        pub fn protocol_proxy_env_vars(
            mut self,
            protocol: Protocol,
            names: impl IntoIterator<Item = impl Into<String>>,
        ) -> Self {
            self.schemes.set_names(protocol, names);
            self
        }
    }

    generate_set_and_with! {
        /// Replace the ordered all-protocol proxy environment-variable names.
        ///
        /// The default is `all_proxy`, then `ALL_PROXY`. Supplying no names
        /// disables the fallback entirely.
        pub fn all_proxy_env_vars(
            mut self,
            names: impl IntoIterator<Item = impl Into<String>>,
        ) -> Self {
            self.all.set_names(names);
            self
        }
    }

    generate_set_and_with! {
        /// Handle each lazy load error through an [`ErrorSink`] and treat that
        /// variable group as absent. By default errors reject the request.
        ///
        /// The handled result is cached, so a sink is called at most once for
        /// each variable group.
        pub fn load_error_sink(mut self, sink: impl ErrorSink) -> Self {
            self.load_error_policy = LoadErrorPolicy::Handle(Arc::new(sink));
            self.schemes.reset();
            self.all.reset();
            self
        }
    }

    generate_set_and_with! {
        /// Replace an existing [`ProxyRoute`] or
        /// [`ProxyRoutes`][crate::client::ProxyRoutes] decision.
        pub fn overwrite(mut self, overwrite: bool) -> Self {
            self.overwrite = overwrite;
            self
        }
    }

    fn proxy_for(&self, protocol: &Protocol) -> Result<Option<ProxyAddress>, BoxError> {
        let specific = self.schemes.load(protocol, &self.load_error_policy)?;
        match specific {
            Some(address) => Ok(Some(address)),
            None => self.all.load(&self.load_error_policy),
        }
    }
}

impl Default for ProxyEnvLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Layer<S> for ProxyEnvLayer {
    type Service = ProxyEnvService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ProxyEnvService {
            inner,
            layer: self.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        ProxyEnvService { inner, layer: self }
    }
}

/// Service produced by [`ProxyEnvLayer`].
#[derive(Debug, Clone)]
pub struct ProxyEnvService<S> {
    inner: S,
    layer: ProxyEnvLayer,
}

impl<S, Input> Service<Input> for ProxyEnvService<S>
where
    S: Service<Input, Error: Into<BoxError>>,
    Input: UriInputExt + ProtocolInputExt + ExtensionsRef + Send + 'static,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        if !self.layer.overwrite && is_already_routed(&input) {
            return self.inner.serve(input).await.map_err(Into::into);
        }
        if let Some(address) = self.layer.proxy_for(&request_protocol(&input))? {
            let route = ProxyRoute::Proxy(address);
            if self.layer.overwrite {
                input
                    .extensions()
                    .insert(ProxyRoutes::from(route).with_overwrite(true));
            } else {
                input.extensions().insert(route);
            }
        }
        self.inner.serve(input).await.map_err(Into::into)
    }
}

#[derive(Clone)]
struct LazyBypassRules {
    names: Arc<[Box<str>]>,
    reader: Arc<EnvironmentReader>,
    cached: Arc<OnceLock<Result<Arc<[BypassRule]>, CachedLoadError>>>,
}

impl fmt::Debug for LazyBypassRules {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LazyBypassRules")
            .field("names", &self.names)
            .field("cached", &self.cached.get())
            .finish_non_exhaustive()
    }
}

impl LazyBypassRules {
    fn new(reader: Arc<EnvironmentReader>) -> Self {
        Self {
            names: default_env_names(NO_PROXY_ENV),
            reader,
            cached: Arc::new(OnceLock::new()),
        }
    }

    fn set_names(&mut self, names: impl IntoIterator<Item = impl Into<String>>) {
        self.names = env_names(names);
        self.cached = Arc::new(OnceLock::new());
    }

    fn reset(&mut self) {
        self.cached = Arc::new(OnceLock::new());
    }

    fn load(&self, policy: &LoadErrorPolicy) -> Result<Arc<[BypassRule]>, BoxError> {
        match self
            .cached
            .get_or_init(|| match self.load_uncached(policy) {
                Ok(rules) => Ok(rules),
                Err(error) => match policy {
                    LoadErrorPolicy::Reject => Err(CachedLoadError(Arc::new(error))),
                    LoadErrorPolicy::Handle(sink) => {
                        sink.sink_error(error);
                        Ok(Arc::new([]))
                    }
                },
            }) {
            Ok(rules) => Ok(rules.clone()),
            Err(error) => Err(Box::new(error.clone())),
        }
    }

    fn load_uncached(&self, policy: &LoadErrorPolicy) -> Result<Arc<[BypassRule]>, BoxError> {
        let Some((name, value)) = first_non_empty_value(&self.names, self.reader.as_ref())? else {
            return Ok(Arc::new([]));
        };
        let mut rules = Vec::new();
        for value in value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            match BypassRule::compile_with_dialect(value, BypassRuleDialect::NoProxy) {
                Ok(rule) => rules.push(rule),
                Err(error) => {
                    let error = error
                        .context("parse no-proxy environment variable")
                        .context_str_field("environment_variable", name);
                    match policy {
                        LoadErrorPolicy::Reject => return Err(error),
                        LoadErrorPolicy::Handle(sink) => sink.sink_error(error),
                    }
                }
            }
        }
        Ok(rules.into())
    }
}

/// Lazily apply conventional `NO_PROXY` bypass rules.
///
/// Lowercase `no_proxy` takes precedence over uppercase `NO_PROXY`. Entries
/// are comma-separated. As in curl, wget, Go and Python, a plain domain such as
/// `example.com` matches its apex and descendants. Leading-dot and `*.` forms
/// have the same subtree behavior. Rama additionally accepts arbitrary host
/// globs; a single `*` matches every host, and IP addresses and CIDR networks
/// use typed address matching. When a rule matches, the layer inserts
/// [`ProxyRoute::Direct`].
///
/// Place this layer before explicit, environment, and system proxy layers to
/// give bypass rules priority without enabling route overwrites.
///
/// The environment-variable names and core matching behavior follow curl's
/// [proxy environment variable documentation][curl-env]. Rama's arbitrary
/// glob support is a backwards-compatible extension of that shared convention.
///
/// [curl-env]: https://everything.curl.dev/usingcurl/proxies/env.html
#[derive(Clone)]
pub struct NoProxyEnvLayer {
    rules: LazyBypassRules,
    load_error_policy: LoadErrorPolicy,
    overwrite: bool,
}

impl fmt::Debug for NoProxyEnvLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NoProxyEnvLayer")
            .field("rules", &self.rules)
            .field("load_error_policy", &self.load_error_policy)
            .field("overwrite", &self.overwrite)
            .finish()
    }
}

impl NoProxyEnvLayer {
    /// Create a lazy layer backed by the process environment.
    #[must_use]
    pub fn new() -> Self {
        Self::new_with_reader(read_proxy_environment_variable)
    }

    /// Create a lazy layer backed by a custom environment reader.
    #[must_use]
    pub fn new_with_reader<F>(reader: F) -> Self
    where
        F: Fn(&str) -> Result<Option<String>, BoxError> + Send + Sync + 'static,
    {
        Self {
            rules: LazyBypassRules::new(Arc::new(reader)),
            load_error_policy: LoadErrorPolicy::Reject,
            overwrite: false,
        }
    }

    generate_set_and_with! {
        /// Replace the ordered no-proxy environment-variable names.
        ///
        /// The default is `no_proxy`, then `NO_PROXY`. Supplying no names
        /// disables environment bypass rules.
        pub fn no_proxy_env_vars(
            mut self,
            names: impl IntoIterator<Item = impl Into<String>>,
        ) -> Self {
            self.rules.set_names(names);
            self
        }
    }

    generate_set_and_with! {
        /// Send invalid rules or environment-read errors to an [`ErrorSink`].
        /// Invalid individual rules are omitted while valid rules remain in
        /// effect. By default any such error rejects the request.
        pub fn load_error_sink(mut self, sink: impl ErrorSink) -> Self {
            self.load_error_policy = LoadErrorPolicy::Handle(Arc::new(sink));
            self.rules.reset();
            self
        }
    }

    generate_set_and_with! {
        /// Replace an existing [`ProxyRoute`] or
        /// [`ProxyRoutes`][crate::client::ProxyRoutes] decision with a direct
        /// route when a no-proxy rule matches.
        pub fn overwrite(mut self, overwrite: bool) -> Self {
            self.overwrite = overwrite;
            self
        }
    }
}

impl Default for NoProxyEnvLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Layer<S> for NoProxyEnvLayer {
    type Service = NoProxyEnvService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        NoProxyEnvService {
            inner,
            layer: self.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        NoProxyEnvService { inner, layer: self }
    }
}

/// Service produced by [`NoProxyEnvLayer`].
#[derive(Debug, Clone)]
pub struct NoProxyEnvService<S> {
    inner: S,
    layer: NoProxyEnvLayer,
}

impl<S, Input> Service<Input> for NoProxyEnvService<S>
where
    S: Service<Input, Error: Into<BoxError>>,
    Input: UriInputExt + AuthorityInputExt + ProtocolInputExt + ExtensionsRef + Send + 'static,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        if !self.layer.overwrite && is_already_routed(&input) {
            return self.inner.serve(input).await.map_err(Into::into);
        }
        let rules = self.layer.rules.load(&self.layer.load_error_policy)?;
        if !rules.is_empty() {
            let Ok(uri) = absolute_uri(&input) else {
                return self.inner.serve(input).await.map_err(Into::into);
            };
            let Some(host) = uri.host() else {
                return self.inner.serve(input).await.map_err(Into::into);
            };
            let port = uri
                .port_u16()
                .or_else(|| uri.scheme().and_then(Protocol::default_port));
            if super::bypass::matches_any_rule(&rules, uri.scheme(), host, port) {
                if self.layer.overwrite {
                    input
                        .extensions()
                        .insert(ProxyRoutes::from(ProxyRoute::Direct).with_overwrite(true));
                } else {
                    input.extensions().insert(ProxyRoute::Direct);
                }
            }
        }
        self.inner.serve(input).await.map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use ahash::HashMap;
    use parking_lot::Mutex;
    use rama_core::{extensions::Extensions, service::service_fn};

    use crate::{
        address::{HostWithOptPort, ProxyAddress},
        client::ProxyRoutes,
        uri::Uri,
    };

    use super::*;

    #[derive(Debug, Clone)]
    struct TestInput {
        uri: Uri,
        protocol: Option<Protocol>,
        authority: Option<HostWithOptPort>,
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

        fn with_route(self, route: ProxyRoute) -> Self {
            self.extensions.insert(route);
            self
        }
    }

    impl UriInputExt for TestInput {
        fn uri(&self) -> &Uri {
            &self.uri
        }
    }

    impl ProtocolInputExt for TestInput {
        fn protocol(&self) -> Option<&Protocol> {
            self.protocol.as_ref().or_else(|| self.uri.scheme())
        }
    }

    impl AuthorityInputExt for TestInput {
        fn authority(&self) -> Option<HostWithOptPort> {
            self.authority.clone().or_else(|| {
                self.uri
                    .authority()
                    .map(|authority| authority.into_owned().address)
            })
        }
    }

    impl ExtensionsRef for TestInput {
        fn extensions(&self) -> &Extensions {
            &self.extensions
        }
    }

    type SeenRoutes = Arc<Mutex<Vec<Option<ProxyRoute>>>>;

    fn recorder() -> (
        impl Service<TestInput, Output = (), Error = Infallible> + Clone,
        SeenRoutes,
    ) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let service = crate::client::ProxyRoutesLayer::new().into_layer(service_fn({
            let seen = seen.clone();
            move |input: TestInput| {
                let route =
                    input
                        .extensions
                        .get_ref::<ProxyRoutes>()
                        .and_then(|routes| match routes.as_slice() {
                            [route] => Some(route.clone()),
                            _ => None,
                        });
                seen.lock().push(route);
                async { Ok::<_, Infallible>(()) }
            }
        }));
        (service, seen)
    }

    type EnvReads = Arc<Mutex<Vec<String>>>;

    fn environment(
        values: impl IntoIterator<Item = (&'static str, &'static str)>,
    ) -> (
        impl Fn(&str) -> Result<Option<String>, BoxError> + Send + Sync + 'static,
        EnvReads,
    ) {
        let values = Arc::new(
            values
                .into_iter()
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
                .collect::<HashMap<_, _>>(),
        );
        let reads = Arc::new(Mutex::new(Vec::new()));
        let reader = {
            let reads = reads.clone();
            move |name: &str| {
                reads.lock().push(name.to_owned());
                Ok(values.get(name).cloned())
            }
        };
        (reader, reads)
    }

    fn proxy_host(route: Option<&ProxyRoute>) -> Option<String> {
        route
            .and_then(ProxyRoute::proxy_address)
            .map(|address| address.address.host.to_string())
    }

    #[test]
    fn process_environment_reader_rejects_invalid_names() {
        for name in ["", "RAMA=PROXY", "RAMA\0PROXY"] {
            read_proxy_environment_variable(name).unwrap_err();
        }
        assert_eq!(
            read_proxy_environment_variable("RAMA_PROXY_ENV_TEST_DEFINITELY_ABSENT_9D72B4")
                .unwrap(),
            None,
        );
    }

    #[tokio::test]
    async fn proxy_variables_follow_curl_precedence_and_load_lazily() {
        let (reader, reads) = environment([
            ("http_proxy", "http://http.proxy:8080"),
            ("HTTP_PROXY", "http://unsafe.proxy:8080"),
            ("HTTPS_PROXY", "http://https.proxy:8443"),
            ("ALL_PROXY", "socks5h://all.proxy:1080"),
        ]);
        let (inner, seen) = recorder();
        let service = ProxyEnvLayer::new_with_reader(reader).into_layer(inner);

        service
            .serve(TestInput::new("http://example.com/"))
            .await
            .unwrap();
        service
            .serve(TestInput::new("https://example.com/"))
            .await
            .unwrap();
        service
            .serve(TestInput::new("ftp://example.com/file"))
            .await
            .unwrap();
        service
            .serve(TestInput::new("ws://example.com/socket"))
            .await
            .unwrap();

        let seen = seen.lock();
        assert_eq!(proxy_host(seen[0].as_ref()).as_deref(), Some("http.proxy"));
        assert_eq!(proxy_host(seen[1].as_ref()).as_deref(), Some("https.proxy"));
        assert_eq!(proxy_host(seen[2].as_ref()).as_deref(), Some("all.proxy"));
        assert_eq!(proxy_host(seen[3].as_ref()).as_deref(), Some("all.proxy"));
        assert_eq!(
            reads.lock().as_slice(),
            [
                "http_proxy",
                "https_proxy",
                "HTTPS_PROXY",
                "ftp_proxy",
                "FTP_PROXY",
                "all_proxy",
                "ALL_PROXY",
                "ws_proxy",
                "WS_PROXY",
            ]
        );
    }

    #[tokio::test]
    async fn http_proxy_is_not_an_https_fallback() {
        let (reader, reads) = environment([("http_proxy", "http://http.proxy:8080")]);
        let (inner, seen) = recorder();
        let service = ProxyEnvLayer::new_with_reader(reader).into_layer(inner);

        service
            .serve(TestInput::new("https://example.com/"))
            .await
            .unwrap();
        service
            .serve(TestInput::new("http://example.com/"))
            .await
            .unwrap();

        assert!(seen.lock()[0].is_none());
        assert_eq!(
            proxy_host(seen.lock()[1].as_ref()).as_deref(),
            Some("http.proxy")
        );
        assert_eq!(
            reads.lock().as_slice(),
            [
                "https_proxy",
                "HTTPS_PROXY",
                "all_proxy",
                "ALL_PROXY",
                "http_proxy"
            ]
        );
    }

    #[tokio::test]
    async fn malformed_proxy_group_is_not_parsed_for_another_scheme() {
        let (reader, reads) = environment([
            ("http_proxy", "http://"),
            ("HTTPS_PROXY", "http://secure.proxy:8443"),
        ]);
        let (inner, seen) = recorder();

        ProxyEnvLayer::new_with_reader(reader)
            .into_layer(inner)
            .serve(TestInput::new("https://example.com/"))
            .await
            .unwrap();

        assert_eq!(
            proxy_host(seen.lock()[0].as_ref()).as_deref(),
            Some("secure.proxy")
        );
        assert_eq!(reads.lock().as_slice(), ["https_proxy", "HTTPS_PROXY"]);
    }

    #[tokio::test]
    async fn empty_lowercase_value_falls_through_to_uppercase() {
        let (reader, reads) = environment([
            ("https_proxy", "  "),
            ("HTTPS_PROXY", "http://upper.proxy:8443"),
        ]);
        let (inner, seen) = recorder();

        ProxyEnvLayer::new_with_reader(reader)
            .into_layer(inner)
            .serve(TestInput::new("https://example.com/"))
            .await
            .unwrap();

        assert_eq!(
            proxy_host(seen.lock()[0].as_ref()).as_deref(),
            Some("upper.proxy")
        );
        assert_eq!(reads.lock().as_slice(), ["https_proxy", "HTTPS_PROXY"]);
    }

    #[tokio::test]
    async fn non_empty_lowercase_value_wins_over_uppercase() {
        let (reader, reads) = environment([
            ("https_proxy", "http://lower.proxy:8443"),
            ("HTTPS_PROXY", "http://upper.proxy:8443"),
        ]);
        let (inner, seen) = recorder();

        ProxyEnvLayer::new_with_reader(reader)
            .into_layer(inner)
            .serve(TestInput::new("https://example.com/"))
            .await
            .unwrap();

        assert_eq!(
            proxy_host(seen.lock()[0].as_ref()).as_deref(),
            Some("lower.proxy")
        );
        assert_eq!(reads.lock().as_slice(), ["https_proxy"]);
    }

    #[tokio::test]
    async fn proxy_variable_names_are_customizable_and_groups_can_be_disabled() {
        let (reader, reads) = environment([("RAMA_PROXY", "socks5://custom.proxy:1080")]);
        let (inner, seen) = recorder();
        let service = ProxyEnvLayer::new_with_reader(reader)
            .with_http_proxy_env_vars(["RAMA_PROXY"])
            .with_https_proxy_env_vars([] as [&str; 0])
            .with_all_proxy_env_vars([] as [&str; 0])
            .into_layer(inner);

        service
            .serve(TestInput::new("http://example.com/"))
            .await
            .unwrap();
        service
            .serve(TestInput::new("https://example.com/"))
            .await
            .unwrap();

        let seen = seen.lock();
        assert_eq!(
            proxy_host(seen[0].as_ref()).as_deref(),
            Some("custom.proxy")
        );
        assert!(seen[1].is_none());
        assert_eq!(reads.lock().as_slice(), ["RAMA_PROXY"]);
    }

    #[tokio::test]
    async fn websocket_and_custom_protocols_use_their_own_lazy_groups() {
        let (reader, reads) = environment([
            ("WS_PROXY", "http://websocket.proxy:8080"),
            ("git_proxy", "socks5://git.proxy:1080"),
            ("ALL_PROXY", "http://fallback.proxy:8080"),
        ]);
        let (inner, seen) = recorder();
        let service = ProxyEnvLayer::new_with_reader(reader).into_layer(inner);

        service
            .serve(TestInput::new("ws://example.com/socket"))
            .await
            .unwrap();
        service
            .serve(TestInput::new("git://example.com/repository"))
            .await
            .unwrap();

        assert_eq!(
            seen.lock()
                .iter()
                .map(|route| proxy_host(route.as_ref()).unwrap())
                .collect::<Vec<_>>(),
            ["websocket.proxy", "git.proxy"]
        );
        assert_eq!(
            reads.lock().as_slice(),
            ["ws_proxy", "WS_PROXY", "git_proxy"]
        );
    }

    #[tokio::test]
    async fn proxy_load_errors_reject_by_default_and_are_cached() {
        let (reader, reads) = environment([("http_proxy", "http://")]);
        let (inner, _) = recorder();
        let service = ProxyEnvLayer::new_with_reader(reader).into_layer(inner);

        for _ in 0..2 {
            service
                .serve(TestInput::new("http://example.com/"))
                .await
                .unwrap_err();
        }
        assert_eq!(reads.lock().as_slice(), ["http_proxy"]);
    }

    #[tokio::test]
    async fn handled_proxy_error_falls_back_and_sinks_once() {
        let (reader, reads) = environment([
            ("http_proxy", "http://"),
            ("all_proxy", "socks5://fallback.proxy:1080"),
        ]);
        let sink_calls = Arc::new(Mutex::new(Vec::new()));
        let (inner, seen) = recorder();
        let service = ProxyEnvLayer::new_with_reader(reader)
            .with_load_error_sink({
                let sink_calls = sink_calls.clone();
                move |error: BoxError| sink_calls.lock().push(error.to_string())
            })
            .into_layer(inner);

        for _ in 0..2 {
            service
                .serve(TestInput::new("http://example.com/"))
                .await
                .unwrap();
        }

        assert_eq!(sink_calls.lock().len(), 1);
        assert_eq!(reads.lock().as_slice(), ["http_proxy", "all_proxy"]);
        assert!(
            seen.lock()
                .iter()
                .all(|route| proxy_host(route.as_ref()).as_deref() == Some("fallback.proxy"))
        );
    }

    #[tokio::test]
    async fn preserved_route_avoids_every_environment_read() {
        let (reader, reads) = environment([("http_proxy", "http://env.proxy:8080")]);
        let (inner, seen) = recorder();

        ProxyEnvLayer::new_with_reader(reader)
            .into_layer(inner)
            .serve(
                TestInput::new("http://example.com/").with_route(ProxyRoute::Proxy(
                    "http://explicit.proxy:8080"
                        .parse::<ProxyAddress>()
                        .unwrap(),
                )),
            )
            .await
            .unwrap();

        assert!(reads.lock().is_empty());
        assert_eq!(
            proxy_host(seen.lock()[0].as_ref()).as_deref(),
            Some("explicit.proxy")
        );
    }

    #[tokio::test]
    async fn no_proxy_domains_and_networks_use_environment_patterns() {
        let (reader, reads) = environment([("NO_PROXY", ".example.com,10.0.0.0/8")]);
        let (inner, seen) = recorder();
        let service = NoProxyEnvLayer::new_with_reader(reader).into_layer(inner);

        for uri in [
            "http://example.com/",
            "http://api.example.com/",
            "http://nonexample.com/",
            "http://10.2.3.4/",
            "http://11.2.3.4/",
        ] {
            service.serve(TestInput::new(uri)).await.unwrap();
        }

        assert_eq!(
            seen.lock()
                .iter()
                .map(|route| route == &Some(ProxyRoute::Direct))
                .collect::<Vec<_>>(),
            [true, true, false, true, false]
        );
        assert_eq!(reads.lock().as_slice(), ["no_proxy", "NO_PROXY"]);
    }

    #[tokio::test]
    async fn no_proxy_plain_domains_match_descendants_and_globs_are_supported() {
        let (reader, _) = environment([("no_proxy", "exact.example,api-*.example")]);
        let (inner, seen) = recorder();
        let service = NoProxyEnvLayer::new_with_reader(reader).into_layer(inner);

        for uri in [
            "http://exact.example/",
            "http://child.exact.example/",
            "http://api-v1.example/",
            "http://www.example/",
        ] {
            service.serve(TestInput::new(uri)).await.unwrap();
        }

        assert_eq!(
            seen.lock()
                .iter()
                .map(|route| route == &Some(ProxyRoute::Direct))
                .collect::<Vec<_>>(),
            [true, true, true, false]
        );
    }

    #[tokio::test]
    async fn lowercase_no_proxy_wins_over_uppercase() {
        let (reader, reads) =
            environment([("no_proxy", "lower.example"), ("NO_PROXY", "upper.example")]);
        let (inner, seen) = recorder();
        let service = NoProxyEnvLayer::new_with_reader(reader).into_layer(inner);

        service
            .serve(TestInput::new("http://upper.example/"))
            .await
            .unwrap();
        service
            .serve(TestInput::new("http://lower.example/"))
            .await
            .unwrap();

        assert!(seen.lock()[0].is_none());
        assert_eq!(seen.lock()[1], Some(ProxyRoute::Direct));
        assert_eq!(reads.lock().as_slice(), ["no_proxy"]);
    }

    #[tokio::test]
    async fn no_proxy_variable_names_are_customizable() {
        let (reader, reads) = environment([
            ("no_proxy", "lower.example"),
            ("NO_PROXY", "upper.example"),
            ("RAMA_NO_PROXY", "custom.example"),
        ]);
        let (inner, seen) = recorder();
        let service = NoProxyEnvLayer::new_with_reader(reader)
            .with_no_proxy_env_vars(["RAMA_NO_PROXY"])
            .into_layer(inner);

        service
            .serve(TestInput::new("http://custom.example/"))
            .await
            .unwrap();
        service
            .serve(TestInput::new("http://lower.example/"))
            .await
            .unwrap();

        assert_eq!(seen.lock()[0], Some(ProxyRoute::Direct));
        assert!(seen.lock()[1].is_none());
        assert_eq!(reads.lock().as_slice(), ["RAMA_NO_PROXY"]);
    }

    #[tokio::test]
    async fn no_proxy_single_wildcard_matches_every_host() {
        let (reader, _) = environment([("no_proxy", "*")]);
        let (inner, seen) = recorder();
        let service = NoProxyEnvLayer::new_with_reader(reader).into_layer(inner);

        for uri in ["http://example.com/", "https://192.0.2.1/"] {
            service.serve(TestInput::new(uri)).await.unwrap();
        }

        assert!(
            seen.lock()
                .iter()
                .all(|route| route == &Some(ProxyRoute::Direct))
        );
    }

    #[tokio::test]
    async fn no_proxy_port_rules_use_the_destination_default_port() {
        let (reader, _) = environment([("no_proxy", "port.example:80")]);
        let (inner, seen) = recorder();
        let service = NoProxyEnvLayer::new_with_reader(reader).into_layer(inner);

        for uri in [
            "http://port.example/",
            "http://port.example:8080/",
            "https://port.example/",
        ] {
            service.serve(TestInput::new(uri)).await.unwrap();
        }

        assert_eq!(
            seen.lock()
                .iter()
                .map(|route| route == &Some(ProxyRoute::Direct))
                .collect::<Vec<_>>(),
            [true, false, false]
        );
    }

    #[tokio::test]
    async fn no_proxy_passes_hostless_inputs_through() {
        let (reader, _) = environment([("no_proxy", "*")]);
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let service = NoProxyEnvLayer::new_with_reader(reader).into_layer(service_fn({
            let calls = calls.clone();
            move |_input: TestInput| {
                calls.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
                async { Ok::<_, Infallible>(()) }
            }
        }));

        service.serve(TestInput::new("*")).await.unwrap();
        assert_eq!(calls.load(std::sync::atomic::Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn no_proxy_preserves_existing_routes_without_reading_environment() {
        let reads = Arc::new(Mutex::new(Vec::new()));
        let (inner, seen) = recorder();
        let service = NoProxyEnvLayer::new_with_reader({
            let reads = reads.clone();
            move |name| {
                reads.lock().push(name.to_owned());
                Ok(Some("*".to_owned()))
            }
        })
        .into_layer(inner);

        service
            .serve(
                TestInput::new("http://example.com/").with_route(ProxyRoute::Proxy(
                    "http://explicit.proxy:8080".parse().unwrap(),
                )),
            )
            .await
            .unwrap();

        assert!(reads.lock().is_empty());
        assert_eq!(
            proxy_host(seen.lock()[0].as_ref()).as_deref(),
            Some("explicit.proxy")
        );
    }

    #[tokio::test]
    async fn no_proxy_can_overwrite_an_existing_route() {
        let (reader, _) = environment([("no_proxy", "*")]);
        let (inner, seen) = recorder();

        NoProxyEnvLayer::new_with_reader(reader)
            .with_overwrite(true)
            .into_layer(inner)
            .serve(
                TestInput::new("http://example.com/").with_route(ProxyRoute::Proxy(
                    "http://explicit.proxy:8080".parse().unwrap(),
                )),
            )
            .await
            .unwrap();

        assert_eq!(seen.lock()[0], Some(ProxyRoute::Direct));
    }

    #[tokio::test]
    async fn overwrite_replaces_an_authoritative_route_plan() {
        let old_routes = ProxyRoutes::new([
            ProxyRoute::Proxy("http://old.proxy:8080".parse().unwrap()),
            ProxyRoute::Direct,
        ])
        .with_overwrite(true);

        let (proxy_reader, _) = environment([("http_proxy", "http://new.proxy:8080")]);
        let (inner, seen) = recorder();
        let proxy_service = ProxyEnvLayer::new_with_reader(proxy_reader)
            .with_overwrite(true)
            .into_layer(inner);
        let input = TestInput::new("http://example.com/");
        input.extensions.insert(old_routes.clone());
        proxy_service.serve(input).await.unwrap();
        assert_eq!(
            proxy_host(seen.lock()[0].as_ref()).as_deref(),
            Some("new.proxy")
        );

        let (bypass_reader, _) = environment([("no_proxy", "*")]);
        let (inner, seen) = recorder();
        let bypass_service = NoProxyEnvLayer::new_with_reader(bypass_reader)
            .with_overwrite(true)
            .into_layer(inner);
        let input = TestInput::new("http://example.com/");
        input.extensions.insert(old_routes);
        bypass_service.serve(input).await.unwrap();
        assert_eq!(seen.lock()[0], Some(ProxyRoute::Direct));
    }

    #[tokio::test]
    async fn invalid_no_proxy_rules_reject_atomically_by_default() {
        let (reader, reads) = environment([("no_proxy", "example.com,.not a valid domain")]);
        let (inner, _) = recorder();
        let service = NoProxyEnvLayer::new_with_reader(reader).into_layer(inner);

        for _ in 0..2 {
            service
                .serve(TestInput::new("http://example.com/"))
                .await
                .unwrap_err();
        }
        assert_eq!(reads.lock().as_slice(), ["no_proxy"]);
    }

    #[tokio::test]
    async fn handled_invalid_no_proxy_rule_keeps_valid_rules() {
        let (reader, reads) = environment([("no_proxy", "example.com,.not a valid domain")]);
        let sink_calls = Arc::new(Mutex::new(Vec::new()));
        let (inner, seen) = recorder();
        let service = NoProxyEnvLayer::new_with_reader(reader)
            .with_load_error_sink({
                let sink_calls = sink_calls.clone();
                move |error: BoxError| sink_calls.lock().push(error.to_string())
            })
            .into_layer(inner);

        service
            .serve(TestInput::new("http://example.com/"))
            .await
            .unwrap();
        service
            .serve(TestInput::new("http://example.net/"))
            .await
            .unwrap();

        assert_eq!(sink_calls.lock().len(), 1);
        assert_eq!(reads.lock().as_slice(), ["no_proxy"]);
        assert_eq!(seen.lock()[0], Some(ProxyRoute::Direct));
        assert!(seen.lock()[1].is_none());
    }
}
