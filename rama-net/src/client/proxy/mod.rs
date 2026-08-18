mod address;
#[doc(inline)]
pub use address::{
    LazyProxyAddressLayer, LazyProxyAddressService, ProxyAddressLayer, ProxyAddressService,
};

mod bypass;

mod env;
#[doc(inline)]
pub use env::{NoProxyEnvLayer, NoProxyEnvService, ProxyEnvLayer, ProxyEnvService};

mod route;
#[doc(inline)]
pub use route::{
    ProxyRoute, ProxyRouteConnectError, ProxyRouteFailureCache, ProxyRouteFailureCacheConfig,
    ProxyRouteFailureCacheConnector, ProxyRouteFailureCacheLayer, ProxyRouteFailureCacheScope,
    ProxyRouteFailureCachedError, ProxyRouteIndex, ProxyRoutes, ProxyRoutesConnector,
    ProxyRoutesConnectorLayer,
};

mod system;
#[doc(inline)]
pub use system::{
    DEFAULT_SYSTEM_PROXY_CONFIG_TTL, SystemProxyConfig, SystemProxyInvalidBypassRulePolicy,
    SystemProxyLayer, SystemProxyPacDisabled, SystemProxyPacDisabledResolver,
    SystemProxyPacRequest, SystemProxyPacResolver, SystemProxyPacService, SystemProxyService,
    proxy_request_uri,
};
