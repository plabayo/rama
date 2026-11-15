mod address;
#[doc(inline)]
pub use address::{
    LazyProxyAddressLayer, LazyProxyAddressService, ProxyAddressLayer, ProxyAddressService,
};

mod bypass;
#[doc(inline)]
pub use bypass::{BypassRules, ProxyBypassLayer, ProxyBypassService};

mod connect;
#[doc(inline)]
pub use connect::{connect_to_proxy, proxy_http_version, proxy_request};

mod direct;
#[doc(inline)]
pub use direct::{DirectOnlyConnector, DirectOnlyConnectorLayer};

mod maybe;
#[doc(inline)]
pub use maybe::{MaybeProxied, MaybeProxiedConnector, ProxiedRoute, ProxySelector};

mod env;
#[doc(inline)]
pub use env::{NoProxyEnvLayer, NoProxyEnvService, ProxyEnvLayer, ProxyEnvService};

mod load;

mod route;
#[doc(inline)]
pub use route::{
    EstablishedProxyRoute, ProxyRoute, ProxyRouteConnectError, ProxyRouteContext,
    ProxyRouteFailureCache, ProxyRouteFailureCacheConfig, ProxyRouteFailureCacheConnector,
    ProxyRouteFailureCacheLayer, ProxyRouteFailureCacheScope, ProxyRouteFailureCachedError,
    ProxyRouteIndex, ProxyRoutes, ProxyRoutesConnector, ProxyRoutesConnectorLayer,
    ProxyRoutesLayer, ProxyRoutesService,
};

mod system;
#[doc(inline)]
pub use system::{
    DEFAULT_SYSTEM_PROXY_CONFIG_TTL, SystemProxyConfig, SystemProxyConnectLayer,
    SystemProxyConnectService, SystemProxyInvalidBypassRulePolicy, SystemProxyLayer,
    SystemProxyPacDisabled, SystemProxyPacDisabledResolver, SystemProxyPacRequest,
    SystemProxyPacResolver, SystemProxyPacService, SystemProxyService, proxy_request_uri,
};
