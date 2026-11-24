mod address;
#[doc(inline)]
pub use address::{
    LazyProxyAddressLayer, LazyProxyAddressService, ProxyAddressLayer, ProxyAddressService,
};

mod bypass;
#[doc(inline)]
pub use bypass::{BypassRules, ProxyBypassLayer, ProxyBypassService};

mod connect;
use connect::ProxyLeg;
#[doc(inline)]
pub use connect::{
    DialedProxyConnection, ProxyConnectionExtensions, ProxyConnectionExtensionsTransfer,
    ProxyDialRequest, ProxyDialer, ProxyDialerLayer, proxy_request,
};

mod reuse;
#[doc(inline)]
pub use reuse::proxy_connection_reuse;

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

mod secure;
#[doc(inline)]
pub use secure::{PlaintextProxyOnly, PlaintextProxyOnlyLayer};

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
