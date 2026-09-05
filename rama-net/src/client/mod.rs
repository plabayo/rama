//! generic client net logic

mod conn;
#[doc(inline)]
pub use conn::{BoxedConnectorService, ConnectorService, EstablishedClientConnection};

mod error;
#[doc(inline)]
pub use error::{ConnectionError, ConnectionErrorDomain, ConnectionErrorKind};

mod connector;
#[doc(inline)]
pub use connector::{
    AddressCandidates, ConnectorTarget, ConnectorTargetStream, ConnectorTransportProtocol,
    race_connect,
};

mod graceful;
#[doc(inline)]
pub use graceful::GracefulConnectorService;

pub mod pool;

mod either_conn;
#[doc(inline)]
pub use either_conn::{
    EitherConn, EitherConn3, EitherConn3Connected, EitherConn4, EitherConn4Connected, EitherConn5,
    EitherConn5Connected, EitherConn6, EitherConn6Connected, EitherConn7, EitherConn7Connected,
    EitherConn8, EitherConn8Connected, EitherConn9, EitherConn9Connected, EitherConnConnected,
};

mod connect_request;
#[doc(inline)]
pub use connect_request::ConnectRequest;

mod proxy;
#[doc(inline)]
pub use proxy::{
    BypassRules, DEFAULT_SYSTEM_PROXY_CONFIG_TTL, EstablishedProxyRoute, LazyProxyAddressLayer,
    LazyProxyAddressService, NoProxyEnvLayer, NoProxyEnvService, ProxyAddressLayer,
    ProxyAddressService, ProxyBypassLayer, ProxyBypassService, ProxyEnvLayer, ProxyEnvService,
    ProxyRoute, ProxyRouteConnectError, ProxyRouteFailureCache, ProxyRouteFailureCacheConfig,
    ProxyRouteFailureCacheConnector, ProxyRouteFailureCacheLayer, ProxyRouteFailureCacheScope,
    ProxyRouteFailureCachedError, ProxyRouteIndex, ProxyRoutes, ProxyRoutesConnector,
    ProxyRoutesConnectorLayer, ProxyRoutesLayer, ProxyRoutesService, SystemProxyConfig,
    SystemProxyConnectLayer, SystemProxyConnectService, SystemProxyInvalidBypassRulePolicy,
    SystemProxyLayer, SystemProxyPacDisabled, SystemProxyPacDisabledResolver,
    SystemProxyPacRequest, SystemProxyPacResolver, SystemProxyPacService, SystemProxyService,
    proxy_request_uri,
};
