//! Http Proxy Connector Layers for Rama Http Clients

mod proxy_auth_header;
pub use proxy_auth_header::{SetProxyAuthHttpHeaderLayer, SetProxyAuthHttpHeaderService};

mod proxy_connector;
#[doc(inline)]
pub use proxy_connector::{
    HttpProxyConnectResponseHeaders, HttpProxyConnector, HttpProxyConnectorLayer, HttpProxyError,
    MaybeHttpProxiedConnection,
};
