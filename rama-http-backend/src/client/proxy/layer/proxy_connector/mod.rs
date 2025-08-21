mod connector;
// internal usage only
use connector::InnerHttpProxyConnector;

mod proxy_error;
#[doc(inline)]
pub use proxy_error::HttpProxyError;

mod layer;
#[doc(inline)]
pub use layer::HttpProxyConnectorLayer;

mod service;
#[doc(inline)]
pub use service::{
    HttpProxyConnectResponseHeaders, HttpProxyConnector, MaybeHttpProxiedConnection,
};
