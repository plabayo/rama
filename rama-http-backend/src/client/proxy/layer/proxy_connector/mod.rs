mod connect;
#[doc(inline)]
pub use connect::{connect_request, upgrade_connect_response};

mod proxy_error;
#[doc(inline)]
pub use proxy_error::HttpProxyError;

mod layer;
#[doc(inline)]
pub use layer::HttpConnectProxyConnectorLayer;

mod service;
#[doc(inline)]
pub use service::{HttpConnectProxyConnector, HttpProxyConnectResponseHeaders};
