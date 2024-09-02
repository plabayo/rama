mod connector;
// internal usage only
use connector::InnerHttpProxyConnector;

mod layer;
#[doc(inline)]
pub use layer::HttpProxyConnectorLayer;

mod service;
#[doc(inline)]
pub use service::HttpProxyConnector;
