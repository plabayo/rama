//! Client Http Proxy Connector Support.

pub mod layer;

mod forward;
#[doc(inline)]
pub use forward::{HttpForwardProxyConnection, HttpForwardProxyConnector, forwarding_proxy};

mod select;
#[doc(inline)]
pub use select::{HttpForwardRoute, HttpTunnelRoute};
