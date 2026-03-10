//! middleware to handle branching into http upgrade services
//!
//! See [`UpgradeService`] for more details.

pub mod service;
#[doc(inline)]
pub use service::UpgradeService;

mod layer;
#[doc(inline)]
pub use layer::UpgradeLayer;

pub use rama_http::io::upgrade::Upgraded;

mod http_proxy_connect;
pub use http_proxy_connect::{
    DefaultHttpProxyConnectReplyService, HttpProxyConnectMitmRelay, HttpProxyConnectMitmRelayLayer,
    is_req_http_proxy_connect,
};
