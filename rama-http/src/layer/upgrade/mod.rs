//! middleware to handle branching into http upgrade services
//!
//! See [`UpgradeService`] for more details.

pub mod service;
#[doc(inline)]
pub use service::{UpgradeResponse, UpgradeService};

mod layer;
#[doc(inline)]
pub use layer::UpgradeLayer;

pub use crate::io::upgrade::Upgraded;

mod http_proxy_connect;
pub use http_proxy_connect::{
    DefaultHttpProxyConnectReplyService, HttpProxyConnectRelayServiceRequestMatcher,
    HttpProxyConnectRelayServiceResponseMatcher,
};

pub mod mitm;
