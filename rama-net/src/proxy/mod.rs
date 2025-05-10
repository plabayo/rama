//! Proxy utilities and types.

use crate::address::Authority;

mod request;
#[doc(inline)]
pub use request::ProxyRequest;

mod forward;
#[doc(inline)]
pub use forward::StreamForwardService;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Target [`Authority`] for a proxy/forwarder service.
pub struct ProxyTarget(pub Authority);
