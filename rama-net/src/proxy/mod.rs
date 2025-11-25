//! Proxy utilities and types.

use crate::address::HostWithPort;

mod request;
#[doc(inline)]
pub use request::ProxyRequest;

mod forward;
#[doc(inline)]
pub use forward::StreamForwardService;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// Target [`HostWithPort`] for a proxy/forwarder service.
pub struct ProxyTarget(pub HostWithPort);
