//! Proxy utilities and types.

use crate::address::HostWithPort;

mod forward;
#[doc(inline)]
pub use forward::IoForwardService;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// Target [`HostWithPort`] for a proxy/forwarder service.
pub struct ProxyTarget(pub HostWithPort);
