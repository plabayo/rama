//! Proxy utilities and types.

use crate::address::HostWithPort;
use rama_core::extensions::Extension;

mod forward;
#[doc(inline)]
pub use forward::IoForwardService;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Extension)]
/// Target [`HostWithPort`] for a proxy/forwarder service.
pub struct ProxyTarget(pub HostWithPort);
