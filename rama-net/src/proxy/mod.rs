//! Proxy utilities and types.

use crate::address::HostWithPort;
use rama_core::extensions::Extension;

#[cfg(feature = "dial9")]
#[cfg_attr(docsrs, doc(cfg(feature = "dial9")))]
pub mod dial9;

mod forward;
#[doc(inline)]
pub use forward::{BridgeCloseReason, IoForwardService};

mod idle;
#[doc(inline)]
pub use idle::IdleGuard;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Extension)]
#[extension(tags(net, proxy))]
/// Target [`HostWithPort`] for a proxy/forwarder service.
pub struct ProxyTarget(pub HostWithPort);
