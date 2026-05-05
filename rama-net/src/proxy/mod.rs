//! Proxy utilities and types.

use crate::address::HostWithPort;
use rama_core::extensions::Extension;

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
