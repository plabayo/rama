//! Proxy utilities and types.

#[cfg(feature = "dial9")]
#[cfg_attr(docsrs, doc(cfg(feature = "dial9")))]
pub mod dial9;

mod forward;
#[doc(inline)]
pub use forward::{BridgeCloseReason, IoForwardService};

mod idle;
#[doc(inline)]
pub use idle::IdleGuard;
