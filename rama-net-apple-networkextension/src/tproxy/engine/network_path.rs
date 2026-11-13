//! Provider-wide network observations. These are policy hints, not per-flow route proofs.

/// Reachability reported by the platform path monitor.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TransparentProxyNetworkStatus {
    #[default]
    Unknown,
    Satisfied,
    Unsatisfied,
    RequiresConnection,
}

/// Latest provider network snapshot, coalesced instead of queued per flow.
///
/// An available interface is a hint: it does not override NECP, tunnel or application policy.
/// Consumers must use their configured connector when selecting replacement transports.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, rama_core::extensions::Extension)]
pub struct TransparentProxyNetworkPath {
    pub revision: u64,
    /// Advances on reachability or preferred-interface changes, not cost flags alone.
    pub routing_revision: u64,
    pub status: TransparentProxyNetworkStatus,
    /// First interface in the platform's preference order, or zero if unavailable.
    pub preferred_interface: u32,
    pub expensive: bool,
    pub constrained: bool,
}

impl TransparentProxyNetworkPath {
    /// Decode the scalar C ABI. Unknown status values remain Unknown.
    pub(crate) fn from_ffi(status: u32, preferred_interface: u32, flags: u32) -> Self {
        Self {
            revision: 0,
            routing_revision: 0,
            status: match status {
                1 => TransparentProxyNetworkStatus::Satisfied,
                2 => TransparentProxyNetworkStatus::Unsatisfied,
                3 => TransparentProxyNetworkStatus::RequiresConnection,
                _ => TransparentProxyNetworkStatus::Unknown,
            },
            preferred_interface,
            expensive: flags & 1 != 0,
            constrained: flags & 2 != 0,
        }
    }
}
