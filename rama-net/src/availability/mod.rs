//! Network availability observations shared by recovering transports.
//!
//! A trusted platform or routing-policy observer publishes [`NetworkState`]s through
//! `NetworkChanges`. Transports which can replace their egress path (UDP forwarding,
//! QUIC migration) subscribe to it and prepare replacements with `prepare_network_change`.

/// Whether the platform reports a usable network path.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum NetworkAvailability {
    /// The platform has not (yet) reported whether a path is usable.
    #[default]
    Unknown,
    /// A usable path exists.
    Available,
    /// No usable path exists.
    Unavailable,
}

impl NetworkAvailability {
    /// Whether a usable path is known to exist; [`Self::Unknown`] is not.
    #[must_use]
    pub fn is_available(self) -> bool {
        matches!(self, Self::Available)
    }
}

/// A trusted routing revision with the availability observed for it.
///
/// Revisions need only change, not increase.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct NetworkState {
    pub revision: u64,
    pub availability: NetworkAvailability,
}

#[cfg(feature = "std")]
mod changes;
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
#[doc(inline)]
pub use changes::{NetworkChanges, prepare_network_change};

#[cfg(all(test, feature = "std"))]
mod tests;
