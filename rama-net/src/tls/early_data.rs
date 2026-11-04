//! Per-operation controls for TLS early data.

use rama_core::extensions::Extension;

/// Require handshake confirmation before sending this operation.
///
/// Recovery policies retain this in their caller's extension store so later
/// attempts cannot use early data, even when they select another connection.
#[derive(Debug, Clone, Copy, Default, Extension)]
#[extension(tags(tls))]
#[non_exhaustive]
pub struct ForbidEarlyData;

/// An operation whose caller owns early-data rejection recovery.
///
/// This permits a connector to return a resumed connection before confirmation.
/// It neither proves early transmission nor overrides [`ForbidEarlyData`]. The
/// application protocol must still enforce replay safety and gate authenticated
/// responses and normal connection reuse on successful handshake confirmation.
///
/// Ordinary clients should obtain this through their protocol's recovery
/// composition. Low-level callers must supply a replayable operation and handle
/// both TLS rejection and any application-level early-data rejection. Insert it
/// into an attempt's fork, never a shared caller or connection store.
#[derive(Debug, Clone, Copy, Extension)]
#[extension(tags(tls))]
#[non_exhaustive]
pub struct EarlyDataPermit;

impl EarlyDataPermit {
    /// Assert that this attempt has an owner for early-data rejection recovery.
    #[must_use]
    pub const fn with_recovery_owner() -> Self {
        Self
    }
}
