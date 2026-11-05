//! Cancellation trees with a graceful and a hard phase.
//!
//! A [`Scope`] is one node of such a tree. It is first cancelled (the graceful phase: stop
//! taking new work, finish what runs) and then aborted (the hard phase: stop now). Both phases
//! flow from a parent to its children, never upwards, and the earliest cause wins.
//!
//! A root comes from [`Scope::new`]. A process-wide root is usually
//! `Scope::new().with_default_signal()`, optionally with [`Scope::with_grace`] to bound the
//! drain. Every unit of work (a connection, a request, a relay) gets its own [`Scope::child`],
//! tightened with timeouts, deadlines or signals as it needs.
//!
//! Holding a [`Scope`] keeps its drain open, while a [`WeakScope`] only observes.
//! [`Scope::join`] gives up its own hold and returns once every holder of the scope and its
//! subtree is gone, or with [`JoinAborted`] when the hard phase came first.

mod cause;
mod join;
mod node;
mod scope;
mod signal;
mod sync;

pub use cause::Cause;
pub use join::JoinAborted;
pub use scope::{Aborted, Cancelled, Drained, Scope, WeakScope};
pub use signal::default_signal;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod loom_tests;
