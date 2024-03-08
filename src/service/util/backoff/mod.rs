//! This module contains generic [backoff] utilities to be used with the retry
//! and limit layers.
//!
//! The [`Backoff`] trait is a generic way to represent backoffs that can use
//! any timer type.
//!
//! [`ExponentialBackoffMaker`] implements the maker type for  
//! [`ExponentialBackoff`] which implements the [`Backoff`] trait and provides
//! a batteries included exponential backoff and jitter strategy.
//!
//! [backoff]: https://en.wikipedia.org/wiki/Exponential_backoff

/// Trait used to construct [`Backoff`] trait implementors.
pub trait MakeBackoff {
    /// The backoff type produced by this maker.
    type Backoff: Backoff;

    /// Constructs a new backoff type.
    fn make_backoff(&self) -> Self::Backoff;
}

/// A backoff trait where a single mutable reference represents a single
/// backoff session. Implementors must also implement [`Clone`] which will
/// reset the backoff back to the default state for the next session.
pub trait Backoff: Send + Sync + 'static {
    /// Initiate the next backoff in the sequence.
    fn next_backoff(&self) -> impl std::future::Future<Output = ()> + Send + '_;
}

mod exponential;
pub use exponential::{ExponentialBackoff, ExponentialBackoffMaker};
