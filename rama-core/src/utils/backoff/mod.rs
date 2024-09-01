//! This module contains generic [backoff] utilities to be used with the retry
//! and limit layers.
//!
//! The [`Backoff`] trait is a generic way to represent backoffs that can use
//! any timer type.
//!
//! [`ExponentialBackoff`] which implements the [`Backoff`] trait and provides
//! a batteries included exponential backoff and jitter strategy.
//!
//! [backoff]: https://en.wikipedia.org/wiki/Exponential_backoff

/// A backoff trait where a single mutable reference represents a single
/// backoff session.
///
/// Backoffs are expected to implement [`Clone`] and make sure when cloning too reset any state within the backoff,
/// to ensure that each backoff clone has its own independent state, which starts from a clean slate.
pub trait Backoff: Send + Sync + 'static {
    /// Initiate the next backoff in the sequence.
    /// Return false in case no backoff is possible anymore (e.g. max retries).
    ///
    /// It is expected that the backoff implementation resets itself prior to returning false.
    fn next_backoff(&self) -> impl std::future::Future<Output = bool> + Send + '_;

    /// Reset the backoff to its initial state.
    ///
    /// Note that [`Backoff::next_backoff`] resets automatically when it returns false,
    /// so this method should only be used when the backoff needs to be reset before it has completed.
    fn reset(&self) -> impl std::future::Future<Output = ()> + Send + '_;
}

mod exponential;
#[doc(inline)]
pub use exponential::ExponentialBackoff;
