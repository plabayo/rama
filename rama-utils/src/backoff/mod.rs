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
    fn next_backoff(&self) -> impl Future<Output = bool> + Send + '_;

    /// Reset the backoff to its initial state.
    ///
    /// Note that [`Backoff::next_backoff`] resets automatically when it returns false,
    /// so this method should only be used when the backoff needs to be reset before it has completed.
    fn reset(&self) -> impl Future<Output = ()> + Send + '_;
}

impl Backoff for () {
    async fn next_backoff(&self) -> bool {
        false
    }

    async fn reset(&self) {}
}

impl<T: Backoff> Backoff for Option<T> {
    async fn next_backoff(&self) -> bool {
        match self {
            Some(backoff) => backoff.next_backoff().await,
            None => false,
        }
    }

    async fn reset(&self) {
        if let Some(backoff) = self {
            backoff.reset().await;
        }
    }
}

impl<T: Backoff> Backoff for crate::std::Arc<T> {
    #[inline]
    fn next_backoff(&self) -> impl Future<Output = bool> + Send + '_ {
        (**self).next_backoff()
    }

    fn reset(&self) -> impl Future<Output = ()> + Send + '_ {
        (**self).reset()
    }
}

mod exponential;
#[doc(inline)]
pub use exponential::ExponentialBackoff;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn option_backoff_delegates_to_some() {
        let backoff = Some(ExponentialBackoff::default());
        // a fresh exponential backoff offers retries; before the fix this
        // returned false unconditionally, silently disabling all backoff
        assert!(backoff.next_backoff().await);
        backoff.reset().await;
        assert!(backoff.next_backoff().await);
    }

    #[tokio::test]
    async fn option_backoff_none_gives_up() {
        let backoff: Option<ExponentialBackoff<()>> = None;
        assert!(!backoff.next_backoff().await);
    }
}
