//! Input counting middleware.
//!
//! This module provides a small middleware and layer for tracking how many
//! inputs a service has processed in total and how many are currently being
//! served concurrently.
//!
//! The core concepts are:
//!
//! - [`InputCounter`]: a counter abstraction that tracks total and concurrent inputs
//! - [`InputCounterTracker`]: a per input tracker that is inserted into input extensions
//! - [`CountInput`]: a service wrapper that increments and decrements the counter
//! - [`CountInputLayer`]: a [`Layer`] producing [`CountInput`] services
//!
//! The tracker allows any inner service to observe:
//!
//! - The live number of concurrent inputs
//! - The total number of inputs seen so far
//! - The sequence number of the current input
//!
//! [`Layer`]: crate::Layer

use crate::{
    Layer, Service,
    extensions::{Extension, ExtensionsMut},
};
use rama_utils::macros::define_inner_service_accessors;
use std::sync::{
    Arc,
    atomic::{self, AtomicU64},
};

/// Tracks per input counters and exposes them as an extension.
///
/// A tracker is inserted into the input extensions by [`CountInput`]
/// for each input that enters the service. The inner service can then read
/// this tracker from extensions to observe total and concurrent counts.
pub trait InputCounterTracker: Extension + Clone {
    /// Live concurrent count of inputs actively being served.
    fn concurrent_active_input_count(&self) -> u64;

    /// Total inputs served since creation of the counter that created this tracker.
    fn total_input_count(&self) -> u64;

    /// Per input number assigned when this tracker was created.
    ///
    /// This is a one based monotonic sequence number.
    fn input_count(&self) -> u64;
}

/// A counter used by [`CountInput`] to track total and concurrent inputs.
///
/// Contract:
/// - `increment` is called exactly once per input and returns the tracker inserted into extensions
/// - `decrement` is called exactly once when the input is finished
pub trait InputCounter: Clone + Send + Sync + 'static {
    /// Tracker that will be inserted into the input extensions.
    type Tracker: InputCounterTracker;

    /// Registers a new in flight input and returns a tracker for that input.
    fn increment(&self) -> Self::Tracker;

    /// Marks the end of an in flight input.
    fn decrement(&self);
}

/// Default counter implementation based on atomics.
///
/// Stores:
/// - `total_inputs`: monotonic count of observed inputs
/// - `concurrent_inputs`: number of inputs currently in flight
#[derive(Debug, Clone, Default)]
pub struct DefaultInputCounter(Arc<DefaultInputCounterData>);

/// The default tracker extension inserted into input extensions by [`CountInput`]
/// when using [`DefaultInputCounter`].
#[derive(Debug, Clone)]
pub struct InputCounterExtension {
    data: Arc<DefaultInputCounterData>,
    input_count: u64,
}

impl InputCounterExtension {
    /// Create a tracker for a newly observed input.
    ///
    /// Uses acquire release ordering for sensible cross thread visibility without locks.
    fn new(data: Arc<DefaultInputCounterData>) -> Self {
        let input_count = data.total_inputs.fetch_add(1, atomic::Ordering::AcqRel) + 1;
        let _ = data
            .concurrent_inputs
            .fetch_add(1, atomic::Ordering::AcqRel);

        Self { data, input_count }
    }
}

impl InputCounterTracker for InputCounterExtension {
    #[inline(always)]
    fn concurrent_active_input_count(&self) -> u64 {
        self.data.concurrent_inputs.load(atomic::Ordering::Acquire)
    }

    #[inline(always)]
    fn total_input_count(&self) -> u64 {
        self.data.total_inputs.load(atomic::Ordering::Acquire)
    }

    #[inline(always)]
    fn input_count(&self) -> u64 {
        self.input_count
    }
}

impl InputCounter for DefaultInputCounter {
    type Tracker = InputCounterExtension;

    #[inline(always)]
    fn increment(&self) -> Self::Tracker {
        InputCounterExtension::new(self.0.clone())
    }

    #[inline(always)]
    fn decrement(&self) {
        let prev = self
            .0
            .concurrent_inputs
            .fetch_sub(1, atomic::Ordering::AcqRel);

        debug_assert!(
            prev > 0,
            "concurrent_inputs underflow, decrement called more times than increment"
        );
    }
}

#[derive(Debug, Default)]
struct DefaultInputCounterData {
    total_inputs: AtomicU64,
    concurrent_inputs: AtomicU64,
}

/// Drop guard that ensures `decrement` runs even if the inner service panics.
///
/// This guard is created after [`InputCounter::increment`] and dropped
/// when the `serve` call ends. On unwind it will also be dropped, making the
/// concurrent counter robust against panics (best-effort).
struct DecrementGuard<C: InputCounter> {
    counter: C,
}

impl<C: InputCounter> DecrementGuard<C> {
    #[inline(always)]
    fn new(counter: C) -> Self {
        Self { counter }
    }
}

impl<C: InputCounter> Drop for DecrementGuard<C> {
    #[inline(always)]
    fn drop(&mut self) {
        self.counter.decrement();
    }
}

/// Service that counts total and concurrent inputs and exposes a tracker via extensions.
///
/// For each input:
/// - increments the counter
/// - inserts the returned tracker into `input.extensions_mut()`
/// - ensures decrement is executed by relying on a drop guard
#[derive(Debug, Clone)]
pub struct CountInput<S, C = DefaultInputCounter> {
    inner: S,
    counter: C,
}

impl<S, C> CountInput<S, C> {
    #[inline(always)]
    /// Creates a new [`CountInput`] service using a user supplied counter.
    pub const fn new_with_counter(inner: S, counter: C) -> Self {
        Self { inner, counter }
    }

    define_inner_service_accessors!();
}

impl<S> CountInput<S> {
    /// Creates a new [`CountInput`] service using the [`DefaultInputCounter`].
    pub fn new(inner: S) -> Self {
        Self::new_with_counter(inner, DefaultInputCounter::default())
    }
}

impl<S, C, Input> Service<Input> for CountInput<S, C>
where
    S: Service<Input>,
    C: InputCounter,
    Input: ExtensionsMut + Send + 'static,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, mut input: Input) -> Result<Self::Output, Self::Error> {
        let tracker = self.counter.increment();
        let _guard = DecrementGuard::new(self.counter.clone());

        input.extensions_mut().insert(tracker);

        self.inner.serve(input).await
    }
}

/// A [`Layer`] that produces [`CountInput`] services.
#[derive(Debug, Clone, Default)]
pub struct CountInputLayer<C = DefaultInputCounter> {
    counter: C,
}

impl<C> CountInputLayer<C> {
    /// Creates a new [`CountInputLayer`] using a user supplied counter.
    pub const fn new_with_counter(counter: C) -> Self {
        Self { counter }
    }
}

impl CountInputLayer {
    #[inline(always)]
    /// Creates a new [`CountInputLayer`] using the [`DefaultInputCounter`].
    pub fn new() -> Self {
        Self::new_with_counter(DefaultInputCounter::default())
    }
}

impl<S, C> Layer<S> for CountInputLayer<C>
where
    C: Clone,
{
    type Service = CountInput<S, C>;

    fn layer(&self, inner: S) -> Self::Service {
        CountInput {
            inner,
            counter: self.counter.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        let Self { counter } = self;
        CountInput { inner, counter }
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use crate::{ServiceInput, service::service_fn};

    use super::*;

    #[test]
    fn default_counter_increments_total_and_concurrent() {
        let counter = DefaultInputCounter::default();

        let t1 = counter.increment();
        assert_eq!(t1.input_count(), 1);
        assert_eq!(t1.total_input_count(), 1);
        assert_eq!(t1.concurrent_active_input_count(), 1);

        let t2 = counter.increment();
        assert_eq!(t2.input_count(), 2);
        assert_eq!(t2.total_input_count(), 2);
        assert_eq!(t2.concurrent_active_input_count(), 2);

        counter.decrement();
        assert_eq!(t2.concurrent_active_input_count(), 1);
        assert_eq!(t2.total_input_count(), 2);

        counter.decrement();
        assert_eq!(t2.concurrent_active_input_count(), 0);
        assert_eq!(t2.total_input_count(), 2);
    }

    #[test]
    fn tracker_is_a_snapshot_of_input_count_but_reads_live_totals() {
        let counter = DefaultInputCounter::default();

        let t1 = counter.increment();
        assert_eq!(t1.input_count(), 1);
        assert_eq!(t1.total_input_count(), 1);
        assert_eq!(t1.concurrent_active_input_count(), 1);

        let _t2 = counter.increment();

        assert_eq!(t1.input_count(), 1);
        assert_eq!(t1.total_input_count(), 2);
        assert_eq!(t1.concurrent_active_input_count(), 2);

        counter.decrement();
        counter.decrement();

        assert_eq!(t1.total_input_count(), 2);
        assert_eq!(t1.concurrent_active_input_count(), 0);
    }

    #[test]
    fn decrement_guard_decrements_on_drop() {
        let counter = DefaultInputCounter::default();

        let t1 = counter.increment();
        assert_eq!(t1.concurrent_active_input_count(), 1);

        {
            let _guard = DecrementGuard::new(counter);
            // On drop the guard will decrement once.
        }

        assert_eq!(t1.concurrent_active_input_count(), 0);
    }

    #[tokio::test]
    async fn input_count_svc() {
        let svc = CountInput::new(service_fn(async |input: ServiceInput<()>| {
            Ok::<_, Infallible>(
                input
                    .extensions
                    .get::<InputCounterExtension>()
                    .unwrap()
                    .input_count(),
            )
        }));

        for expected_count in 1..3 {
            let Ok(count) = svc.serve(ServiceInput::new(())).await;
            assert_eq!(expected_count, count);
        }
    }
}
