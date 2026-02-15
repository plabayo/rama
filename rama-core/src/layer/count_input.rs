use crate::{
    Layer, Service,
    extensions::{Extension, ExtensionsMut},
};
use rama_utils::macros::define_inner_service_accessors;
use std::sync::{
    Arc,
    atomic::{self, AtomicU64},
};

pub trait InputCounterTracker: Extension + Clone {
    /// Live concurrent count of inputs actively being served.
    fn concurrent_active_input_count(&self) -> u64;
    /// Total inputs served since creation of the [`InputCounter`]
    /// creating this tracker.
    fn total_input_count(&self) -> u64;
    /// (Total) input count at time of creation of this [`InputCounterTracker`].
    fn input_count(&self) -> u64;
}

pub trait InputCounter: Clone + Send + Sync + 'static {
    type Tracker: InputCounterTracker;

    fn increment(&self) -> Self::Tracker;
    fn decrement(&self);
}

// &self.0.fetch_add(1, Ordering::AcqRel).to_string()

#[derive(Debug, Clone, Default)]
pub struct DefaultInputCounter(Arc<DefaultInputCounterData>);

#[derive(Debug, Clone, Default)]
pub struct InputCounterExtension {
    data: Arc<DefaultInputCounterData>,
    input_count: u64,
}

impl InputCounterExtension {
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
        let _ = self
            .0
            .concurrent_inputs
            .fetch_sub(1, atomic::Ordering::AcqRel);
    }
}

#[derive(Debug, Default)]
struct DefaultInputCounterData {
    total_inputs: AtomicU64,
    concurrent_inputs: AtomicU64,
}

/// Count total and concurrent inputs.
#[derive(Debug, Clone)]
pub struct CountInput<S, C = DefaultInputCounter> {
    inner: S,
    counter: C,
}

impl<S, C> CountInput<S, C> {
    /// Creates a new [`CountInput`] service.
    pub const fn new_wiht_counter(inner: S, counter: C) -> Self {
        Self { inner, counter }
    }

    define_inner_service_accessors!();
}

impl<S> CountInput<S> {
    /// Creates a new [`CountInput`] service using the [`DefaultInputCounter`].
    pub fn new(inner: S) -> Self {
        Self::new_wiht_counter(inner, DefaultInputCounter::default())
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
        input.extensions_mut().insert(tracker);
        let result = self.inner.serve(input).await;
        self.counter.decrement();
        result
    }
}

/// A [`Layer`] that produces [`CountInput`] services.
///
/// [`Layer`]: crate::Layer
#[derive(Debug, Clone)]
pub struct CountInputLayer<C = DefaultInputCounter> {
    counter: C,
}

impl<C> CountInputLayer<C> {
    #[inline(always)]
    /// Creates a new [`CountInputLayer`].
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

impl<S, F> Layer<S> for CountInputLayer<F>
where
    F: Clone,
{
    type Service = CountInput<S, F>;

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
