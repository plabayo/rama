use core::{fmt, mem};

use super::{Event, EventDispatcher, Listener, SpanAdapter, SpanStart, Subscription};
use crate::std::vec::Vec;

/// Adds span adapters to a dispatcher, one by one or in groups such as the
/// `DefaultSpanAdapters` of each rama crate.
///
/// Every adapter is added right away. [`build`](Self::build) hands over the
/// [`Subscriptions`] that keep them added.
pub struct SpanAdapters {
    dispatcher: EventDispatcher,
    subscriptions: Vec<Subscription>,
}

impl SpanAdapters {
    /// Add span adapters to `dispatcher`.
    #[must_use]
    pub fn new(dispatcher: &EventDispatcher) -> Self {
        Self {
            dispatcher: dispatcher.clone(),
            subscriptions: Vec::new(),
        }
    }

    /// Add one span adapter.
    #[must_use]
    pub fn with<S: SpanStart>(mut self, adapter: impl SpanAdapter<S>) -> Self {
        self.add(adapter);
        self
    }

    /// Add one span adapter.
    pub fn add<S: SpanStart>(&mut self, adapter: impl SpanAdapter<S>) -> &mut Self {
        let subscription = self.dispatcher.add_span_adapter(adapter);
        self.subscriptions.push(subscription);
        self
    }

    /// Add a group of span adapters, such as `DefaultSpanAdapters::tracing`.
    #[must_use]
    pub fn with_group(self, group: impl FnOnce(Self) -> Self) -> Self {
        group(self)
    }

    /// Add a group of span adapters, such as `DefaultSpanAdapters::tracing`.
    pub fn add_group(&mut self, group: impl FnOnce(Self) -> Self) -> &mut Self {
        let this = Self {
            dispatcher: self.dispatcher.clone(),
            subscriptions: mem::take(&mut self.subscriptions),
        };
        *self = group(this);
        self
    }

    /// Keep the added span adapters for as long as the result is alive.
    pub fn build(self) -> Subscriptions {
        Subscriptions(self.subscriptions)
    }
}

impl fmt::Debug for SpanAdapters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpanAdapters")
            .field("added", &self.subscriptions.len())
            .finish_non_exhaustive()
    }
}

/// Adds listeners to a dispatcher, one by one or in groups such as the
/// `DefaultListeners` of each rama crate.
///
/// Every listener is added right away. [`build`](Self::build) hands over the
/// [`Subscriptions`] that keep them added.
pub struct Listeners {
    dispatcher: EventDispatcher,
    subscriptions: Vec<Subscription>,
}

impl Listeners {
    /// Add listeners to `dispatcher`.
    #[must_use]
    pub fn new(dispatcher: &EventDispatcher) -> Self {
        Self {
            dispatcher: dispatcher.clone(),
            subscriptions: Vec::new(),
        }
    }

    /// Add one listener.
    #[must_use]
    pub fn with<E: Event>(mut self, listener: impl Listener<E>) -> Self {
        self.add(listener);
        self
    }

    /// Add one listener.
    pub fn add<E: Event>(&mut self, listener: impl Listener<E>) -> &mut Self {
        let subscription = self.dispatcher.subscribe(listener);
        self.subscriptions.push(subscription);
        self
    }

    /// Add a group of listeners, such as `DefaultListeners::tracing`.
    #[must_use]
    pub fn with_group(self, group: impl FnOnce(Self) -> Self) -> Self {
        group(self)
    }

    /// Add a group of listeners, such as `DefaultListeners::tracing`.
    pub fn add_group(&mut self, group: impl FnOnce(Self) -> Self) -> &mut Self {
        let this = Self {
            dispatcher: self.dispatcher.clone(),
            subscriptions: mem::take(&mut self.subscriptions),
        };
        *self = group(this);
        self
    }

    /// Keep the added listeners for as long as the result is alive.
    pub fn build(self) -> Subscriptions {
        Subscriptions(self.subscriptions)
    }
}

impl fmt::Debug for Listeners {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Listeners")
            .field("added", &self.subscriptions.len())
            .finish_non_exhaustive()
    }
}

/// Keeps a group of listeners or span adapters added. Dropping it removes
/// them all.
#[must_use = "everything is removed again when this is dropped"]
pub struct Subscriptions(Vec<Subscription>);

impl fmt::Debug for Subscriptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Subscriptions").field(&self.0.len()).finish()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::{Listeners, SpanAdapters};
    use crate::telemetry::event::{
        self, Emitted, Emitter, Event, EventDispatcher, SpanAdapter, SpanEmitter, SpanStart,
    };

    #[derive(Clone, Event, SpanStart)]
    #[span(end = Ended)]
    struct Started;

    #[derive(Clone, Event)]
    struct Ended;

    struct Counting(Arc<AtomicUsize>);

    impl SpanAdapter<Started> for Counting {
        type State = ();

        fn open(&self, _start: &Emitted<'_, Started>) -> Option<()> {
            self.0.fetch_add(1, Ordering::Relaxed);
            None
        }

        fn enter(&self, _state: &(), poll: &mut dyn FnMut()) {
            poll();
        }

        fn close(&self, _state: (), _end: &Emitted<'_, Ended>) {}
    }

    fn counting_group(opened: &Arc<AtomicUsize>) -> impl FnOnce(SpanAdapters) -> SpanAdapters {
        let opened = opened.clone();
        move |span_adapters| span_adapters.with(Counting(opened))
    }

    #[event::isolated]
    #[test]
    fn span_adapters_stay_added_until_the_subscriptions_drop(dispatcher: EventDispatcher) {
        let opened = Arc::new(AtomicUsize::new(0));
        let spans = SpanEmitter::<Started>::new();

        let subscriptions = SpanAdapters::new(&dispatcher)
            .with(Counting(opened.clone()))
            .with_group(counting_group(&opened))
            .build();
        drop(spans.open_with(|| Started, || Ended));
        assert_eq!(
            opened.load(Ordering::Relaxed),
            2,
            "one alone, one in a group"
        );

        drop(subscriptions);
        assert!(!spans.is_active());
    }

    #[event::isolated]
    #[test]
    fn span_adapters_added_through_a_mutable_builder_stay_added(dispatcher: EventDispatcher) {
        let opened = Arc::new(AtomicUsize::new(0));
        let spans = SpanEmitter::<Started>::new();

        let mut span_adapters = SpanAdapters::new(&dispatcher);
        span_adapters
            .add(Counting(opened.clone()))
            .add_group(counting_group(&opened));
        let _subscriptions = span_adapters.build();
        drop(spans.open_with(|| Started, || Ended));

        assert_eq!(
            opened.load(Ordering::Relaxed),
            2,
            "one alone, one in a group"
        );
    }

    #[event::isolated]
    #[test]
    fn listeners_stay_added_until_the_subscriptions_drop(dispatcher: EventDispatcher) {
        let seen = Arc::new(AtomicUsize::new(0));
        let counter = seen.clone();
        let emitter = Emitter::<Ended>::new();

        let subscriptions = Listeners::new(&dispatcher)
            .with(move |_: &Emitted<'_, Ended>| {
                counter.fetch_add(1, Ordering::Relaxed);
            })
            .build();
        emitter.emit_with(|| Ended);
        assert_eq!(seen.load(Ordering::Relaxed), 1);

        drop(subscriptions);
        assert!(!emitter.is_active());
    }
}
