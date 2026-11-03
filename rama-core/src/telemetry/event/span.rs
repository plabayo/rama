use core::fmt;
use core::marker::PhantomData;
use core::pin::Pin;
use core::task::{Context, Poll};

use pin_project_lite::pin_project;
use smallvec::SmallVec;

use super::pool::{ErasedSlotPtr, StatePool};
use super::slot::{Entries, Slot};
use super::{Emitted, Emitter, Event, EventDispatcher};
use crate::std::sync::Arc;

/// An event that starts a unit of work, with a guaranteed end event.
///
/// Derive it with `#[derive(SpanStart)]` and `#[span(end = TheEndEvent)]`. The
/// type also needs `#[derive(Event)]`, and so does its end event.
pub trait SpanStart: Event {
    /// The event that ends this span.
    type End: Event;
}

/// Carries rama spans over into another tool, such as tracing or dial9.
///
/// For each span, [`open`](Self::open) returns the state this adapter keeps
/// for it, such as a `tracing::Span`. The core stores it, hands it to
/// [`enter`](Self::enter) around every poll of the span's work and around the
/// listeners of its start and end event, and gives it back to
/// [`close`](Self::close) when the span ends.
///
/// `open` returning `None` means this adapter skips the span: it is then not
/// entered or closed for it.
pub trait SpanAdapter<S: SpanStart>: Send + Sync + 'static {
    /// What this adapter keeps per span.
    type State: Send + Sync + 'static;

    /// Make the state for a span that is opening.
    fn open(&self, start: &Emitted<'_, S>) -> Option<Self::State>;

    /// Run `poll` with `state` entered. It must be called exactly once: work
    /// that is not polled never makes progress.
    fn enter(&self, state: &Self::State, poll: &mut dyn FnMut());

    /// End `state`. The span's end listeners already ran.
    fn close(&self, state: Self::State, end: &Emitted<'_, S::End>);
}

// A span adapter with its state type erased, so one span can hold adapters
// with different states.
pub(super) trait ErasedSpanAdapter<S: SpanStart>: Send + Sync {
    fn open(&self, start: &Emitted<'_, S>) -> Option<ErasedSlotPtr>;

    /// # Safety
    ///
    /// `state` must come from [`open`](Self::open) on this same adapter.
    unsafe fn enter(&self, state: &ErasedSlotPtr, poll: &mut dyn FnMut());

    /// # Safety
    ///
    /// `state` must come from [`open`](Self::open) on this same adapter.
    unsafe fn close(&self, state: ErasedSlotPtr, end: &Emitted<'_, S::End>);
}

// Keeps the states of one span adapter in a pool, so a span only carries a
// pointer per adapter.
pub(super) struct PooledSpanAdapter<S: SpanStart, A: SpanAdapter<S>> {
    adapter: A,
    states: StatePool<A::State>,
    _span: PhantomData<fn() -> S>,
}

impl<S: SpanStart, A: SpanAdapter<S>> PooledSpanAdapter<S, A> {
    pub(super) fn new(adapter: A) -> Self {
        Self {
            adapter,
            states: StatePool::new(),
            _span: PhantomData,
        }
    }
}

impl<S: SpanStart, A: SpanAdapter<S>> ErasedSpanAdapter<S> for PooledSpanAdapter<S, A> {
    fn open(&self, start: &Emitted<'_, S>) -> Option<ErasedSlotPtr> {
        self.adapter
            .open(start)
            .map(|state| self.states.insert(state))
    }

    unsafe fn enter(&self, state: &ErasedSlotPtr, poll: &mut dyn FnMut()) {
        // SAFETY: the caller guarantees `state` came from `open`, so from
        // this pool.
        let state = unsafe { self.states.get(state) };
        self.adapter.enter(state, poll);
    }

    unsafe fn close(&self, state: ErasedSlotPtr, end: &Emitted<'_, S::End>) {
        // SAFETY: the caller guarantees `state` came from `open`, so from
        // this pool; consuming it means it is taken once.
        let state = unsafe { self.states.take(state) };
        self.adapter.close(state, end);
    }
}

/// Opens spans of one type, like [`Emitter`] emits events of one type.
///
/// Resolve it once in a long-lived component and copy it into the units that
/// open spans.
#[derive(Clone)]
pub struct SpanEmitter<S: SpanStart> {
    start: Emitter<S>,
    end: Emitter<S::End>,
    span_adapters: &'static Slot<dyn ErasedSpanAdapter<S>>,
}

// Hand-written: a derive would bound `S: Copy`, which a span type is not.
impl<S: SpanStart> Copy for SpanEmitter<S> {}

impl<S: SpanStart> SpanEmitter<S> {
    /// Resolve a span emitter from [`EventDispatcher::current`].
    #[must_use]
    pub fn new() -> Self {
        Self::from_dispatcher(&EventDispatcher::current())
    }

    /// Resolve a span emitter from a specific dispatcher.
    #[must_use]
    pub fn from_dispatcher(dispatcher: &EventDispatcher) -> Self {
        Self {
            start: Emitter::from_dispatcher(dispatcher),
            end: Emitter::from_dispatcher(dispatcher),
            span_adapters: dispatcher.span_adapter_slot::<S>(),
        }
    }

    /// Whether a listener or a span adapter is registered for this span.
    #[must_use]
    pub fn is_active(self) -> bool {
        (self.start.active() | self.end.active() | self.span_adapters.active()) != 0
    }

    /// Open a span, building the start event only when the span is active.
    ///
    /// `on_drop` builds the end event of a span that is dropped instead of
    /// closed, so a span always ends. Closing builds on that same event.
    pub fn open_with<D>(self, start: impl FnOnce() -> S, on_drop: D) -> OpenSpan<S, D>
    where
        D: FnOnce() -> S::End + Send + 'static,
    {
        if !self.is_active() {
            return OpenSpan {
                end: self.end,
                states: None,
                on_drop: Some(on_drop),
            };
        }

        let start = start();
        let start = Emitted::new(&start);

        let span_adapters = self.span_adapters.snapshot();
        let states = span_adapters
            .iter()
            .map(|(_, adapter)| adapter.open(&start))
            .collect();
        let states = SpanAdapterStates {
            span_adapters,
            states,
        };

        if self.start.is_active() {
            states.enter(&mut || self.start.emit(&start));
        }

        OpenSpan {
            end: self.end,
            states: Some(states),
            on_drop: Some(on_drop),
        }
    }
}

impl<S: SpanStart> Default for SpanEmitter<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: SpanStart> fmt::Debug for SpanEmitter<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpanEmitter")
            .field("active", &self.is_active())
            .finish_non_exhaustive()
    }
}

/// A span that is open: run work in it, then close it.
///
/// Futures run in it through [`SpanFutureExt`], sync work through
/// [`observe_sync`](Self::observe_sync).
///
/// A span that was not active when it opened stays inactive: it builds no
/// event, its work runs as it is, and closing or dropping it does nothing.
/// Whether it is active is decided once, at open.
#[must_use = "an open span ends when it is dropped"]
pub struct OpenSpan<S: SpanStart, D: FnOnce() -> S::End + Send + 'static> {
    end: Emitter<S::End>,
    states: Option<SpanAdapterStates<S>>,
    on_drop: Option<D>,
}

// Safety invariant: `states` is index-aligned with `span_adapters`, each state
// coming from the span adapter at its own index. The snapshot also keeps the
// span adapters, and with them their pools, alive for as long as the span.
struct SpanAdapterStates<S: SpanStart> {
    span_adapters: Arc<Entries<dyn ErasedSpanAdapter<S>>>,
    states: SmallVec<[Option<ErasedSlotPtr>; 2]>,
}

impl<S: SpanStart, D: FnOnce() -> S::End + Send + 'static> OpenSpan<S, D> {
    /// Whether a listener or a span adapter was registered when this span
    /// opened.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.states.is_some()
    }

    /// Run `work` with every span adapter of this span entered.
    #[expect(
        clippy::expect_used,
        reason = "`SpanAdapter::enter` must call the poll it is given"
    )]
    pub fn observe_sync<T>(&self, work: impl FnOnce() -> T) -> T {
        let Some(states) = &self.states else {
            return work();
        };

        let mut work = Some(work);
        let mut result = None;
        states.enter(&mut || {
            if let Some(work) = work.take() {
                result = Some(work());
            }
        });
        result.expect("span adapter did not run the work it was given")
    }

    /// End this span with the event `end` builds from the one `on_drop` gives.
    pub fn close_with(mut self, end: impl FnOnce(S::End) -> S::End) {
        let Some(on_drop) = self.on_drop.take() else {
            return;
        };
        self.close(|| end(on_drop()));
    }

    fn close(&mut self, end: impl FnOnce() -> S::End) {
        let Some(states) = self.states.take() else {
            return;
        };
        let end = end();
        let end = Emitted::new(&end);
        if self.end.is_active() {
            states.enter(&mut || self.end.emit(&end));
        }
        for ((_, adapter), state) in states.span_adapters.iter().zip(states.states) {
            if let Some(state) = state {
                // SAFETY: `states` is index-aligned with `span_adapters`, so
                // this state came from this adapter.
                unsafe { adapter.close(state, &end) };
            }
        }
    }
}

impl<S: SpanStart, D: FnOnce() -> S::End + Send + 'static> Drop for OpenSpan<S, D> {
    fn drop(&mut self) {
        if let Some(on_drop) = self.on_drop.take() {
            self.close(on_drop);
        }
    }
}

impl<S: SpanStart, D: FnOnce() -> S::End + Send + 'static> fmt::Debug for OpenSpan<S, D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenSpan")
            .field("active", &self.is_active())
            .finish_non_exhaustive()
    }
}

impl<S: SpanStart> SpanAdapterStates<S> {
    // The span adapters nest through closures on the stack, so none needs to
    // know about the others and nothing is boxed.
    fn enter(&self, poll: &mut dyn FnMut()) {
        // SAFETY: each state is paired with the span adapter at its own index.
        unsafe { enter_nested(&self.span_adapters, &self.states, poll) };
    }
}

/// # Safety
///
/// `states` must be index-aligned with `span_adapters` as in
/// [`SpanAdapterStates`].
unsafe fn enter_nested<S: SpanStart>(
    span_adapters: &[(u64, Arc<dyn ErasedSpanAdapter<S>>)],
    states: &[Option<ErasedSlotPtr>],
    poll: &mut dyn FnMut(),
) {
    let (Some(((_, adapter), span_adapters)), Some((state, states))) =
        (span_adapters.split_first(), states.split_first())
    else {
        poll();
        return;
    };

    // SAFETY: the tails of aligned slices stay aligned.
    let enter_rest = &mut || unsafe { enter_nested(span_adapters, states, poll) };
    match state {
        // SAFETY: the heads of aligned slices are a state and its adapter.
        Some(state) => unsafe { adapter.enter(state, enter_rest) },
        None => enter_rest(),
    }
}

/// Runs futures inside an [`OpenSpan`].
pub trait SpanFutureExt: Future + Sized {
    /// Poll this future with every span adapter of `span` entered, and end
    /// the span through its `on_drop` when the future completes or is dropped.
    fn observe<S, D>(self, span: OpenSpan<S, D>) -> impl Future<Output = Self::Output>
    where
        S: SpanStart,
        D: FnOnce() -> S::End + Send + 'static;

    /// Poll this future with every span adapter of `span` entered. The span
    /// stays open, so one span can cover several futures; it ends when closed
    /// or dropped.
    fn observe_ref<S, D>(self, span: &OpenSpan<S, D>) -> Observed<'_, S, Self>
    where
        S: SpanStart,
        D: FnOnce() -> S::End + Send + 'static;

    /// Poll this future like [`observe`](Self::observe), then close `span` with
    /// the event `on_complete` builds from the one `on_drop` gives and the
    /// output. Dropping the future before it completes ends the span through
    /// `on_drop` alone.
    fn observe_and_close<S, D, C>(
        self,
        span: OpenSpan<S, D>,
        on_complete: C,
    ) -> impl Future<Output = Self::Output>
    where
        S: SpanStart,
        D: FnOnce() -> S::End + Send + 'static,
        C: FnOnce(S::End, &Self::Output) -> S::End;
}

impl<F: Future> SpanFutureExt for F {
    async fn observe<S, D>(self, span: OpenSpan<S, D>) -> Self::Output
    where
        S: SpanStart,
        D: FnOnce() -> S::End + Send + 'static,
    {
        self.observe_ref(&span).await
    }

    fn observe_ref<S, D>(self, span: &OpenSpan<S, D>) -> Observed<'_, S, Self>
    where
        S: SpanStart,
        D: FnOnce() -> S::End + Send + 'static,
    {
        Observed {
            states: span.states.as_ref(),
            future: self,
        }
    }

    async fn observe_and_close<S, D, C>(self, span: OpenSpan<S, D>, on_complete: C) -> Self::Output
    where
        S: SpanStart,
        D: FnOnce() -> S::End + Send + 'static,
        C: FnOnce(S::End, &Self::Output) -> S::End,
    {
        let output = self.observe_ref(&span).await;
        span.close_with(|end| on_complete(end, &output));
        output
    }
}

pin_project! {
    /// A future polled inside an [`OpenSpan`].
    pub struct Observed<'a, S, F>
    where
        S: SpanStart,
    {
        states: Option<&'a SpanAdapterStates<S>>,
        #[pin]
        future: F,
    }
}

impl<S: SpanStart, F: Future> Future for Observed<'_, S, F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        let this = self.project();
        let Some(states) = this.states else {
            return this.future.poll(cx);
        };

        let mut future = this.future;
        let mut polled = Poll::Pending;
        states.enter(&mut || polled = future.as_mut().poll(cx));
        polled
    }
}

impl<S: SpanStart, F> fmt::Debug for Observed<'_, S, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Observed").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use parking_lot::Mutex;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use crate::telemetry::event;
    use crate::telemetry::event::{
        Emitted, Event, EventDispatcher, OpenSpan, SpanAdapter, SpanEmitter, SpanFutureExt,
        SpanStart, Subscription,
    };

    #[derive(Clone, Event, SpanStart)]
    #[span(end = Ended)]
    struct Started {
        unit: u64,
    }

    #[derive(Clone, Event)]
    struct Ended {
        unit: u64,
        closed: bool,
    }

    type Log = Arc<Mutex<Vec<String>>>;

    struct Recorder {
        name: &'static str,
        log: Log,
        next_token: AtomicUsize,
        opens: bool,
    }

    impl Recorder {
        fn new(name: &'static str, log: &Log) -> Self {
            Self {
                name,
                log: log.clone(),
                next_token: AtomicUsize::new(1),
                opens: true,
            }
        }

        fn declining(name: &'static str, log: &Log) -> Self {
            Self {
                opens: false,
                ..Self::new(name, log)
            }
        }

        fn push(&self, what: &str, token: u64) {
            self.log
                .lock()
                .push(format!("{}:{what}:{token}", self.name));
        }
    }

    // A custom adapter with its own per span state, like the shipped ones.
    impl SpanAdapter<Started> for Recorder {
        type State = u64;

        fn open(&self, start: &Emitted<'_, Started>) -> Option<u64> {
            if !self.opens {
                self.log.lock().push(format!("{}:declined", self.name));
                return None;
            }
            let token = self.next_token.fetch_add(1, Ordering::Relaxed) as u64;
            self.push("open", start.event().unit);
            Some(token)
        }

        fn enter(&self, token: &u64, poll: &mut dyn FnMut()) {
            let token = *token;
            self.push("enter", token);
            poll();
            self.push("exit", token);
        }

        fn close(&self, token: u64, end: &Emitted<'_, Ended>) {
            self.push(if end.event().closed { "close" } else { "drop" }, token);
        }
    }

    fn ended(unit: u64) -> impl Fn(bool) -> Ended {
        move |closed| Ended { unit, closed }
    }

    fn start_and_end_counter(
        dispatcher: &EventDispatcher,
    ) -> (Arc<AtomicUsize>, Vec<Subscription>) {
        let seen = Arc::new(AtomicUsize::new(0));
        let starts = seen.clone();
        let ends = seen.clone();
        (
            seen,
            vec![
                dispatcher.subscribe(move |_: &Emitted<'_, Started>| {
                    starts.fetch_add(1, Ordering::Relaxed);
                }),
                dispatcher.subscribe(move |_: &Emitted<'_, Ended>| {
                    ends.fetch_add(1, Ordering::Relaxed);
                }),
            ],
        )
    }

    #[event::isolated]
    #[test]
    fn an_inactive_span_builds_nothing(dispatcher: EventDispatcher) {
        let emitter = SpanEmitter::<Started>::new();
        let built = Arc::new(AtomicUsize::new(0));

        assert!(!emitter.is_active());

        let counter = built.clone();
        let span = emitter.open_with(
            || {
                counter.fetch_add(1, Ordering::Relaxed);
                Started { unit: 1 }
            },
            || Ended {
                unit: 1,
                closed: false,
            },
        );
        assert!(!span.is_active());
        assert_eq!(span.observe_sync(|| 7), 7);
        span.close_with(|_| Ended {
            unit: 1,
            closed: true,
        });

        assert_eq!(built.load(Ordering::Relaxed), 0);
    }

    #[event::isolated]
    #[test]
    fn a_listener_on_the_start_sees_the_span(dispatcher: EventDispatcher) {
        let units = Arc::new(Mutex::new(Vec::new()));

        let starts = units.clone();
        let _start = dispatcher.subscribe(move |event: &Emitted<'_, Started>| {
            starts.lock().push(format!("start:{}", event.event().unit));
        });
        let ends = units.clone();
        let _end = dispatcher.subscribe(move |event: &Emitted<'_, Ended>| {
            ends.lock().push(format!(
                "end:{}:{}",
                event.event().unit,
                event.event().closed
            ));
        });

        let emitter = SpanEmitter::<Started>::new();
        let end = ended(4);
        let span = emitter.open_with(|| Started { unit: 4 }, move || end(false));
        assert!(span.is_active());
        span.close_with(|_| Ended {
            unit: 4,
            closed: true,
        });

        assert_eq!(*units.lock(), vec!["start:4", "end:4:true"]);
    }

    #[event::isolated]
    #[test]
    fn a_dropped_span_ends_with_its_on_drop_event(dispatcher: EventDispatcher) {
        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let _adapter = dispatcher.add_span_adapter(Recorder::new("a", &log));

        let emitter = SpanEmitter::<Started>::new();
        let end = ended(2);
        drop(emitter.open_with(|| Started { unit: 2 }, move || end(false)));

        assert_eq!(*log.lock(), vec!["a:open:2", "a:drop:1"]);
    }

    #[event::isolated]
    #[test]
    fn start_and_end_listeners_run_inside_every_span_adapter(dispatcher: EventDispatcher) {
        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let _adapter = dispatcher.add_span_adapter(Recorder::new("a", &log));
        let starts = log.clone();
        let _start = dispatcher.subscribe(move |_: &Emitted<'_, Started>| {
            starts.lock().push("start".to_owned());
        });
        let ends = log.clone();
        let _end = dispatcher.subscribe(move |_: &Emitted<'_, Ended>| {
            ends.lock().push("end".to_owned());
        });

        let end = ended(11);
        drop(SpanEmitter::<Started>::new().open_with(|| Started { unit: 11 }, move || end(false)));

        assert_eq!(
            *log.lock(),
            vec![
                "a:open:11",
                "a:enter:1",
                "start",
                "a:exit:1",
                "a:enter:1",
                "end",
                "a:exit:1",
                "a:drop:1",
            ]
        );
    }

    #[event::isolated]
    #[test]
    fn span_adapters_nest_in_registration_order_around_every_poll(dispatcher: EventDispatcher) {
        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let _outer = dispatcher.add_span_adapter(Recorder::new("outer", &log));
        let _inner = dispatcher.add_span_adapter(Recorder::new("inner", &log));

        let emitter = SpanEmitter::<Started>::new();
        let end = ended(1);
        let span = emitter.open_with(|| Started { unit: 1 }, move || end(false));
        log.lock().clear();

        span.observe_sync(|| log.lock().push("work".to_owned()));
        span.close_with(|_| Ended {
            unit: 1,
            closed: true,
        });

        assert_eq!(
            *log.lock(),
            vec![
                "outer:enter:1",
                "inner:enter:1",
                "work",
                "inner:exit:1",
                "outer:exit:1",
                "outer:close:1",
                "inner:close:1",
            ]
        );
    }

    #[event::isolated]
    #[test]
    fn a_declining_span_adapter_is_skipped(dispatcher: EventDispatcher) {
        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let _declining = dispatcher.add_span_adapter(Recorder::declining("none", &log));
        let _accepting = dispatcher.add_span_adapter(Recorder::new("accepting", &log));

        let emitter = SpanEmitter::<Started>::new();
        let end = ended(3);
        let span = emitter.open_with(|| Started { unit: 3 }, move || end(false));
        log.lock().clear();

        span.observe_sync(|| ());
        span.close_with(|_| Ended {
            unit: 3,
            closed: true,
        });

        assert_eq!(
            *log.lock(),
            vec!["accepting:enter:1", "accepting:exit:1", "accepting:close:1"]
        );
    }

    #[event::isolated]
    #[test]
    fn a_span_adapter_added_after_open_stays_out_of_that_span(dispatcher: EventDispatcher) {
        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let _first = dispatcher.add_span_adapter(Recorder::new("first", &log));

        let emitter = SpanEmitter::<Started>::new();
        let end = ended(5);
        let span = emitter.open_with(|| Started { unit: 5 }, move || end(false));

        let _late = dispatcher.add_span_adapter(Recorder::new("late", &log));
        log.lock().clear();

        span.observe_sync(|| ());
        span.close_with(|_| Ended {
            unit: 5,
            closed: true,
        });

        assert_eq!(
            *log.lock(),
            vec!["first:enter:1", "first:exit:1", "first:close:1"]
        );
    }

    #[event::isolated]
    #[test]
    fn closing_a_span_ends_it_once(dispatcher: EventDispatcher) {
        let (seen, _subscriptions) = start_and_end_counter(&dispatcher);

        let emitter = SpanEmitter::<Started>::new();
        let end = ended(6);
        let span = emitter.open_with(|| Started { unit: 6 }, move || end(false));
        span.close_with(|_| Ended {
            unit: 6,
            closed: true,
        });

        assert_eq!(seen.load(Ordering::Relaxed), 2, "one start, one end");
    }

    #[event::isolated]
    #[tokio::test]
    async fn an_observed_future_is_polled_in_every_span_adapter(dispatcher: EventDispatcher) {
        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let _adapter = dispatcher.add_span_adapter(Recorder::new("a", &log));

        let emitter = SpanEmitter::<Started>::new();
        let end = ended(7);
        let span = emitter.open_with(|| Started { unit: 7 }, move || end(false));
        log.lock().clear();

        async {
            tokio::task::yield_now().await;
        }
        .observe_ref(&span)
        .await;
        span.close_with(|_| Ended {
            unit: 7,
            closed: true,
        });

        let log = log.lock();
        assert_eq!(
            log.iter().filter(|entry| *entry == "a:enter:1").count(),
            2,
            "once per poll: {log:?}"
        );
        assert_eq!(log.last().map(String::as_str), Some("a:close:1"));
    }

    #[event::isolated]
    #[tokio::test]
    async fn a_future_in_an_inactive_span_still_completes(dispatcher: EventDispatcher) {
        let emitter = SpanEmitter::<Started>::new();
        let span = emitter.open_with(
            || Started { unit: 8 },
            || Ended {
                unit: 8,
                closed: false,
            },
        );

        let value = async {
            tokio::task::yield_now().await;
            9
        }
        .observe_ref(&span)
        .await;
        assert_eq!(value, 9);
    }

    #[event::isolated]
    #[tokio::test]
    async fn a_spawned_future_that_owns_its_span_ends_it_through_on_drop(
        dispatcher: EventDispatcher,
    ) {
        let ends = Arc::new(Mutex::new(Vec::new()));
        let seen = ends.clone();
        let _ends = dispatcher.subscribe(move |end: &Emitted<'_, Ended>| {
            let end = end.event();
            seen.lock().push((end.unit, end.closed));
        });

        let span = SpanEmitter::<Started>::new().open_with(
            || Started { unit: 12 },
            || Ended {
                unit: 12,
                closed: false,
            },
        );
        let value = tokio::spawn(async { 13 }.observe(span)).await;

        assert_eq!(value.ok(), Some(13));
        assert_eq!(*ends.lock(), [(12, false)]);
    }

    #[event::isolated]
    #[tokio::test]
    async fn a_spawned_future_closes_its_span_from_the_drop_event_and_output(
        dispatcher: EventDispatcher,
    ) {
        let ends = Arc::new(Mutex::new(Vec::new()));
        let seen = ends.clone();
        let _ends = dispatcher.subscribe(move |end: &Emitted<'_, Ended>| {
            let end = end.event();
            seen.lock().push((end.unit, end.closed));
        });

        let span = SpanEmitter::<Started>::new().open_with(
            || Started { unit: 10 },
            || Ended {
                unit: 10,
                closed: false,
            },
        );
        let value = tokio::spawn(async { 11 }.observe_and_close(span, |end, value| Ended {
            unit: end.unit + value,
            closed: true,
        }))
        .await;

        assert_eq!(value.ok(), Some(11));
        assert_eq!(*ends.lock(), [(21, true)]);
    }

    #[test]
    fn an_open_span_is_small() {
        use super::super::pool::ErasedSlotPtr;

        assert_eq!(
            size_of::<Option<ErasedSlotPtr>>(),
            size_of::<ErasedSlotPtr>(),
            "a declining span adapter keeps its place for free"
        );

        let size = size_of::<OpenSpan<Started, fn() -> Ended>>();
        assert!(size <= 64, "OpenSpan is {size} bytes");
    }
}
