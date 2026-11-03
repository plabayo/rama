use core::any::{Any, TypeId};
use core::fmt;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicUsize, Ordering};
use std::sync::LazyLock;

use ahash::HashMap;
use parking_lot::Mutex;

use super::slot::{Slot, Unsubscribe};
use super::span::{ErasedSpanAdapter, PooledSpanAdapter};
use super::{Event, Listener, SpanAdapter, SpanStart};
use crate::futures::future::Either;
use crate::std::{boxed::Box, sync::Arc};

/// Where emitters resolve their listeners, and where listeners subscribe.
///
/// A dispatcher is a handle to a registry of listeners, so all clones share
/// them. Tests make their own with [`Default`] and run inside it with
/// [`scope`](Self::scope) or [`scope_sync`](Self::scope_sync).
///
/// A dispatcher lives for the process or a test: its per event type state is
/// never freed, so do not create one per request or connection.
#[derive(Clone, Default)]
pub struct EventDispatcher {
    registry: Arc<Registry>,
}

#[derive(Default)]
struct Registry {
    slots: Mutex<HashMap<TypeId, &'static (dyn Any + Send + Sync)>>,
}

static GLOBAL: LazyLock<EventDispatcher> = LazyLock::new(EventDispatcher::default);

// Overrides alive in this process, so resolving a dispatcher never touches the
// task local in the common case (= 0 overrides).
static OVERRIDES: AtomicUsize = AtomicUsize::new(0);

tokio::task_local! {
    static TASK_OVERRIDE: TaskOverride;
}

struct TaskOverride {
    dispatcher: EventDispatcher,
    _active: ActiveOverride,
}

struct ActiveOverride;

impl ActiveOverride {
    fn new() -> Self {
        OVERRIDES.fetch_add(1, Ordering::Relaxed);
        Self
    }
}

impl Drop for ActiveOverride {
    fn drop(&mut self) {
        OVERRIDES.fetch_sub(1, Ordering::Relaxed);
    }
}

impl EventDispatcher {
    /// The dispatcher of this process, used whenever no override is active.
    #[must_use]
    pub fn global() -> &'static Self {
        &GLOBAL
    }

    /// The dispatcher events of the current task go to: the override of the
    /// current scope if there is one, else [`global`](Self::global).
    #[must_use]
    pub fn current() -> Self {
        current_override().unwrap_or_else(|| Self::global().clone())
    }

    /// Run `future` with this dispatcher as [`current`](Self::current).
    ///
    /// The override applies to the future and to everything rama spawns from
    /// it. It does not apply to a `tokio::spawn` of your own.
    pub fn scope<F: Future>(&self, future: F) -> impl Future<Output = F::Output> + use<F> {
        TASK_OVERRIDE.scope(self.task_override(), future)
    }

    /// Run `f` with this dispatcher as [`current`](Self::current), for
    /// synchronous code such as building a stack.
    pub fn scope_sync<T>(&self, f: impl FnOnce() -> T) -> T {
        TASK_OVERRIDE.sync_scope(self.task_override(), f)
    }

    fn task_override(&self) -> TaskOverride {
        TaskOverride {
            dispatcher: self.clone(),
            _active: ActiveOverride::new(),
        }
    }

    /// Call `listener` for every `E` emitted through this dispatcher, until the
    /// returned [`Subscription`] is dropped. It runs inline at the emit site,
    /// so a listener with heavy work needs to hand that off itself.
    pub fn subscribe<E: Event>(&self, listener: impl Listener<E>) -> Subscription {
        Self::register(self.slot::<E>(), Arc::new(listener))
    }

    /// Add `adapter` to every span of type `S` opened through this dispatcher,
    /// for as long as the returned [`Subscription`] is alive.
    ///
    /// A span adapter is how tracing, dial9 or any other tool carries a rama
    /// span over: it is entered around every poll of the span's work, and
    /// closed when the span ends. Span adapters are snapshotted when a span
    /// opens, so one added later does not join a running span.
    pub fn add_span_adapter<S: SpanStart>(&self, adapter: impl SpanAdapter<S>) -> Subscription {
        Self::register(
            self.span_adapter_slot::<S>(),
            Arc::new(PooledSpanAdapter::new(adapter)),
        )
    }

    fn register<L: ?Sized + Send + Sync + 'static>(
        slot: &'static Slot<L>,
        entry: Arc<L>,
    ) -> Subscription {
        let key = slot.insert(entry);
        Subscription { slot, key }
    }

    pub(super) fn slot<E: Event>(&self) -> &'static Slot<dyn Listener<E>> {
        resolve_slot::<E, dyn Listener<E>>(&mut self.registry.slots.lock())
    }

    pub(super) fn span_adapter_slot<S: SpanStart>(
        &self,
    ) -> &'static Slot<dyn ErasedSpanAdapter<S>> {
        resolve_slot::<SpanAdapterKey<S>, dyn ErasedSpanAdapter<S>>(&mut self.registry.slots.lock())
    }
}

// Span adapters of `S` are keyed apart from the listeners of `S` itself.
struct SpanAdapterKey<S>(PhantomData<S>);

impl fmt::Debug for EventDispatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventDispatcher").finish_non_exhaustive()
    }
}

// Slots are never freed, so that an emitter can hold one by `&'static`
// reference instead of looking it up or counting references on every emit.
fn resolve_slot<K: 'static, L: ?Sized + Send + Sync + 'static>(
    slots: &mut HashMap<TypeId, &'static (dyn Any + Send + Sync)>,
) -> &'static Slot<L> {
    let slot = *slots.entry(TypeId::of::<K>()).or_insert_with(|| {
        let slot: &'static Slot<L> = Box::leak(Box::new(Slot::new()));
        slot
    });
    #[expect(
        clippy::expect_used,
        reason = "a slot is only ever stored under the `TypeId` of its own key type"
    )]
    let slot = slot
        .downcast_ref::<Slot<L>>()
        .expect("slot has the type of its key");
    slot
}

fn current_override() -> Option<EventDispatcher> {
    if OVERRIDES.load(Ordering::Relaxed) == 0 {
        return None;
    }
    TASK_OVERRIDE
        .try_with(|current| current.dispatcher.clone())
        .ok()
}

/// Carry the override of the spawning context into a spawned future. Without
/// an override the future is returned as it is.
pub(crate) fn inherit<F: Future>(future: F) -> impl Future<Output = F::Output> {
    match current_override() {
        None => Either::Left(future),
        Some(dispatcher) => Either::Right(dispatcher.scope(future)),
    }
}

#[cfg(test)]
pub(super) fn task_override_is_set() -> bool {
    TASK_OVERRIDE.try_with(|_| ()).is_ok()
}

/// Keeps one listener or span adapter registered. Dropping it unsubscribes.
#[must_use = "a listener is only subscribed while its Subscription is alive"]
pub struct Subscription {
    slot: &'static dyn Unsubscribe,
    key: u64,
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.slot.unsubscribe(self.key);
    }
}

impl fmt::Debug for Subscription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Subscription").finish_non_exhaustive()
    }
}
