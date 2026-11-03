use core::cell::Cell;

use parking_lot::Mutex;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use tokio::time::{Duration, Instant};

use super::{Emitted, Emitter, Event, EventDispatcher, Listener, Subscription, next_id};
use crate::define_id;
use crate::telemetry::event;

#[derive(Clone, Event)]
struct Ping {
    unit: UnitId,
}

#[derive(Clone, Event)]
struct Pong;

define_id! {
    /// Identifies a unit in these tests.
    struct UnitId;
}

fn counter() -> (Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let count = Arc::new(AtomicUsize::new(0));
    (Arc::clone(&count), count)
}

#[event::isolated]
#[test]
fn a_subscribed_listener_sees_events_until_it_unsubscribes(dispatcher: EventDispatcher) {
    let emitter = Emitter::<Ping>::new();
    let (seen, count) = counter();

    let subscription = dispatcher.subscribe(move |_: &Emitted<'_, Ping>| {
        count.fetch_add(1, Ordering::Relaxed);
    });
    assert!(emitter.is_active());
    emitter.emit_with(|| Ping {
        unit: UnitId::next(),
    });
    assert_eq!(seen.load(Ordering::Relaxed), 1);

    drop(subscription);
    assert!(!emitter.is_active());
    emitter.emit_with(|| Ping {
        unit: UnitId::next(),
    });
    assert_eq!(seen.load(Ordering::Relaxed), 1);
}

#[event::isolated]
#[test]
fn without_listeners_the_event_is_not_built(dispatcher: EventDispatcher) {
    let emitter = Emitter::<Ping>::new();
    let (built, count) = counter();

    assert!(!emitter.is_active());
    emitter.emit_with(|| {
        count.fetch_add(1, Ordering::Relaxed);
        Ping {
            unit: UnitId::next(),
        }
    });
    assert_eq!(built.load(Ordering::Relaxed), 0);
}

struct Counting {
    seen: Arc<AtomicUsize>,
}

impl Listener<Ping> for Counting {
    fn on_event(&self, _event: &Emitted<'_, Ping>) {
        self.seen.fetch_add(1, Ordering::Relaxed);
    }
}

#[event::isolated]
#[test]
fn a_listener_can_be_a_type_instead_of_a_closure(dispatcher: EventDispatcher) {
    let emitter = Emitter::<Ping>::new();
    let (seen, count) = counter();

    let subscription = dispatcher.subscribe(Counting { seen: count });
    emitter.emit_with(|| Ping {
        unit: UnitId::next(),
    });
    assert_eq!(seen.load(Ordering::Relaxed), 1);

    drop(subscription);
    emitter.emit_with(|| Ping {
        unit: UnitId::next(),
    });
    assert_eq!(seen.load(Ordering::Relaxed), 1);
}

// A generic event needs no bounds of its own.
#[derive(Clone, Event)]
struct Generic<T> {
    value: T,
}

#[event::isolated]
#[test]
fn a_generic_event_reaches_its_listeners(dispatcher: EventDispatcher) {
    let (seen, count) = counter();

    let _subscription = dispatcher.subscribe(move |event: &Emitted<'_, Generic<u8>>| {
        count.fetch_add(usize::from(event.event().value), Ordering::Relaxed);
    });

    Emitter::new().emit_with(|| Generic { value: 5u8 });

    assert_eq!(seen.load(Ordering::Relaxed), 5);
}

// Send but not Sync: an event is built and read on the emitting thread only.
#[derive(Clone, Event)]
struct Local {
    counter: Cell<u8>,
}

#[event::isolated]
#[test]
fn an_event_that_is_not_sync_reaches_its_listeners(dispatcher: EventDispatcher) {
    fn assert_send<T: Send>() {}
    assert_send::<Local>();

    let (seen, count) = counter();

    let _subscription = dispatcher.subscribe(move |event: &Emitted<'_, Local>| {
        count.fetch_add(usize::from(event.event().counter.get()), Ordering::Relaxed);
    });

    Emitter::new().emit_with(|| Local {
        counter: Cell::new(7),
    });

    assert_eq!(seen.load(Ordering::Relaxed), 7);
}

#[event::isolated]
#[test]
fn all_listeners_of_one_emit_see_one_time(dispatcher: EventDispatcher) {
    let times = Arc::new(Mutex::new(Vec::new()));

    let _subscriptions: Vec<Subscription> = (0..3)
        .map(|_| {
            let seen = Arc::clone(&times);
            dispatcher.subscribe(move |event: &Emitted<'_, Ping>| {
                seen.lock().push(event.at());
            })
        })
        .collect();

    let before = Instant::now();
    Emitter::new().emit_with(|| Ping {
        unit: UnitId::next(),
    });

    let times = times.lock();
    assert_eq!(times.len(), 3);
    assert!(times.iter().all(|at| *at == times[0]), "{times:?}");
    assert!(times[0] >= before);
}

#[event::isolated]
#[test]
fn an_emit_at_keeps_the_time_it_was_given(dispatcher: EventDispatcher) {
    let seen = Arc::new(Mutex::new(None));

    let times = Arc::clone(&seen);
    let _subscription = dispatcher.subscribe(move |event: &Emitted<'_, Ping>| {
        *times.lock() = Some(event.at());
    });

    let at = Instant::now() - Duration::from_secs(60);
    Emitter::new().emit_at(at, || Ping {
        unit: UnitId::next(),
    });

    assert_eq!(*seen.lock(), Some(at));
}

#[event::isolated]
#[test]
fn every_listener_sees_the_same_event(dispatcher: EventDispatcher) {
    let units = Arc::new(Mutex::new(Vec::new()));

    let first = Arc::clone(&units);
    let _one = dispatcher.subscribe(move |event: &Emitted<'_, Ping>| {
        first.lock().push(event.event().unit);
    });
    let second = Arc::clone(&units);
    let _two = dispatcher.subscribe(move |event: &Emitted<'_, Ping>| {
        second.lock().push(event.event().unit);
    });

    let unit = UnitId::next();
    Emitter::new().emit_with(|| Ping { unit });

    assert_eq!(*units.lock(), vec![unit, unit]);
}

#[event::isolated]
#[test]
fn a_listener_can_emit_and_subscribe_from_its_own_callback(dispatcher: EventDispatcher) {
    let pings = Emitter::<Ping>::new();
    let pongs = Emitter::<Pong>::new();
    let (pongs_seen, pong_count) = counter();
    let (late_seen, late_count) = counter();
    let late_subscription: Arc<Mutex<Option<Subscription>>> = Arc::new(Mutex::new(None));

    let _pong = dispatcher.subscribe(move |_: &Emitted<'_, Pong>| {
        pong_count.fetch_add(1, Ordering::Relaxed);
    });

    let subscriber = dispatcher.clone();
    let slot = Arc::clone(&late_subscription);
    let _ping = dispatcher.subscribe(move |_: &Emitted<'_, Ping>| {
        pongs.emit_with(|| Pong);
        let count = Arc::clone(&late_count);
        let late = subscriber.subscribe(move |_: &Emitted<'_, Ping>| {
            count.fetch_add(1, Ordering::Relaxed);
        });
        *slot.lock() = Some(late);
    });

    pings.emit_with(|| Ping {
        unit: UnitId::next(),
    });
    assert_eq!(pongs_seen.load(Ordering::Relaxed), 1);
    assert_eq!(late_seen.load(Ordering::Relaxed), 0);

    pings.emit_with(|| Ping {
        unit: UnitId::next(),
    });
    assert_eq!(pongs_seen.load(Ordering::Relaxed), 2);
    assert_eq!(late_seen.load(Ordering::Relaxed), 1);

    drop(late_subscription.lock().take());
}

#[event::isolated]
#[test]
fn a_listener_can_subscribe_again_from_its_own_destructor(dispatcher: EventDispatcher) {
    struct SubscribeOnDrop {
        dispatcher: EventDispatcher,
        count: Arc<AtomicUsize>,
        replacement: Arc<Mutex<Option<Subscription>>>,
    }

    impl Drop for SubscribeOnDrop {
        fn drop(&mut self) {
            let count = Arc::clone(&self.count);
            *self.replacement.lock() =
                Some(self.dispatcher.subscribe(move |_: &Emitted<'_, Ping>| {
                    count.fetch_add(1, Ordering::Relaxed);
                }));
        }
    }

    let emitter = Emitter::<Ping>::new();
    let (seen, count) = counter();
    let replacement: Arc<Mutex<Option<Subscription>>> = Arc::new(Mutex::new(None));

    let on_drop = SubscribeOnDrop {
        dispatcher: dispatcher.clone(),
        count,
        replacement: Arc::clone(&replacement),
    };
    let subscription = dispatcher.subscribe(move |_: &Emitted<'_, Ping>| {
        let _held = &on_drop;
    });

    drop(subscription);

    emitter.emit_with(|| Ping {
        unit: UnitId::next(),
    });
    assert_eq!(seen.load(Ordering::Relaxed), 1);

    drop(replacement.lock().take());
}

#[test]
fn an_override_keeps_events_away_from_other_dispatchers() {
    let overridden = EventDispatcher::default();
    let other = EventDispatcher::default();
    let (overridden_seen, overridden_count) = counter();
    let (other_seen, other_count) = counter();

    let _one = overridden.subscribe(move |_: &Emitted<'_, Ping>| {
        overridden_count.fetch_add(1, Ordering::Relaxed);
    });
    let _two = other.subscribe(move |_: &Emitted<'_, Ping>| {
        other_count.fetch_add(1, Ordering::Relaxed);
    });

    overridden.scope_sync(|| {
        Emitter::<Ping>::new().emit_with(|| Ping {
            unit: UnitId::next(),
        });
    });

    assert_eq!(overridden_seen.load(Ordering::Relaxed), 1);
    assert_eq!(other_seen.load(Ordering::Relaxed), 0);
}

#[test]
fn a_nested_scope_ends_with_its_closure() {
    let outer = EventDispatcher::default();
    let inner = EventDispatcher::default();
    let (seen, count) = counter();
    let _subscription = outer.subscribe(move |_: &Emitted<'_, Ping>| {
        count.fetch_add(1, Ordering::Relaxed);
    });

    outer.scope_sync(|| {
        inner.scope_sync(|| {
            assert!(
                !Emitter::<Ping>::new().is_active(),
                "the inner dispatcher has no listeners"
            );
        });
        Emitter::<Ping>::new().emit_with(|| Ping {
            unit: UnitId::next(),
        });
    });

    assert_eq!(seen.load(Ordering::Relaxed), 1);
}

#[test]
fn no_override_outside_a_scope() {
    let dispatcher = EventDispatcher::default();
    let (seen, count) = counter();
    let _subscription = dispatcher.subscribe(move |_: &Emitted<'_, Ping>| {
        count.fetch_add(1, Ordering::Relaxed);
    });

    dispatcher.scope_sync(|| {});
    Emitter::<Ping>::new().emit_with(|| Ping {
        unit: UnitId::next(),
    });

    assert_eq!(seen.load(Ordering::Relaxed), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_override_follows_a_rama_spawn() {
    let dispatcher = EventDispatcher::default();
    let (seen, count) = counter();
    let _subscription = dispatcher.subscribe(move |_: &Emitted<'_, Ping>| {
        count.fetch_add(1, Ordering::Relaxed);
    });

    let task = dispatcher.scope_sync(|| {
        crate::rt::spawn(async {
            assert!(super::dispatcher::task_override_is_set());
            let nested = crate::rt::spawn(async {
                Emitter::<Ping>::new().emit_with(|| Ping {
                    unit: UnitId::next(),
                });
            });
            nested.await.unwrap();
        })
    });
    task.await.unwrap();

    assert_eq!(seen.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_spawn_without_an_override_is_not_scoped() {
    let scoped = crate::rt::spawn(async { super::dispatcher::task_override_is_set() })
        .await
        .unwrap();
    assert!(!scoped);
}

#[event::isolated]
#[test]
fn an_emitter_resolved_before_a_subscribe_still_sees_it(dispatcher: EventDispatcher) {
    let emitter = Emitter::<Ping>::new();
    let (seen, count) = counter();

    let _subscription = dispatcher.subscribe(move |_: &Emitted<'_, Ping>| {
        count.fetch_add(1, Ordering::Relaxed);
    });

    emitter.emit_with(|| Ping {
        unit: UnitId::next(),
    });
    assert_eq!(seen.load(Ordering::Relaxed), 1);
}

#[test]
fn ids_are_unique_across_threads() {
    const THREADS: usize = 8;
    const PER_THREAD: usize = 4096;

    let ids: Vec<_> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..THREADS)
            .map(|_| scope.spawn(|| (0..PER_THREAD).map(|_| next_id().get()).collect::<Vec<_>>()))
            .collect();
        handles
            .into_iter()
            .flat_map(|handle| handle.join().unwrap())
            .collect()
    });

    let unique: ahash::HashSet<_> = ids.iter().copied().collect();
    assert_eq!(unique.len(), THREADS * PER_THREAD);
}

#[test]
fn typed_ids_share_the_id_space() {
    define_id! {
        struct OtherId;
    }

    let unit = UnitId::next();
    let other = OtherId::next();
    assert_ne!(unit.get(), other.get());
    assert_eq!(unit.to_string(), unit.get().to_string());
}

#[event::isolated]
#[test]
fn an_isolated_test_runs_in_its_own_dispatcher(events: EventDispatcher) {
    let (seen, count) = counter();
    let _subscription = events.subscribe(move |_: &Emitted<'_, Ping>| {
        count.fetch_add(1, Ordering::Relaxed);
    });

    Emitter::<Ping>::new().emit_with(|| Ping {
        unit: UnitId::next(),
    });

    assert_eq!(seen.load(Ordering::Relaxed), 1);
}

#[event::isolated]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_isolated_async_test_covers_what_rama_spawns(events: EventDispatcher) {
    let (seen, count) = counter();
    let _subscription = events.subscribe(move |_: &Emitted<'_, Ping>| {
        count.fetch_add(1, Ordering::Relaxed);
    });

    crate::rt::spawn(async {
        Emitter::<Ping>::new().emit_with(|| Ping {
            unit: UnitId::next(),
        });
    })
    .await
    .unwrap();

    assert_eq!(seen.load(Ordering::Relaxed), 1);
}

#[test]
fn an_event_knows_the_module_it_is_defined_in() {
    assert_eq!(Ping::MODULE, "rama_core::telemetry::event::tests");
}
