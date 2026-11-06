#![cfg(not(rama_loom))]

use std::{
    future::Future,
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
    time::Duration,
};

use tokio::{
    sync::oneshot,
    time::{Instant, advance},
};

use super::{Cause, Scope, WeakScope, attach_scope, enter_scope, enter_scope_with, scope_context};
use crate::extensions::Extensions;

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap()
}

fn poll<F: Future + Unpin>(future: &mut F, waker: &Waker) -> Poll<F::Output> {
    Pin::new(future).poll(&mut Context::from_waker(waker))
}

fn poll_noop<F: Future + Unpin>(future: &mut F) -> Poll<F::Output> {
    poll(future, Waker::noop())
}

#[derive(Default)]
struct Flag(AtomicBool);

impl Wake for Flag {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }
}

impl Flag {
    fn waker() -> (Arc<Self>, Waker) {
        let flag = Arc::new(Self::default());
        (flag.clone(), Waker::from(flag))
    }

    fn woken(&self) -> bool {
        self.0.swap(false, Ordering::SeqCst)
    }
}

fn reason(cause: Option<&Cause>) -> Option<&'static str> {
    match cause {
        Some(Cause::Reason(reason)) => Some(*reason),
        _ => None,
    }
}

fn waiter_count(scope: &Scope) -> usize {
    scope.node().map_or(0, |node| node.waiters().len())
}

const SEC: Duration = Duration::from_secs(1);

fn cancelled_root() -> Scope {
    let scope = Scope::new();
    scope.cancel(Cause::Owner);
    scope
}

#[test]
fn new_scope_is_active_until_cancelled() {
    let scope = Scope::new();
    assert!(!scope.is_cancelled());
    assert!(!scope.is_aborted());
    assert!(scope.cause().is_none());

    scope.cancel(Cause::Reason("stop"));
    assert!(scope.is_cancelled());
    assert!(!scope.is_aborted());
    assert_eq!(reason(scope.cause().as_ref()), Some("stop"));
    assert!(poll_noop(&mut scope.cancelled()).is_ready());
    assert!(poll_noop(&mut scope.aborted()).is_pending());
}

#[test]
fn waiter_is_woken_by_cancel() {
    let scope = Scope::new();
    let (flag, waker) = Flag::waker();
    let mut cancelled = scope.cancelled();
    assert!(poll(&mut cancelled, &waker).is_pending());
    scope.cancel(Cause::Owner);
    assert!(flag.woken());
    assert!(poll(&mut cancelled, &waker).is_ready());
    assert_eq!(waiter_count(&scope), 0);
}

#[test]
fn child_follows_parent_never_the_reverse() {
    let parent = Scope::new();
    let child = parent.child();
    child.cancel(Cause::Reason("child"));
    assert!(!parent.is_cancelled());

    let sibling = parent.child();
    let (flag, waker) = Flag::waker();
    let mut cancelled = sibling.cancelled();
    assert!(poll(&mut cancelled, &waker).is_pending());
    parent.abort(Cause::Reason("parent"));
    assert!(flag.woken());
    assert!(poll(&mut cancelled, &waker).is_ready());
    assert!(sibling.is_aborted());
    assert_eq!(reason(sibling.cause().as_ref()), Some("parent"));
    assert_eq!(reason(sibling.abort_cause().as_ref()), Some("parent"));
    assert_eq!(reason(child.cause().as_ref()), Some("child"));
    assert_eq!(reason(child.abort_cause().as_ref()), Some("parent"));
}

#[test]
fn child_of_cancelled_parent_is_born_cancelled() {
    let parent = Scope::new();
    parent.cancel(Cause::Reason("before"));
    let child = parent.child();
    assert!(child.is_cancelled());
    assert_eq!(reason(child.cause().as_ref()), Some("before"));
}

#[test]
fn abort_implies_cancel_and_first_cause_wins() {
    let scope = Scope::new();
    scope.abort(Cause::Reason("first"));
    scope.abort(Cause::Reason("second"));
    scope.cancel(Cause::Reason("third"));
    assert!(scope.is_cancelled());
    assert_eq!(reason(scope.cause().as_ref()), Some("first"));
    assert_eq!(reason(scope.abort_cause().as_ref()), Some("first"));
}

#[test]
fn never_scope_and_its_children() {
    let never = Scope::never();
    never.cancel(Cause::Owner);
    assert!(!never.is_cancelled());
    assert!(poll_noop(&mut never.cancelled()).is_pending());

    let first = never.child();
    let second = never.child();
    first.cancel(Cause::Owner);
    assert!(first.is_cancelled());
    assert!(!second.is_cancelled());
}

#[test]
fn never_scope_is_drained_and_never_ends_its_phases() {
    let never = Scope::never();
    let weak = never.clone_weak();
    let mut drained = never.drained();
    let mut weak_drained = weak.drained();
    let mut cancelled = weak.cancelled();
    let mut aborted = weak.aborted();
    for _ in 0..2 {
        assert!(poll_noop(&mut drained).is_ready());
        assert!(poll_noop(&mut weak_drained).is_ready());
        assert!(poll_noop(&mut cancelled).is_pending());
        assert!(poll_noop(&mut aborted).is_pending());
    }
    drop(never);
    assert!(poll_noop(&mut weak.drained()).is_ready());
    assert!(weak.into_scope().is_some_and(|scope| scope.is_never()));
}

#[test]
fn timeout_on_never_creates_a_root() {
    rt().block_on(async {
        let scope = Scope::never().with_timeout(SEC);
        assert!(!scope.is_cancelled());
        advance(SEC).await;
        assert!(scope.is_cancelled());
    });
}

#[test]
fn timeout_is_observed_without_waiting() {
    rt().block_on(async {
        let scope = Scope::new().with_timeout(10 * SEC);
        advance(9 * SEC).await;
        assert!(!scope.is_cancelled());
        advance(SEC).await;
        assert!(scope.is_cancelled());
        assert!(!scope.is_aborted());
        assert!(matches!(scope.cause(), Some(Cause::Deadline)));
    });
}

#[test]
fn waiter_completes_at_the_deadline() {
    rt().block_on(async {
        let start = Instant::now();
        let scope = Scope::new().with_timeout(10 * SEC);
        scope.cancelled().await;
        assert_eq!(start.elapsed(), 10 * SEC);
    });
}

#[test]
fn tightened_deadline_wakes_a_registered_waiter() {
    rt().block_on(async {
        let start = Instant::now();
        let scope = Scope::new().with_timeout(100 * SEC);
        let waiter = tokio::spawn(scope.cancelled());
        tokio::task::yield_now().await;
        let _scope = scope.clone().with_timeout(SEC);
        waiter.await.unwrap();
        assert_eq!(start.elapsed(), SEC);
    });
}

#[test]
fn grace_counts_from_manual_cancel() {
    rt().block_on(async {
        let scope = Scope::new().with_grace(5 * SEC);
        advance(3 * SEC).await;
        let cancelled_at = Instant::now();
        scope.cancel(Cause::Owner);
        assert!(!scope.is_aborted());
        scope.aborted().await;
        assert_eq!(cancelled_at.elapsed(), 5 * SEC);
        assert!(matches!(scope.abort_cause(), Some(Cause::GraceElapsed)));
    });
}

#[test]
fn grace_is_anchored_at_the_schedule_not_the_first_observation() {
    rt().block_on(async {
        let scope = Scope::new()
            .with_timeout(10 * SEC)
            .with_grace(5 * SEC)
            .with_hard_timeout(20 * SEC);
        advance(100 * SEC).await;
        assert!(scope.is_aborted());
        assert!(matches!(scope.cause(), Some(Cause::Deadline)));
        assert!(matches!(scope.abort_cause(), Some(Cause::GraceElapsed)));
    });
}

#[test]
fn zero_grace_aborts_with_the_cancel() {
    let scope = Scope::new().with_grace(Duration::ZERO);
    scope.cancel(Cause::Owner);
    assert!(scope.is_aborted());
}

#[test]
fn child_grace_follows_parent_cancel() {
    rt().block_on(async {
        let parent = Scope::new();
        let child = parent.child().with_grace(3 * SEC);
        parent.cancel(Cause::Reason("parent"));
        assert!(child.is_cancelled());
        child.aborted().await;
        assert!(!parent.is_aborted());
        assert!(matches!(child.abort_cause(), Some(Cause::GraceElapsed)));
        assert_eq!(reason(child.cause().as_ref()), Some("parent"));
    });
}

#[test]
fn parent_hard_deadline_caps_child_grace() {
    rt().block_on(async {
        let start = Instant::now();
        let parent = Scope::new().with_hard_timeout(2 * SEC);
        let child = parent.child().with_grace(10 * SEC);
        child.cancel(Cause::Owner);
        child.aborted().await;
        assert_eq!(start.elapsed(), 2 * SEC);
        assert!(matches!(child.abort_cause(), Some(Cause::Deadline)));
    });
}

#[test]
fn overdue_deadline_counts_from_now() {
    rt().block_on(async {
        let past = Instant::now();
        advance(10 * SEC).await;
        let scope = Scope::new().with_deadline(past);
        assert!(scope.is_cancelled());
        assert!(matches!(scope.cause(), Some(Cause::Deadline)));
    });
}

#[test]
fn observed_parent_cause_survives_equal_time_child_cancel() {
    rt().block_on(async {
        let parent = Scope::new();
        let child = parent.child();
        parent.cancel(Cause::Reason("a"));
        assert_eq!(reason(child.cause().as_ref()), Some("a"));
        child.cancel(Cause::Reason("b"));
        assert_eq!(reason(child.cause().as_ref()), Some("a"));
    });
}

#[test]
fn unobserved_equal_time_child_cancel_wins_locally() {
    rt().block_on(async {
        let parent = Scope::new();
        let child = parent.child();
        parent.cancel(Cause::Reason("a"));
        child.cancel(Cause::Reason("b"));
        assert_eq!(reason(child.cause().as_ref()), Some("b"));
        assert_eq!(reason(parent.cause().as_ref()), Some("a"));
    });
}

#[test]
fn late_grace_does_not_rewrite_an_observed_hard_cause() {
    rt().block_on(async {
        let parent = Scope::new();
        let scope = parent.child();
        scope.cancel(Cause::Reason("local"));
        advance(10 * SEC).await;
        parent.abort(Cause::Reason("parent"));
        assert_eq!(reason(scope.abort_cause().as_ref()), Some("parent"));
        advance(10 * SEC).await;
        let scope = scope.with_grace(5 * SEC);
        assert_eq!(reason(scope.abort_cause().as_ref()), Some("parent"));
        assert_eq!(reason(scope.cause().as_ref()), Some("local"));
    });
}

#[test]
fn late_grace_may_abort_immediately() {
    rt().block_on(async {
        let scope = Scope::new();
        scope.cancel(Cause::Owner);
        advance(20 * SEC).await;
        let scope = scope.with_grace(5 * SEC);
        assert!(scope.is_aborted());
        assert!(matches!(scope.abort_cause(), Some(Cause::GraceElapsed)));
    });
}

#[test]
fn expired_unobserved_deadline_beats_a_later_manual_cancel() {
    rt().block_on(async {
        let scope = Scope::new().with_timeout(10 * SEC);
        advance(12 * SEC).await;
        scope.cancel(Cause::Reason("manual"));
        assert!(matches!(scope.cause(), Some(Cause::Deadline)));
    });
}

#[test]
fn earlier_local_cause_survives_parent_abort() {
    rt().block_on(async {
        let parent = Scope::new();
        let child = parent.child();
        child.cancel(Cause::Reason("local"));
        advance(SEC).await;
        parent.abort(Cause::Reason("parent"));
        assert_eq!(reason(child.cause().as_ref()), Some("local"));
        assert_eq!(reason(child.abort_cause().as_ref()), Some("parent"));
    });
}

#[test]
fn observing_through_a_descendant_publishes_the_ancestor() {
    rt().block_on(async {
        let parent = Scope::new().with_timeout(10 * SEC);
        let child = parent.child();
        advance(10 * SEC).await;
        assert!(matches!(child.cause(), Some(Cause::Deadline)));
        parent.cancel(Cause::Reason("late"));
        assert!(matches!(parent.cause(), Some(Cause::Deadline)));
    });
}

#[test]
fn signal_cancels_and_wakes_the_waiter() {
    rt().block_on(async {
        let (tx, rx) = oneshot::channel::<()>();
        let scope = Scope::new().with_signal(rx);
        let waiter = tokio::spawn(scope.cancelled());
        tokio::task::yield_now().await;
        assert!(!scope.is_cancelled());
        tx.send(()).unwrap();
        waiter.await.unwrap();
        assert!(matches!(scope.cause(), Some(Cause::Signal)));
    });
}

#[test]
fn signal_wakes_survivor_after_last_registered_waiter_dropped() {
    let (tx, rx) = oneshot::channel::<()>();
    let scope = Scope::new().with_signal(rx);
    let (first_flag, first_waker) = Flag::waker();
    let (_second_flag, second_waker) = Flag::waker();
    let mut first = scope.cancelled();
    let mut second = scope.cancelled();
    assert!(poll(&mut first, &first_waker).is_pending());
    assert!(poll(&mut second, &second_waker).is_pending());
    drop(second);
    tx.send(()).unwrap();
    assert!(first_flag.woken());
    assert!(poll(&mut first, &first_waker).is_ready());
}

#[test]
fn child_waiting_for_abort_drives_parent_signal_and_grace() {
    rt().block_on(async {
        let (tx, rx) = oneshot::channel::<()>();
        let parent = Scope::new().with_signal(rx);
        let child = parent.child().with_grace(5 * SEC);
        let waiter = tokio::spawn(child.aborted());
        tokio::task::yield_now().await;
        let sent = Instant::now();
        tx.send(()).unwrap();
        waiter.await.unwrap();
        assert_eq!(sent.elapsed(), 5 * SEC);
        assert!(matches!(parent.cause(), Some(Cause::Signal)));
        assert!(!parent.is_aborted());
    });
}

#[test]
fn hard_signal_progresses_after_graceful_waiters_are_done() {
    rt().block_on(async {
        let (tx, rx) = oneshot::channel::<()>();
        let scope = Scope::new().with_hard_signal(rx);
        scope.cancel(Cause::Owner);
        scope.cancelled().await;
        let waiter = tokio::spawn(scope.aborted());
        tokio::task::yield_now().await;
        tx.send(()).unwrap();
        waiter.await.unwrap();
        assert!(matches!(scope.abort_cause(), Some(Cause::Signal)));
    });
}

#[test]
fn hard_budget_starts_at_a_second_event() {
    rt().block_on(async {
        let (closed_tx, closed_rx) = oneshot::channel::<()>();
        let relay = Scope::new().with_hard_signal(async move {
            let _closed = closed_rx.await;
            tokio::time::sleep(5 * SEC).await;
        });
        relay.cancel(Cause::Reason("egress goaway"));
        let waiter = tokio::spawn(relay.aborted());
        advance(60 * SEC).await;
        assert!(!relay.is_aborted());
        let closed = Instant::now();
        closed_tx.send(()).unwrap();
        waiter.await.unwrap();
        assert_eq!(closed.elapsed(), 5 * SEC);
    });
}

#[test]
fn later_waker_replaces_the_earlier_one() {
    let scope = Scope::new();
    let (first_flag, first_waker) = Flag::waker();
    let (second_flag, second_waker) = Flag::waker();
    let mut cancelled = scope.cancelled();
    assert!(poll(&mut cancelled, &first_waker).is_pending());
    assert!(poll(&mut cancelled, &second_waker).is_pending());
    assert_eq!(waiter_count(&scope), 1);
    scope.cancel(Cause::Owner);
    assert!(!first_flag.woken());
    assert!(second_flag.woken());
}

#[test]
fn waiter_re_registers_after_a_wake_without_phase_change() {
    rt().block_on(async {
        let scope = Scope::new();
        let (flag, waker) = Flag::waker();
        let mut cancelled = scope.cancelled();
        assert!(poll(&mut cancelled, &waker).is_pending());
        let _scope = scope.clone().with_timeout(100 * SEC);
        assert!(flag.woken());
        // Same waker after a wake-up: the registration is gone and must be made again.
        assert!(poll(&mut cancelled, &waker).is_pending());
        scope.cancel(Cause::Owner);
        assert!(flag.woken());
    });
}

#[test]
fn dropped_waiters_leave_no_registrations() {
    let parent = Scope::new();
    let child = parent.child();
    for _ in 0..3 {
        let mut cancelled = child.cancelled();
        let mut aborted = child.aborted();
        let mut drained = child.drained();
        assert!(poll_noop(&mut cancelled).is_pending());
        assert!(poll_noop(&mut aborted).is_pending());
        assert!(poll_noop(&mut drained).is_pending());
        assert!(waiter_count(&child) > 0);
    }
    assert_eq!(waiter_count(&child), 0);
}

#[test]
fn a_waiter_registers_on_its_own_node_at_any_depth() {
    let root = Scope::new();
    let leaf = root.child().child().child();
    let mut waits: Vec<_> = (0..3).map(|_| leaf.cancelled()).collect();
    for wait in &mut waits {
        assert!(poll_noop(wait).is_pending());
    }
    assert_eq!(waiter_count(&leaf), 3);
    // One relay per level on the way up, whatever the number of waiters.
    assert_eq!(waiter_count(&root), 1);
}

#[test]
fn every_ancestor_wake_reaches_a_deep_waiter() {
    let root = Scope::new();
    let leaf = root.child().child();
    let (flag, waker) = Flag::waker();
    let mut aborted = leaf.aborted();
    assert!(poll(&mut aborted, &waker).is_pending());
    root.cancel(Cause::Owner);
    assert!(flag.woken());
    assert!(poll(&mut aborted, &waker).is_pending());
    root.abort(Cause::Owner);
    assert!(flag.woken());
    assert!(poll(&mut aborted, &waker).is_ready());
}

#[test]
fn a_dropped_child_leaves_no_relay_on_its_parent() {
    let root = Scope::new();
    for _ in 0..3 {
        let child = root.child();
        let mut cancelled = child.cancelled();
        assert!(poll_noop(&mut cancelled).is_pending());
        assert_eq!(waiter_count(&root), 1);
    }
    assert_eq!(waiter_count(&root), 0);
}

#[test]
fn signal_body_may_reenter_its_own_scope() {
    rt().block_on(async {
        let slot: Arc<parking_lot::Mutex<Option<WeakScope>>> = Arc::default();
        let polls = Arc::new(AtomicUsize::new(0));
        let signal = {
            let slot = slot.clone();
            let polls = polls.clone();
            std::future::poll_fn(move |cx| {
                let weak = slot.lock().clone().unwrap();
                if polls.fetch_add(1, Ordering::SeqCst) == 0 {
                    cx.waker().wake_by_ref();
                    let mut nested = weak.cancelled();
                    assert!(poll_noop(&mut nested).is_pending());
                    let _scope = weak.into_scope().map(|scope| {
                        scope
                            .with_hard_timeout(100 * SEC)
                            .with_grace(50 * SEC)
                            .with_signal(std::future::pending::<()>())
                    });
                    Poll::Pending
                } else {
                    weak.cancel(Cause::Reason("from signal"));
                    Poll::Ready(())
                }
            })
        };
        let scope = Scope::new().with_signal(signal);
        *slot.lock() = Some(scope.clone_weak());
        scope.cancelled().await;
        assert_eq!(reason(scope.cause().as_ref()), Some("from signal"));
        assert!(polls.load(Ordering::SeqCst) >= 2);
    });
}

struct Reenter(Scope);

impl Wake for Reenter {
    fn wake(self: Arc<Self>) {
        let child = self.0.child();
        child.abort(Cause::Reason("from waker"));
        let _cancelled = self.0.is_cancelled();
    }
}

impl Drop for Reenter {
    fn drop(&mut self) {
        let _child = self.0.child();
        let _aborted = self.0.is_aborted();
    }
}

#[test]
fn wakers_may_reenter_the_tree() {
    let scope = Scope::new();
    let first = Waker::from(Arc::new(Reenter(scope.clone())));
    let second = Waker::from(Arc::new(Reenter(scope.clone())));
    let mut cancelled = scope.cancelled();
    assert!(poll(&mut cancelled, &first).is_pending());
    drop(first);
    assert!(poll(&mut cancelled, &second).is_pending());
    drop(second);
    scope.cancel(Cause::Owner);
    assert!(poll_noop(&mut cancelled).is_ready());
}

#[test]
fn panicking_signal_is_dropped_and_others_keep_driving() {
    let polls = Arc::new(AtomicUsize::new(0));
    let panicking = {
        let polls = polls.clone();
        std::future::poll_fn(move |_cx| -> Poll<()> {
            polls.fetch_add(1, Ordering::SeqCst);
            panic!("signal panics");
        })
    };
    let (tx, rx) = oneshot::channel::<()>();
    let scope = Scope::new().with_signal(panicking).with_signal(rx);
    let mut cancelled = scope.cancelled();
    let panicked = catch_unwind(AssertUnwindSafe(|| poll_noop(&mut cancelled)));
    panicked.unwrap_err();

    let mut cancelled = scope.cancelled();
    assert!(poll_noop(&mut cancelled).is_pending());
    assert_eq!(polls.load(Ordering::SeqCst), 1);
    tx.send(()).unwrap();
    assert!(poll_noop(&mut cancelled).is_ready());
    assert!(matches!(scope.cause(), Some(Cause::Signal)));
}

#[test]
fn join_waits_for_strong_holders() {
    rt().block_on(async {
        let (tx, rx) = oneshot::channel::<()>();
        let root = Scope::new().with_signal(rx);
        let scope = root.clone();
        let weak = root.clone_weak();
        let worker = tokio::spawn(async move {
            scope.cancelled().await;
            tokio::time::sleep(3 * SEC).await;
            drop(scope);
        });
        tokio::task::yield_now().await;
        tx.send(()).unwrap();
        let elapsed = root.join().await.unwrap().elapsed();
        assert_eq!(elapsed, 3 * SEC);
        worker.await.unwrap();
        assert!(weak.clone().into_scope().is_none());
        assert!(weak.is_cancelled());
    });
}

#[test]
fn join_returns_at_the_hard_phase_with_live_holders() {
    rt().block_on(async {
        let root = cancelled_root().with_grace(5 * SEC);
        let holder = root.clone();
        let weak = root.clone_weak();
        let aborted = root.join().await.unwrap_err();
        assert_eq!(aborted.elapsed(), 5 * SEC);
        assert!(matches!(aborted.cause(), Some(Cause::GraceElapsed)));

        let mut drained = weak.drained();
        assert!(poll_noop(&mut drained).is_pending());
        drop(holder);
        assert!(poll_noop(&mut drained).is_ready());
    });
}

#[test]
fn join_after_abort_returns_immediately() {
    rt().block_on(async {
        let root = Scope::new().with_signal(std::future::pending::<()>());
        let _holder = root.clone();
        root.abort(Cause::Reason("now"));
        let aborted = root.join().await.unwrap_err();
        assert_eq!(aborted.elapsed(), Duration::ZERO);
    });
}

#[test]
fn join_is_a_waitgroup() {
    rt().block_on(async {
        let root = Scope::new();
        let scope = root.clone();
        let worker = tokio::spawn(async move {
            tokio::time::sleep(SEC).await;
            drop(scope);
        });
        assert_eq!(root.join().await.unwrap().elapsed(), SEC);
        worker.await.unwrap();
    });
}

#[test]
fn dropping_a_holder_cancels_nothing() {
    let root = Scope::new().with_signal(std::future::pending::<()>());
    let scope = root.clone();
    drop(root);
    assert!(!scope.is_cancelled());
}

#[test]
fn weak_upgrade_until_closed() {
    rt().block_on(async {
        let root = cancelled_root();
        let weak = root.clone_weak();
        let upgraded = weak.clone().into_scope().unwrap();
        drop(upgraded);
        root.join().await.unwrap();
        assert!(weak.clone().into_scope().is_none());
        // A refused upgrade releases nothing it did not take.
        assert!(weak.clone().into_scope().is_none());
        assert!(poll_noop(&mut weak.drained()).is_ready());
    });
}

#[test]
fn child_join_owns_its_subtree() {
    rt().block_on(async {
        let root = Scope::new().with_signal(std::future::pending::<()>());
        let flow = root.child();
        let flow_scope = flow.clone();
        let root_scope = root.clone();

        flow.cancel(Cause::Reason("flow done"));
        drop(flow_scope);
        flow.join().await.unwrap();
        assert!(!root_scope.is_cancelled());

        let other = root.child();
        root.cancel(Cause::Owner);
        assert!(other.is_cancelled());
        assert!(matches!(other.cause(), Some(Cause::Owner)));
    });
}

#[test]
fn drained_does_not_hold_the_scope() {
    let scope = Scope::new();
    let weak = scope.clone_weak();
    let mut drained = scope.drained();
    assert!(poll_noop(&mut drained).is_pending());
    drop(scope);
    assert!(poll_noop(&mut drained).is_ready());
    assert!(poll_noop(&mut weak.drained()).is_ready());
}

#[test]
fn strong_holders_count_up_the_chain() {
    let root = Scope::new();
    let weak_root = root.clone_weak();
    let child = root.child();
    let grandchild = child.child();
    drop(root);
    drop(child);
    assert!(poll_noop(&mut weak_root.drained()).is_pending());
    drop(grandchild);
    assert!(poll_noop(&mut weak_root.drained()).is_ready());
}

#[test]
fn weak_scope_observes_and_drives_its_node() {
    let scope = Scope::new();
    let weak = scope.clone().into_weak_scope();
    assert!(!weak.is_aborted());
    weak.abort(Cause::Reason("weak"));
    assert!(scope.is_cancelled());
    assert!(weak.is_aborted());
    assert_eq!(reason(weak.cause().as_ref()), Some("weak"));
    assert_eq!(reason(weak.abort_cause().as_ref()), Some("weak"));
}

#[test]
fn weak_never_scope_stays_inert() {
    let weak = Scope::default().into_weak_scope();
    weak.cancel(Cause::Owner);
    weak.abort(Cause::Owner);
    assert!(!weak.is_cancelled());
    assert!(!weak.is_aborted());
    assert!(weak.cause().is_none());
    let scope = weak.into_scope().unwrap();
    assert!(!scope.is_aborted());
    assert!(scope.cause().is_none());
}

#[test]
fn causes_and_outcomes_describe_themselves() {
    let error = Cause::error(std::io::Error::other("disk on fire"));
    assert!(error.to_string().contains("disk on fire"));
    assert_eq!(Cause::Reason("draining").to_string(), "draining");
    let fixed = [
        Cause::Signal,
        Cause::Deadline,
        Cause::GraceElapsed,
        Cause::Owner,
    ]
    .map(|cause| cause.to_string());
    for (i, text) in fixed.iter().enumerate() {
        assert!(!text.is_empty());
        assert!(!fixed[i + 1..].contains(text));
    }

    rt().block_on(async {
        let root = cancelled_root();
        let _holder = root.clone();
        root.abort(Cause::Reason("operator"));
        assert!(format!("{root:?}").contains("aborted: true"));
        let aborted = root.join().await.unwrap_err();
        assert!(aborted.to_string().contains("operator"));
    });
}

#[test]
fn debug_reflects_the_phase() {
    let scope = Scope::new();
    let weak = scope.clone_weak();
    assert!(format!("{scope:?}").contains("cancelled: false"));
    scope.cancel(Cause::Owner);
    assert!(format!("{weak:?}").contains("cancelled: true"));
    assert!(format!("{:?}", Scope::never()).contains("never"));
    assert!(format!("{:?}", scope.cancelled()).starts_with("Cancelled"));
}

#[test]
fn refused_child_upgrade_rolls_back_its_own_level() {
    rt().block_on(async {
        let root = cancelled_root();
        let child = root.child();
        let weak_child = child.clone_weak();
        drop(child);
        root.join().await.unwrap();
        assert!(weak_child.clone().into_scope().is_none());
        // The child level took a count before the closed root refused; it must be given back.
        assert!(poll_noop(&mut weak_child.drained()).is_ready());
    });
}

#[test]
fn abort_drops_pending_signals() {
    let resource = Arc::new(());
    let signal = {
        let resource = resource.clone();
        async move {
            std::future::pending::<()>().await;
            drop(resource);
        }
    };
    let scope = Scope::new().with_hard_signal(signal);
    let mut aborted = scope.aborted();
    assert!(poll_noop(&mut aborted).is_pending());
    assert_eq!(Arc::strong_count(&resource), 2);
    scope.abort(Cause::Owner);
    assert!(poll_noop(&mut aborted).is_ready());
    assert!(poll_noop(&mut aborted).is_ready());
    let mut cancelled = scope.cancelled();
    assert!(poll_noop(&mut cancelled).is_ready());
    assert_eq!(Arc::strong_count(&resource), 1);
}

#[test]
fn self_waking_signal_hands_driving_back_to_the_waiters() {
    let polls = Arc::new(AtomicUsize::new(0));
    let signal = {
        let polls = polls.clone();
        std::future::poll_fn(move |cx| {
            polls.fetch_add(1, Ordering::SeqCst);
            cx.waker().wake_by_ref();
            Poll::<()>::Pending
        })
    };
    let scope = Scope::new().with_signal(signal);
    let (flag, waker) = Flag::waker();
    let mut cancelled = scope.cancelled();
    assert!(poll(&mut cancelled, &waker).is_pending());
    let bounded = polls.load(Ordering::SeqCst);
    assert!(bounded > 1);
    assert!(flag.woken());
    assert!(poll(&mut cancelled, &waker).is_pending());
    assert!(polls.load(Ordering::SeqCst) > bounded);
    assert!(!scope.is_cancelled());
}

#[test]
fn signal_holding_its_own_scope_does_not_block_the_drain() {
    let scope = Scope::new();
    let held = scope.clone();
    let scope = scope.with_hard_signal(async move {
        std::future::pending::<()>().await;
        drop(held);
    });
    let weak = scope.clone_weak();
    drop(scope);
    let mut drained = weak.drained();
    assert!(poll_noop(&mut drained).is_pending());
    weak.abort(Cause::Owner);
    assert!(poll_noop(&mut drained).is_ready());
}

#[test]
fn signal_aborting_its_own_scope_is_dropped_by_the_driver() {
    let resource = Arc::new(());
    let slot: Arc<parking_lot::Mutex<Option<WeakScope>>> = Arc::default();
    let signal = {
        let slot = slot.clone();
        let resource = resource.clone();
        std::future::poll_fn(move |_cx| {
            let _resource = &resource;
            if let Some(weak) = slot.lock().take() {
                weak.abort(Cause::Reason("from signal"));
            }
            Poll::<()>::Pending
        })
    };
    let scope = Scope::new().with_signal(signal);
    *slot.lock() = Some(scope.clone_weak());
    let mut aborted = scope.aborted();
    assert!(poll_noop(&mut aborted).is_ready());
    assert_eq!(reason(scope.abort_cause().as_ref()), Some("from signal"));
    assert_eq!(Arc::strong_count(&resource), 1);
}

#[test]
fn run_until_cancelled_returns_the_output_while_active() {
    rt().block_on(async {
        let scope = Scope::new();
        let output = tokio::spawn(scope.run_until_cancelled(async {
            tokio::time::sleep(SEC).await;
            7
        }));
        assert_eq!(output.await.unwrap(), Some(7));
        assert!(!scope.is_cancelled());
    });
}

#[test]
fn run_until_cancelled_stops_at_the_graceful_phase() {
    rt().block_on(async {
        let scope = Scope::new().with_timeout(SEC).with_grace(10 * SEC);
        let start = Instant::now();
        let output = scope
            .run_until_cancelled(std::future::pending::<()>())
            .await;
        assert!(output.is_none());
        assert_eq!(start.elapsed(), SEC);
        assert!(!scope.is_aborted());
    });
}

#[test]
fn run_until_aborted_keeps_running_through_the_graceful_phase() {
    rt().block_on(async {
        let scope = Scope::new().with_grace(5 * SEC);
        scope.cancel(Cause::Owner);
        let finishes = scope.run_until_aborted(async {
            tokio::time::sleep(SEC).await;
            "done"
        });
        assert_eq!(finishes.await, Some("done"));
        let start = Instant::now();
        let cut = scope.run_until_aborted(std::future::pending::<()>());
        assert!(cut.await.is_none());
        assert_eq!(start.elapsed(), 4 * SEC);
    });
}

#[test]
fn run_until_never_polls_a_future_of_a_finished_phase() {
    let polls = Arc::new(AtomicUsize::new(0));
    let counted = || {
        let polls = polls.clone();
        std::future::poll_fn(move |_cx| {
            polls.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(())
        })
    };
    let scope = Scope::new();
    scope.abort(Cause::Owner);
    let mut cancelled = Box::pin(scope.run_until_cancelled(counted()));
    assert_eq!(poll_noop(&mut cancelled), Poll::Ready(None));
    let mut aborted = Box::pin(scope.run_until_aborted(counted()));
    assert_eq!(poll_noop(&mut aborted), Poll::Ready(None));
    assert_eq!(polls.load(Ordering::SeqCst), 0);
}

#[test]
fn join_of_a_never_scope_returns_at_once() {
    let mut join = Box::pin(Scope::never().join());
    assert!(matches!(
        poll_noop(&mut join),
        Poll::Ready(Ok(joined)) if joined.elapsed() == Duration::ZERO
    ));
}

#[test]
fn join_returns_when_the_work_ends_before_any_signal() {
    rt().block_on(async {
        let root = Scope::new().with_signal(std::future::pending::<()>());
        let worker = tokio::spawn({
            let scope = root.clone();
            async move {
                tokio::time::sleep(2 * SEC).await;
                drop(scope);
            }
        });
        let weak = root.clone_weak();
        assert_eq!(root.join().await.unwrap().elapsed(), 2 * SEC);
        assert!(!weak.is_cancelled());
        worker.await.unwrap();
    });
}

#[test]
fn join_of_a_child_ignores_holders_elsewhere_in_the_tree() {
    rt().block_on(async {
        let root = Scope::new();
        let _elsewhere = root.child();
        let flow = root.child();
        let worker = tokio::spawn({
            let scope = flow.clone();
            async move {
                tokio::time::sleep(SEC).await;
                drop(scope);
            }
        });
        assert_eq!(flow.join().await.unwrap().elapsed(), SEC);
        worker.await.unwrap();
        assert!(poll_noop(&mut root.drained()).is_pending());
    });
}

#[test]
#[cfg_attr(miri, ignore = "the signal driver is not supported under Miri")]
fn default_signal_keeps_the_scope_active_until_it_fires() {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let scope = Scope::new().with_default_signal();
            let mut cancelled = scope.cancelled();
            assert!(poll_noop(&mut cancelled).is_pending());
            assert!(!scope.is_cancelled());
        });
}

#[derive(Debug)]
struct ReenterOnDrop(WeakScope);

impl std::fmt::Display for ReenterOnDrop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("re-entering cause")
    }
}

impl std::error::Error for ReenterOnDrop {}

impl Drop for ReenterOnDrop {
    fn drop(&mut self) {
        self.0.cancel(Cause::Reason("drop"));
        self.0.abort(Cause::Reason("drop"));
        let _phase = self.0.cause();
    }
}

/// Runs `f` on its own thread: a deadlock shows up as a timeout instead of a hung suite.
fn within_two_seconds(f: impl FnOnce() + Send + 'static) {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        f();
        let _sent = tx.send(());
    });
    rx.recv_timeout(Duration::from_secs(2))
        .expect("deadlocked on a node lock");
}

#[test]
#[cfg_attr(miri, ignore = "uses a wall-clock timeout")]
fn losing_graceful_error_cause_is_dropped_outside_the_locks() {
    within_two_seconds(|| {
        let scope = Scope::new().with_timeout(Duration::ZERO);
        let error = ReenterOnDrop(scope.clone_weak());
        scope.cancel(Cause::error(error));
        assert!(matches!(scope.cause(), Some(Cause::Deadline)));
    });
}

#[test]
#[cfg_attr(miri, ignore = "uses a wall-clock timeout")]
fn losing_hard_error_cause_is_dropped_outside_the_locks() {
    within_two_seconds(|| {
        let scope = Scope::new().with_hard_timeout(Duration::ZERO);
        let error = ReenterOnDrop(scope.clone_weak());
        scope.abort(Cause::error(error));
        assert!(matches!(scope.abort_cause(), Some(Cause::Deadline)));
    });
}

#[test]
#[cfg_attr(miri, ignore = "uses a wall-clock timeout")]
fn redundant_error_cause_is_dropped_outside_the_locks() {
    within_two_seconds(|| {
        let scope = Scope::new();
        scope.abort(Cause::Owner);
        scope.cancel(Cause::error(ReenterOnDrop(scope.clone_weak())));
        scope.abort(Cause::error(ReenterOnDrop(scope.clone_weak())));
        assert!(matches!(scope.abort_cause(), Some(Cause::Owner)));
    });
}

#[test]
#[cfg_attr(miri, ignore = "uses a wall-clock timeout")]
fn error_cause_losing_to_an_ancestor_is_dropped_outside_the_locks() {
    within_two_seconds(|| {
        let parent = Scope::new().with_timeout(Duration::ZERO);
        let child = parent.child();
        child.cancel(Cause::error(ReenterOnDrop(child.clone_weak())));
        child.abort(Cause::error(ReenterOnDrop(parent.clone_weak())));
        assert!(matches!(child.cause(), Some(Cause::Deadline)));
    });
}

#[test]
fn winning_error_cause_is_kept() {
    let scope = Scope::new();
    scope.cancel(Cause::error(std::io::Error::other("kept")));
    assert!(matches!(scope.cause(), Some(Cause::Error(error)) if error.to_string() == "kept"));
}

#[derive(Default)]
struct CountWake(AtomicUsize);

impl Wake for CountWake {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn descendant_drain_observer_is_woken_by_an_ancestor_signal() {
    let parent = Scope::new();
    let child = parent.child();
    let observer = child.clone_weak();
    let (tx, rx) = oneshot::channel::<()>();
    let parent = parent.with_signal(async move {
        let _sent = rx.await;
        drop(child);
    });
    let counter = Arc::new(CountWake::default());
    let waker = Waker::from(counter.clone());
    let mut drained = observer.drained();
    assert!(poll(&mut drained, &waker).is_pending());
    counter.0.store(0, Ordering::SeqCst);
    tx.send(()).unwrap();
    assert!(counter.0.load(Ordering::SeqCst) > 0);
    assert!(poll(&mut drained, &waker).is_ready());
    drop(parent);
}

#[test]
fn descendant_drain_completes_on_an_executor_through_ancestor_signals() {
    rt().block_on(async {
        let parent = Scope::new();
        let grandchild = parent.child().child();
        let observer = grandchild.clone_weak();
        let (tx, rx) = oneshot::channel::<()>();
        let _parent = parent.with_signal(async move {
            let _sent = rx.await;
            drop(grandchild);
        });
        let drained = tokio::spawn(observer.drained());
        let cancelled_waiter = tokio::spawn(observer.cancelled());
        tokio::task::yield_now().await;
        cancelled_waiter.abort();
        tokio::spawn(async move {
            tokio::time::sleep(SEC).await;
            tx.send(()).unwrap();
        });
        tokio::time::timeout(10 * SEC, drained)
            .await
            .expect("drain observer was never woken")
            .unwrap();
    });
}

#[test]
fn drain_observer_publishes_deadlines_and_releases_settled_signals() {
    rt().block_on(async {
        let scope = Scope::new().with_timeout(SEC);
        let held = scope.clone();
        let weak = scope.clone_weak();
        let scope = scope.with_signal(async move {
            std::future::pending::<()>().await;
            drop(held);
        });
        drop(scope);
        let mut drained = weak.drained();
        assert!(poll_noop(&mut drained).is_pending());
        advance(2 * SEC).await;
        assert!(poll_noop(&mut drained).is_ready());
    });
}

#[test]
fn drain_completes_on_an_executor_at_grace_and_inherited_hard_caps() {
    rt().block_on(async {
        // Grace: the hard signal holding the scope goes when the grace runs out.
        let scope = Scope::new().with_grace(3 * SEC);
        let held = scope.clone();
        let weak = scope.clone_weak();
        let scope = scope.with_hard_signal(async move {
            std::future::pending::<()>().await;
            drop(held);
        });
        scope.cancel(Cause::Owner);
        drop(scope);
        let start = Instant::now();
        tokio::time::timeout(10 * SEC, weak.drained())
            .await
            .expect("grace never released the drain");
        assert_eq!(start.elapsed(), 3 * SEC);

        // Inherited hard cap: a child's signals go when its ancestor's hard deadline passes.
        let parent = Scope::new().with_hard_timeout(2 * SEC);
        let child = parent.child();
        let held = child.clone();
        let weak = child.clone_weak();
        let child = child.with_hard_signal(async move {
            std::future::pending::<()>().await;
            drop(held);
        });
        drop(child);
        let start = Instant::now();
        tokio::time::timeout(10 * SEC, weak.drained())
            .await
            .expect("inherited hard cap never released the drain");
        assert_eq!(start.elapsed(), 2 * SEC);
        drop(parent);
    });
}

#[test]
fn late_child_grace_is_anchored_at_the_inherited_instant() {
    rt().block_on(async {
        let parent = Scope::new();
        parent.cancel(Cause::Owner);
        advance(10 * SEC).await;
        let child = parent.child().with_grace(20 * SEC);
        assert!(child.is_cancelled());
        advance(11 * SEC).await;
        assert!(child.is_aborted());
    });
}

#[test]
fn nested_late_descendant_observed_later_keeps_the_ancestor_anchor() {
    rt().block_on(async {
        let root = Scope::new().with_grace(30 * SEC);
        let middle = root.child();
        root.cancel(Cause::Owner);
        advance(5 * SEC).await;
        let leaf = middle.child().child();
        advance(5 * SEC).await;
        // First observation at t=10 of a phase reached at t=0.
        assert!(leaf.is_cancelled());
        let late = leaf.clone().with_grace(15 * SEC);
        advance(4 * SEC).await;
        assert!(!late.is_aborted());
        advance(SEC).await;
        assert!(late.is_aborted());
        assert!(matches!(late.abort_cause(), Some(Cause::GraceElapsed)));
        assert!(!root.is_aborted());
    });
}

#[test]
fn weak_cannot_revive_a_cancelled_scope_without_holders() {
    let scope = Scope::new();
    scope.cancel(Cause::Owner);
    let weak = scope.into_weak_scope();
    assert!(weak.clone().into_scope().is_none());
    assert!(poll_noop(&mut weak.drained()).is_ready());
}

#[test]
fn weak_revives_an_active_scope_without_holders() {
    let scope = Scope::new();
    let weak = scope.into_weak_scope();
    let revived = weak.clone().into_scope().unwrap();
    assert!(poll_noop(&mut weak.drained()).is_pending());
    revived.cancel(Cause::Owner);
    drop(revived);
    assert!(weak.into_scope().is_none());
}

#[test]
fn revived_child_holds_its_parent_and_a_refused_one_holds_nothing() {
    let parent = Scope::new();
    let child = parent.child();
    let weak_child = child.into_weak_scope();
    let weak_parent = parent.clone_weak();
    drop(parent);
    assert!(poll_noop(&mut weak_parent.drained()).is_ready());

    let revived = weak_child.clone().into_scope().unwrap();
    assert!(poll_noop(&mut weak_parent.drained()).is_pending());
    drop(revived);
    assert!(poll_noop(&mut weak_parent.drained()).is_ready());

    weak_parent.cancel(Cause::Owner);
    assert!(weak_child.into_scope().is_none());
    assert!(weak_parent.into_scope().is_none());
}

#[test]
fn panicking_driver_wakes_a_waiter_that_registered_during_its_drive() {
    let scope = Scope::new();
    let survivor = Arc::new(parking_lot::Mutex::new(scope.cancelled()));
    let counter = Arc::new(CountWake::default());
    let waker = Waker::from(counter.clone());
    let nested = survivor.clone();
    let nested_waker = waker.clone();
    let scope = scope
        .with_signal(std::future::poll_fn(move |_cx| -> Poll<()> {
            assert!(poll(&mut *nested.lock(), &nested_waker).is_pending());
            panic!("driver dies after another waiter registered");
        }))
        .with_signal(async {});
    let mut driver = scope.cancelled();
    counter.0.store(0, Ordering::SeqCst);
    let _panic = catch_unwind(AssertUnwindSafe(|| poll_noop(&mut driver))).unwrap_err();
    drop(driver);
    assert!(counter.0.load(Ordering::SeqCst) > 0);
    assert!(poll(&mut *survivor.lock(), &waker).is_ready());
}

#[test]
fn only_never_is_never() {
    assert!(Scope::never().is_never());
    assert!(Scope::default().is_never());
    assert!(!Scope::new().is_never());
    assert!(!Scope::never().child().is_never());
    assert!(!Scope::never().with_timeout(SEC).is_never());
}

// ---- scopes below several parents ----

#[test]
fn child_of_ends_with_any_parent_and_holds_each() {
    let a = Scope::new();
    let b = Scope::new();
    let work = Scope::child_of([&a, &b]);
    let (weak_a, weak_b) = (a.clone_weak(), b.clone_weak());
    drop((a, b));
    let mut a_drained = weak_a.drained();
    let mut b_drained = weak_b.drained();
    assert!(poll_noop(&mut a_drained).is_pending());
    assert!(poll_noop(&mut b_drained).is_pending());

    assert!(!work.is_cancelled());
    weak_b.cancel(Cause::Reason("b"));
    assert!(work.is_cancelled());
    assert!(!weak_a.is_cancelled(), "a part never reaches its parents");
    assert_eq!(reason(work.cause().as_ref()), Some("b"));

    drop(work);
    assert!(poll_noop(&mut a_drained).is_ready());
    assert!(poll_noop(&mut b_drained).is_ready());
}

#[test]
fn child_of_one_lineage_is_a_single_child_of_the_deepest() {
    let a = Scope::new();
    let x = a.child();
    let work = Scope::child_of([&a, &Scope::never(), &x, &x]);
    assert!(work.node().is_some(), "one part");
    x.cancel(Cause::Owner);
    assert!(work.is_cancelled());

    let root = Scope::child_of([&Scope::never()]);
    assert!(!root.is_never());
    assert!(!root.is_cancelled());
}

#[test]
fn own_phases_of_a_composite_stay_below_its_parents() {
    let a = Scope::new();
    let b = Scope::new();
    let work = Scope::child_of([&a, &b]);
    work.cancel(Cause::Owner);
    work.abort(Cause::Owner);
    assert!(work.is_aborted());
    assert!(!a.is_cancelled());
    assert!(!b.is_cancelled());
}

#[test]
fn a_composite_cause_is_fixed_once_observed() {
    rt().block_on(async {
        let a = Scope::new();
        let b = Scope::new();
        let work = Scope::child_of([&a, &b]);
        let clone = work.clone();
        b.cancel(Cause::Reason("first seen"));
        assert_eq!(reason(work.cause().as_ref()), Some("first seen"));
        // Same instant on the paused clock: a recomputed tie would now pick the first part.
        a.cancel(Cause::Reason("first part"));
        assert_eq!(reason(clone.cause().as_ref()), Some("first seen"));
        assert_eq!(reason(work.cause().as_ref()), Some("first seen"));
    });
}

#[test]
fn a_reached_composite_phase_wait_fixes_its_cause() {
    rt().block_on(async {
        let a = Scope::new();
        let b = Scope::new();
        let work = Scope::child_of([&a, &b]);
        b.cancel(Cause::Reason("first seen"));
        assert!(poll_noop(&mut work.cancelled()).is_ready());
        a.cancel(Cause::Reason("first part"));
        assert_eq!(reason(work.cause().as_ref()), Some("first seen"));

        b.abort(Cause::Reason("first seen"));
        assert!(poll_noop(&mut work.aborted()).is_ready());
        a.abort(Cause::Reason("first part"));
        assert_eq!(reason(work.abort_cause().as_ref()), Some("first seen"));
    });
}

#[test]
fn a_reached_wait_of_a_weak_composite_fixes_its_cause() {
    rt().block_on(async {
        let a = Scope::new();
        let b = Scope::new();
        let work = Scope::child_of([&a, &b]);
        let weak = work.clone_weak();
        b.abort(Cause::Reason("first seen"));
        assert!(poll_noop(&mut weak.aborted()).is_ready());
        a.abort(Cause::Reason("first part"));
        assert_eq!(reason(work.cause().as_ref()), Some("first seen"));
        assert_eq!(reason(work.abort_cause().as_ref()), Some("first seen"));
    });
}

#[test]
fn a_child_of_a_composite_inherits_its_fixed_cause() {
    rt().block_on(async {
        let a = Scope::new();
        let b = Scope::new();
        let work = Scope::child_of([&a, &b]);
        b.cancel(Cause::Reason("first seen"));
        assert!(work.is_cancelled());
        a.cancel(Cause::Reason("first part"));
        let child = work.child();
        assert_eq!(reason(child.cause().as_ref()), Some("first seen"));
        assert_eq!(reason(child.child().cause().as_ref()), Some("first seen"));
        let other = Scope::new();
        let joint = Scope::child_of([&other, &work]);
        assert_eq!(reason(joint.cause().as_ref()), Some("first seen"));

        b.abort(Cause::Reason("first seen"));
        assert!(work.is_aborted());
        a.abort(Cause::Reason("first part"));
        assert_eq!(reason(child.abort_cause().as_ref()), Some("first seen"));
        assert_eq!(reason(joint.abort_cause().as_ref()), Some("first seen"));
    });
}

#[test]
fn a_child_made_before_the_phase_follows_its_composites_fact() {
    rt().block_on(async {
        let a = Scope::new();
        let b = Scope::new();
        let work = Scope::child_of([&a, &b]);
        let child = work.child();
        b.cancel(Cause::Reason("first seen"));
        assert!(work.is_cancelled());
        a.cancel(Cause::Reason("first part"));
        assert!(poll_noop(&mut child.cancelled()).is_ready());
        assert_eq!(reason(child.cause().as_ref()), Some("first seen"));
    });
}

#[test]
fn a_child_observed_first_fixes_its_composite_alike() {
    rt().block_on(async {
        let a = Scope::new();
        let b = Scope::new();
        let work = Scope::child_of([&a, &b]);
        let child = work.child();
        b.cancel(Cause::Reason("first seen"));
        assert_eq!(reason(child.cause().as_ref()), Some("first seen"));
        a.cancel(Cause::Reason("first part"));
        assert_eq!(reason(work.cause().as_ref()), Some("first seen"));
    });
}

#[test]
fn an_own_phase_of_a_child_of_a_composite_is_its_own() {
    rt().block_on(async {
        let a = Scope::new();
        let b = Scope::new();
        let work = Scope::child_of([&a, &b]);
        let child = work.child();
        child.cancel(Cause::Reason("own"));
        assert_eq!(reason(child.cause().as_ref()), Some("own"));
        a.cancel(Cause::Reason("parent"));
        assert_eq!(reason(child.cause().as_ref()), Some("own"));
        assert_eq!(reason(work.cause().as_ref()), Some("parent"));
    });
}

#[test]
fn a_scope_context_keeps_the_fixed_cause_of_its_composite() {
    rt().block_on(async {
        let a = Scope::new();
        let b = Scope::new();
        let work = Scope::child_of([&a, &b]);
        let extensions = Extensions::new();
        attach_scope(&extensions, &work);
        b.cancel(Cause::Reason("first seen"));
        assert!(work.is_cancelled());
        a.cancel(Cause::Reason("first part"));
        let context = scope_context(&extensions).unwrap();
        assert_eq!(reason(context.cause().as_ref()), Some("first seen"));
    });
}

#[test]
fn any_aborted_part_ends_a_grouped_join_at_once() {
    rt().block_on(async {
        let a = Scope::new();
        let b = Scope::new();
        let work = Scope::child_of([&a, &b]);
        let held = work.clone();
        b.abort(Cause::Reason("b"));
        let err = tokio::time::timeout(SEC, work.join())
            .await
            .expect("an aborted part ends the join at once")
            .unwrap_err();
        assert_eq!(reason(err.cause()), Some("b"));
        drop(held);
    });
}

#[test]
fn a_grouped_join_waits_for_every_holder() {
    let a = Scope::new();
    let b = Scope::new();
    let work = Scope::child_of([&a, &b]);
    let weak = work.clone_weak();
    let held = work.clone();
    let mut join = Box::pin(work.join());
    assert!(poll_noop(&mut join).is_pending());
    drop(held);
    assert!(matches!(poll_noop(&mut join), Poll::Ready(Ok(_))));
    assert!(weak.into_scope().is_none(), "closed as a whole");
}

#[test]
fn a_dropped_pending_grouped_join_closes_nothing() {
    let a = Scope::new();
    let b = Scope::new();
    let work = Scope::child_of([&a, &b]);
    let weak = work.clone_weak();
    let held = work.clone();
    let mut join = Box::pin(work.join());
    assert!(poll_noop(&mut join).is_pending());
    drop(join);
    let revived = weak.into_scope().expect("nothing closed");
    drop((held, revived));
}

#[test]
fn into_scope_of_a_composite_is_all_or_nothing() {
    let a = Scope::new();
    let b = Scope::new();
    let weak_a = a.clone_weak();
    let work = Scope::child_of([&a, &b]);
    let weak = work.clone_weak();
    drop(a);
    b.cancel(Cause::Owner);
    drop(work);
    // The part below b is cancelled without holders, which refuses it; the part below a,
    // taken first, is released again.
    assert!(weak.into_scope().is_none());
    let mut a_drained = weak_a.drained();
    assert!(poll_noop(&mut a_drained).is_ready());
}

#[test]
fn every_wait_of_a_composite_releases_its_registrations() {
    let a = Scope::new();
    let b = Scope::new();
    let work = Scope::child_of([&a, &b]);
    for _ in 0..3 {
        let mut cancelled = work.cancelled();
        let mut aborted = work.aborted();
        let mut drained = work.drained();
        assert!(poll_noop(&mut cancelled).is_pending());
        assert!(poll_noop(&mut aborted).is_pending());
        assert!(poll_noop(&mut drained).is_pending());
    }
    // Each part keeps one relay on its parent while it lives, whatever the number of waits.
    assert_eq!(waiter_count(&a), 1);
    assert_eq!(waiter_count(&b), 1);
    drop(work);
    assert_eq!(waiter_count(&a), 0);
    assert_eq!(waiter_count(&b), 0);
}

#[test]
fn signals_on_a_composite_end_every_part_once() {
    rt().block_on(async {
        let a = Scope::new();
        let b = Scope::new();
        let (cancel, cancelled) = oneshot::channel::<()>();
        let (abort, aborted) = oneshot::channel::<()>();
        let work = Scope::child_of([&a, &b])
            .with_signal(cancelled)
            .with_hard_signal(aborted);
        let observer = work.clone();
        cancel.send(()).unwrap();
        observer.cancelled().await;
        assert!(work.is_cancelled());
        assert!(!work.is_aborted());
        abort.send(()).unwrap();
        work.aborted().await;
        assert!(observer.is_aborted());
        assert!(!a.is_cancelled() && !b.is_cancelled());
    });
}

// ---- delayed signals and joins ----

#[test]
fn a_delayed_signal_cancels_after_its_delay() {
    rt().block_on(async {
        let (trigger, triggered) = oneshot::channel::<()>();
        let scope = Scope::new().with_delayed_signal(triggered, 2 * SEC);
        trigger.send(()).unwrap();
        let start = Instant::now();
        scope.cancelled().await;
        assert_eq!(start.elapsed(), 2 * SEC);
        assert!(matches!(scope.cause(), Some(Cause::Signal)));
    });
}

#[test]
fn a_delayed_signal_holds_back_no_ancestor() {
    let parent = Scope::new();
    let child = parent
        .child()
        .with_delayed_signal(std::future::pending::<()>(), 100 * SEC);
    parent.cancel(Cause::Owner);
    assert!(child.is_cancelled());
}

#[test]
fn join_reports_the_cause_or_none() {
    rt().block_on(async {
        let idle = Scope::new();
        let joined = idle.join().await.unwrap();
        assert!(joined.cause().is_none());

        let cancelled = Scope::new();
        cancelled.cancel(Cause::Reason("done"));
        let joined = cancelled.join().await.unwrap();
        assert_eq!(reason(joined.cause()), Some("done"));
    });
}

#[test]
fn join_once_cancelled_waits_for_the_cancel_even_without_work() {
    rt().block_on(async {
        let root = Scope::new();
        let weak = root.clone_weak();
        tokio::spawn(async move {
            tokio::time::sleep(SEC).await;
            weak.cancel(Cause::Reason("signal"));
        });
        let start = Instant::now();
        let joined = root.join_once_cancelled().await.unwrap();
        assert_eq!(start.elapsed(), SEC);
        assert_eq!(joined.elapsed(), Duration::ZERO, "the drain only");
        assert_eq!(reason(joined.cause()), Some("signal"));
    });
}

#[test]
fn join_once_cancelled_waits_for_work_after_the_cancel() {
    rt().block_on(async {
        let root = Scope::new();
        let finished_early = root.child();
        drop(finished_early);
        let work = root.child();
        let weak = root.clone_weak();
        tokio::spawn(async move {
            tokio::time::sleep(SEC).await;
            weak.cancel(Cause::Owner);
            tokio::time::sleep(SEC).await;
            drop(work);
        });
        let start = Instant::now();
        let joined = root.join_once_cancelled().await.unwrap();
        assert_eq!(start.elapsed(), 2 * SEC);
        assert_eq!(joined.elapsed(), SEC);
    });
}

#[test]
fn a_dropped_join_once_cancelled_closes_nothing() {
    let root = Scope::new();
    let weak = root.clone_weak();
    let held = root.clone();
    let mut waiting_for_the_cancel = Box::pin(root.clone().join_once_cancelled());
    assert!(poll_noop(&mut waiting_for_the_cancel).is_pending());
    drop(waiting_for_the_cancel);

    root.cancel(Cause::Owner);
    let mut waiting_for_the_drain = Box::pin(root.join_once_cancelled());
    assert!(poll_noop(&mut waiting_for_the_drain).is_pending());
    drop(waiting_for_the_drain);
    assert!(weak.into_scope().is_some(), "still held, so not closed");
    drop(held);
}

// ---- the scope an input runs in ----

#[test]
fn entering_without_any_scope_makes_a_root() {
    let extensions = Extensions::new();
    let scope = enter_scope(&extensions).unwrap();
    assert!(!scope.is_never());
    assert!(scope_context(&extensions).is_some());
}

#[test]
fn entering_with_only_an_own_scope_makes_its_child() {
    let own = Scope::new();
    let extensions = Extensions::new();
    let scope = enter_scope_with(&extensions, &own).unwrap();
    own.cancel(Cause::Owner);
    assert!(scope.is_cancelled());
}

#[test]
fn an_attached_never_scope_is_no_context() {
    let extensions = Extensions::new();
    attach_scope(&extensions, &Scope::never());
    assert!(scope_context(&extensions).is_none());
    assert!(!enter_scope(&extensions).unwrap().is_never());
}

#[test]
fn a_closed_context_refuses_whatever_the_own_scope() {
    for own in [None, Some(Scope::new())] {
        let extensions = Extensions::new();
        let context = Scope::new();
        attach_scope(&extensions, &context);
        context.cancel(Cause::Owner);
        drop(context);
        let _closed = match &own {
            None => enter_scope(&extensions),
            Some(own) => enter_scope_with(&extensions, own),
        }
        .unwrap_err();
    }
}

#[test]
fn an_entered_scope_follows_its_context_and_its_own_scope() {
    for cancel_context in [true, false] {
        let context = Scope::new();
        let own = Scope::new();
        let extensions = Extensions::new();
        attach_scope(&extensions, &context);
        let scope = enter_scope_with(&extensions, &own).unwrap();
        if cancel_context {
            context.cancel(Cause::Owner);
        } else {
            own.cancel(Cause::Owner);
        }
        assert!(scope.is_cancelled());
        // It runs in the entered scope from now on.
        assert!(scope_context(&extensions).unwrap().is_cancelled());
    }
}

#[test]
fn every_attached_scope_counts_not_only_the_latest() {
    let extensions = Extensions::new();
    let first = Scope::new();
    let second = Scope::new();
    attach_scope(&extensions, &first);
    attach_scope(&extensions, &second);
    let scope = enter_scope(&extensions).unwrap();
    first.cancel(Cause::Owner);
    assert!(scope.is_cancelled());
}

#[test]
fn retained_extensions_hold_no_drain() {
    rt().block_on(async {
        let root = Scope::new();
        let extensions = Extensions::new();
        let entered = enter_scope_with(&extensions, &root).unwrap();
        let retained = extensions.clone();
        drop(entered);
        tokio::time::timeout(SEC, root.join())
            .await
            .expect("retained extensions do not hold the drain")
            .unwrap();
        drop(retained);
    });
}

// ---- deep trees cost heap, not stack ----

const DEEP: usize = 20_000;
const SMALL_STACK: usize = 256 * 1024;

/// Runs `test` on a thread with a small stack: a recursive walk over a deep tree overflows it.
fn on_a_small_stack(test: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(SMALL_STACK)
        .spawn(test)
        .unwrap()
        .join()
        .unwrap();
}

/// A chain of `DEEP` children below `root`, and its leaf.
fn deep_chain(root: &Scope) -> (Vec<Scope>, Scope) {
    let mut chain = Vec::with_capacity(DEEP);
    let mut leaf = root.child();
    for _ in 1..DEEP {
        let next = leaf.child();
        chain.push(leaf);
        leaf = next;
    }
    (chain, leaf)
}

#[test]
#[cfg_attr(miri, ignore = "a deep tree is slow under Miri")]
fn a_deep_tree_registers_propagates_and_tears_down_on_a_small_stack() {
    on_a_small_stack(|| {
        rt().block_on(async {
            let root = Scope::new().with_grace(SEC);
            let (chain, leaf) = deep_chain(&root);
            let (flag, waker) = Flag::waker();
            let mut cancelled = leaf.cancelled();
            assert!(poll(&mut cancelled, &waker).is_pending());

            root.cancel(Cause::Reason("root"));
            assert!(
                flag.woken(),
                "the wake reached the leaf through every relay"
            );
            assert!(poll(&mut cancelled, &waker).is_ready());
            assert_eq!(reason(leaf.cause().as_ref()), Some("root"));

            // The root's grace reaches the leaf by time alone.
            let start = Instant::now();
            leaf.aborted().await;
            assert_eq!(start.elapsed(), SEC);

            let weak_root = root.clone_weak();
            drop((chain, leaf, root));
            assert!(poll_noop(&mut weak_root.drained()).is_ready());
        });
    });
}

#[test]
#[cfg_attr(miri, ignore = "a deep tree is slow under Miri")]
fn a_deep_chain_is_revived_and_joined_on_a_small_stack() {
    on_a_small_stack(|| {
        rt().block_on(async {
            let root = Scope::new();
            let (chain, leaf) = deep_chain(&root);
            let weak_leaf = leaf.clone_weak();
            drop((chain, leaf));

            let revived = weak_leaf.into_scope().expect("an active chain revives");
            let mut join = Box::pin(root.clone().join());
            assert!(
                poll_noop(&mut join).is_pending(),
                "the revived leaf holds the root"
            );
            drop(revived);
            drop(root);
            assert!(matches!(poll_noop(&mut join), Poll::Ready(Ok(_))));
        });
    });
}

#[test]
#[cfg_attr(miri, ignore = "a deep tree is slow under Miri")]
fn a_deep_deadline_is_observed_on_a_small_stack() {
    on_a_small_stack(|| {
        rt().block_on(async {
            let root = Scope::new().with_timeout(SEC);
            let (_chain, leaf) = deep_chain(&root);
            let start = Instant::now();
            leaf.cancelled().await;
            assert_eq!(start.elapsed(), SEC);
            assert!(matches!(leaf.cause(), Some(Cause::Deadline)));
        });
    });
}

// ---- a waker whose clones live at other addresses ----

mod waker_identity {
    use std::{
        future::Future,
        pin::Pin,
        ptr,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, RawWaker, RawWakerVTable, Waker},
    };

    use parking_lot::{Mutex, MutexGuard};

    use super::super::{Cause, Scope};

    /// One entry per live raw waker instance: a clone takes another entry for the same task,
    /// a consuming wake or a drop frees its own.
    static SLOTS: Mutex<[Option<Arc<AtomicUsize>>; 8]> = Mutex::new([const { None }; 8]);
    /// The tests share `SLOTS`.
    static SERIAL: Mutex<()> = Mutex::new(());
    static TOKENS: [u8; 8] = [0, 1, 2, 3, 4, 5, 6, 7];
    static VTABLE: RawWakerVTable =
        RawWakerVTable::new(clone_raw, wake_raw, wake_by_ref_raw, drop_raw);

    fn slots() -> MutexGuard<'static, [Option<Arc<AtomicUsize>>; 8]> {
        SLOTS.lock()
    }

    fn index(data: *const ()) -> usize {
        TOKENS
            .iter()
            .position(|token| ptr::eq(data, ptr::from_ref(token).cast()))
            .unwrap()
    }

    fn raw(slot: usize) -> RawWaker {
        RawWaker::new(ptr::from_ref(&TOKENS[slot]).cast(), &VTABLE)
    }

    fn clone_raw(data: *const ()) -> RawWaker {
        let mut slots = slots();
        let task = slots[index(data)].clone().unwrap();
        let free = slots.iter().position(Option::is_none).unwrap();
        slots[free] = Some(task);
        raw(free)
    }

    fn wake_raw(data: *const ()) {
        let task = slots()[index(data)].take().unwrap();
        task.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref_raw(data: *const ()) {
        let task = slots()[index(data)].clone().unwrap();
        task.fetch_add(1, Ordering::SeqCst);
    }

    fn drop_raw(data: *const ()) {
        drop(slots()[index(data)].take());
    }

    fn waker(slot: usize, task: Arc<AtomicUsize>) -> Waker {
        {
            let mut slots = slots();
            assert!(slots[slot].is_none(), "the slot is free");
            slots[slot] = Some(task);
        }
        // SAFETY: the data pointer of every raw waker made here or by `clone_raw` is the
        // address of an element of the immutable static `TOKENS`, valid for `'static`, and
        // the callbacks only compare it with those addresses, never dereferencing it. Each raw
        // waker owns exactly one occupied `SLOTS` entry: this function fills a free entry
        // before handing it out and `clone_raw` fills a different free one, while
        // `wake_raw` and `drop_raw` empty the entry of the instance they consume and
        // `wake_by_ref_raw` leaves it. So every callback finds the entry of a live instance,
        // and an entry is reused only after its previous instance was consumed. The
        // registry is behind a mutex and holds `Arc<AtomicUsize>`, so the callbacks are
        // sound from any thread, as `Waker` requires.
        unsafe { Waker::from_raw(raw(slot)) }
    }

    fn poll<F: Future + Unpin>(future: &mut F, waker: &Waker) -> bool {
        Pin::new(future)
            .poll(&mut Context::from_waker(waker))
            .is_pending()
    }

    /// A waiter registered with a waker whose clone lives elsewhere, polled again by another
    /// task's waker, which takes the dropped first waker's address if `reuse`.
    fn the_latest_task_is_woken(reuse: bool) {
        let _serial = SERIAL.lock();
        let scope = Scope::new();
        let mut waiter = scope.cancelled();
        let old_task = Arc::new(AtomicUsize::new(0));
        let new_task = Arc::new(AtomicUsize::new(0));

        let first = waker(0, old_task.clone());
        assert!(poll(&mut waiter, &first));
        drop(first);
        let second = waker(if reuse { 0 } else { 2 }, new_task.clone());
        assert!(poll(&mut waiter, &second));

        scope.cancel(Cause::Owner);
        assert_eq!(new_task.load(Ordering::SeqCst), 1);
        assert_eq!(old_task.load(Ordering::SeqCst), 0);
        assert!(!poll(&mut waiter, &second));
        drop(waiter);
        drop(second);
        assert!(
            slots().iter().all(Option::is_none),
            "every instance is released"
        );
    }

    #[test]
    fn a_new_waker_at_a_dropped_wakers_address_replaces_it() {
        the_latest_task_is_woken(true);
    }

    #[test]
    fn a_new_waker_at_another_address_replaces_it() {
        the_latest_task_is_woken(false);
    }
}

// ---- a panicking waker stays with its own wake ----

struct PanicWake;

impl Wake for PanicWake {
    fn wake(self: Arc<Self>) {
        panic!("a waker panics");
    }
}

#[test]
fn a_panicking_waker_leaves_later_scopes_on_the_thread_alone() {
    let first_scope = Scope::new();
    let mut first = first_scope.cancelled();
    let bad = Waker::from(Arc::new(PanicWake));
    assert!(poll(&mut first, &bad).is_pending());
    assert!(catch_unwind(AssertUnwindSafe(|| first_scope.cancel(Cause::Owner))).is_err());

    let next_scope = Scope::new();
    let child = next_scope.child();
    let mut next = child.cancelled();
    let (flag, waker) = Flag::waker();
    assert!(poll(&mut next, &waker).is_pending());
    next_scope.cancel(Cause::Owner);
    assert!(flag.woken());
    assert!(poll(&mut next, &waker).is_ready());
}

#[test]
fn a_panicking_branch_carries_no_wake_into_another_scope() {
    let first_scope = Scope::new();
    let a = first_scope.child();
    let b = first_scope.child();
    let mut first = a.cancelled();
    let mut leftover = b.cancelled();
    let bad = Waker::from(Arc::new(PanicWake));
    assert!(poll(&mut first, &bad).is_pending());
    assert!(poll(&mut leftover, &bad).is_pending());
    assert!(catch_unwind(AssertUnwindSafe(|| first_scope.cancel(Cause::Owner))).is_err());

    let next_scope = Scope::new();
    let mut next = next_scope.cancelled();
    let (flag, waker) = Flag::waker();
    assert!(poll(&mut next, &waker).is_pending());
    catch_unwind(AssertUnwindSafe(|| next_scope.cancel(Cause::Owner))).unwrap();
    assert!(flag.woken());
}

#[test]
fn a_panicking_drain_waker_of_one_parent_leaves_the_other_released() {
    let a = Scope::new();
    let b = Scope::new();
    let work = Scope::child_of([&a, &b]);
    let weak_a = a.into_weak_scope();
    let weak_b = b.into_weak_scope();
    let mut a_drained = weak_a.drained();
    let bad = Waker::from(Arc::new(PanicWake));
    assert!(poll(&mut a_drained, &bad).is_pending());
    assert!(catch_unwind(AssertUnwindSafe(|| drop(work))).is_err());
    assert!(poll_noop(&mut weak_b.drained()).is_ready());
    assert!(poll_noop(&mut weak_a.drained()).is_ready());
}

/// A panic payload whose destructor panics again.
struct PanickingPayload;

impl Drop for PanickingPayload {
    fn drop(&mut self) {
        panic!("a panic payload panics once dropped");
    }
}

struct PayloadWake;

impl Wake for PayloadWake {
    fn wake(self: Arc<Self>) {
        std::panic::panic_any(PanickingPayload);
    }
}

#[test]
fn a_panic_payload_that_panics_once_dropped_leaves_every_parent_released() {
    let a = Scope::new();
    let b = Scope::new();
    let c = Scope::new();
    let work = Scope::child_of([&a, &b, &c]);
    let [a, b, c] = [a, b, c].map(Scope::into_weak_scope);
    let mut a_drained = a.drained();
    let mut b_drained = b.drained();
    assert!(poll(&mut a_drained, &Waker::from(Arc::new(PanicWake))).is_pending());
    assert!(poll(&mut b_drained, &Waker::from(Arc::new(PayloadWake))).is_pending());
    catch_unwind(AssertUnwindSafe(|| drop(work))).unwrap_err();
    assert!(poll_noop(&mut c.drained()).is_ready());
    assert!(poll_noop(&mut b.drained()).is_ready());
}

type Parked = Arc<parking_lot::Mutex<Option<Pin<Box<dyn Future<Output = ()> + Send>>>>>;

/// A signal that, once dropped, parks a drain wait of `scope` on a [`PayloadWake`] and panics.
struct ParkThenPanic {
    scope: WeakScope,
    parked: Parked,
}

impl Future for ParkThenPanic {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        Poll::Pending
    }
}

impl Drop for ParkThenPanic {
    fn drop(&mut self) {
        let mut drained: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(self.scope.drained());
        assert!(poll(&mut drained, &Waker::from(Arc::new(PayloadWake))).is_pending());
        *self.parked.lock() = Some(drained);
        panic!("a signal panics once dropped");
    }
}

#[test]
fn a_rollback_panic_payload_that_panics_once_dropped_keeps_the_first_panic() {
    rt().block_on(async {
        let a = Scope::new();
        let b = Scope::new();
        let work = Scope::child_of([&a, &b]);
        let weak = work.clone_weak();
        drop(work);
        let weak_a = a.into_weak_scope();
        let parked = Parked::default();
        // Parked while the first part, held again, holds `a`: the rollback wakes it.
        let b = b
            .with_signal(ParkThenPanic {
                scope: weak_a.clone(),
                parked: parked.clone(),
            })
            .with_deadline(Instant::now() + SEC);
        advance(SEC).await;
        let payload = catch_unwind(AssertUnwindSafe(|| weak.clone().into_scope())).unwrap_err();
        assert_eq!(
            payload.downcast_ref::<&str>(),
            Some(&"a signal panics once dropped")
        );
        assert!(poll_noop(&mut weak_a.drained()).is_ready());
        drop((b, parked));
    });
}

#[test]
fn a_panicking_waker_of_one_part_leaves_a_composite_cancel_whole() {
    let a = Scope::new();
    let b = Scope::new();
    let work = Scope::child_of([&a, &b]);
    let mut cancelled = work.cancelled();
    let bad = Waker::from(Arc::new(PanicWake));
    assert!(poll(&mut cancelled, &bad).is_pending());
    assert!(catch_unwind(AssertUnwindSafe(|| work.cancel(Cause::Owner))).is_err());
    assert!(work.parts().iter().all(|part| part.phase().graceful));

    let work = Scope::child_of([&a, &b]);
    let mut aborted = work.aborted();
    assert!(poll(&mut aborted, &bad).is_pending());
    assert!(catch_unwind(AssertUnwindSafe(|| work.abort(Cause::Owner))).is_err());
    assert!(work.parts().iter().all(|part| part.phase().hard));
}

#[test]
fn a_panicking_waker_of_one_part_leaves_a_composite_deadline_whole() {
    rt().block_on(async {
        let a = Scope::new();
        let b = Scope::new();
        let work = Scope::child_of([&a, &b]);
        let mut cancelled = work.cancelled();
        let bad = Waker::from(Arc::new(PanicWake));
        assert!(poll(&mut cancelled, &bad).is_pending());
        let deadline = Instant::now();
        let work = catch_unwind(AssertUnwindSafe(|| work.clone().with_deadline(deadline)))
            .err()
            .map(|_| work)
            .unwrap_or_else(|| panic!("the first part's waker panics"));
        assert!(work.parts().iter().all(|part| part.phase().graceful));
        drop(cancelled);
    });
}

/// A signal that never completes and panics once dropped, as a scope drops it on its cancel.
struct PanicOnDrop;

impl Future for PanicOnDrop {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        Poll::Pending
    }
}

impl Drop for PanicOnDrop {
    fn drop(&mut self) {
        panic!("a signal panics once dropped");
    }
}

#[test]
fn a_panic_while_holding_a_part_again_lets_go_of_the_parts_held() {
    rt().block_on(async {
        let a = Scope::new();
        let b = Scope::new()
            .with_signal(PanicOnDrop)
            .with_deadline(Instant::now() + SEC);
        let work = Scope::child_of([&a, &b]);
        let weak = work.clone_weak();
        drop(work);
        // Due, but published only once the second part is held again: its signal goes then.
        advance(SEC).await;
        catch_unwind(AssertUnwindSafe(|| weak.clone().into_scope())).unwrap_err();
        let weak_a = a.into_weak_scope();
        assert!(
            poll_noop(&mut weak_a.drained()).is_ready(),
            "the part held before the panic is let go"
        );
        drop(b);
    });
}

#[test]
#[cfg_attr(miri, ignore = "a deep tree is slow under Miri")]
fn a_deep_chain_of_composites_fixes_and_tears_down_on_a_small_stack() {
    on_a_small_stack(|| {
        rt().block_on(async {
            let a = Scope::new();
            let b = Scope::new();
            let mut chain = Vec::with_capacity(DEEP);
            let mut leaf = Scope::child_of([&a, &b]);
            for _ in 1..DEEP {
                let next = leaf.child();
                chain.push(leaf);
                leaf = next;
            }
            b.cancel(Cause::Reason("first seen"));
            assert!(chain[0].is_cancelled());
            a.cancel(Cause::Reason("first part"));
            assert_eq!(reason(leaf.cause().as_ref()), Some("first seen"));
            drop(chain);
            drop(leaf);
        });
    });
}

#[test]
#[cfg_attr(miri, ignore = "a deep tree is slow under Miri")]
fn the_first_observation_of_a_chain_of_composites_walks_each_node_a_bounded_number_of_times() {
    for depth in [256, 2048] {
        let a = Scope::new();
        let b = Scope::new();
        let mut chain = vec![Scope::child_of([&a, &b])];
        for _ in 1..depth {
            let next = chain.last().unwrap().child();
            chain.push(next);
        }
        a.cancel(Cause::Owner);
        let _before = super::node::walk_steps::take();
        assert!(chain.last().unwrap().is_cancelled());
        let steps = super::node::walk_steps::take();
        // Each of the two parts walks its chain of `depth` nodes a few times, never once per
        // composite above it.
        assert!(steps <= 8 * depth, "{steps} steps at depth {depth}");
        assert!(chain.iter().all(Scope::is_cancelled));
    }
}

/// Ends `scope`'s graceful (or `hard`) phase with `reason`.
fn end_phase(scope: &WeakScope, hard: bool, reason: &'static str) {
    if hard {
        scope.abort(Cause::Reason(reason));
    } else {
        scope.cancel(Cause::Reason(reason));
    }
}

fn phase_cause(scope: &Scope, hard: bool) -> Option<&'static str> {
    let cause = if hard {
        scope.abort_cause()
    } else {
        scope.cause()
    };
    reason(cause.as_ref())
}

/// Runs `racer` once, at the `step`-th step of the next composite observation on this thread;
/// the returned flag tells whether it ran.
fn race_at_step(step: usize, racer: impl FnOnce() + 'static) -> Arc<AtomicBool> {
    let ran = Arc::new(AtomicBool::new(false));
    let mut racer = Some(racer);
    let mut steps = 0;
    let done = ran.clone();
    super::sync::observation::set(Some(Box::new(move || {
        steps += 1;
        if steps == step
            && let Some(racer) = racer.take()
        {
            racer();
            done.store(true, Ordering::SeqCst);
        }
    })));
    ran
}

/// One fresh tree per step, so the racing parent lands at every step of the first observation.
fn race_each_step_of_a_composite_observation(hard: bool, pre_reached: bool) {
    let mut raced = 0;
    for step in 1..=16 {
        rt().block_on(async {
            let a = Scope::new();
            let b = Scope::new();
            let work = Scope::child_of([&a, &b]);
            let child = work.child();
            let (first, second, part) = if pre_reached {
                (b.clone_weak(), a.clone_weak(), child.parts()[0].clone())
            } else {
                (a.clone_weak(), b.clone_weak(), child.parts()[1].clone())
            };
            if pre_reached {
                end_phase(&first, hard, "first");
            }
            let ran = race_at_step(step, move || {
                end_phase(&second, hard, "second");
                // Published up to the part, as an observer of that part alone would.
                let _phase = part.phase();
            });
            let observed = phase_cause(&child, hard);
            super::sync::observation::set(None);
            if ran.load(Ordering::SeqCst) && observed.is_some() {
                raced += 1;
            }
            if !pre_reached {
                end_phase(&first, hard, "first");
            }
            let child_cause = phase_cause(&child, hard);
            if observed.is_some() {
                assert_eq!(observed, child_cause, "step {step}");
            }
            assert_eq!(phase_cause(&work, hard), child_cause, "step {step}");
        });
    }
    assert!(raced > 0, "no step raced an observation that saw a phase");
}

#[test]
fn a_parent_ending_during_a_composite_observation_leaves_parent_and_child_agreeing() {
    for hard in [false, true] {
        race_each_step_of_a_composite_observation(hard, false);
    }
}

#[test]
fn a_part_ending_while_a_reached_composite_is_read_leaves_parent_and_child_agreeing() {
    for hard in [false, true] {
        race_each_step_of_a_composite_observation(hard, true);
    }
}

/// As [`race_each_step_of_a_composite_observation`], for the cancel an observed abort implies.
fn abort_each_step_of_an_abort_observation(of_child: bool) {
    let mut raced = 0;
    for step in 1..=16 {
        rt().block_on(async {
            let a = Scope::new();
            let b = Scope::new();
            let work = Scope::child_of([&a, &b]);
            let child = work.child();
            let observed = if of_child { &child } else { &work };
            let (weak_b, part) = (b.clone_weak(), observed.parts()[1].clone());
            let ran = race_at_step(step, move || {
                weak_b.abort(Cause::Reason("b"));
                let _phase = part.phase();
            });
            let aborted = reason(observed.abort_cause().as_ref());
            super::sync::observation::set(None);
            a.cancel(Cause::Reason("a"));
            if aborted.is_some() {
                if ran.load(Ordering::SeqCst) {
                    raced += 1;
                }
                assert_eq!(reason(observed.cause().as_ref()), aborted, "step {step}");
            }
            assert_eq!(
                reason(work.cause().as_ref()),
                reason(child.cause().as_ref()),
                "step {step}"
            );
        });
    }
    assert!(
        raced > 0,
        "no step raced an abort observation that saw the abort"
    );
}

#[test]
fn an_abort_observed_on_a_composite_fixes_the_cancel_it_implies() {
    abort_each_step_of_an_abort_observation(false);
}

#[test]
fn an_abort_observed_below_a_composite_fixes_the_cancel_it_implies() {
    abort_each_step_of_an_abort_observation(true);
}
