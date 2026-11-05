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

use super::{Cause, Scope, WeakScope};

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
    assert!(weak.upgrade().is_some_and(|scope| scope.is_never()));
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
                    let _scope = weak.upgrade().map(|scope| {
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
        let elapsed = root.join().await.unwrap();
        assert_eq!(elapsed, 3 * SEC);
        worker.await.unwrap();
        assert!(weak.clone().upgrade().is_none());
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
        assert_eq!(root.join().await.unwrap(), SEC);
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
        let upgraded = weak.clone().upgrade().unwrap();
        drop(upgraded);
        root.join().await.unwrap();
        assert!(weak.clone().upgrade().is_none());
        // A refused upgrade releases nothing it did not take.
        assert!(weak.clone().upgrade().is_none());
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
    let weak = scope.clone().downgrade();
    assert!(!weak.is_aborted());
    weak.abort(Cause::Reason("weak"));
    assert!(scope.is_cancelled());
    assert!(weak.is_aborted());
    assert_eq!(reason(weak.cause().as_ref()), Some("weak"));
    assert_eq!(reason(weak.abort_cause().as_ref()), Some("weak"));
}

#[test]
fn weak_never_scope_stays_inert() {
    let weak = Scope::default().downgrade();
    weak.cancel(Cause::Owner);
    weak.abort(Cause::Owner);
    assert!(!weak.is_cancelled());
    assert!(!weak.is_aborted());
    assert!(weak.cause().is_none());
    let scope = weak.upgrade().unwrap();
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
        assert!(weak_child.clone().upgrade().is_none());
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
        Poll::Ready(Ok(Duration::ZERO))
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
        assert_eq!(root.join().await.unwrap(), 2 * SEC);
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
        assert_eq!(flow.join().await.unwrap(), SEC);
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
    let weak = scope.downgrade();
    assert!(weak.clone().upgrade().is_none());
    assert!(poll_noop(&mut weak.drained()).is_ready());
}

#[test]
fn weak_revives_an_active_scope_without_holders() {
    let scope = Scope::new();
    let weak = scope.downgrade();
    let revived = weak.clone().upgrade().unwrap();
    assert!(poll_noop(&mut weak.drained()).is_pending());
    revived.cancel(Cause::Owner);
    drop(revived);
    assert!(weak.upgrade().is_none());
}

#[test]
fn revived_child_holds_its_parent_and_a_refused_one_holds_nothing() {
    let parent = Scope::new();
    let child = parent.child();
    let weak_child = child.downgrade();
    let weak_parent = parent.clone_weak();
    drop(parent);
    assert!(poll_noop(&mut weak_parent.drained()).is_ready());

    let revived = weak_child.clone().upgrade().unwrap();
    assert!(poll_noop(&mut weak_parent.drained()).is_pending());
    drop(revived);
    assert!(poll_noop(&mut weak_parent.drained()).is_ready());

    weak_parent.cancel(Cause::Owner);
    assert!(weak_child.upgrade().is_none());
    assert!(weak_parent.upgrade().is_none());
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
