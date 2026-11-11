#![cfg(rama_loom)]

use std::{
    cell::Cell,
    future::Future,
    pin::Pin,
    rc::Rc,
    // Outside loom's view: they only count the schedules a model explored.
    sync::{
        Arc as StdArc,
        atomic::{
            AtomicBool as StdAtomicBool, AtomicUsize as StdAtomicUsize, Ordering as StdOrdering,
        },
    },
    task::{Context, Poll, Waker},
};

use loom::{
    future::block_on,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

use super::{Cause, Scope, node::COUNT_CLOSED, sync::timer};

#[test]
fn cancel_wakes_a_registering_waiter() {
    loom::model(|| {
        let scope = Scope::new();
        let canceller = {
            let scope = scope.clone_weak();
            thread::spawn(move || scope.cancel(Cause::Owner))
        };
        block_on(scope.cancelled());
        canceller.join().unwrap();
    });
}

#[test]
fn parent_cancel_reaches_a_child_created_concurrently() {
    loom::model(|| {
        let parent = Scope::new();
        let canceller = {
            let parent = parent.clone_weak();
            thread::spawn(move || parent.cancel(Cause::Owner))
        };
        let child = parent.child();
        block_on(child.cancelled());
        canceller.join().unwrap();
        assert!(child.is_cancelled());
    });
}

#[test]
fn abort_wakes_a_waiter_on_the_hard_phase() {
    loom::model(|| {
        let parent = Scope::new();
        let child = parent.child();
        let aborter = {
            let parent = parent.clone_weak();
            thread::spawn(move || parent.abort(Cause::Owner))
        };
        block_on(child.aborted());
        aborter.join().unwrap();
        assert!(child.is_cancelled());
    });
}

#[test]
fn last_drop_wakes_a_drain_waiter() {
    loom::model(|| {
        let root = Scope::new();
        let weak = root.clone_weak();
        let holder = root.child();
        drop(root);
        let dropper = thread::spawn(move || drop(holder));
        block_on(weak.drained());
        dropper.join().unwrap();
    });
}

#[test]
fn upgrade_never_succeeds_on_a_closed_node() {
    loom::model(|| {
        let scope = Scope::new();
        let node = scope.node().cloned().unwrap();
        let weak = scope.clone_weak();
        let dropper = thread::spawn(move || drop(scope));
        let upgrader = thread::spawn(move || {
            weak.into_scope().is_some_and(|scope| {
                let node = scope.node().cloned().unwrap();
                // Held: the node is open and counts this holder.
                assert_eq!(node.strong_word() & COUNT_CLOSED.1, 0);
                assert!(node.strong_count() >= 1);
                true
            })
        });
        let closed = node.close_if_drained();
        dropper.join().unwrap();
        let upgraded = upgrader.join().unwrap();
        if closed {
            assert_eq!(node.strong_word(), COUNT_CLOSED.1);
        } else {
            // Not closed: a holder was alive when the close was tried.
            assert!(upgraded || node.strong_count() == 0);
        }
    });
}

/// One-shot signal built on loom primitives, so loom explores its wake-ups.
#[derive(Clone, Default)]
struct LoomSignal {
    fired: Arc<AtomicBool>,
    waker: Arc<Mutex<Option<Waker>>>,
}

impl LoomSignal {
    fn fire(&self) {
        self.fired.store(true, Ordering::Release);
        let waker = self.waker.lock().unwrap().take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

impl Future for LoomSignal {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.fired.load(Ordering::Acquire) {
            return Poll::Ready(());
        }
        *self.waker.lock().unwrap() = Some(cx.waker().clone());
        if self.fired.load(Ordering::Acquire) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

#[test]
fn signal_completion_reaches_every_waiter() {
    loom::model(|| {
        let signal = LoomSignal::default();
        let scope = Scope::new().with_signal(signal.clone());
        let other = {
            let scope = scope.clone_weak();
            thread::spawn(move || block_on(scope.cancelled()))
        };
        let firer = thread::spawn(move || signal.fire());
        block_on(scope.cancelled());
        other.join().unwrap();
        firer.join().unwrap();
        assert!(matches!(scope.cause(), Some(Cause::Signal)));
    });
}

#[test]
fn cancel_last_drop_and_upgrade_never_revive_a_drained_cancelled_scope() {
    loom::model(|| {
        let scope = Scope::new();
        let canceller = {
            let weak = scope.clone_weak();
            thread::spawn(move || weak.cancel(Cause::Owner))
        };
        let upgrader = {
            let weak = scope.clone_weak();
            thread::spawn(move || {
                weak.into_scope().is_some_and(|scope| {
                    assert!(scope.node().unwrap().strong_count() >= 1);
                    true
                })
            })
        };
        let weak = scope.clone_weak();
        drop(scope);
        canceller.join().unwrap();
        let _upgraded = upgrader.join().unwrap();
        // Cancelled with no holder left: closed for good, whatever the interleaving was.
        assert!(weak.clone().into_scope().is_none());
        block_on(weak.drained());
    });
}

#[test]
fn revived_child_never_leaves_its_parent_without_a_hold() {
    loom::model(|| {
        let parent = Scope::new();
        let parent_node = parent.node().cloned().unwrap();
        let child = parent.child();
        let weak_child = child.clone_weak();
        let dropper = thread::spawn(move || drop(child));
        let reviver = {
            let parent_node = parent_node.clone();
            thread::spawn(move || {
                if let Some(revived) = weak_child.into_scope() {
                    // The parent's own holder plus the live child.
                    assert!(parent_node.strong_count() >= 2);
                    drop(revived);
                }
            })
        };
        dropper.join().unwrap();
        reviver.join().unwrap();
        assert_eq!(parent_node.strong_count(), 1);
        drop(parent);
        assert_eq!(parent_node.strong_count(), 0);
    });
}

#[test]
fn every_ancestor_wake_reaches_a_deep_waiter() {
    loom::model(|| {
        let root = Scope::new();
        let leaf = root.child().child();
        let ender = {
            let root = root.clone_weak();
            thread::spawn(move || {
                root.cancel(Cause::Owner);
                root.abort(Cause::Owner);
            })
        };
        block_on(leaf.aborted());
        ender.join().unwrap();
    });
}

// A graced chain stays on the quick path until a level is cancelled. No waiter here outlives
// a cancel pending: its timer would need a runtime.
#[test]
fn an_ancestor_end_reaches_a_waiter_below_a_graced_root() {
    for abort in [false, true] {
        loom::model(move || {
            let root = Scope::new().with_grace(std::time::Duration::from_secs(3600));
            let leaf = root.child().child();
            let ender = {
                let root = root.clone_weak();
                thread::spawn(move || {
                    if abort {
                        root.abort(Cause::Owner);
                    } else {
                        root.cancel(Cause::Owner);
                    }
                })
            };
            if abort {
                block_on(leaf.aborted());
            } else {
                block_on(leaf.cancelled());
            }
            ender.join().unwrap();
            assert!(leaf.is_cancelled());
        });
    }
}

#[test]
fn a_grace_set_while_a_waiter_registers_loses_no_cancel() {
    loom::model(|| {
        let root = Scope::new();
        let leaf = root.child();
        let ender = {
            let root = root.clone();
            thread::spawn(move || {
                let root = root.with_grace(std::time::Duration::from_secs(3600));
                root.cancel(Cause::Owner);
            })
        };
        block_on(leaf.cancelled());
        ender.join().unwrap();
        assert!(leaf.is_cancelled());
        assert!(!leaf.is_aborted());
    });
}

#[test]
fn concurrent_ancestor_wakes_both_reach_a_deep_waiter() {
    loom::model(|| {
        let root = Scope::new();
        let leaf = root.child();
        let threads: Vec<_> = [false, true]
            .into_iter()
            .map(|abort| {
                let root = root.clone_weak();
                thread::spawn(move || {
                    if abort {
                        root.abort(Cause::Owner);
                    } else {
                        root.cancel(Cause::Owner);
                    }
                })
            })
            .collect();
        block_on(leaf.aborted());
        for thread in threads {
            thread.join().unwrap();
        }
    });
}

#[test]
fn a_child_dropped_while_its_parent_wakes_it() {
    loom::model(|| {
        let root = Scope::new();
        let child = root.child();
        let mut cancelled = Box::pin(child.cancelled());
        assert!(
            cancelled
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        let canceller = {
            let root = root.clone_weak();
            thread::spawn(move || root.cancel(Cause::Owner))
        };
        drop(cancelled);
        drop(child);
        canceller.join().unwrap();
        block_on(root.cancelled());
    });
}

#[test]
fn a_grouped_join_and_a_concurrent_revival_never_split_a_composite() {
    loom::model(|| {
        let a = Scope::new();
        let b = Scope::new();
        let work = Scope::child_of([&a, &b]);
        let weak = work.clone_weak();
        let after = work.clone_weak();
        let reviver = thread::spawn(move || {
            // Dropped at once: a successful revival only delays the join.
            drop(weak.into_scope());
        });
        block_on(work.join()).unwrap();
        reviver.join().unwrap();
        assert!(after.into_scope().is_none(), "closed as a whole");
    });
}

/// A loom yield hands over without branching: one more racer yield per model lands it later.
fn race_a_composite_observation(hard: bool, pre_reached: bool) {
    let raced = StdArc::new(StdAtomicUsize::new(0));
    for racer_yields in 0..8 {
        race_a_composite_observation_after(hard, pre_reached, racer_yields, &raced);
    }
    assert!(
        raced.load(StdOrdering::SeqCst) > 0,
        "no schedule raced the observation"
    );
}

fn race_a_composite_observation_after(
    hard: bool,
    pre_reached: bool,
    racer_yields: usize,
    raced: &StdArc<StdAtomicUsize>,
) {
    let mut model = loom::model::Builder::new();
    model.preemption_bound = Some(2);
    model.check({
        let raced = raced.clone();
        move || {
            // Paused: every phase lands on one instant, so only the fixed facts tell them apart.
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .start_paused(true)
                .build()
                .unwrap();
            let _entered = runtime.enter();
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
            let landed = StdArc::new(StdAtomicBool::new(false));
            let racer = {
                let landed = landed.clone();
                let handle = runtime.handle().clone();
                thread::spawn(move || {
                    let _entered = handle.enter();
                    // Lets the observation start first, so the end lands inside it.
                    for _ in 0..=racer_yields {
                        thread::yield_now();
                    }
                    end_phase(&second, hard, "second");
                    // Published up to the part, as an observer of that part alone would.
                    let _phase = part.phase();
                    landed.store(true, StdOrdering::SeqCst);
                })
            };
            thread::yield_now();
            let at_first_step = Rc::new(Cell::new(None));
            {
                let (at_first_step, landed) = (at_first_step.clone(), landed.clone());
                super::sync::observation::set(Some(Box::new(move || {
                    if at_first_step.get().is_none() {
                        at_first_step.set(Some(landed.load(StdOrdering::SeqCst)));
                    }
                })));
            }
            let observed = phase_cause(&child, hard);
            super::sync::observation::set(None);
            let during = at_first_step.get() == Some(false) && landed.load(StdOrdering::SeqCst);
            racer.join().unwrap();
            if observed.is_some() && during {
                raced.fetch_add(1, StdOrdering::SeqCst);
            }
            if !pre_reached {
                end_phase(&first, hard, "first");
            }
            let child_cause = phase_cause(&child, hard);
            if observed.is_some() {
                assert_eq!(observed, child_cause);
            }
            assert_eq!(
                phase_cause(&work, hard),
                child_cause,
                "racer yields: {racer_yields}"
            );
        }
    });
}

/// As [`race_a_composite_observation`]; the aborting thread observes too, so one observer may
/// take the fact the other fixed.
fn race_an_abort_observation(of_child: bool) {
    let raced = StdArc::new(StdAtomicUsize::new(0));
    for racer_yields in 0..8 {
        let mut model = loom::model::Builder::new();
        model.preemption_bound = Some(2);
        model.check({
            let raced = raced.clone();
            move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_time()
                    .start_paused(true)
                    .build()
                    .unwrap();
                let _entered = runtime.enter();
                let a = Scope::new();
                let b = Scope::new();
                let work = Scope::child_of([&a, &b]);
                let child = work.child();
                let observed = if of_child {
                    child.clone()
                } else {
                    work.clone()
                };
                // Sees the abort, then cancels `a`: the graceful cause stays the abort's.
                let observe = {
                    let a = a.clone_weak();
                    move |observed: &Scope| {
                        let aborted = phase_cause(observed, true);
                        if aborted.is_some() {
                            a.cancel(Cause::Reason("a"));
                            assert_eq!(phase_cause(observed, false), aborted);
                        }
                        aborted
                    }
                };
                let landed = StdArc::new(StdAtomicBool::new(false));
                let racer = {
                    let (b, part) = (b.clone_weak(), observed.parts()[1].clone());
                    let (observed, observe) = (observed.clone(), observe.clone());
                    let landed = landed.clone();
                    let handle = runtime.handle().clone();
                    thread::spawn(move || {
                        let _entered = handle.enter();
                        // From none on: the observation takes no lock before its first step.
                        for _ in 0..racer_yields {
                            thread::yield_now();
                        }
                        b.abort(Cause::Reason("b"));
                        let _phase = part.phase();
                        landed.store(true, StdOrdering::SeqCst);
                        observe(&observed)
                    })
                };
                let at_first_step = Rc::new(Cell::new(None));
                {
                    let (at_first_step, landed) = (at_first_step.clone(), landed.clone());
                    super::sync::observation::set(Some(Box::new(move || {
                        if at_first_step.get().is_none() {
                            at_first_step.set(Some(landed.load(StdOrdering::SeqCst)));
                        }
                    })));
                }
                let aborted = observe(&observed);
                super::sync::observation::set(None);
                if aborted.is_some()
                    && at_first_step.get() == Some(false)
                    && landed.load(StdOrdering::SeqCst)
                {
                    raced.fetch_add(1, StdOrdering::SeqCst);
                }
                let _racer = racer.join().unwrap();
                assert_eq!(phase_cause(&work, false), phase_cause(&child, false));
            }
        });
    }
    assert!(
        raced.load(StdOrdering::SeqCst) > 0,
        "no schedule raced the abort observation"
    );
}

#[test]
fn an_abort_observed_on_a_composite_keeps_the_cancel_it_implies() {
    race_an_abort_observation(false);
}

#[test]
fn an_abort_observed_below_a_composite_keeps_the_cancel_it_implies() {
    race_an_abort_observation(true);
}

fn end_phase(scope: &super::WeakScope, hard: bool, reason: &'static str) {
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

#[test]
fn a_parent_cancelled_during_a_composite_observation_leaves_parent_and_child_agreeing() {
    race_a_composite_observation(false, false);
}

#[test]
fn a_parent_aborted_during_a_composite_observation_leaves_parent_and_child_agreeing() {
    race_a_composite_observation(true, false);
}

#[test]
fn a_part_cancelled_while_a_reached_composite_is_read_leaves_parent_and_child_agreeing() {
    race_a_composite_observation(false, true);
}

#[test]
fn a_part_aborted_while_a_reached_composite_is_read_leaves_parent_and_child_agreeing() {
    race_a_composite_observation(true, true);
}

fn reason(cause: Option<&Cause>) -> Option<&'static str> {
    match cause {
        Some(Cause::Reason(reason)) => Some(reason),
        _ => None,
    }
}

// The wait leaves its timer alone until the timer asks for a poll. However the asks of two
// threads fall around its polls, the last one is answered by a poll of the timer.
#[test]
fn a_timer_that_asks_for_a_poll_gets_one() {
    loom::model(|| {
        let scope = Scope::new().with_timeout(std::time::Duration::from_secs(3600));
        let mut wait = Box::pin(scope.aborted());
        let mut cx = Context::from_waker(Waker::noop());
        // The second poll gives the timer its own waker.
        assert!(wait.as_mut().poll(&mut cx).is_pending());
        assert!(wait.as_mut().poll(&mut cx).is_pending());
        let timer = Arc::new(timer::last().expect("a timer is set"));
        let askers = [(); 2].map(|()| {
            let timer = timer.clone();
            thread::spawn(move || timer.ask())
        });
        assert!(wait.as_mut().poll(&mut cx).is_pending());
        for asker in askers {
            asker.join().unwrap();
        }
        assert!(wait.as_mut().poll(&mut cx).is_pending());
        assert!(
            !timer.is_waiting(),
            "the timer asked for a poll it never got"
        );
    });
}

// The same with a task behind the wait, which loom also polls at moments of its own: only
// the wake of the ask is sure to come, and the poll it leads to has to answer the ask. A
// lost wake leaves the model stuck.
#[test]
fn a_timer_that_asks_for_a_poll_wakes_the_task() {
    loom::model(|| {
        let scope = Scope::new().with_timeout(std::time::Duration::from_secs(3600));
        let mut wait = Box::pin(scope.aborted());
        let mut cx = Context::from_waker(Waker::noop());
        assert!(wait.as_mut().poll(&mut cx).is_pending());
        let mut asker = None;
        block_on(std::future::poll_fn(|cx| {
            assert!(wait.as_mut().poll(cx).is_pending());
            let timer = timer::last().expect("a timer is set");
            if timer.was_answered() {
                return Poll::Ready(());
            }
            if asker.is_none() {
                // Asked once the timer was polled with the waker the wait made for it.
                asker = Some(thread::spawn(move || timer.ask()));
            }
            Poll::Pending
        }));
        asker.take().expect("asked").join().unwrap();
    });
}
