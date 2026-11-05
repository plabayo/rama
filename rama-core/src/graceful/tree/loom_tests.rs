#![cfg(rama_loom)]

use std::{
    future::Future,
    pin::Pin,
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

use super::{Cause, Scope, node::COUNT_CLOSED};

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
            weak.upgrade().is_some_and(|scope| {
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
                weak.upgrade().is_some_and(|scope| {
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
        assert!(weak.clone().upgrade().is_none());
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
                if let Some(revived) = weak_child.upgrade() {
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
