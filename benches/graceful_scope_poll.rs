//! Cost of one poll of a task spawned on a scope, per scope shape.
//!
//! Not a divan bench: run it under `/usr/bin/time -l` with two poll counts and divide the
//! difference in instructions retired, as wall time is noisy on a shared machine.
//!
//! `graceful_scope_poll <mode> <shape> <polls>`; modes: `task` (a task that wakes itself and
//! returns pending `polls` times), `conn` (such a task that also selects on `Cancelled`, as a
//! served connection does), `wait` (an `Aborted` future polled directly with one waker),
//! `observe` (`WeakScope::is_cancelled` called `polls` times), `first_poll` (an `Aborted`
//! future made, polled once and dropped), `spawn` (a task spawned and awaited), `child` (a
//! child scope made and dropped), `input` (a child scope with a max age, a grace and a hard
//! max age made, awaited once and dropped, as a scope layer does per input), `waiters` (as
//! `first_poll`, for 64 futures at a time on the one scope, counted per future), `wake` (64
//! `Aborted` futures registered on a child scope, woken by its abort and polled to their end,
//! counted per future).
//!
//! The `bound_*` modes compare ways to bound one future by the hard phase of the scope and a
//! timeout of its own, as the close of a tunnel does: `bound_timer` (an `Aborted` future next
//! to `tokio::time::timeout`), `bound_child` (`run_until_aborted` of a child scope with a hard
//! timeout), `bound_within` (`run_until_aborted_within`). Each is made, polled once and
//! dropped; with the suffix `_make` it is made and dropped unpolled, with `_repoll` it is made
//! once and polled `polls` times.

#![expect(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    reason = "bench: panic-on-error and printing results is the standard pattern for harnesses"
)]

use rama::graceful::{Aborted, Cause, Scope};
use std::future::Future;
use std::hint::black_box;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};
use tokio::time::{Timeout, timeout};

/// Returns pending and wakes itself `left` times.
struct Spin {
    left: u64,
}

impl Future for Spin {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.left == 0 {
            return Poll::Ready(());
        }
        self.left -= 1;
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

const HOUR: Duration = Duration::from_secs(3600);

/// The futures the `waiters` and `wake` modes keep on one scope at a time.
const WAITERS: usize = 64;

/// The scope a task runs in, and what keeps its ancestors alive.
fn shape(name: &str) -> Option<(Scope, Vec<Scope>)> {
    let signal = std::future::pending::<()>;
    Some(match name {
        "plain" => return None,
        "detached" => (Scope::detached(), vec![]),
        "root" => (Scope::new(), vec![]),
        "child" => {
            let root = Scope::new();
            (root.child(), vec![root])
        }
        "grandchild" => {
            let root = Scope::new();
            let child = root.child();
            (child.child(), vec![root, child])
        }
        "root_signal" => (Scope::new().with_signal(signal()), vec![]),
        "grandchild_signal" => {
            let root = Scope::new().with_signal(signal());
            let child = root.child();
            (child.child(), vec![root, child])
        }
        "root_signal_grace" => (
            Scope::new()
                .with_signal(signal())
                .with_grace(Duration::from_secs(30)),
            vec![],
        ),
        "child_signal_grace" => {
            let root = Scope::new()
                .with_signal(signal())
                .with_grace(Duration::from_secs(30));
            (root.child(), vec![root])
        }
        "grandchild_signal_grace" => {
            let root = Scope::new()
                .with_signal(signal())
                .with_grace(Duration::from_secs(30));
            let child = root.child();
            (child.child(), vec![root, child])
        }
        "root_timeout" => (Scope::new().with_timeout(HOUR), vec![]),
        "child_timeout" => {
            let root = Scope::new();
            (root.child().with_timeout(HOUR), vec![root])
        }
        "grandchild_root_timeout" => {
            let root = Scope::new().with_timeout(HOUR);
            let child = root.child();
            (child.child(), vec![root, child])
        }
        "composite" => {
            let a = Scope::new();
            let b = Scope::new();
            (Scope::child_of([&a, &b]), vec![a, b])
        }
        "composite_signal_grace" => {
            let a = Scope::new()
                .with_signal(signal())
                .with_grace(Duration::from_secs(30));
            let b = Scope::new();
            (Scope::child_of([&a, &b]), vec![a, b])
        }
        "depth8" => {
            let mut keep = vec![Scope::new()];
            for _ in 0..6 {
                let child = keep.last().expect("a root").child();
                keep.push(child);
            }
            (keep.last().expect("a root").child(), keep)
        }
        // What a scope layer with a max age, a grace and a hard max age gives a connection.
        "input_max_age" => {
            let root = Scope::new()
                .with_signal(signal())
                .with_grace(Duration::from_secs(30));
            let server = root.child();
            let input = server
                .child()
                .with_timeout(HOUR)
                .with_grace(Duration::from_secs(30))
                .with_hard_timeout(2 * HOUR);
            (input, vec![root, server])
        }
        // Draining: cancelled, the hard phase comes when the grace ends.
        "root_grace_draining" => {
            let root = Scope::new().with_grace(HOUR);
            root.cancel(Cause::Owner);
            (root, vec![])
        }
        "grandchild_grace_draining" => {
            let root = Scope::new().with_signal(signal()).with_grace(HOUR);
            let child = root.child();
            let grandchild = child.child();
            root.cancel(Cause::Owner);
            (grandchild, vec![root, child])
        }
        other => panic!("unknown shape {other}"),
    })
}

/// A served connection: runs until `spin` ends or the scope is cancelled.
async fn serve(scope: Scope, spin: Spin) {
    tokio::select! {
        () = scope.cancelled() => {}
        () = spin => {}
    }
}

/// The future the `bound_*` modes bound: a close that waits for its peer.
type Close = std::future::Pending<()>;

/// How long the `bound_*` modes give [`Close`].
const CLOSE_GRACE: Duration = Duration::from_secs(5);

pin_project_lite::pin_project! {
    /// What `bound_timer` polls: the hard phase of the scope first, then the timed future.
    struct TimerBound<F> {
        #[pin]
        stop: Aborted,
        #[pin]
        timed: Timeout<F>,
    }
}

impl<F: Future> Future for TimerBound<F> {
    type Output = Option<F::Output>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        if this.stop.poll(cx).is_ready() {
            return Poll::Ready(None);
        }
        this.timed.poll(cx).map(Result::ok)
    }
}

pin_project_lite::pin_project! {
    /// A future and the scope held while it runs, as a scope made within an awaited
    /// expression is.
    struct Held<F> {
        scope: Scope,
        #[pin]
        future: F,
    }
}

impl<F: Future> Future for Held<F> {
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.project().future.poll(cx)
    }
}

fn bound_timer(scope: &Scope) -> TimerBound<Close> {
    TimerBound {
        stop: scope.aborted(),
        timed: timeout(CLOSE_GRACE, std::future::pending()),
    }
}

fn bound_child(scope: &Scope) -> Held<impl Future<Output = Option<()>> + use<>> {
    let scope = scope.child().with_hard_timeout(CLOSE_GRACE);
    let future = scope.run_until_aborted(std::future::pending());
    Held { scope, future }
}

fn bound_within(scope: &Scope) -> impl Future<Output = Option<()>> + use<> {
    scope.run_until_aborted_within(CLOSE_GRACE, std::future::pending())
}

/// Times `polls` rounds of a `bound_*` mode: the future `make` returns is made, polled once
/// and dropped per round (`stage` empty), made and dropped unpolled (`_make`), or made once
/// and polled every round (`_repoll`).
fn bound_rounds<T: Future>(polls: u64, stage: &str, make: impl Fn() -> T) -> Duration {
    let mut cx = Context::from_waker(Waker::noop());
    match stage {
        "" => {
            let start = Instant::now();
            for _ in 0..polls {
                let mut bound = std::pin::pin!(make());
                assert!(bound.as_mut().poll(&mut cx).is_pending());
            }
            start.elapsed()
        }
        "_make" => {
            let start = Instant::now();
            for _ in 0..polls {
                drop(black_box(make()));
            }
            start.elapsed()
        }
        "_repoll" => {
            let mut bound = std::pin::pin!(make());
            assert!(bound.as_mut().poll(&mut cx).is_pending());
            let start = Instant::now();
            for _ in 0..polls {
                assert!(black_box(bound.as_mut()).poll(&mut cx).is_pending());
            }
            start.elapsed()
        }
        other => panic!("unknown stage {other}"),
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mode = args.next().expect("mode");
    let name = args.next().expect("shape");
    let polls: u64 = args.next().expect("polls").parse().expect("poll count");

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("runtime build");

    let elapsed = runtime.block_on(async {
        let scope = shape(&name);
        match mode.as_str() {
            "task" => {
                let spin = Spin { left: polls };
                let start = Instant::now();
                match &scope {
                    None => tokio::spawn(spin).await.expect("task"),
                    Some((scope, _)) => scope.spawn_task(spin).await.expect("task").expect("ran"),
                }
                start.elapsed()
            }
            "conn" => {
                let (scope, _keep) = scope.as_ref().expect("a scope shape");
                let conn = serve(scope.clone(), Spin { left: polls });
                let start = Instant::now();
                scope.spawn_task(conn).await.expect("task").expect("ran");
                start.elapsed()
            }
            "wait" => {
                let (scope, _keep) = scope.as_ref().expect("a scope shape");
                let mut wait = std::pin::pin!(scope.aborted());
                let mut cx = Context::from_waker(Waker::noop());
                let start = Instant::now();
                for _ in 0..polls {
                    assert!(black_box(wait.as_mut()).poll(&mut cx).is_pending());
                }
                start.elapsed()
            }
            "observe" => {
                let (scope, _keep) = scope.as_ref().expect("a scope shape");
                let weak = scope.clone_weak();
                let cancelled = weak.is_cancelled();
                let start = Instant::now();
                for _ in 0..polls {
                    assert_eq!(black_box(&weak).is_cancelled(), cancelled);
                }
                start.elapsed()
            }
            "first_poll" => {
                let (scope, _keep) = scope.as_ref().expect("a scope shape");
                let mut cx = Context::from_waker(Waker::noop());
                let start = Instant::now();
                for _ in 0..polls {
                    let mut wait = std::pin::pin!(black_box(scope).aborted());
                    assert!(wait.as_mut().poll(&mut cx).is_pending());
                }
                start.elapsed()
            }
            "spawn" => {
                let start = Instant::now();
                for _ in 0..polls {
                    let spin = Spin { left: 0 };
                    match &scope {
                        None => tokio::spawn(spin).await.expect("task"),
                        Some((scope, _)) => {
                            scope.spawn_task(spin).await.expect("task").expect("ran");
                        }
                    }
                }
                start.elapsed()
            }
            "child" => {
                let (scope, _keep) = scope.as_ref().expect("a scope shape");
                let start = Instant::now();
                for _ in 0..polls {
                    drop(black_box(black_box(scope).child()));
                }
                start.elapsed()
            }
            "input" => {
                let (scope, _keep) = scope.as_ref().expect("a scope shape");
                let mut cx = Context::from_waker(Waker::noop());
                let start = Instant::now();
                for _ in 0..polls {
                    let input = black_box(scope)
                        .child()
                        .with_timeout(HOUR)
                        .with_grace(Duration::from_secs(30))
                        .with_hard_timeout(2 * HOUR);
                    let mut wait = std::pin::pin!(input.aborted());
                    assert!(wait.as_mut().poll(&mut cx).is_pending());
                }
                start.elapsed()
            }
            "waiters" => {
                let (scope, _keep) = scope.as_ref().expect("a scope shape");
                let mut cx = Context::from_waker(Waker::noop());
                let start = Instant::now();
                for _ in 0..polls / WAITERS as u64 {
                    let mut waits: [Aborted; WAITERS] =
                        std::array::from_fn(|_| black_box(scope).aborted());
                    for wait in &mut waits {
                        assert!(Pin::new(wait).poll(&mut cx).is_pending());
                    }
                }
                start.elapsed()
            }
            "wake" => {
                let (scope, _keep) = scope.as_ref().expect("a scope shape");
                let mut cx = Context::from_waker(Waker::noop());
                let start = Instant::now();
                for _ in 0..polls / WAITERS as u64 {
                    let child = black_box(scope).child();
                    let mut waits: [Aborted; WAITERS] = std::array::from_fn(|_| child.aborted());
                    for wait in &mut waits {
                        assert!(Pin::new(wait).poll(&mut cx).is_pending());
                    }
                    child.abort(Cause::Owner);
                    for wait in &mut waits {
                        assert!(Pin::new(wait).poll(&mut cx).is_ready());
                    }
                }
                start.elapsed()
            }
            other => {
                let (scope, _keep) = scope.as_ref().expect("a scope shape");
                if let Some(stage) = other.strip_prefix("bound_timer") {
                    bound_rounds(polls, stage, || bound_timer(black_box(scope)))
                } else if let Some(stage) = other.strip_prefix("bound_child") {
                    bound_rounds(polls, stage, || bound_child(black_box(scope)))
                } else if let Some(stage) = other.strip_prefix("bound_within") {
                    bound_rounds(polls, stage, || bound_within(black_box(scope)))
                } else {
                    panic!("unknown mode {other}")
                }
            }
        }
    });
    #[expect(clippy::cast_precision_loss, reason = "a rate for reading")]
    let per_poll = elapsed.as_nanos() as f64 / polls.max(1) as f64;
    println!("{mode} {name} polls={polls} ns_per_poll={per_poll:.2}");
}
