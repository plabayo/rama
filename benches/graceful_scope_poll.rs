//! Cost of one poll of a task spawned on a scope, per scope shape.
//!
//! Not a divan bench: run it under `/usr/bin/time -l` with two poll counts and divide the
//! difference in instructions retired, as wall time is noisy on a shared machine.
//!
//! `graceful_scope_poll <mode> <shape> <polls>`; modes: `task` (a task that wakes itself and
//! returns pending `polls` times), `wait` (an `Aborted` future polled directly with one
//! waker), `observe` (`WeakScope::is_cancelled` called `polls` times).

#![expect(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    reason = "bench: panic-on-error and printing results is the standard pattern for harnesses"
)]

use rama::graceful::Scope;
use std::future::Future;
use std::hint::black_box;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

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
        other => panic!("unknown shape {other}"),
    })
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
                let start = Instant::now();
                for _ in 0..polls {
                    assert!(!black_box(&weak).is_cancelled());
                }
                start.elapsed()
            }
            other => panic!("unknown mode {other}"),
        }
    });
    #[expect(clippy::cast_precision_loss, reason = "a rate for reading")]
    let per_poll = elapsed.as_nanos() as f64 / polls.max(1) as f64;
    println!("{mode} {name} polls={polls} ns_per_poll={per_poll:.2}");
}
