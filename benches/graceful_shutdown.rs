#![expect(
    clippy::expect_used,
    reason = "bench: panic-on-error is the standard pattern for harnesses"
)]

use divan::counter::ItemsCount;
use rama::graceful::{Shutdown, ShutdownGuard, tree::Scope};
use std::assert_matches;
use std::future::Future;
use std::pin::Pin;
use std::sync::{
    Arc, Barrier,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::task::{Context, Poll, Waker};
use tokio::sync::oneshot;

mod bench_alloc;

const WAITER_COUNTS: &[usize] = &[1, 64, 1_024];
const THREAD_COUNTS: &[usize] = &[1, 4, 16];
const WAITERS_PER_THREAD: usize = 64;

fn main() {
    divan::main();
}

#[divan::bench(args = WAITER_COUNTS, sample_count = 100)]
fn first_waiter_registration(bencher: divan::Bencher, waiter_count: usize) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime build");
    let _runtime_guard = runtime.enter();
    let shutdown = Shutdown::new(std::future::pending::<()>());

    bencher
        .counter(ItemsCount::new(waiter_count))
        .with_inputs(|| make_waiter_futures(&shutdown, waiter_count))
        .bench_local_values(|mut futures| {
            let mut cx = Context::from_waker(Waker::noop());
            for future in &mut futures {
                assert_matches!(future.as_mut().poll(&mut cx), Poll::Pending);
            }
        });
}

#[divan::bench(args = THREAD_COUNTS, sample_count = 50)]
fn contended_coordination_control(bencher: divan::Bencher, thread_count: usize) {
    run_contended(bencher, thread_count, || || || {});
}

#[divan::bench(args = WAITER_COUNTS, sample_count = 100)]
fn cancellation_and_completion(bencher: divan::Bencher, waiter_count: usize) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime build");
    let _runtime_guard = runtime.enter();

    bencher
        .counter(ItemsCount::new(waiter_count))
        .with_inputs(|| {
            let (trigger, signal) = oneshot::channel();
            let shutdown = Shutdown::new(async move {
                _ = signal.await;
            });
            runtime.block_on(tokio::task::yield_now());

            let mut futures = make_waiter_futures(&shutdown, waiter_count);
            let mut cx = Context::from_waker(Waker::noop());
            for future in &mut futures {
                assert_matches!(future.as_mut().poll(&mut cx), Poll::Pending);
            }
            (trigger, futures)
        })
        .bench_local_values(|(trigger, futures)| {
            trigger.send(()).expect("shutdown signal receiver alive");
            runtime.block_on(async move {
                for future in futures {
                    future.await;
                }
            });
        });
}

#[divan::bench(args = WAITER_COUNTS, sample_count = 100)]
fn steady_state_registered_waiters(bencher: divan::Bencher, waiter_count: usize) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime build");
    let _runtime_guard = runtime.enter();
    let shutdown = Shutdown::new(std::future::pending::<()>());
    let mut futures = make_waiter_futures(&shutdown, waiter_count);
    let mut cx = Context::from_waker(Waker::noop());
    for future in &mut futures {
        assert_matches!(future.as_mut().poll(&mut cx), Poll::Pending);
    }

    bencher
        .counter(ItemsCount::new(waiter_count))
        .bench_local(|| {
            for future in &mut futures {
                assert_matches!(future.as_mut().poll(&mut cx), Poll::Pending);
            }
        });
}

#[divan::bench(args = THREAD_COUNTS, sample_count = 50)]
fn contended_steady_state_registered_waiters(bencher: divan::Bencher, thread_count: usize) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime build");
    let _runtime_guard = runtime.enter();
    let shutdown = Shutdown::new(std::future::pending::<()>());
    let guard = shutdown.guard();

    run_contended(bencher, thread_count, move || {
        let guards: Vec<_> = (0..WAITERS_PER_THREAD).map(|_| guard.clone()).collect();
        move || {
            let mut futures: Vec<Pin<Box<dyn Future<Output = ()>>>> = guards
                .into_iter()
                .map(|guard| Box::pin(async move { guard.cancelled().await }) as _)
                .collect();
            let mut cx = Context::from_waker(Waker::noop());
            move || {
                for future in &mut futures {
                    assert_matches!(future.as_mut().poll(&mut cx), Poll::Pending);
                }
            }
        }
    });
}

// Same scenarios on `graceful::tree`, measured in the same run.

#[divan::bench(args = WAITER_COUNTS, sample_count = 100)]
fn scope_first_waiter_registration(bencher: divan::Bencher, waiter_count: usize) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime build");
    let _runtime_guard = runtime.enter();
    let shutdown = Scope::new().with_signal(std::future::pending::<()>());

    bencher
        .counter(ItemsCount::new(waiter_count))
        .with_inputs(|| make_scope_waiter_futures(&shutdown, waiter_count))
        .bench_local_values(|mut futures| {
            let mut cx = Context::from_waker(Waker::noop());
            for future in &mut futures {
                assert_matches!(future.as_mut().poll(&mut cx), Poll::Pending);
            }
        });
}

#[divan::bench(args = WAITER_COUNTS, sample_count = 100)]
fn scope_cancellation_and_completion(bencher: divan::Bencher, waiter_count: usize) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime build");
    let _runtime_guard = runtime.enter();

    bencher
        .counter(ItemsCount::new(waiter_count))
        .with_inputs(|| {
            let (trigger, signal) = oneshot::channel();
            let shutdown = Scope::new().with_signal(async move {
                _ = signal.await;
            });
            let mut futures = make_scope_waiter_futures(&shutdown, waiter_count);
            let mut cx = Context::from_waker(Waker::noop());
            for future in &mut futures {
                assert_matches!(future.as_mut().poll(&mut cx), Poll::Pending);
            }
            (trigger, futures, shutdown)
        })
        .bench_local_values(|(trigger, futures, _shutdown)| {
            trigger.send(()).expect("shutdown signal receiver alive");
            runtime.block_on(async move {
                for future in futures {
                    future.await;
                }
            });
        });
}

#[divan::bench(args = WAITER_COUNTS, sample_count = 100)]
fn scope_steady_state_registered_waiters(bencher: divan::Bencher, waiter_count: usize) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime build");
    let _runtime_guard = runtime.enter();
    let shutdown = Scope::new().with_signal(std::future::pending::<()>());
    let mut futures = make_scope_waiter_futures(&shutdown, waiter_count);
    let mut cx = Context::from_waker(Waker::noop());
    for future in &mut futures {
        assert_matches!(future.as_mut().poll(&mut cx), Poll::Pending);
    }

    bencher
        .counter(ItemsCount::new(waiter_count))
        .bench_local(|| {
            for future in &mut futures {
                assert_matches!(future.as_mut().poll(&mut cx), Poll::Pending);
            }
        });
}

#[divan::bench(args = THREAD_COUNTS, sample_count = 50)]
fn scope_contended_steady_state_registered_waiters(bencher: divan::Bencher, thread_count: usize) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime build");
    let _runtime_guard = runtime.enter();
    let scope = Scope::new().with_signal(std::future::pending::<()>());

    run_contended(bencher, thread_count, move || {
        let scopes: Vec<_> = (0..WAITERS_PER_THREAD).map(|_| scope.clone()).collect();
        move || {
            let mut futures: Vec<Pin<Box<dyn Future<Output = ()>>>> = scopes
                .into_iter()
                .map(|scope| Box::pin(async move { scope.cancelled().await }) as _)
                .collect();
            let mut cx = Context::from_waker(Waker::noop());
            move || {
                for future in &mut futures {
                    assert_matches!(future.as_mut().poll(&mut cx), Poll::Pending);
                }
            }
        }
    });
}

#[divan::bench(sample_count = 100)]
fn guard_clone_and_drop(bencher: divan::Bencher) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime build");
    let _runtime_guard = runtime.enter();
    let shutdown = Shutdown::new(std::future::pending::<()>());
    let guard = shutdown.guard();
    bencher.bench_local(|| drop(divan::black_box(guard.clone())));
}

#[divan::bench(sample_count = 100)]
fn scope_clone_and_drop(bencher: divan::Bencher) {
    let scope = Scope::new().with_signal(std::future::pending::<()>());
    bencher.bench_local(|| drop(divan::black_box(scope.clone())));
}

#[divan::bench(sample_count = 100)]
fn scope_child_clone_and_drop(bencher: divan::Bencher) {
    let connection = Scope::new()
        .with_signal(std::future::pending::<()>())
        .child();
    bencher.bench_local(|| drop(divan::black_box(connection.clone())));
}

#[divan::bench(sample_count = 100)]
fn scope_is_cancelled(bencher: divan::Bencher) {
    let connection = Scope::new()
        .with_signal(std::future::pending::<()>())
        .child();
    bencher.bench_local(|| divan::black_box(&connection).is_cancelled());
}

#[divan::bench(sample_count = 100)]
fn scope_child_create_and_drop(bencher: divan::Bencher) {
    let scope = Scope::new().with_signal(std::future::pending::<()>());
    bencher.bench_local(|| drop(divan::black_box(scope.child())));
}

const DEPTHS: &[usize] = &[0, 16, 64];

fn scope_at_depth(depth: usize) -> (Vec<Scope>, Scope) {
    let mut chain = vec![Scope::new().with_signal(std::future::pending::<()>())];
    for _ in 0..depth {
        let child = chain.last().expect("root").child();
        chain.push(child);
    }
    let leaf = chain.pop().expect("leaf");
    (chain, leaf)
}

#[divan::bench(args = DEPTHS, sample_count = 100)]
fn scope_clone_and_drop_at_depth(bencher: divan::Bencher, depth: usize) {
    let (_chain, leaf) = scope_at_depth(depth);
    bencher.bench_local(|| drop(divan::black_box(leaf.clone())));
}

#[divan::bench(args = DEPTHS, sample_count = 100)]
fn scope_is_cancelled_at_depth(bencher: divan::Bencher, depth: usize) {
    let (_chain, leaf) = scope_at_depth(depth);
    bencher.bench_local(|| divan::black_box(&leaf).is_cancelled());
}

#[divan::bench(args = DEPTHS, sample_count = 100)]
fn scope_first_waiter_registration_at_depth(bencher: divan::Bencher, depth: usize) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime build");
    let _runtime_guard = runtime.enter();
    let (_chain, leaf) = scope_at_depth(depth);

    bencher
        .counter(ItemsCount::new(64_usize))
        .with_inputs(|| make_scope_waiter_futures(&leaf, 64))
        .bench_local_values(|mut futures| {
            let mut cx = Context::from_waker(Waker::noop());
            for future in &mut futures {
                assert_matches!(future.as_mut().poll(&mut cx), Poll::Pending);
            }
        });
}

/// A server scope handing every connection a child that the connection clones a few times.
#[divan::bench(args = THREAD_COUNTS, sample_count = 50)]
fn scope_contended_connection_lifecycle(bencher: divan::Bencher, thread_count: usize) {
    let server = Scope::new()
        .with_signal(std::future::pending::<()>())
        .child();
    run_contended(bencher, thread_count, move || {
        let server = server.clone();
        move || {
            move || {
                for _ in 0..WAITERS_PER_THREAD {
                    let connection = server.child();
                    let request = connection.clone();
                    drop(divan::black_box(request));
                    drop(connection);
                }
            }
        }
    });
}

#[divan::bench(sample_count = 100)]
fn scope_run_until_cancelled_ready(bencher: divan::Bencher) {
    let scope = Scope::new()
        .with_signal(std::future::pending::<()>())
        .child();
    let mut cx = Context::from_waker(Waker::noop());
    bencher.bench_local(|| {
        let mut future = std::pin::pin!(scope.run_until_cancelled(std::future::ready(1)));
        assert_matches!(future.as_mut().poll(&mut cx), Poll::Ready(Some(1)));
    });
}

fn make_scope_waiter_futures(shutdown: &Scope, waiter_count: usize) -> Vec<WaiterFuture> {
    (0..waiter_count)
        .map(|_| {
            let scope: Scope = shutdown.clone();
            Box::pin(async move { scope.cancelled().await }) as WaiterFuture
        })
        .collect()
}

type WaiterFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

fn make_waiter_futures(shutdown: &Shutdown, waiter_count: usize) -> Vec<WaiterFuture> {
    (0..waiter_count)
        .map(|_| {
            let guard: ShutdownGuard = shutdown.guard();
            Box::pin(async move { guard.cancelled().await }) as WaiterFuture
        })
        .collect()
}

fn run_contended<WorkerFactory, Worker, Poll>(
    bencher: divan::Bencher,
    thread_count: usize,
    mut worker_factory: WorkerFactory,
) where
    WorkerFactory: FnMut() -> Worker,
    Worker: FnOnce() -> Poll + Send,
    Poll: FnMut(),
{
    let barrier = Arc::new(Barrier::new(thread_count + 1));
    let stop = Arc::new(AtomicBool::new(false));
    let (done_tx, done_rx) = mpsc::sync_channel(thread_count);

    std::thread::scope(|scope| {
        for _ in 0..thread_count {
            let barrier = Arc::clone(&barrier);
            let stop = Arc::clone(&stop);
            let done_tx = done_tx.clone();
            let worker = worker_factory();
            scope.spawn(move || {
                let mut poll = worker();
                loop {
                    barrier.wait();
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    poll();
                    done_tx.send(()).expect("benchmark coordinator alive");
                }
            });
        }

        bencher
            .counter(ItemsCount::new(thread_count * WAITERS_PER_THREAD))
            .bench_local(|| {
                barrier.wait();
                for _ in 0..thread_count {
                    done_rx.recv().expect("benchmark worker alive");
                }
            });

        stop.store(true, Ordering::Relaxed);
        barrier.wait();
    });
}
