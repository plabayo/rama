use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use parking_lot::{Condvar, Mutex};
use rama_js::{JsErrorKind, JsRuntime, JsValue, JsWorker};

const TEST_WATCHDOG: Duration = Duration::from_secs(30);

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    let mut cx = Context::from_waker(Waker::noop());
    future.poll(&mut cx)
}

fn poll_pending<F: Future>(future: Pin<&mut F>) {
    assert!(matches!(poll_once(future), Poll::Pending));
}

#[expect(clippy::expect_used, reason = "test watchdog")]
async fn wait_until_available(worker: &JsWorker) {
    tokio::time::timeout(TEST_WATCHDOG, async {
        while worker.is_abandoned() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("worker did not finish its abandoned job");
}

#[derive(Debug, Default)]
struct GateState {
    entered: bool,
    released: bool,
}

#[derive(Debug, Clone, Default)]
struct WorkerGate(Arc<(Mutex<GateState>, Condvar)>);

impl WorkerGate {
    fn block(&self) {
        let (state, changed) = &*self.0;
        let mut state = state.lock();
        state.entered = true;
        changed.notify_all();
        while !state.released {
            changed.wait(&mut state);
        }
    }

    fn wait_until_entered(&self) {
        let deadline = Instant::now() + TEST_WATCHDOG;
        let (state, changed) = &*self.0;
        let mut state = state.lock();
        while !state.entered {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero(), "worker job did not start");
            let timed_out = changed.wait_for(&mut state, remaining);
            assert!(!timed_out.timed_out(), "worker job did not start");
        }
    }

    fn release(&self) {
        let (state, changed) = &*self.0;
        state.lock().released = true;
        changed.notify_all();
    }
}

#[tokio::test]
async fn worker_state_persists_across_calls() {
    let worker = JsWorker::spawn(JsRuntime::builder()).unwrap();
    worker
        .exec("let n = 0; function bump() { return ++n; }")
        .await
        .unwrap();

    let no_args = Vec::<JsValue>::new;
    assert_eq!(
        worker.call("bump", no_args()).await.unwrap(),
        JsValue::Number(1.0)
    );
    assert_eq!(
        worker.call("bump", no_args()).await.unwrap(),
        JsValue::Number(2.0)
    );

    let clone = worker.clone();
    assert_eq!(
        clone.call("bump", no_args()).await.unwrap(),
        JsValue::Number(3.0)
    );
}

#[tokio::test]
async fn worker_call_with_arguments() {
    let worker = JsWorker::spawn(JsRuntime::builder().with_fn("double", |n: f64| n * 2.0)).unwrap();
    worker
        .exec("function compute(a, b) { return double(a) + b; }")
        .await
        .unwrap();

    let value = worker.call("compute", [20.0, 2.0]).await.unwrap();
    assert_eq!(value, JsValue::Number(42.0));
}

#[tokio::test]
async fn worker_errors_do_not_poison_the_runtime() {
    let worker = JsWorker::spawn(JsRuntime::builder()).unwrap();
    worker.exec("let calls = 0").await.unwrap();

    let err = worker.eval("calls++; throw 'boom'").await.unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::Throw);

    let err = worker.eval("calls++; syntax error {").await.unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::Parse);

    // thrown and parse errors leave the runtime usable, with state intact
    assert_eq!(worker.eval("calls").await.unwrap(), JsValue::Number(1.0));
}

#[tokio::test]
async fn worker_survives_abandoned_callers() {
    let gate = WorkerGate::default();
    let worker = JsWorker::spawn(JsRuntime::builder().with_fn("block", {
        let gate = gate.clone();
        move || gate.block()
    }))
    .unwrap();

    let mut abandoned = Box::pin(worker.eval("block(); 1"));
    poll_pending(abandoned.as_mut());
    gate.wait_until_entered();
    drop(abandoned);
    gate.release();

    // the abandoned job still ran to completion; the worker keeps serving
    assert_eq!(worker.eval("2").await.unwrap(), JsValue::Number(2.0));
}

#[tokio::test]
async fn worker_builder_timeout_fails_slow_jobs() {
    let gate = WorkerGate::default();
    let worker = JsWorker::builder()
        .with_timeout(Duration::from_millis(20))
        .spawn(JsRuntime::builder().with_fn("block", {
            let gate = gate.clone();
            move || gate.block()
        }))
        .unwrap();

    let mut slow = Box::pin(worker.eval("block(); 1"));
    poll_pending(slow.as_mut());
    gate.wait_until_entered();
    tokio::time::sleep(Duration::from_millis(20)).await;

    let err = slow.await.unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::Timeout);
    assert!(worker.is_abandoned());
    gate.release();

    // once the abandoned job drained, fast jobs keep working
    wait_until_available(&worker).await;
    assert_eq!(worker.eval("2").await.unwrap(), JsValue::Number(2.0));
}

#[tokio::test]
async fn a_timed_out_queued_job_never_runs_later() {
    let gate = WorkerGate::default();
    let ran_queued = Arc::new(AtomicUsize::new(0));
    let worker = JsWorker::builder()
        .with_queue_capacity(1)
        .with_timeout(Duration::from_millis(40))
        .spawn(JsRuntime::builder().with_fn("block", {
            let gate = gate.clone();
            move || gate.block()
        }))
        .unwrap();

    let mut blocking = Box::pin(worker.eval("block()"));
    poll_pending(blocking.as_mut());
    gate.wait_until_entered();

    let mut queued = Box::pin({
        let ran_queued = ran_queued.clone();
        worker.run(move |_runtime| {
            ran_queued.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
    });
    poll_pending(queued.as_mut());
    tokio::time::sleep(Duration::from_millis(40)).await;

    let queued_error = queued.await.unwrap_err();
    assert_eq!(queued_error.kind(), JsErrorKind::Timeout);
    assert!(
        queued_error
            .message()
            .contains("before it began and was cancelled"),
        "{}",
        queued_error.message()
    );
    assert_eq!(blocking.await.unwrap_err().kind(), JsErrorKind::Timeout);
    assert!(worker.is_abandoned());
    gate.release();

    wait_until_available(&worker).await;
    assert_eq!(ran_queued.load(Ordering::Relaxed), 0);
    assert_eq!(worker.eval("42").await.unwrap(), JsValue::Number(42.0));
}

#[tokio::test]
async fn worker_builder_custom_queue_capacity() {
    let worker = JsWorker::builder()
        .with_queue_capacity(1)
        .spawn(JsRuntime::builder())
        .unwrap();
    worker.exec("let total = 0").await.unwrap();

    let tasks: Vec<_> = (0..4)
        .map(|_| {
            let worker = worker.clone();
            tokio::spawn(async move { worker.exec("total += 1").await })
        })
        .collect();
    for task in tasks {
        task.await.unwrap().unwrap();
    }

    assert_eq!(worker.eval("total").await.unwrap(), JsValue::Number(4.0));
}

#[tokio::test]
async fn worker_compiles_script_once_and_calls_many_times() {
    let worker = JsWorker::spawn(JsRuntime::builder()).unwrap();
    worker
        .exec(
            r#"
            let topLevelRuns = (globalThis.topLevelRuns ?? 0) + 1;
            const cache = {};
            function resolve(host) {
                if (host in cache) return cache[host] + " (cached)";
                cache[host] = host.endsWith(".internal") ? "DIRECT" : "PROXY p:8080";
                return cache[host];
            }
            "#,
        )
        .await
        .unwrap();

    let probe = worker
        .run(|runtime| Ok(runtime.has_global_fn("resolve")))
        .await
        .unwrap();
    assert!(probe);

    for (host, expected) in [
        ("db.internal", "DIRECT"),
        ("example.com", "PROXY p:8080"),
        ("db.internal", "DIRECT (cached)"),
        ("example.com", "PROXY p:8080 (cached)"),
    ] {
        let value = worker.call("resolve", [host]).await.unwrap();
        assert_eq!(value.as_str(), Some(expected), "{host}");
    }

    // script-side cache filling up proves calls never re-ran the top level
    assert_eq!(
        worker.eval("topLevelRuns").await.unwrap(),
        JsValue::Number(1.0)
    );
}

#[tokio::test]
async fn replacement_worker_does_not_inherit_globals() {
    let blueprint = JsRuntime::builder();

    let worker = JsWorker::spawn(blueprint.clone()).unwrap();
    worker
        .exec("globalThis.stale = 'old script'")
        .await
        .unwrap();

    let replacement = JsWorker::spawn(blueprint).unwrap();
    assert_eq!(
        replacement.eval("typeof stale").await.unwrap().as_str(),
        Some("undefined")
    );
}

#[tokio::test]
async fn panicking_host_fn_kills_the_worker_loudly() {
    let worker =
        JsWorker::spawn(JsRuntime::builder().with_fn("boom", || -> bool { panic!("kaboom") }))
            .unwrap();

    let err = worker.eval("boom()").await.unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::Setup);

    // the worker is gone for good: later calls fail fast instead of hanging
    let err = worker.eval("1").await.unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::Setup);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worker_exits_on_graceful_shutdown() {
    use rama_core::graceful::Shutdown;

    let (trigger, signal) = tokio::sync::oneshot::channel::<()>();
    let shutdown = Shutdown::new(async {
        let _triggered = signal.await;
    });

    let gate = WorkerGate::default();
    let worker = JsWorker::builder()
        .with_graceful(shutdown.guard())
        .spawn(JsRuntime::builder().with_fn("block", {
            let gate = gate.clone();
            move || gate.block()
        }))
        .unwrap();
    worker.exec("let x = 41").await.unwrap();

    // a job accepted before the shutdown trigger still completes
    let mut pending = Box::pin(worker.eval("block(); x + 1"));
    poll_pending(pending.as_mut());
    gate.wait_until_entered();
    trigger.send(()).unwrap();
    gate.release();
    shutdown.shutdown().await;

    assert_eq!(pending.await.unwrap(), JsValue::Number(42.0));
    let err = worker.eval("1").await.unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::Setup);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn poisoned_runtime_kills_the_worker_loudly() {
    let worker = JsWorker::spawn(
        JsRuntime::builder()
            .without_loop_iteration_limit()
            .with_execution_time_limit(Duration::from_millis(50)),
    )
    .unwrap();

    let err = worker.eval("while (true) {}").await.unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::LimitExceeded);

    // the poisoned worker is gone for good: later calls fail fast
    let err = worker.eval("1").await.unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::Setup);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn graceful_shutdown_is_bounded_under_sustained_backlog() {
    use rama_core::graceful::Shutdown;

    let (trigger, signal) = tokio::sync::oneshot::channel::<()>();
    let shutdown = Shutdown::new(async {
        let _triggered = signal.await;
    });

    let gate = WorkerGate::default();
    let worker = JsWorker::builder()
        .with_queue_capacity(1)
        .with_graceful(shutdown.guard())
        .spawn(JsRuntime::builder().with_fn("block", {
            let gate = gate.clone();
            move || gate.block()
        }))
        .unwrap();

    let mut jobs: Vec<_> = (0..4)
        .map(|_| Box::pin(worker.eval("block(); 1")))
        .collect();
    poll_pending(jobs[0].as_mut());
    gate.wait_until_entered();

    // One job is running, one fits in the queue, and the remaining senders
    // wait on the full queue. Polling them here establishes the backlog
    // without assuming the executor scheduled spawned producers in time.
    for job in &mut jobs[1..] {
        poll_pending(job.as_mut());
    }
    trigger.send(()).unwrap();
    gate.release();

    // only jobs accepted by the cutoff may still run: the backlog
    // must not extend the shutdown beyond the queue capacity
    tokio::time::timeout(TEST_WATCHDOG, shutdown.shutdown())
        .await
        .expect("graceful shutdown extended by jobs sent after the cutoff");

    for job in jobs {
        let _result = job.await;
    }
}

#[tokio::test]
async fn graceful_worker_requires_tokio_runtime() {
    use rama_core::graceful::Shutdown;

    let shutdown = Shutdown::new(async {});
    let guard = shutdown.guard();
    let err = std::thread::spawn(move || {
        JsWorker::builder()
            .with_graceful(guard)
            .spawn(JsRuntime::builder())
            .unwrap_err()
    })
    .join()
    .unwrap();
    assert_eq!(err.kind(), JsErrorKind::Setup);
    assert!(err.message().contains("tokio runtime"), "{}", err.message());
}

#[tokio::test]
async fn thread_guard_is_dropped_when_the_worker_exits() {
    struct NotifyOnDrop(std::sync::Arc<tokio::sync::Notify>);

    impl Drop for NotifyOnDrop {
        fn drop(&mut self) {
            self.0.notify_one();
        }
    }

    let dropped = std::sync::Arc::new(tokio::sync::Notify::new());
    let guard: std::sync::Arc<dyn Send + Sync> = std::sync::Arc::new(NotifyOnDrop(dropped.clone()));
    let worker = JsWorker::builder()
        .with_thread_guard(guard)
        .spawn(JsRuntime::builder())
        .expect("spawn worker");

    drop(worker);
    tokio::time::timeout(TEST_WATCHDOG, dropped.notified())
        .await
        .expect("thread guard outlived the worker");
}

#[tokio::test]
async fn worker_calls_serialize_across_handles() {
    let worker = JsWorker::spawn(JsRuntime::builder()).unwrap();
    worker.exec("let total = 0").await.unwrap();

    let tasks: Vec<_> = (0..8)
        .map(|_| {
            let worker = worker.clone();
            tokio::spawn(async move { worker.exec("total += 1").await })
        })
        .collect();
    for task in tasks {
        task.await.unwrap().unwrap();
    }

    assert_eq!(worker.eval("total").await.unwrap(), JsValue::Number(8.0));
}

#[tokio::test]
async fn a_wedged_worker_refuses_later_jobs_instead_of_queueing() {
    let gate = WorkerGate::default();
    let worker = JsWorker::builder()
        .with_timeout(Duration::from_millis(20))
        .spawn(JsRuntime::builder().with_fn("wedge", {
            let gate = gate.clone();
            move || gate.block()
        }))
        .unwrap();

    let mut wedged = Box::pin(worker.eval("wedge(); 1"));
    poll_pending(wedged.as_mut());
    gate.wait_until_entered();
    tokio::time::sleep(Duration::from_millis(20)).await;

    let err = wedged.await.unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::Timeout);
    assert!(worker.is_abandoned());

    // later callers must not queue behind a job that may never return
    let mut later = Box::pin(worker.eval("2"));
    let err = match poll_once(later.as_mut()) {
        Poll::Ready(Err(err)) => err,
        Poll::Ready(Ok(value)) => panic!("abandoned worker returned {value:?}"),
        Poll::Pending => panic!("later job queued behind the wedged job"),
    };
    assert_eq!(err.kind(), JsErrorKind::Setup, "{}", err.message());
    gate.release();
}
