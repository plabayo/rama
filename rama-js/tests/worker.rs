use std::time::Duration;

use rama_js::{JsErrorKind, JsRuntime, JsValue, JsWorker};

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worker_survives_abandoned_callers() {
    let worker = JsWorker::spawn(JsRuntime::builder().with_fn("nap", || {
        std::thread::sleep(Duration::from_millis(200));
    }))
    .unwrap();

    let timed_out = tokio::time::timeout(Duration::from_millis(20), worker.eval("nap(); 1"))
        .await
        .is_err();
    assert!(timed_out);

    // the abandoned job still ran to completion; the worker keeps serving
    assert_eq!(worker.eval("2").await.unwrap(), JsValue::Number(2.0));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worker_builder_timeout_fails_slow_jobs() {
    let worker = JsWorker::builder()
        .with_timeout(Duration::from_millis(20))
        .spawn(JsRuntime::builder().with_fn("nap", || {
            std::thread::sleep(Duration::from_millis(200));
        }))
        .unwrap();

    let err = worker.eval("nap(); 1").await.unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::Timeout);

    // once the abandoned job drained, fast jobs keep working
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(worker.eval("2").await.unwrap(), JsValue::Number(2.0));
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

    let worker = JsWorker::builder()
        .with_graceful(shutdown.guard())
        .spawn(JsRuntime::builder().with_fn("nap", || {
            std::thread::sleep(Duration::from_millis(50));
        }))
        .unwrap();
    worker.exec("let x = 41").await.unwrap();

    // a job accepted before the shutdown trigger still completes
    let pending = {
        let worker = worker.clone();
        tokio::spawn(async move { worker.eval("nap(); x + 1").await })
    };
    tokio::time::sleep(Duration::from_millis(10)).await;
    trigger.send(()).unwrap();
    shutdown.shutdown().await;

    assert_eq!(pending.await.unwrap().unwrap(), JsValue::Number(42.0));
    let err = worker.eval("1").await.unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::Setup);
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
