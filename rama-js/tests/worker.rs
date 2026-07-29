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
