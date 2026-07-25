use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rama_core::Service;
use rama_js::{JsEngine, JsError, JsErrorKind, JsHostObject, JsRuntime, JsValue};

#[tokio::test]
async fn engine_eval_and_run() {
    let engine = JsEngine::new(JsRuntime::builder().with_fn("triple", |n: f64| n * 3.0));

    assert_eq!(
        engine.eval("triple(3)").await.unwrap(),
        JsValue::Number(9.0)
    );

    let result = engine
        .run(|runtime| {
            runtime.eval("function add(a, b) { return a + b; }")?;
            runtime.call("add", [20, 22])
        })
        .await
        .unwrap();
    assert_eq!(result, JsValue::Number(42.0));
}

#[tokio::test]
async fn engine_blocking_and_discarding_entrypoints_execute() {
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let engine = JsEngine::new(JsRuntime::builder().with_fn("hit", move || {
        counter.fetch_add(1, Ordering::SeqCst);
    }));

    engine.exec("hit()").await.unwrap();
    engine.exec_blocking("hit()").unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    assert_eq!(
        engine.eval_blocking("6 * 7").unwrap(),
        JsValue::Number(42.0)
    );
}

#[tokio::test]
async fn engine_runs_are_isolated() {
    let engine = JsEngine::new(JsRuntime::builder());

    // each run gets a fresh runtime: state cannot leak between runs
    for _ in 0..4 {
        let count = engine
            .eval("globalThis.counter = (globalThis.counter || 0) + 1; counter")
            .await
            .unwrap();
        assert_eq!(count, JsValue::Number(1.0));
    }
}

#[tokio::test]
async fn engine_host_state_is_shared_by_design() {
    // host functions belong to the blueprint: unlike script state,
    // state captured by them is intentionally shared across runs
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let engine = JsEngine::new(
        JsRuntime::builder().with_fn("hit", move || counter.fetch_add(1, Ordering::SeqCst) as u32),
    );

    for _ in 0..3 {
        engine.eval("hit()").await.unwrap();
    }
    assert_eq!(hits.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn engine_script_errors_propagate() {
    let engine = JsEngine::new(JsRuntime::builder());

    let err = engine.eval("function {").await.unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::Parse);

    let err = engine
        .run(|runtime| runtime.call("missing", [] as [JsValue; 0]))
        .await
        .unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::NotFound);
}

#[tokio::test]
async fn engine_run_accepts_execution_local_host_objects() {
    let engine = JsEngine::new(JsRuntime::builder());
    let request = ("GET".to_owned(), Vec::<(String, String)>::new());

    let request = engine
        .run(move |runtime| {
            let (object, handle) = JsHostObject::builder(request)
                .getter("method", |request: &(String, Vec<(String, String)>)| {
                    request.0.clone()
                })
                .method_mut(
                    "setHeader",
                    |request: &mut (String, Vec<(String, String)>), name: String, value: String| {
                        request.1.push((name, value))
                    },
                )
                .build();
            runtime.set_host_global("request", object)?;
            runtime.eval("request.setHeader('x-rama', request.method)")?;
            handle.take()
        })
        .await
        .unwrap();

    assert_eq!(
        request,
        (
            "GET".to_owned(),
            vec![("x-rama".to_owned(), "GET".to_owned())]
        )
    );
}

/// A service which owns one engine (created once) and evaluates
/// a script on a fresh runtime per `serve` call.
struct ScriptedTagger {
    engine: JsEngine,
    script: Arc<str>,
}

impl ScriptedTagger {
    fn new(script: impl Into<Arc<str>>) -> Self {
        Self {
            engine: JsEngine::new(
                JsRuntime::builder().with_fn("normalize", |s: rama_js::JsStr| s.to_lowercase()),
            ),
            script: script.into(),
        }
    }
}

impl Service<String> for ScriptedTagger {
    type Output = String;
    type Error = JsError;

    async fn serve(&self, input: String) -> Result<Self::Output, Self::Error> {
        let script = self.script.clone();
        let verdict = self
            .engine
            .run(move |runtime| {
                runtime.eval(&*script)?;
                runtime.call("tag", [input])
            })
            .await?;
        String::try_from(verdict)
    }
}

const TAGGER_SCRIPT: &str = include_str!("engine_tagger_script.js");

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn service_with_per_serve_runtime_has_no_side_effects() {
    let service = Arc::new(ScriptedTagger::new(TAGGER_SCRIPT));

    // sequential serves: the script-global counter never carries over
    for _ in 0..3 {
        let tagged = service.serve("Rama".to_owned()).await.unwrap();
        assert_eq!(tagged, "rama#1");
    }

    // concurrent serves: still fully isolated
    let mut handles = Vec::new();
    for i in 0..32 {
        let service = service.clone();
        handles.push(tokio::spawn(async move {
            service.serve(format!("User-{i}")).await.unwrap()
        }));
    }
    for (i, handle) in handles.into_iter().enumerate() {
        assert_eq!(handle.await.unwrap(), format!("user-{i}#1"));
    }
}
