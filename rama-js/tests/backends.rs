#![cfg(all(feature = "interpreter", not(target_os = "ios")))]

#[cfg(feature = "disk-cache")]
use rama_js::JsErrorKind;
use rama_js::{JsBackend, JsRuntime, JsWorker};

#[tokio::test]
async fn native_and_interpreter_coexist_with_independent_caches() {
    assert_eq!(JsBackend::default(), JsBackend::Native);
    let native = JsRuntime::builder();
    let interpreter = JsRuntime::builder().with_backend(JsBackend::Interpreter);
    #[cfg(feature = "disk-cache")]
    let cache = rama_utils::fs::tempdir().unwrap();
    #[cfg(feature = "disk-cache")]
    {
        native
            .warm_up_with_disk_cache(cache.path(), "native")
            .unwrap();
        interpreter
            .warm_up_with_disk_cache(cache.path(), "interpreter")
            .unwrap();
        native
            .warm_up_with_disk_cache(cache.path(), "native")
            .unwrap();
        interpreter
            .warm_up_with_disk_cache(cache.path(), "interpreter")
            .unwrap();
        assert_eq!(
            native
                .warm_up_with_disk_cache(cache.path(), "interpreter")
                .unwrap_err()
                .kind(),
            JsErrorKind::Setup
        );
        assert_eq!(
            interpreter
                .warm_up_with_disk_cache(cache.path(), "native")
                .unwrap_err()
                .kind(),
            JsErrorKind::Setup
        );
    }
    let mut native_runtime = native.build().unwrap();
    let mut interpreted_runtime = interpreter.clone().build().unwrap();
    native_runtime.exec("globalThis.answer = 41").unwrap();
    interpreted_runtime.exec("globalThis.answer = 42").unwrap();
    assert_eq!(native_runtime.eval("answer").unwrap().as_f64(), Some(41.0));
    assert_eq!(
        interpreted_runtime.eval("answer").unwrap().as_f64(),
        Some(42.0)
    );
    let worker = JsWorker::spawn(interpreter).unwrap();
    assert_eq!(worker.eval("6 * 7").await.unwrap().as_f64(), Some(42.0));
}
