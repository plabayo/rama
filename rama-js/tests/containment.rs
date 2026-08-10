use rama_js::{JsErrorKind, JsRuntime};

#[test]
fn parser_recursion_is_contained_by_wasm() {
    let sources = [
        format!("{}true{}", "(".repeat(100_000), ")".repeat(100_000)),
        format!("{}1", "1 + ".repeat(100_000)),
        format!("{}true", "!".repeat(100_000)),
        format!("let a = {{}}; {}a", "a.".repeat(100_000)),
    ];

    for source in sources {
        let mut runtime = JsRuntime::builder().build().unwrap();
        let _result = runtime.exec(source);
    }

    assert_eq!(JsRuntime::eval_once("40 + 2").unwrap().as_f64(), Some(42.0));
}

#[test]
fn wasm_memory_limit_contains_excessive_allocation() {
    let mut runtime = JsRuntime::builder().build().unwrap();
    let error = runtime
        .exec("new Uint8Array(256 * 1024 * 1024).fill(1)")
        .unwrap_err();
    assert_eq!(error.kind(), JsErrorKind::LimitExceeded, "{error}");
    assert!(runtime.is_poisoned());
}
