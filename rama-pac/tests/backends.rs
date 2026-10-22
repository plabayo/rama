#![cfg(feature = "js-interpreter")]

#[path = "support/representative.rs"]
mod representative;

#[tokio::test]
async fn explicit_interpreter_resolves_representative_pac() {
    let (mut runtime, budget) = rama_pac::PacEnv::default()
        .register(rama_js::JsRuntime::builder())
        .unwrap()
        .with_backend(rama_js::JsBackend::Interpreter)
        .build()
        .unwrap();
    budget.arm();
    assert_eq!(
        runtime
            .eval("dnsDomainIs('www.example.com', '.example.com')")
            .unwrap()
            .as_bool(),
        Some(true)
    );

    let resolver = rama_pac::PacResolver::builder()
        .with_backend(rama_js::JsBackend::Interpreter)
        .build_static(representative::SCRIPT)
        .unwrap();
    for (url, expected) in representative::CASES {
        assert_eq!(
            resolver
                .find_proxy(&url.parse().unwrap())
                .await
                .unwrap()
                .to_string(),
            expected
        );
    }
}
