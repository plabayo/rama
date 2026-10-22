fn runtime_builder() -> rama_js::JsRuntimeBuilder {
    rama_js::JsRuntime::builder().with_backend(rama_js::JsBackend::Interpreter)
}

#[path = "../suites/runtime.rs"]
mod suite;
