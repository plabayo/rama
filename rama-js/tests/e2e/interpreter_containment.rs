fn runtime_builder() -> rama_js::JsRuntimeBuilder {
    rama_js::JsRuntime::builder().with_backend(rama_js::JsBackend::Interpreter)
}

#[path = "../suites/containment.rs"]
mod suite;
