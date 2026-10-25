fn runtime_builder() -> rama_js::JsRuntimeBuilder {
    rama_js::JsRuntime::builder()
}

#[path = "suites/worker.rs"]
mod suite;
