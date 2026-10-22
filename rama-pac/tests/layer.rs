#![cfg(feature = "http")]
fn runtime_builder() -> rama_js::JsRuntimeBuilder {
    rama_js::JsRuntime::builder()
}

fn resolver_builder() -> rama_pac::PacResolverBuilder {
    rama_pac::PacResolver::builder().with_runtime(runtime_builder().without_loop_iteration_limit())
}

#[path = "suites/layer.rs"]
mod suite;
