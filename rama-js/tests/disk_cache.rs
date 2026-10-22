#![cfg(feature = "disk-cache")]
fn runtime_builder() -> rama_js::JsRuntimeBuilder {
    rama_js::JsRuntime::builder()
}

#[path = "suites/disk_cache.rs"]
mod suite;
