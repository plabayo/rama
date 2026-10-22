#[cfg(test)]
pub(crate) fn builder() -> rama_js::JsRuntimeBuilder {
    let builder = rama_js::JsRuntime::builder();
    match std::env::var("RAMA_TEST_JS_INTERPRETER").as_deref() {
        Err(std::env::VarError::NotPresent) => builder,
        Ok("1") => {
            #[cfg(any(target_os = "ios", feature = "js-interpreter"))]
            {
                builder.with_backend(rama_js::JsBackend::Interpreter)
            }
            #[cfg(not(any(target_os = "ios", feature = "js-interpreter")))]
            {
                panic!("interpreter test run requires the interpreter feature")
            }
        }
        value => panic!("invalid interpreter test selection: {value:?}"),
    }
}
