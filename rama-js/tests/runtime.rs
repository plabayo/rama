use std::net::IpAddr;

use rama_js::{
    Console, IntoJsGlobal, JsArgs, JsArray, JsError, JsErrorKind, JsHostClass, JsHostObject,
    JsNamespace, JsObject, JsRuntime, JsRuntimeBuilder, JsSnapshotLimits, JsStr, JsValue,
};
use rama_net::address::Domain;
use rama_utils::octets::{kib, mib};

#[test]
fn eval_value_matrix() {
    let mut runtime = JsRuntime::builder().build().unwrap();

    assert_eq!(runtime.eval("undefined").unwrap(), JsValue::Undefined);
    assert_eq!(runtime.eval("null").unwrap(), JsValue::Null);
    assert_eq!(runtime.eval("true").unwrap(), JsValue::Bool(true));
    assert_eq!(runtime.eval("1 + 2").unwrap(), JsValue::Number(3.0));
    assert_eq!(runtime.eval("0.5 * 3").unwrap(), JsValue::Number(1.5));
    assert_eq!(runtime.eval(r#""a" + "b""#).unwrap().as_str(), Some("ab"));

    let array = runtime.eval(r#"[1, "two", false, null]"#).unwrap();
    let array = array.as_array().unwrap();
    assert_eq!(array.len(), 4);
    assert_eq!(array.get(0), Some(&JsValue::Number(1.0)));
    assert_eq!(array.get(1).and_then(|v| v.as_str()), Some("two"));
    assert_eq!(array.get(2), Some(&JsValue::Bool(false)));
    assert_eq!(array.get(3), Some(&JsValue::Null));

    let object = runtime
        .eval(r#"({ a: 1, b: "two", c: { nested: [true] } })"#)
        .unwrap();
    let object = object.as_object().unwrap();
    assert_eq!(object.len(), 3);
    assert_eq!(object.get("a"), Some(&JsValue::Number(1.0)));
    assert_eq!(object.get("b").and_then(|v| v.as_str()), Some("two"));
    let nested = object.get("c").and_then(|v| v.as_object()).unwrap();
    let nested = nested.get("nested").and_then(|v| v.as_array()).unwrap();
    assert_eq!(nested.get(0), Some(&JsValue::Bool(true)));
}

#[test]
fn eval_once_uses_a_fresh_default_runtime() {
    assert_eq!(
        JsRuntime::eval_once("globalThis.counter = 42").unwrap(),
        JsValue::Number(42.0),
    );
    assert_eq!(
        JsRuntime::eval_once("typeof counter").unwrap().as_str(),
        Some("undefined"),
    );
}

#[test]
fn opaque_runtime_and_host_debug_output_identifies_types() {
    let global = 42.into_global_entry();
    assert!(format!("{global:?}").starts_with("JsGlobal"));

    let builder = JsRuntime::builder().with_strict(true);
    assert!(format!("{builder:?}").starts_with("JsRuntimeBuilder"));
    let worker = rama_js::JsWorker::spawn(builder.clone()).unwrap();
    assert!(format!("{worker:?}").starts_with("JsWorker"));
    let runtime = builder.build().unwrap();
    assert_eq!(format!("{runtime:?}"), "JsRuntime { .. }");

    let class_builder =
        JsHostClass::<u8>::builder().getter("value", |value: &u8| u32::from(*value));
    assert!(format!("{class_builder:?}").starts_with("JsHostClassBuilder"));
    let class = class_builder.build();
    assert!(format!("{class:?}").starts_with("JsHostClass"));
    let (object, handle) = class.bind(42);
    assert!(format!("{object:?}").starts_with("JsHostObject"));
    assert_eq!(format!("{handle:?}"), "JsHostHandle { .. }");

    let object_builder =
        JsHostObject::builder(42_u8).getter("value", |value: &u8| u32::from(*value));
    assert!(format!("{object_builder:?}").starts_with("JsHostObjectBuilder"));
}

#[test]
fn eval_state_persists_and_call() {
    let mut runtime = JsRuntime::builder().build().unwrap();
    runtime.eval("let counter = 0;").unwrap();
    runtime
        .eval("function next(by) { counter += by; return counter; }")
        .unwrap();

    assert!(runtime.has_global_fn("next"));
    assert!(!runtime.has_global_fn("previous"));

    assert_eq!(runtime.call("next", [2]).unwrap(), JsValue::Number(2.0));
    assert_eq!(runtime.call("next", [3]).unwrap(), JsValue::Number(5.0));
}

#[test]
fn global_script_lexical_bindings_persist_across_evaluations() {
    for strict in [false, true] {
        let mut runtime = JsRuntime::builder().with_strict(strict).build().unwrap();
        runtime
            .exec("let lexical = 40; const constant = 2; class Marker {}")
            .unwrap();

        assert_eq!(
            runtime.eval("lexical + constant").unwrap(),
            JsValue::Number(42.0),
            "strict={strict}",
        );
        assert_eq!(
            runtime.eval("typeof Marker").unwrap().as_str(),
            Some("function"),
            "strict={strict}",
        );
        let error = runtime.exec("let lexical = 1").unwrap_err();
        assert_eq!(error.kind(), JsErrorKind::Throw, "strict={strict}");
    }
}

#[test]
fn global_function_declaration_cannot_delete_itself_while_loading() {
    let mut runtime = JsRuntime::builder().build().unwrap();
    runtime
        .exec(
            "function stable() { return 42 }\n\
             globalThis.deletedStable = delete globalThis.stable",
        )
        .unwrap();

    assert_eq!(runtime.eval("deletedStable").unwrap(), JsValue::Bool(false));
    assert!(runtime.has_global_fn("stable"));
    assert_eq!(
        runtime.call("stable", [] as [JsValue; 0]).unwrap(),
        JsValue::Number(42.0),
    );
}

#[test]
fn native_script_evaluator_is_not_exposed_to_loaded_code() {
    let mut runtime = JsRuntime::builder().build().unwrap();
    assert_eq!(
        runtime
            .eval(
                "typeof globalThis.__rama_evaluate_script__ === 'undefined'\
                 && typeof globalThis.__rama_take_parse_failure__ === 'undefined'",
            )
            .unwrap(),
        JsValue::Bool(true),
    );
}

#[test]
fn call_not_found() {
    let mut runtime = JsRuntime::builder().build().unwrap();
    let err = runtime.call("nope", [1]).unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::NotFound);

    runtime.eval("const notAFunction = 42;").unwrap();
    let err = runtime.call("notAFunction", [1]).unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::NotFound);
}

#[test]
fn parse_error() {
    let mut runtime = JsRuntime::builder().build().unwrap();
    let err = runtime.eval("function {").unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::Parse);
}

#[test]
fn runtime_syntax_errors_are_throws() {
    let mut runtime = JsRuntime::builder().build().unwrap();

    let err = runtime
        .eval(r#"throw new SyntaxError("runtime syntax error")"#)
        .unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::Throw);

    runtime
        .eval(r#"function failSyntax() { throw new SyntaxError("called syntax error"); }"#)
        .unwrap();
    let err = runtime.call("failSyntax", [] as [JsValue; 0]).unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::Throw);

    let parse_error = runtime.eval("function {").unwrap_err();
    assert_eq!(parse_error.kind(), JsErrorKind::Parse);
    let runtime_error = runtime
        .eval(r#"throw new SyntaxError("still a runtime error")"#)
        .unwrap_err();
    assert_eq!(runtime_error.kind(), JsErrorKind::Throw);
}

#[test]
fn throw_error_carries_value() {
    let mut runtime = JsRuntime::builder().build().unwrap();

    let err = runtime.eval(r#"throw "boom""#).unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::Throw);
    assert_eq!(err.thrown().and_then(|v| v.as_str()), Some("boom"));

    let err = runtime.eval(r#"throw new Error("kaput")"#).unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::Throw);
    assert!(err.message().contains("kaput"), "{}", err.message());
}

#[test]
fn loop_iteration_limit() {
    let mut runtime = JsRuntime::builder()
        .with_loop_iteration_limit(100)
        .build()
        .unwrap();
    let err = runtime.eval("while (true) {}").unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::LimitExceeded);
}

#[test]
fn non_ascii_strings_round_trip() {
    let mut runtime = JsRuntime::builder()
        .with_global("input", "héllo é ÿ 🦀 \u{00e9}")
        .with_fn("echo", |value: JsValue| value)
        .build()
        .unwrap();

    let value = runtime.eval("echo(input)").unwrap();
    assert_eq!(value.as_str(), Some("héllo é ÿ 🦀 \u{00e9}"));

    let value = runtime.eval(r#" "Ã©" + "🦀" "#).unwrap();
    assert_eq!(value.as_str(), Some("Ã©🦀"));

    // lone surrogates cannot cross into utf-8 and are replaced (lossy)
    let value = runtime.eval(r#" "\uD83E" "#).unwrap();
    assert_eq!(value.as_str(), Some("\u{FFFD}"));
}

#[test]
fn lone_surrogate_keys_collapse_after_replacement() {
    // distinct js keys differing only in unpaired surrogates become the
    // same utf-8 key (U+FFFD): the collapse keeps the last value
    let value = JsRuntime::eval_once(r#" ({ "\uD800": 1, "\uD801": 2 }) "#).unwrap();
    let object = value.as_object().unwrap();
    assert_eq!(object.len(), 1);
    assert_eq!(object.get("\u{FFFD}"), Some(&JsValue::Number(2.0)));
}

#[test]
fn execution_time_limit_bounds_total_work() {
    // work spread across function calls sidesteps the per-frame loop
    // limit; the wall-clock execution limit is what stops it
    let mut runtime = JsRuntime::builder()
        .with_execution_time_limit(std::time::Duration::from_millis(50))
        .build()
        .unwrap();
    let err = runtime
        .eval("function f() { for (let i = 0; i < 900000; i++) {} } while (true) f()")
        .unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::LimitExceeded);
    assert!(
        err.message().contains("execution time limit"),
        "{}",
        err.message()
    );

    // exceeding the limit poisons the runtime: everything after fails
    assert!(runtime.is_poisoned());
    let err = runtime.eval("1").unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::Setup);
    assert!(!runtime.has_global_fn("f"));
}

#[test]
fn execution_time_limit_bounds_calls() {
    let mut runtime = JsRuntime::builder()
        .without_loop_iteration_limit()
        .with_execution_time_limit(std::time::Duration::from_millis(50))
        .build()
        .unwrap();
    runtime.eval("function spin() { while (true) {} }").unwrap();

    let err = runtime.call("spin", [] as [JsValue; 0]).unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::LimitExceeded);
    assert!(runtime.is_poisoned());
}

#[test]
fn execution_time_limit_keeps_normal_scripts_working() {
    let mut runtime = JsRuntime::builder()
        .with_execution_time_limit(std::time::Duration::from_secs(5))
        .build()
        .unwrap();

    assert_eq!(runtime.eval("1 + 2").unwrap(), JsValue::Number(3.0));

    runtime.eval("function add(a, b) { return a + b }").unwrap();
    assert_eq!(
        runtime.call("add", [20.0, 22.0]).unwrap(),
        JsValue::Number(42.0)
    );

    let err = runtime.call("nope", [1.0]).unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::NotFound);

    runtime.eval("const notFn = 42").unwrap();
    let err = runtime.call("notFn", [] as [JsValue; 0]).unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::NotFound);

    assert!(!runtime.is_poisoned());
}

#[test]
fn execution_time_limit_call_channel_is_sealed() {
    let mut runtime = JsRuntime::builder()
        .with_execution_time_limit(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    runtime.eval("function id(x) { return x }").unwrap();

    // out-of-band probes never yield host data
    let err = runtime.eval("__rama_js_call__()").unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::Throw);
    assert!(
        err.message().contains("no pending host call"),
        "{}",
        err.message()
    );

    // the binding is frozen: tampering fails, dispatch keeps working
    runtime
        .eval("globalThis.__rama_js_call__ = 1; delete globalThis.__rama_js_call__")
        .unwrap();
    assert_eq!(runtime.call("id", [7.0]).unwrap(), JsValue::Number(7.0));

    // the name is reserved: registering it as a global fails setup
    let err = JsRuntime::builder()
        .with_execution_time_limit(std::time::Duration::from_secs(5))
        .with_global("__rama_js_call__", 1.0)
        .build()
        .unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::Setup);
}

#[test]
fn default_limits_stop_runaway_scripts() {
    let err = JsRuntime::eval_once("while (true) {}").unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::LimitExceeded);

    let err =
        JsRuntime::eval_once("function recurse() { return recurse(); } recurse()").unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::LimitExceeded);
}

#[test]
fn unset_loop_iteration_limit_means_unlimited() {
    let mut runtime = JsRuntime::builder()
        .without_loop_iteration_limit()
        .build()
        .unwrap();
    let iterations = 2 * JsRuntimeBuilder::DEFAULT_LOOP_ITERATION_LIMIT;
    let value = runtime
        .eval(format!(
            "let n = 0; for (let i = 0; i < {iterations}; i++) n++; n"
        ))
        .unwrap();
    assert_eq!(value.as_f64(), Some(iterations as f64));
}

#[test]
fn wasm_stack_contains_deep_recursion() {
    let mut runtime = JsRuntime::builder().build().unwrap();
    let err = runtime
        .eval("function recurse() { return recurse(); } recurse()")
        .unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::LimitExceeded);
}

#[test]
fn call_reaches_function_declarations_not_lexical_bindings() {
    let mut runtime = JsRuntime::builder().build().unwrap();
    runtime
        .exec("function decl(x) { return x * 2; } const arrow = (x) => x * 2;")
        .unwrap();

    // a function declaration lands on the global object: callable
    assert_eq!(runtime.call("decl", [21.0]).unwrap(), JsValue::Number(42.0));
    assert!(runtime.has_global_fn("decl"));

    // a top-level const arrow lives in the declarative scope: not callable
    let err = runtime.call("arrow", [21.0]).unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::NotFound);
    assert!(!runtime.has_global_fn("arrow"));
}

#[test]
fn promise_jobs_are_drained_within_the_operation() {
    let mut runtime = JsRuntime::builder().build().unwrap();
    runtime
        .exec("globalThis.ran = false; Promise.resolve(1).then(() => { globalThis.ran = true; });")
        .unwrap();
    assert_eq!(runtime.eval("ran").unwrap(), JsValue::Bool(true));
}

#[test]
fn strict_mode() {
    let mut strict = JsRuntime::builder().with_strict(true).build().unwrap();
    strict.eval("implicitGlobal = 1").unwrap_err();

    let mut sloppy = JsRuntime::builder().build().unwrap();
    sloppy.eval("implicitGlobal = 1").unwrap();
}

#[test]
fn globals_value_and_namespace() {
    let mut runtime = JsRuntime::builder()
        .with_global("answer", 42)
        .with_global("labels", vec!["a", "b"])
        .with_global(
            "rama",
            JsNamespace::default()
                .with_value("version", "0.3")
                .with_fn("ping", || "pong")
                .with_fn("double", |value: f64| value * 2.0),
        )
        .build()
        .unwrap();

    assert_eq!(runtime.eval("answer").unwrap(), JsValue::Number(42.0));
    assert_eq!(runtime.eval("labels[1]").unwrap().as_str(), Some("b"));
    assert_eq!(runtime.eval("rama.version").unwrap().as_str(), Some("0.3"));
    assert_eq!(runtime.eval("rama.ping()").unwrap().as_str(), Some("pong"));
    assert_eq!(
        runtime.eval("rama.double.length").unwrap(),
        JsValue::Number(1.0)
    );
}

#[test]
fn namespace_proto_is_an_own_data_property() {
    let proto_value = JsValue::Object([("marker", JsValue::Bool(true))].into_iter().collect());
    let mut runtime = JsRuntime::builder()
        .with_global(
            "rama",
            JsNamespace::default().with_value("__proto__", proto_value),
        )
        .build()
        .unwrap();

    assert_eq!(
        runtime
            .eval("Object.getPrototypeOf(rama) === Object.prototype")
            .unwrap(),
        JsValue::Bool(true)
    );
    assert_eq!(
        runtime
            .eval("Object.prototype.hasOwnProperty.call(rama, '__proto__')")
            .unwrap(),
        JsValue::Bool(true)
    );
    assert_eq!(
        runtime.eval("rama.__proto__.marker").unwrap(),
        JsValue::Bool(true)
    );
}

#[test]
fn host_fn_typed_extraction() {
    let mut runtime = JsRuntime::builder()
        .with_fn("isPrivate", |ip: IpAddr| match ip {
            IpAddr::V4(ip) => ip.is_private(),
            IpAddr::V6(_) => false,
        })
        .with_fn("tld", |domain: Domain| {
            domain
                .as_str()
                .rsplit('.')
                .next()
                .unwrap_or_default()
                .to_owned()
        })
        .with_fn("clamp", |value: f64, min: f64, max: Option<f64>| {
            value.max(min).min(max.unwrap_or(f64::INFINITY))
        })
        .build()
        .unwrap();

    assert_eq!(
        runtime.eval(r#"isPrivate("10.0.0.1")"#).unwrap(),
        JsValue::Bool(true)
    );
    assert_eq!(
        runtime.eval(r#"tld("www.example.com")"#).unwrap().as_str(),
        Some("com")
    );
    // optional trailing argument may be omitted
    assert_eq!(runtime.eval("clamp(-3, 0)").unwrap(), JsValue::Number(0.0));
    assert_eq!(
        runtime.eval("clamp(7, 0, 5)").unwrap(),
        JsValue::Number(5.0)
    );
    // extra arguments are ignored, js style
    assert_eq!(
        runtime.eval("clamp(2, 0, 5, 999)").unwrap(),
        JsValue::Number(2.0)
    );
}

#[test]
fn host_fn_ignored_arguments_are_not_materialized() {
    let mut runtime = JsRuntime::builder()
        .with_fn("answer", || 42)
        .with_fn("identity", |value: f64| value)
        .build()
        .unwrap();

    assert_eq!(
        runtime
            .eval("answer(Symbol('extra'), function () {}, 1n)")
            .unwrap(),
        JsValue::Number(42.0)
    );
    assert_eq!(
        runtime.eval("identity(7, Symbol('extra'))").unwrap(),
        JsValue::Number(7.0)
    );
    assert_eq!(
        runtime.eval("identity.length").unwrap(),
        JsValue::Number(1.0)
    );
    assert_eq!(
        runtime
            .eval("const cyclic = {}; cyclic.self = cyclic; answer(cyclic)")
            .unwrap(),
        JsValue::Number(42.0)
    );
}

#[test]
fn host_fn_conversion_error_is_catchable_type_error() {
    let mut runtime = JsRuntime::builder()
        .with_fn("needsNumber", |n: f64| n)
        .build()
        .unwrap();

    // missing argument
    let caught = runtime
        .eval("try { needsNumber() } catch (e) { e instanceof TypeError }")
        .unwrap();
    assert_eq!(caught, JsValue::Bool(true));

    // wrong type
    let caught = runtime
        .eval(r#"try { needsNumber("nope") } catch (e) { e instanceof TypeError }"#)
        .unwrap();
    assert_eq!(caught, JsValue::Bool(true));

    // uncaught it surfaces as a throw, mentioning the function
    let err = runtime.eval("needsNumber()").unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::Throw);
    assert!(err.message().contains("needsNumber"), "{}", err.message());
}

#[test]
fn host_fn_error_result_is_thrown() {
    let mut runtime = JsRuntime::builder()
        .with_fn("fail", || -> Result<bool, JsError> {
            Err(JsError::throw("host says no"))
        })
        .build()
        .unwrap();

    let caught = runtime
        .eval("try { fail() } catch (e) { String(e) }")
        .unwrap();
    assert!(
        caught.as_str().unwrap().contains("host says no"),
        "{caught:?}"
    );
}

#[test]
fn host_fn_variadic() {
    let mut runtime = JsRuntime::builder()
        .with_fn("sum", |args: JsArgs| {
            args.iter().filter_map(JsValue::as_f64).sum::<f64>()
        })
        .build()
        .unwrap();

    assert_eq!(
        runtime.eval("sum(1, 2, 3, 4)").unwrap(),
        JsValue::Number(10.0)
    );
    assert_eq!(runtime.eval("sum()").unwrap(), JsValue::Number(0.0));
}

#[test]
fn console_void_by_default() {
    let mut runtime = JsRuntime::builder().build().unwrap();
    assert_eq!(
        runtime.eval(r#"console.log("into the void")"#).unwrap(),
        JsValue::Undefined
    );
    assert_eq!(
        runtime.eval(r#"console.error("also void")"#).unwrap(),
        JsValue::Undefined
    );
    assert_eq!(
        runtime
            .eval("console.log(Symbol('ignored'), function () {})")
            .unwrap(),
        JsValue::Undefined
    );
}

#[test]
fn console_void_is_added_alongside_unrelated_globals() {
    let mut runtime = JsRuntime::builder()
        .with_global("answer", 42)
        .build()
        .unwrap();
    assert_eq!(
        runtime
            .eval("answer === 42 && typeof console.log === 'function'")
            .unwrap(),
        true.into(),
    );
}

#[test]
fn snapshot_access_errors_are_preserved() {
    let mut runtime = JsRuntime::builder().build().unwrap();

    let err = runtime
        .eval(
            r#"
                new Proxy([], {
                    get(target, key) {
                        if (key === "length") throw new Error("length failed");
                        return Reflect.get(target, key);
                    }
                })
            "#,
        )
        .unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::Throw);
    assert!(err.message().contains("length failed"), "{}", err.message());

    let err = runtime
        .eval(r#"({ get value() { throw new SyntaxError("getter failed"); } })"#)
        .unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::Throw);

    let mut limited = JsRuntime::builder()
        .with_loop_iteration_limit(10)
        .build()
        .unwrap();
    let err = limited
        .eval("({ get value() { while (true) {} } })")
        .unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::LimitExceeded);
}

#[test]
fn snapshot_rejects_sparse_array_before_reading_elements() {
    let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = hits.clone();
    let limits = JsSnapshotLimits::default().with_max_array_length(8);
    let mut runtime = JsRuntime::builder()
        .with_snapshot_limits(limits)
        .with_fn("hit", move || {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        })
        .build()
        .unwrap();

    let err = runtime
        .eval(
            r#"
                (() => {
                    const value = new Array(9);
                    Object.defineProperty(value, 0, { get() { hit(); return 1; } });
                    return value;
                })()
            "#,
        )
        .unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::LimitExceeded);
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[test]
fn snapshot_rejects_cycles_immediately() {
    let limits = JsSnapshotLimits::default().with_max_depth(1_000);
    let mut runtime = JsRuntime::builder()
        .with_snapshot_limits(limits)
        .build()
        .unwrap();

    let err = runtime
        .eval("(() => { const value = {}; value.self = value; return value; })()")
        .unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::Conversion);
    assert!(err.message().contains("cyclic"), "{}", err.message());

    let err = runtime
        .eval("(() => { const value = []; value[0] = value; return value; })()")
        .unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::Conversion);
    assert!(err.message().contains("cyclic"), "{}", err.message());
}

#[test]
fn snapshot_bounds_shared_dag_expansion_and_breadth() {
    let dag_limits = JsSnapshotLimits::default()
        .with_max_depth(64)
        .with_max_nodes(32);
    let mut dag_runtime = JsRuntime::builder()
        .with_snapshot_limits(dag_limits)
        .build()
        .unwrap();
    let err = dag_runtime
        .eval(
            r#"
                (() => {
                    let value = { leaf: true };
                    for (let i = 0; i < 10; i++) value = [value, value];
                    return value;
                })()
            "#,
        )
        .unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::LimitExceeded);
    assert!(err.message().contains("nodes"), "{}", err.message());

    let breadth_limits = JsSnapshotLimits::default()
        .with_max_array_length(100)
        .with_max_nodes(10);
    let mut breadth_runtime = JsRuntime::builder()
        .with_snapshot_limits(breadth_limits)
        .build()
        .unwrap();
    let err = breadth_runtime.eval("new Array(10)").unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::LimitExceeded);
    assert!(err.message().contains("nodes"), "{}", err.message());
}

#[test]
fn snapshot_bounds_depth_strings_and_object_properties() {
    let mut depth_runtime = JsRuntime::builder()
        .with_snapshot_limits(JsSnapshotLimits::default().with_max_depth(2))
        .build()
        .unwrap();
    let err = depth_runtime.eval("[[[0]]]").unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::LimitExceeded);
    assert!(err.message().contains("depth"), "{}", err.message());

    let mut string_runtime = JsRuntime::builder()
        .with_snapshot_limits(JsSnapshotLimits::default().with_max_string_bytes(4))
        .build()
        .unwrap();
    let err = string_runtime.eval(r#""ééé""#).unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::LimitExceeded);
    assert!(err.message().contains("string bytes"), "{}", err.message());

    let mut object_runtime = JsRuntime::builder()
        .with_snapshot_limits(JsSnapshotLimits::default().with_max_object_properties(2))
        .build()
        .unwrap();
    let err = object_runtime.eval("({ a: 1, b: 2, c: 3 })").unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::LimitExceeded);
    assert!(
        err.message().contains("property count"),
        "{}",
        err.message()
    );
}

#[test]
fn snapshot_accepts_values_exactly_at_each_limit() {
    let mut node_runtime = JsRuntime::builder()
        .with_snapshot_limits(JsSnapshotLimits::default().with_max_nodes(2))
        .build()
        .unwrap();
    assert_eq!(
        node_runtime.eval("[0]").unwrap(),
        JsValue::Array(vec![JsValue::Number(0.0)].into())
    );

    let mut zero_node_runtime = JsRuntime::builder()
        .with_snapshot_limits(JsSnapshotLimits::default().with_max_nodes(0))
        .build()
        .unwrap();
    assert_eq!(
        zero_node_runtime.eval("0").unwrap_err().kind(),
        JsErrorKind::LimitExceeded
    );

    let mut depth_runtime = JsRuntime::builder()
        .with_snapshot_limits(JsSnapshotLimits::default().with_max_depth(2))
        .build()
        .unwrap();
    depth_runtime.eval("[[0]]").unwrap();

    let mut array_runtime = JsRuntime::builder()
        .with_snapshot_limits(JsSnapshotLimits::default().with_max_array_length(2))
        .build()
        .unwrap();
    array_runtime.eval("new Array(2)").unwrap();
    array_runtime.eval("[]").unwrap();

    let mut object_runtime = JsRuntime::builder()
        .with_snapshot_limits(JsSnapshotLimits::default().with_max_object_properties(2))
        .build()
        .unwrap();
    object_runtime.eval("({ a: 1, b: 2 })").unwrap();

    let mut string_runtime = JsRuntime::builder()
        .with_snapshot_limits(JsSnapshotLimits::default().with_max_string_bytes(4))
        .build()
        .unwrap();
    assert_eq!(string_runtime.eval(r#""éé""#).unwrap().as_str(), Some("éé"));

    let mut nested_object_runtime = JsRuntime::builder()
        .with_snapshot_limits(JsSnapshotLimits::default().with_max_depth(2))
        .build()
        .unwrap();
    assert_eq!(
        nested_object_runtime
            .eval("({ a: { b: { c: 0 } } })")
            .unwrap_err()
            .kind(),
        JsErrorKind::LimitExceeded
    );
}

#[test]
fn snapshot_limits_apply_to_host_arguments_and_thrown_values() {
    let limits = JsSnapshotLimits::default().with_max_string_bytes(4);
    let mut runtime = JsRuntime::builder()
        .with_snapshot_limits(limits)
        .with_fn("accept", |_value: JsStr| true)
        .build()
        .unwrap();

    let err = runtime.eval("accept('12345')").unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::LimitExceeded);

    let err = runtime.eval("throw '12345'").unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::Throw);
    assert!(err.thrown().is_none());

    let err = runtime.exec("throw '12345'").unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::Throw);
    assert!(err.thrown().is_none());
}

#[test]
fn host_values_beyond_snapshot_depth_are_rejected() {
    let mut value = JsValue::Null;
    for _ in 0..100 {
        value = JsValue::Array(JsArray::from([value]));
    }

    let err = JsRuntime::builder()
        .with_global("deep", value.clone())
        .build()
        .unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::Setup);
    assert!(err.message().contains("nesting depth"), "{}", err.message());

    let mut runtime = JsRuntime::builder()
        .with_fn("deep", move || value.clone())
        .build()
        .unwrap();
    let err = runtime.eval("deep()").unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::LimitExceeded);
}

#[test]
fn host_object_values_beyond_snapshot_depth_are_rejected() {
    fn nested_objects(levels: usize) -> JsValue {
        let mut value = JsValue::Null;
        for _ in 0..levels {
            value = JsValue::Object([("inner", value)].into_iter().collect());
        }
        value
    }

    let limits = JsSnapshotLimits::default().with_max_depth(4);

    // an object nests just like an array does: one level past the limit
    // is refused rather than walked
    let err = JsRuntime::builder()
        .with_snapshot_limits(limits)
        .with_global("deep", nested_objects(5))
        .build()
        .unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::Setup);
    assert!(err.message().contains("nesting depth"), "{}", err.message());

    let deep = nested_objects(5);
    let mut runtime = JsRuntime::builder()
        .with_snapshot_limits(limits)
        .with_fn("deep", move || deep.clone())
        .build()
        .unwrap();
    let err = runtime.eval("deep()").unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::LimitExceeded);

    // ... while one exactly at the limit crosses and stays walkable
    let mut runtime = JsRuntime::builder()
        .with_snapshot_limits(limits)
        .with_global("deep", nested_objects(4))
        .build()
        .unwrap();
    assert_eq!(
        runtime.eval("deep.inner.inner.inner.inner").unwrap(),
        JsValue::Null,
    );
}

#[test]
fn object_duplicate_keys_collapse_last_wins() {
    let object: JsObject = [("a", 1.0), ("b", 2.0), ("a", 3.0)].into_iter().collect();
    assert_eq!(object.len(), 2);
    assert_eq!(object.get("a"), Some(&JsValue::Number(3.0)));
    assert_eq!(
        object.keys().map(JsStr::as_str).collect::<Vec<_>>(),
        ["a", "b"]
    );

    let mut runtime = JsRuntime::builder()
        .with_global("input", JsValue::Object(object))
        .build()
        .unwrap();
    assert_eq!(runtime.eval("input.a").unwrap(), JsValue::Number(3.0));
}

#[test]
fn conversion_error_messages_preview_bounded_input() {
    let mut runtime = JsRuntime::builder()
        .with_fn("parse_ip", |ip: IpAddr| ip.to_string())
        .build()
        .unwrap();

    let err = runtime
        .eval(format!("parse_ip('x'.repeat({}))", mib(1)))
        .unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::Throw);
    assert!(
        err.message().len() <= kib(1),
        "unbounded message ({} bytes)",
        err.message().len()
    );
    assert!(
        err.message().contains("invalid an ip address"),
        "{}",
        err.message()
    );
}

#[test]
fn thrown_error_messages_are_bounded() {
    for script in [
        format!("throw 'x'.repeat({})", mib(1)),
        format!("throw new Error('x'.repeat({}))", mib(1)),
        format!("throw ['x'.repeat({})]", mib(1)),
    ] {
        let err = JsRuntime::eval_once(&script).unwrap_err();
        assert!(
            err.message().len() <= kib(5),
            "unbounded message ({} bytes) for `{script}`",
            err.message().len()
        );
        assert!(err.message().ends_with("… (truncated)"), "{script}");
    }
}

#[test]
fn thrown_error_messages_truncate_on_a_character_boundary() {
    // mirrors the engine's cap and marker, so an over-long cut shows up
    const MAX_ERROR_MESSAGE_BYTES: usize = kib(4);
    const TRUNCATED: &str = "… (truncated)";
    const PREFIX: &str = "script threw: ";

    // two, three and four byte characters, so the cap lands mid-character
    // whatever the prefix costs
    for filler in ["é", "€", "😀"] {
        let err =
            JsRuntime::eval_once(format!(r#"throw "{filler}".repeat({})"#, kib(4))).unwrap_err();
        let message = err.message();
        let kept = message
            .strip_suffix(TRUNCATED)
            .unwrap_or_else(|| panic!("untruncated message for {filler}: {} bytes", message.len()));
        assert!(
            kept.len() <= MAX_ERROR_MESSAGE_BYTES,
            "{filler}: kept {} bytes past the cap",
            kept.len(),
        );

        // the cut keeps whole characters: no replacement, no partial one
        let body = kept
            .strip_prefix(PREFIX)
            .unwrap_or_else(|| panic!("unexpected message shape: {kept:?}"));
        let kept_char = filler.chars().next().unwrap();
        assert!(!body.is_empty(), "{filler}: nothing kept");
        assert!(body.chars().all(|c| c == kept_char), "{body:?}");
    }
}

#[test]
fn console_trace_never_throws_and_renders_placeholders() {
    use std::io;
    use std::sync::Arc;

    use parking_lot::Mutex;

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let capture = Capture::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing_subscriber::filter::LevelFilter::DEBUG)
        .with_writer(move || writer.clone())
        .finish();

    let mut runtime = JsRuntime::builder()
        .with_global("console", Console::trace())
        .build()
        .unwrap();

    rama_core::telemetry::tracing::subscriber::with_default(subscriber, || {
        runtime
            .eval(
                r#"
                const o = {}; o.self = o;
                console.log("ok", Symbol("boom"), o, () => 1, 42n);
                "#,
            )
            .unwrap();
    });

    let logs = String::from_utf8(capture.0.lock().clone()).unwrap();
    assert!(logs.contains("ok"), "{logs}");
    for placeholder in [
        "<symbol values cannot cross the js boundary",
        "<cyclic object graph cannot cross the js boundary",
        "<function values cannot cross the js boundary",
        "<bigint values cannot cross the js boundary",
    ] {
        assert!(
            logs.contains(placeholder),
            "missing `{placeholder}`: {logs}"
        );
    }
}

#[test]
fn console_trace_escapes_control_characters() {
    use std::io;
    use std::sync::Arc;

    use parking_lot::Mutex;

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let capture = Capture::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing_subscriber::filter::LevelFilter::DEBUG)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();

    let mut runtime = JsRuntime::builder()
        .with_global("console", Console::trace())
        .build()
        .unwrap();

    rama_core::telemetry::tracing::subscriber::with_default(subscriber, || {
        runtime
            .eval(r#" console.log("a\r\n2026-01-01 ERROR forged", "\u001b[31mred") "#)
            .unwrap();
    });

    let logs = String::from_utf8(capture.0.lock().clone()).unwrap();
    // one event stays one physical line: CR/LF and ESC arrive escaped
    assert_eq!(logs.trim_end().lines().count(), 1, "{logs}");
    assert!(!logs.contains('\u{1b}'), "{logs}");
    assert!(logs.contains(r"a\r\n2026-01-01 ERROR forged"), "{logs}");
    assert!(logs.contains(r"\u{1b}[31mred"), "{logs}");
}

#[test]
fn console_custom_override() {
    let (sink, captured) = std::sync::mpsc::channel();

    let mut runtime = JsRuntime::builder()
        .with_global(
            "console",
            Console::void().with_warn(move |args: JsArgs| {
                sink.send(args.iter().map(ToString::to_string).collect::<Vec<_>>())
                    .unwrap();
            }),
        )
        .build()
        .unwrap();

    runtime.eval(r#"console.warn("watch", "out", 42)"#).unwrap();
    runtime.eval(r#"console.log("dropped")"#).unwrap();

    assert_eq!(
        captured.try_iter().collect::<Vec<_>>(),
        vec![vec!["watch".to_owned(), "out".to_owned(), "42".to_owned()]]
    );
}

#[test]
fn user_global_shadows_console() {
    let mut runtime = JsRuntime::builder()
        .with_global("console", "not a console")
        .build()
        .unwrap();
    assert_eq!(
        runtime.eval("console").unwrap().as_str(),
        Some("not a console")
    );
}

#[test]
fn function_values_do_not_cross() {
    let mut runtime = JsRuntime::builder().build().unwrap();

    let err = runtime.eval("(function() {})").unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::Conversion);

    // function properties are skipped, like JSON.stringify
    let object = runtime.eval("({ keep: 1, drop: function() {} })").unwrap();
    let object = object.as_object().unwrap();
    assert_eq!(object.len(), 1);
    assert!(object.contains_key("keep"));
}

#[test]
fn args_roundtrip_into_call() {
    let mut runtime = JsRuntime::builder().build().unwrap();
    runtime
        .eval("function echo(value) { return value; }")
        .unwrap();

    let object: JsValue = runtime
        .call(
            "echo",
            [JsValue::Object(
                [("key", JsValue::from("value"))].into_iter().collect(),
            )],
        )
        .unwrap();
    assert_eq!(
        object
            .as_object()
            .and_then(|o| o.get("key"))
            .and_then(|v| v.as_str()),
        Some("value")
    );
}

#[test]
fn access_rules_end_to_end() {
    const RULES_SCRIPT: &str = r#"
        function decideAccess(user, resource) {
            if (user === "root") {
                return "allow";
            }
            var role = lookupRole(user);
            if (role === "admin" || isPublic(resource)) {
                return "allow";
            }
            if (role === "member" && matchPrefix(resource, "team/")) {
                return "allow";
            }
            return "deny";
        }
    "#;

    let mut runtime = JsRuntime::builder()
        .with_fn("lookupRole", |user: JsStr| -> Option<String> {
            match user.as_str() {
                "alice" => Some("admin".to_owned()),
                "bob" => Some("member".to_owned()),
                _ => None,
            }
        })
        .with_fn("isPublic", |resource: JsStr| {
            resource.starts_with("public/")
        })
        .with_fn("matchPrefix", |value: JsStr, prefix: JsStr| {
            value.starts_with(prefix.as_str())
        })
        .build()
        .unwrap();

    runtime.eval(RULES_SCRIPT).unwrap();

    for (user, resource, expected) in [
        ("root", "secret/keys", "allow"),
        ("alice", "secret/keys", "allow"),
        ("bob", "team/notes", "allow"),
        ("bob", "secret/keys", "deny"),
        ("mallory", "public/readme", "allow"),
        ("mallory", "team/notes", "deny"),
    ] {
        let verdict = runtime.call("decideAccess", [user, resource]).unwrap();
        assert_eq!(verdict.as_str(), Some(expected), "{user} -> {resource}");
    }
}

#[derive(Debug, PartialEq, Eq)]
struct RequestState {
    method: String,
    headers: Vec<(String, String)>,
}

#[test]
fn native_host_object_reads_mutates_and_recovers_rust_state() {
    let request = RequestState {
        method: "GET".to_owned(),
        headers: vec![("accept".to_owned(), "text/plain".to_owned())],
    };
    let (object, handle) = JsHostObject::builder(request)
        .getter("method", |request: &RequestState| request.method.clone())
        .setter("method", |request: &mut RequestState, method: String| {
            request.method = method
        })
        .method(
            "header",
            |request: &RequestState, name: String| -> Option<String> {
                request
                    .headers
                    .iter()
                    .find(|(key, _)| key == &name)
                    .map(|(_, value)| value.clone())
            },
        )
        .method_mut(
            "setHeader",
            |request: &mut RequestState, name: String, value: String| {
                if let Some((_, current)) = request.headers.iter_mut().find(|(key, _)| key == &name)
                {
                    *current = value;
                } else {
                    request.headers.push((name, value));
                }
            },
        )
        .build();

    let mut runtime = JsRuntime::builder().build().unwrap();
    runtime.set_host_global("request", object).unwrap();
    assert_eq!(runtime.eval("request === request").unwrap(), true.into());
    assert_eq!(
        runtime
            .eval(
                r#"
                request.method = "POST";
                request.setHeader("accept", "application/json");
                request.setHeader("x-rama", "native");
                `${request.method} ${request.header("accept")}`;
                "#,
            )
            .unwrap(),
        "POST application/json".into(),
    );

    let request = handle.take().unwrap();
    assert_eq!(
        request,
        RequestState {
            method: "POST".to_owned(),
            headers: vec![
                ("accept".to_owned(), "application/json".to_owned()),
                ("x-rama".to_owned(), "native".to_owned()),
            ],
        },
    );
    assert_eq!(
        runtime
            .eval("try { request.header('accept'); false } catch (_) { true }")
            .unwrap(),
        true.into(),
    );
}

#[test]
fn native_host_object_keeps_identity_when_passed_inside_javascript() {
    let (object, _handle) = JsHostObject::builder(7_u32)
        .method("value", |value: &u32| *value)
        .build();
    let mut runtime = JsRuntime::builder().build().unwrap();
    runtime.set_host_global("counter", object).unwrap();

    assert_eq!(
        runtime
            .eval(
                r#"
                function pass(value) { return value; }
                const passed = pass(counter);
                passed === counter && passed.value(Symbol("ignored")) === 7;
                "#,
            )
            .unwrap(),
        true.into(),
    );
}

#[test]
fn native_host_object_cannot_be_snapshotted() {
    let (object, _handle) = JsHostObject::builder(7_u32).build();
    let mut runtime = JsRuntime::builder().build().unwrap();
    runtime.set_host_global("resource", object).unwrap();

    let err = runtime.eval("resource").unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::Conversion);
    assert!(err.message().contains("native host objects"));

    let err = runtime.eval("({ nested: resource })").unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::Conversion);

    runtime.exec("resource").unwrap();
}

#[test]
fn native_host_method_rejects_an_invalid_receiver() {
    let (object, _handle) = JsHostObject::builder(7_u32)
        .method("value", |value: &u32| *value)
        .build();
    let mut runtime = JsRuntime::builder().build().unwrap();
    runtime.set_host_global("resource", object).unwrap();

    let err = runtime
        .eval("const value = resource.value; value()")
        .unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::Throw);
    assert!(err.message().contains("invalid host object receiver"));
}

#[test]
fn native_host_method_rejects_a_different_host_class() {
    let (left, _left_handle) = JsHostObject::builder(7_u32)
        .method("value", |value: &u32| *value)
        .build();
    let (right, _right_handle) = JsHostObject::builder(9_u32)
        .method("value", |value: &u32| *value)
        .build();
    let mut runtime = JsRuntime::builder().build().unwrap();
    runtime.set_host_global("left", left).unwrap();
    runtime.set_host_global("right", right).unwrap();

    let err = runtime.eval("left.value.call(right)").unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::Throw);
    assert!(err.message().contains("incompatible host object receiver"));
}

#[test]
fn native_host_object_rejects_duplicate_members() {
    let (object, handle) = JsHostObject::builder(7_u32)
        .method("value", |value: &u32| *value)
        .getter("value", |value: &u32| *value)
        .build();
    let mut runtime = JsRuntime::builder().build().unwrap();

    let err = runtime.set_host_global("resource", object).unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::Setup);
    assert!(
        err.message()
            .contains("duplicate host object member `value`")
    );
    assert_eq!(handle.take().unwrap(), 7);

    let (object, _handle) = JsHostObject::builder(7_u32)
        .getter("value", |value: &u32| *value)
        .setter("value", |value: &mut u32, next: u32| *value = next)
        .setter("value", |value: &mut u32, next: u32| *value = next)
        .build();
    let err = runtime.set_host_global("resource", object).unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::Setup);
}

#[test]
fn native_host_class_reuses_one_definition_for_multiple_values() {
    let class = JsHostClass::<u32>::builder()
        .method("value", |value: &u32| *value)
        .method_mut("increment", |value: &mut u32| *value += 1)
        .build();
    let (left, left_handle) = class.bind(7);
    let (right, right_handle) = class.bind(9);
    let mut runtime = JsRuntime::builder().build().unwrap();
    runtime.set_host_global("left", left).unwrap();
    runtime.set_host_global("right", right).unwrap();

    assert_eq!(
        runtime
            .eval(
                "left.increment(); right.increment.call(left); \
                 left.value() === 9 && right.value() === 9",
            )
            .unwrap(),
        true.into(),
    );
    assert_eq!(left_handle.take().unwrap(), 9);
    assert_eq!(right_handle.take().unwrap(), 9);
}

#[test]
fn native_host_class_supports_a_setter_without_a_matching_getter() {
    let (object, handle) = JsHostObject::builder(7_u32)
        .getter("read", |value: &u32| *value)
        .setter("write", |value: &mut u32, next: u32| *value = next)
        .build();
    let mut runtime = JsRuntime::builder().build().unwrap();
    runtime.set_host_global("resource", object).unwrap();

    runtime.exec("resource.write = 41").unwrap();
    assert_eq!(handle.take().unwrap(), 41);
}

#[test]
fn deadline_dispatch_survives_hostile_globals() {
    let limit = std::time::Duration::from_secs(5);
    // every one of these used to redirect or kill deadline-bounded dispatch
    for tamper in [
        "globalThis = 1",
        "var globalThis = 1",
        "globalThis = { id: function() { return 'hijacked' } }",
        "Array.prototype[Symbol.iterator] = function() { throw new Error('hijacked') }",
        "Object.defineProperty(Object.prototype, 'f', { get: function() { throw new Error('proto') } })",
        "Object.defineProperty(Object.prototype, 'a0', { get: function() { throw new Error('proto') } })",
        "Object.prototype.f = function() { return 'hijacked' }",
        "Object.prototype.value = function() { return 'hijacked' }",
    ] {
        let mut runtime = JsRuntime::builder()
            .with_execution_time_limit(limit)
            .build()
            .unwrap();
        runtime.eval("function id(x) { return x }").unwrap();
        runtime.exec(tamper).unwrap_or_else(|err| {
            panic!("tamper `{tamper}` must be allowed to run: {err}");
        });

        assert_eq!(
            runtime.call("id", [7.0]).unwrap_or_else(|err| {
                panic!("dispatch broken by `{tamper}`: {err}");
            }),
            JsValue::Number(7.0),
            "{tamper}",
        );
    }
}

#[test]
fn deadline_dispatch_survives_tampering_from_inside_the_call() {
    let mut runtime = JsRuntime::builder()
        .with_execution_time_limit(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    // a script can hold its tampering back until it is already serving
    runtime
        .eval("function id(x) { globalThis = 1; Array.prototype[Symbol.iterator] = 0; return x }")
        .unwrap();

    assert_eq!(runtime.call("id", [1.0]).unwrap(), JsValue::Number(1.0));
    assert_eq!(runtime.call("id", [2.0]).unwrap(), JsValue::Number(2.0));
}

#[test]
fn an_accessor_entry_point_is_not_invoked() {
    let mut runtime = JsRuntime::builder()
        .with_execution_time_limit(std::time::Duration::from_millis(200))
        .build()
        .unwrap();
    // invoking this getter would hang uninterruptibly: it must read as absent
    runtime
        .exec("Object.defineProperty(globalThis, 'evil', { get: function() { while (true) {} } })")
        .unwrap();

    assert!(!runtime.has_global_fn("evil"));
    let started = std::time::Instant::now();
    let err = runtime.call("evil", [1.0]).unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::NotFound);
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
}

#[test]
fn a_thrown_not_found_marker_is_not_mistaken_for_a_missing_function() {
    let mut runtime = JsRuntime::builder()
        .with_execution_time_limit(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    runtime
        .eval("function boom() { throw new TypeError('__rama_js_not_found__') }")
        .unwrap();

    let err = runtime.call("boom", Vec::<JsValue>::new()).unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::Throw, "{}", err.message());
}

#[test]
fn deadline_dispatch_passes_arguments_by_arity() {
    let mut runtime = JsRuntime::builder()
        .with_execution_time_limit(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    runtime
        .eval("function count() { return arguments.length } function sum(a, b, c) { return a + b + c }")
        .unwrap();

    assert_eq!(
        runtime.call("count", Vec::<JsValue>::new()).unwrap(),
        JsValue::Number(0.0)
    );
    assert_eq!(
        runtime.call("count", [1.0, 2.0]).unwrap(),
        JsValue::Number(2.0)
    );
    assert_eq!(
        runtime.call("sum", [1.0, 2.0, 3.0]).unwrap(),
        JsValue::Number(6.0)
    );
    // `this` is the global object, as a plain call, not the payload
    runtime
        .eval("function self() { return this === globalThis }")
        .unwrap();
    assert_eq!(
        runtime.call("self", Vec::<JsValue>::new()).unwrap(),
        JsValue::Bool(true)
    );
}

#[test]
fn error_text_never_leaks_engine_internals() {
    let mut runtime = JsRuntime::builder().build().unwrap();
    // a thrown value that cannot be snapshotted must not be Debug-printed
    let err = runtime
        .eval("throw { get message() { throw new Error('nope') } }")
        .unwrap_err();
    assert!(
        !["wasmtime", "starling", "wasm backtrace", "0x"]
            .iter()
            .any(|needle| err.message().contains(needle)),
        "{}",
        err.message()
    );
}

#[test]
fn a_slow_but_legitimate_script_completes_under_a_generous_limit() {
    let mut runtime = JsRuntime::builder()
        .with_execution_time_limit(std::time::Duration::from_secs(30))
        // enough work to need many budget rounds, so the deadline is really
        // consulted rather than never reached
        .without_loop_iteration_limit()
        .build()
        .unwrap();

    assert_eq!(
        runtime
            .eval("var total = 0; for (var i = 0; i < 3000000; i++) { total += i } total > 0")
            .unwrap(),
        JsValue::Bool(true)
    );

    runtime
        .eval("function work(n) { var t = 0; for (var i = 0; i < n; i++) { t += i } return t > 0 }")
        .unwrap();
    assert_eq!(
        runtime.call("work", [3_000_000.0]).unwrap(),
        JsValue::Bool(true)
    );
}

#[test]
fn error_messages_are_bounded() {
    let mut runtime = JsRuntime::builder().build().unwrap();
    let err = runtime
        .eval(format!("throw new Error('x'.repeat({}))", mib(2)))
        .unwrap_err();

    // the message must be cut to the bounded prefix, not carry the payload
    assert!(err.message().len() <= kib(8), "{}", err.message().len());
}

#[test]
fn each_snapshot_limit_is_enforced_on_its_own() {
    use rama_js::JsSnapshotLimits;

    let limits = JsSnapshotLimits::default()
        .with_max_depth(2)
        .with_max_array_length(4)
        .with_max_object_properties(3)
        .with_max_string_bytes(32);

    for (src, what) in [
        ("[[[[1]]]]", "depth"),
        ("[1, 2, 3, 4, 5]", "array length"),
        ("({ a: 1, b: 2, c: 3, d: 4 })", "object properties"),
        ("'x'.repeat(64)", "string bytes"),
    ] {
        let mut runtime = JsRuntime::builder()
            .with_snapshot_limits(limits)
            .build()
            .unwrap();
        let Err(err) = runtime.eval(src) else {
            panic!("{what} limit not enforced for `{src}`");
        };
        assert_eq!(err.kind(), JsErrorKind::LimitExceeded, "{what}: {src}");
    }

    // ... and a value at each limit still crosses
    let mut runtime = JsRuntime::builder()
        .with_snapshot_limits(limits)
        .build()
        .unwrap();
    runtime.eval("[[1]]").unwrap();
    runtime.eval("[1, 2, 3, 4]").unwrap();
    runtime.eval("({ a: 1, b: 2, c: 3 })").unwrap();
    runtime.eval("'x'.repeat(32)").unwrap();
}

#[test]
fn host_values_are_bounded_on_the_way_in_too() {
    use rama_js::JsSnapshotLimits;

    let mut runtime = JsRuntime::builder()
        .with_snapshot_limits(JsSnapshotLimits::default().with_max_depth(1))
        .build()
        .unwrap();
    runtime.eval("function id(x) { return 1 }").unwrap();

    let too_deep = JsValue::Array(vec![JsValue::Array(vec![JsValue::Number(1.0)].into())].into());
    let err = runtime.call("id", [too_deep]).unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::LimitExceeded, "{}", err.message());

    // one level shallower is accepted
    let ok = JsValue::Array(vec![JsValue::Number(1.0)].into());
    assert_eq!(runtime.call("id", [ok]).unwrap(), JsValue::Number(1.0));

    let limits = JsSnapshotLimits::default()
        .with_max_array_length(1)
        .with_max_object_properties(1)
        .with_max_string_bytes(3);
    let err = JsRuntime::builder()
        .with_snapshot_limits(limits)
        .with_global(
            "wide",
            JsValue::Array(vec![JsValue::Number(1.0), JsValue::Number(2.0)].into()),
        )
        .build()
        .unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::Setup, "{}", err.message());

    let mut runtime = JsRuntime::builder()
        .with_snapshot_limits(limits)
        .build()
        .unwrap();
    runtime.eval("function id(x) { return 1 }").unwrap();
    for value in [
        JsValue::Array(vec![JsValue::Number(1.0), JsValue::Number(2.0)].into()),
        JsValue::Object([("a", 1.0), ("b", 2.0)].into_iter().collect()),
        JsValue::from("four"),
    ] {
        let err = runtime.call("id", [value]).unwrap_err();
        assert_eq!(err.kind(), JsErrorKind::LimitExceeded, "{}", err.message());
    }

    let mut runtime = JsRuntime::builder()
        .with_snapshot_limits(JsSnapshotLimits::default().with_max_nodes(3))
        .build()
        .unwrap();
    runtime.eval("function id(x) { return 1 }").unwrap();
    let value = JsValue::Object([("a", 1.0), ("b", 2.0)].into_iter().collect());
    let err = runtime.call("id", [value]).unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::LimitExceeded, "{}", err.message());
}

#[test]
fn latin1_strings_cross_the_boundary_as_their_characters() {
    let mut runtime = JsRuntime::builder().build().unwrap();
    // é is one latin1 byte in the engine, two utf-8 bytes outside it
    assert_eq!(
        runtime.eval(r"'café'").unwrap(),
        JsValue::String("café".into())
    );
    assert_eq!(runtime.eval(r"'ÿþ'").unwrap(), JsValue::String("ÿþ".into()));
}

#[test]
fn a_faked_array_length_never_becomes_a_size() {
    let mut runtime = JsRuntime::builder().build().unwrap();
    // `Array.isArray` follows a proxy to its target, so a script could
    // otherwise choose the length a snapshot allocates for
    for length in ["1.5", "NaN", "-1", "Infinity", "1e20"] {
        let src = format!(
            "new Proxy([], {{ get: function(t, k) {{ return k === 'length' ? {length} : 7 }} }})"
        );
        let value = runtime.eval(&src).unwrap_or_else(|err| {
            panic!("length {length}: {err}");
        });
        assert!(
            matches!(value, JsValue::Object(_)),
            "length {length} was snapshotted as {value:?}, not as a plain object",
        );
    }

    // a real array cannot have its length faked in the first place
    let err = runtime
        .eval("var a = []; Object.defineProperty(a, 'length', { value: 1.5 }); a")
        .unwrap_err();
    assert!(!err.message().is_empty());
}
