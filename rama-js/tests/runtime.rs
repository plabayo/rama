use std::net::IpAddr;

use rama_js::{Console, JsArgs, JsError, JsErrorKind, JsNamespace, JsRuntime, JsStr, JsValue};
use rama_net::address::Domain;

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
fn recursion_limit() {
    let mut runtime = JsRuntime::builder()
        .with_recursion_limit(16)
        .build()
        .unwrap();
    let err = runtime
        .eval("function recurse() { return recurse(); } recurse()")
        .unwrap_err();
    assert_eq!(err.kind(), JsErrorKind::LimitExceeded);
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
                .with_fn("ping", || "pong"),
        )
        .build()
        .unwrap();

    assert_eq!(runtime.eval("answer").unwrap(), JsValue::Number(42.0));
    assert_eq!(runtime.eval("labels[1]").unwrap().as_str(), Some("b"));
    assert_eq!(runtime.eval("rama.version").unwrap().as_str(), Some("0.3"));
    assert_eq!(runtime.eval("rama.ping()").unwrap().as_str(), Some("pong"));
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
