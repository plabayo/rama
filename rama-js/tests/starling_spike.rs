#![cfg(feature = "starling-spike")]

use std::sync::Arc;

use ahash::{HashMap, HashMapExt as _};
use parking_lot::Mutex;
use rama_js::{JsArray, JsObject, JsValue};
use wasmtime::component::{Component, HasSelf, Linker};
use wasmtime::{Config, Engine as WasmEngine, Store, StoreLimits, StoreLimitsBuilder};

pub mod bindings {
    wasmtime::component::bindgen!({
        path: "engine/starling/engine.wit",
        world: "engine",
    });
}

use bindings::rama::js_engine::host::Host;
use bindings::rama::js_engine::types::{
    HostFunction, HostMember, HostMemberKind, NamedValue, Outcome,
};

type Callback = Arc<dyn Fn(Option<u32>, Vec<JsValue>) -> Result<JsValue, String> + Send + Sync>;

#[derive(Default)]
struct HostState {
    callbacks: HashMap<u32, Callback>,
    limits: StoreLimits,
}

impl bindings::rama::js_engine::types::Host for HostState {}

impl Host for HostState {
    fn invoke(&mut self, callback_id: u32, object_id: Option<u32>, arguments: Vec<u8>) -> Outcome {
        let result = decode(&arguments).and_then(|arguments| {
            let JsValue::Array(arguments) = arguments else {
                return Err("host arguments are not an array".to_owned());
            };
            let callback = self
                .callbacks
                .get(&callback_id)
                .ok_or_else(|| format!("unknown host callback {callback_id}"))?;
            callback(object_id, arguments.to_vec())
        });

        match result {
            Ok(value) => Outcome {
                ok: true,
                payload: encode(&value),
            },
            Err(message) => Outcome {
                ok: false,
                payload: message.into_bytes(),
            },
        }
    }
}

#[test]
fn dynamic_runtime_preserves_rama_host_boundary() -> wasmtime::Result<()> {
    let engine = WasmEngine::default();
    let component = Component::from_binary(
        &engine,
        include_bytes!("../engine/starling/rama-js-engine.wasm"),
    )?;
    let mut linker = Linker::new(&engine);
    bindings::Engine::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state)?;

    let counter = Arc::new(Mutex::new(0_f64));
    let mut state = HostState::default();
    state.callbacks.insert(
        1,
        Arc::new(|object_id, arguments| {
            assert_eq!(object_id, None);
            let sum = arguments
                .into_iter()
                .map(|value| match value {
                    JsValue::Number(value) => Ok(value),
                    other => Err(format!("expected number, got {}", other.type_name())),
                })
                .sum::<Result<f64, _>>()?;
            Ok(sum.into())
        }),
    );
    state.callbacks.insert(
        2,
        Arc::new(|object_id, _arguments| {
            assert_eq!(object_id, None);
            Ok("127.0.0.1".into())
        }),
    );
    state.callbacks.insert(10, {
        let counter = Arc::clone(&counter);
        Arc::new(move |object_id, _arguments| {
            assert_eq!(object_id, Some(7));
            Ok((*counter.lock()).into())
        })
    });
    state.callbacks.insert(11, {
        let counter = Arc::clone(&counter);
        Arc::new(move |object_id, arguments| {
            assert_eq!(object_id, Some(7));
            let Some(JsValue::Number(value)) = arguments.first() else {
                return Err("setter expected a number".to_owned());
            };
            *counter.lock() = *value;
            Ok(JsValue::Undefined)
        })
    });
    state.callbacks.insert(12, {
        let counter = Arc::clone(&counter);
        Arc::new(move |object_id, arguments| {
            assert_eq!(object_id, Some(7));
            let Some(JsValue::Number(value)) = arguments.first() else {
                return Err("method expected a number".to_owned());
            };
            *counter.lock() += *value;
            Ok((*counter.lock()).into())
        })
    });

    let mut store = Store::new(&engine, state);
    let bindings = bindings::Engine::instantiate(&mut store, &component, &linker)?;
    let runtime = bindings.rama_js_engine_runtime();

    succeed(assert_ok(&runtime.call_define_global(
        &mut store,
        "seed",
        &encode(&JsValue::from(40_u32)),
    )?));
    succeed(assert_ok(&runtime.call_define_host_function(
        &mut store,
        &HostFunction {
            name: "sum".to_owned(),
            callback_id: 1,
            arity: Some(2),
        },
    )?));
    succeed(assert_ok(&runtime.call_define_host_function(
        &mut store,
        &HostFunction {
            name: "dnsResolve".to_owned(),
            callback_id: 2,
            arity: Some(1),
        },
    )?));
    succeed(assert_ok(&runtime.call_define_namespace(
        &mut store,
        "helpers",
        &[NamedValue {
            name: "suffix".to_owned(),
            value: encode(&JsValue::from("!")),
        }],
        &[HostFunction {
            name: "sum".to_owned(),
            callback_id: 1,
            arity: Some(2),
        }],
    )?));
    succeed(assert_ok(&runtime.call_define_host_object(
        &mut store,
        "counter",
        7,
        3,
        &[
            HostMember {
                name: "value".to_owned(),
                callback_id: 10,
                kind: HostMemberKind::Getter,
                arity: Some(0),
            },
            HostMember {
                name: "value".to_owned(),
                callback_id: 11,
                kind: HostMemberKind::Setter,
                arity: Some(1),
            },
            HostMember {
                name: "add".to_owned(),
                callback_id: 12,
                kind: HostMemberKind::Method,
                arity: Some(1),
            },
        ],
    )?));

    assert_eq!(
        succeed(outcome_value(
            &runtime.call_evaluate(&mut store, "sum(seed, 2)")?
        )),
        JsValue::from(42_u32),
    );
    assert_eq!(
        succeed(outcome_value(&runtime.call_evaluate(
            &mut store,
            "helpers.sum(20, 22) + helpers.suffix",
        )?)),
        JsValue::from("42!"),
    );

    succeed(assert_ok(&runtime.call_exec(
        &mut store,
        r#"
            function FindProxyForURL(url, host) {
                if (dnsResolve(host) === "127.0.0.1") {
                    return "PROXY proxy.internal:8080; DIRECT";
                }
                return "DIRECT";
            }
        "#,
    )?));
    assert!(runtime.call_has_global_function(&mut store, "FindProxyForURL")?);
    assert_eq!(
        succeed(outcome_value(&runtime.call_call(
            &mut store,
            "FindProxyForURL",
            &encode(&JsValue::Array(JsArray::from([
                "https://example.com/",
                "example.com",
            ]))),
        )?)),
        JsValue::from("PROXY proxy.internal:8080; DIRECT"),
    );

    assert_eq!(
        succeed(outcome_value(&runtime.call_evaluate(
            &mut store,
            "counter.value = 40; counter.add(2); counter.value",
        )?)),
        JsValue::from(42_u32),
    );
    assert!((*counter.lock() - 42.0).abs() < f64::EPSILON);

    let receiver_error =
        runtime.call_evaluate(&mut store, "const detached = counter.add; detached(1)")?;
    assert!(!receiver_error.ok);
    let Ok(receiver_error) = String::from_utf8(receiver_error.payload) else {
        panic!("receiver error is not UTF-8")
    };
    assert!(receiver_error.contains("invalid host object receiver"));

    let boundary = succeed(outcome_value(&runtime.call_evaluate(
        &mut store,
        r#"({
            unicode: "🦀",
            negativeZero: -0,
            notANumber: NaN,
            infinity: Infinity,
            nested: [undefined, null, true, 4.5],
        })"#,
    )?));
    let JsValue::Object(boundary) = boundary else {
        panic!("boundary result is not an object");
    };
    assert_eq!(boundary.get("unicode"), Some(&JsValue::from("🦀")));
    assert_eq!(
        boundary.get("negativeZero").and_then(JsValue::as_f64),
        Some(-0.0)
    );
    assert!(
        boundary
            .get("negativeZero")
            .and_then(JsValue::as_f64)
            .is_some_and(f64::is_sign_negative)
    );
    assert!(
        boundary
            .get("notANumber")
            .and_then(JsValue::as_f64)
            .is_some_and(f64::is_nan)
    );
    assert_eq!(
        boundary.get("infinity").and_then(JsValue::as_f64),
        Some(f64::INFINITY)
    );

    Ok(())
}

#[test]
fn parser_recursion_is_contained_by_wasm() -> wasmtime::Result<()> {
    let engine = WasmEngine::default();
    let component = Component::from_binary(
        &engine,
        include_bytes!("../engine/starling/rama-js-engine.wasm"),
    )?;
    let mut linker = Linker::new(&engine);
    bindings::Engine::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state)?;

    let sources = [
        format!("{}true{}", "(".repeat(100_000), ")".repeat(100_000)),
        format!("{}1", "1 + ".repeat(100_000)),
        format!("{}true", "!".repeat(100_000)),
        format!("let a = {{}}; {}a", "a.".repeat(100_000)),
    ];

    for source in sources {
        let mut store = Store::new(&engine, HostState::default());
        let bindings = bindings::Engine::instantiate(&mut store, &component, &linker)?;
        drop(
            bindings
                .rama_js_engine_runtime()
                .call_exec(&mut store, &source),
        );
    }

    Ok(())
}

#[test]
fn fuel_interrupts_runaway_script() -> wasmtime::Result<()> {
    let mut config = Config::new();
    config.consume_fuel(true);
    let engine = WasmEngine::new(&config)?;
    let component = Component::from_binary(
        &engine,
        include_bytes!("../engine/starling/rama-js-engine.wasm"),
    )?;
    let mut linker = Linker::new(&engine);
    bindings::Engine::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state)?;
    let mut store = Store::new(&engine, HostState::default());
    store.set_fuel(u64::MAX)?;
    let bindings = bindings::Engine::instantiate(&mut store, &component, &linker)?;
    store.set_fuel(100_000)?;

    let result = bindings
        .rama_js_engine_runtime()
        .call_exec(&mut store, "for (;;) {};");
    match result {
        Err(_) => {}
        Ok(_) => panic!("runaway script was not interrupted"),
    }
    Ok(())
}

#[test]
fn store_limit_rejects_excessive_guest_memory() -> wasmtime::Result<()> {
    let engine = WasmEngine::default();
    let component = Component::from_binary(
        &engine,
        include_bytes!("../engine/starling/rama-js-engine.wasm"),
    )?;
    let mut linker = Linker::new(&engine);
    bindings::Engine::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state)?;
    let mut store = Store::new(
        &engine,
        HostState {
            callbacks: HashMap::new(),
            limits: StoreLimitsBuilder::new()
                .memory_size(64 * 1024 * 1024)
                .trap_on_grow_failure(true)
                .build(),
        },
    );
    store.limiter(|state| &mut state.limits);
    let bindings = bindings::Engine::instantiate(&mut store, &component, &linker)?;

    let result = bindings
        .rama_js_engine_runtime()
        .call_evaluate(&mut store, "new Uint8Array(256 * 1024 * 1024)");
    assert!(result.is_err() || result.is_ok_and(|outcome| !outcome.ok));
    Ok(())
}

fn assert_ok(outcome: &Outcome) -> Result<(), String> {
    if outcome.ok {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&outcome.payload).into_owned())
    }
}

fn outcome_value(outcome: &Outcome) -> Result<JsValue, String> {
    if outcome.ok {
        decode(&outcome.payload)
    } else {
        Err(String::from_utf8_lossy(&outcome.payload).into_owned())
    }
}

#[expect(clippy::panic, reason = "test helper reports guest failures")]
fn succeed<T>(result: Result<T, String>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{error}"),
    }
}

fn encode(value: &JsValue) -> Vec<u8> {
    #[expect(clippy::panic, reason = "test values must fit the boundary format")]
    fn write_u32(output: &mut Vec<u8>, value: usize) {
        let Ok(value) = u32::try_from(value) else {
            panic!("JavaScript value is too large to encode")
        };
        output.extend_from_slice(&value.to_le_bytes());
    }

    fn write_string(output: &mut Vec<u8>, value: &str) {
        write_u32(output, value.len());
        output.extend_from_slice(value.as_bytes());
    }

    fn write_value(output: &mut Vec<u8>, value: &JsValue) {
        match value {
            JsValue::Undefined => output.push(0),
            JsValue::Null => output.push(1),
            JsValue::Bool(false) => output.push(2),
            JsValue::Bool(true) => output.push(3),
            JsValue::Number(value) => {
                output.push(4);
                output.extend_from_slice(&value.to_le_bytes());
            }
            JsValue::String(value) => {
                output.push(5);
                write_string(output, value);
            }
            JsValue::Array(value) => {
                output.push(6);
                write_u32(output, value.len());
                for value in value {
                    write_value(output, value);
                }
            }
            JsValue::Object(value) => {
                output.push(7);
                write_u32(output, value.len());
                for (key, value) in value {
                    write_string(output, key);
                    write_value(output, value);
                }
            }
        }
    }

    let mut output = Vec::new();
    write_value(&mut output, value);
    output
}

fn decode(bytes: &[u8]) -> Result<JsValue, String> {
    struct Reader<'a> {
        bytes: &'a [u8],
        offset: usize,
    }

    impl<'a> Reader<'a> {
        fn take(&mut self, length: usize) -> Result<&'a [u8], String> {
            let end = self
                .offset
                .checked_add(length)
                .filter(|end| *end <= self.bytes.len())
                .ok_or_else(|| "truncated JavaScript value".to_owned())?;
            let value = &self.bytes[self.offset..end];
            self.offset = end;
            Ok(value)
        }

        fn byte(&mut self) -> Result<u8, String> {
            Ok(self.take(1)?[0])
        }

        fn u32(&mut self) -> Result<usize, String> {
            let bytes = self.take(4)?;
            let bytes: [u8; 4] = bytes
                .try_into()
                .map_err(|error| format!("invalid u32 bytes: {error}"))?;
            Ok(u32::from_le_bytes(bytes) as usize)
        }

        fn string(&mut self) -> Result<String, String> {
            let length = self.u32()?;
            String::from_utf8(self.take(length)?.to_vec())
                .map_err(|error| format!("invalid UTF-8 JavaScript string: {error}"))
        }

        fn value(&mut self) -> Result<JsValue, String> {
            match self.byte()? {
                0 => Ok(JsValue::Undefined),
                1 => Ok(JsValue::Null),
                2 => Ok(false.into()),
                3 => Ok(true.into()),
                4 => {
                    let bytes = self.take(8)?;
                    let bytes: [u8; 8] = bytes
                        .try_into()
                        .map_err(|error| format!("invalid f64 bytes: {error}"))?;
                    Ok(f64::from_le_bytes(bytes).into())
                }
                5 => Ok(self.string()?.into()),
                6 => {
                    let length = self.u32()?;
                    let values = (0..length)
                        .map(|_| self.value())
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok(JsValue::Array(JsArray::from(values)))
                }
                7 => {
                    let length = self.u32()?;
                    let values = (0..length)
                        .map(|_| Ok((self.string()?, self.value()?)))
                        .collect::<Result<Vec<_>, String>>()?;
                    Ok(JsValue::Object(JsObject::from(values)))
                }
                _ => Err("unknown JavaScript value tag".to_owned()),
            }
        }
    }

    let mut reader = Reader { bytes, offset: 0 };
    let value = reader.value()?;
    if reader.offset != bytes.len() {
        return Err("trailing bytes after JavaScript value".to_owned());
    }
    Ok(value)
}
