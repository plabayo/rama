use ahash::HashMap;
use rama_js::{JsRuntime, JsValue, Serde};
use rama_net::address::Host;
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
enum Mode {
    Direct,
    Proxy { host: Host, port: u16 },
    Chain(Vec<String>),
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Settings {
    name: String,
    retries: Option<u8>,
    mode: Mode,
    tags: Vec<String>,
}

#[test]
fn serde_roundtrip_through_script() {
    let mut runtime = JsRuntime::builder()
        .with_fn("passthrough", |Serde(settings): Serde<Settings>| {
            Serde(settings)
        })
        .build()
        .unwrap();

    runtime
        .eval("function relabel(settings) { settings.name = 'relabeled'; return passthrough(settings); }")
        .unwrap();

    let input = Settings {
        name: "original".to_owned(),
        retries: Some(3),
        mode: Mode::Proxy {
            host: Host::from_static("proxy.local"),
            port: 8080,
        },
        tags: vec!["a".to_owned(), "b".to_owned()],
    };

    let input_value = JsValue::try_from(Serde(input)).unwrap();
    let result = runtime.call("relabel", [input_value]).unwrap();
    let output: Settings = result.deserialize_into().unwrap();

    assert_eq!(
        output,
        Settings {
            name: "relabeled".to_owned(),
            retries: Some(3),
            mode: Mode::Proxy {
                host: Host::from_static("proxy.local"),
                port: 8080,
            },
            tags: vec!["a".to_owned(), "b".to_owned()],
        }
    );
}

#[test]
fn serde_enum_representations() {
    let unit: Mode = JsValue::from("Direct").deserialize_into().unwrap();
    assert_eq!(unit, Mode::Direct);

    let newtype_value = JsValue::try_from(Serde(Mode::Chain(vec!["a".to_owned()]))).unwrap();
    let newtype: Mode = newtype_value.deserialize_into().unwrap();
    assert_eq!(newtype, Mode::Chain(vec!["a".to_owned()]));
}

#[test]
fn serde_integer_keyed_maps_roundtrip() {
    let input: HashMap<u16, String> = [(8080, "proxy".to_owned()), (443, "tls".to_owned())]
        .into_iter()
        .collect();

    let value = JsValue::try_from(Serde(input.clone())).unwrap();
    let output: HashMap<u16, String> = value.deserialize_into().unwrap();
    assert_eq!(output, input);

    let signed: HashMap<i32, bool> = JsValue::try_from(Serde(
        [(-1, true), (0, false)]
            .into_iter()
            .collect::<HashMap<_, _>>(),
    ))
    .unwrap()
    .deserialize_into()
    .unwrap();
    assert_eq!(signed, [(-1, true), (0, false)].into_iter().collect());
}

#[test]
fn serde_missing_field_fails_conversion() {
    let value = JsValue::Object([("name", "incomplete")].into_iter().collect());
    let err = value.deserialize_into::<Settings>().unwrap_err();
    assert!(err.message().contains("mode"), "{}", err.message());
}

#[test]
fn serde_unsafe_integer_fails() {
    let err = JsValue::try_from(Serde(u64::MAX)).unwrap_err();
    assert!(
        err.message().contains("cannot be represented"),
        "{}",
        err.message()
    );
}

#[test]
fn serde_preserves_negative_zero() {
    let value: f64 = JsValue::Number(-0.0).deserialize_into().unwrap();
    assert_eq!(value.to_bits(), (-0.0f64).to_bits());
}
