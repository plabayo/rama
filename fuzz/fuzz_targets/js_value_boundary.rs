//! Fuzz the complete engine-agnostic value boundary.
//!
//! A bounded, acyclic [`JsValue`] crosses all four relevant boundaries:
//! Rust -> Boa -> host `JsValue` -> Boa -> Rust. The target deliberately does
//! not evaluate arbitrary JavaScript; its fixed expression only calls `echo`.
//!
//! Invariants:
//! - every generated public value can cross the boundary without an error;
//! - the final snapshot is semantically equal to the original value;
//! - object key reordering, NaN payload canonicalization, and signed zero do
//!   not produce false positives.
//!
//! Run with:
//!     cargo +nightly fuzz run js_value_boundary -- -max_len=16384
#![no_main]

use libfuzzer_sys::{
    arbitrary::{self, Arbitrary, Unstructured},
    fuzz_target,
};
use rama_js::{JsObject, JsRuntime, JsValue, Serde};

/// Boa's collector is thread-local and normally collects at its allocation
/// threshold. libFuzzer checks for leaks between inputs, before that collector
/// is torn down, so collect after this iteration's runtime has been dropped.
#[cfg(fuzzing)]
struct CollectEngineGarbage;

#[cfg(fuzzing)]
impl Drop for CollectEngineGarbage {
    fn drop(&mut self) {
        rama_js::force_collect_for_fuzzing();
    }
}

/// Matches the runtime's default snapshot depth limit, so near-limit and
/// exactly-at-limit nesting is exercised.
const MAX_DEPTH: usize = 64;
const MAX_NODES: usize = 128;
const MAX_CONTAINER_LEN: usize = 12;
const MAX_STRING_BYTES: usize = 128;

#[derive(Debug)]
struct Input {
    value: JsValue,
}

impl<'a> Arbitrary<'a> for Input {
    fn arbitrary(input: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let mut nodes_left = MAX_NODES;
        Ok(Self {
            value: arbitrary_value(input, 0, &mut nodes_left)?,
        })
    }
}

fn arbitrary_value(
    input: &mut Unstructured<'_>,
    depth: usize,
    nodes_left: &mut usize,
) -> arbitrary::Result<JsValue> {
    if *nodes_left == 0 {
        return Ok(JsValue::Undefined);
    }
    *nodes_left -= 1;

    let tag = input.arbitrary::<u8>()?;
    let scalar_only = depth >= MAX_DEPTH || *nodes_left == 0;
    match tag % if scalar_only { 6 } else { 8 } {
        0 => Ok(JsValue::Undefined),
        1 => Ok(JsValue::Null),
        2 => Ok(JsValue::Bool(tag & 0x80 != 0)),
        3 => Ok(JsValue::Number(arbitrary_number(input)?)),
        4 | 5 => Ok(JsValue::from(arbitrary_value_string(input)?)),
        6 => arbitrary_array(input, depth, nodes_left),
        _ => arbitrary_object(input, depth, nodes_left),
    }
}

fn arbitrary_array(
    input: &mut Unstructured<'_>,
    depth: usize,
    nodes_left: &mut usize,
) -> arbitrary::Result<JsValue> {
    let requested = usize::from(input.arbitrary::<u8>()?) % (MAX_CONTAINER_LEN + 1);
    let len = requested.min(*nodes_left);
    let mut values = Vec::with_capacity(len);
    for _ in 0..len {
        if *nodes_left == 0 {
            break;
        }
        values.push(arbitrary_value(input, depth + 1, nodes_left)?);
    }
    Ok(JsValue::Array(values.into()))
}

fn arbitrary_object(
    input: &mut Unstructured<'_>,
    depth: usize,
    nodes_left: &mut usize,
) -> arbitrary::Result<JsValue> {
    let requested = usize::from(input.arbitrary::<u8>()?) % (MAX_CONTAINER_LEN + 1);
    let len = requested.min(*nodes_left);
    let mut entries = Vec::with_capacity(len);

    for _ in 0..len {
        if *nodes_left == 0 {
            break;
        }
        // duplicate keys are deliberately kept: JsObject collapses them
        let key = arbitrary_key(input)?;
        let value = arbitrary_value(input, depth + 1, nodes_left)?;
        entries.push((key, value));
    }

    Ok(JsValue::Object(entries.into_iter().collect()))
}

fn arbitrary_key(input: &mut Unstructured<'_>) -> arbitrary::Result<String> {
    let selector = input.arbitrary::<u8>()?;
    Ok(match selector % 12 {
        0 => String::new(),
        1 => "__proto__".to_owned(),
        2 => "constructor".to_owned(),
        3 => "prototype".to_owned(),
        4 => "0".to_owned(),
        5 => "1".to_owned(),
        6 => "01".to_owned(),
        7 => "4294967294".to_owned(),
        8 => "4294967295".to_owned(),
        9 => "\0".to_owned(),
        _ => arbitrary_string(input)?,
    })
}

fn arbitrary_string(input: &mut Unstructured<'_>) -> arbitrary::Result<String> {
    let requested = usize::from(input.arbitrary::<u8>()?) % (MAX_STRING_BYTES + 1);
    let bytes = input.bytes(requested.min(input.len()))?;
    Ok(String::from_utf8_lossy(bytes).into_owned())
}

fn arbitrary_value_string(input: &mut Unstructured<'_>) -> arbitrary::Result<String> {
    let selector = input.arbitrary::<u8>()?;
    Ok(match selector % 8 {
        0 => String::new(),
        1 => "\0".to_owned(),
        2 => "éÿ".to_owned(),
        3 => "🦀".to_owned(),
        4 => "quote: \"' slash: \\ newline:\n".to_owned(),
        _ => arbitrary_string(input)?,
    })
}

fn arbitrary_number(input: &mut Unstructured<'_>) -> arbitrary::Result<f64> {
    let selector = input.arbitrary::<u8>()?;
    Ok(match selector % 14 {
        0 => 0.0,
        1 => -0.0,
        2 => f64::NAN,
        3 => f64::INFINITY,
        4 => f64::NEG_INFINITY,
        5 => 9_007_199_254_740_991.0,
        6 => -9_007_199_254_740_991.0,
        7 => f64::MIN,
        8 => f64::MAX,
        9 => f64::MIN_POSITIVE,
        10 => f64::EPSILON,
        _ => f64::from_bits(input.arbitrary()?),
    })
}

fn semantically_equal(expected: &JsValue, actual: &JsValue) -> bool {
    match (expected, actual) {
        (JsValue::Undefined, JsValue::Undefined) | (JsValue::Null, JsValue::Null) => true,
        (JsValue::Bool(left), JsValue::Bool(right)) => left == right,
        (JsValue::Number(left), JsValue::Number(right)) => {
            normalized_number_bits(*left) == normalized_number_bits(*right)
        }
        (JsValue::String(left), JsValue::String(right)) => left == right,
        (JsValue::Array(left), JsValue::Array(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .zip(right.iter())
                    .all(|(left, right)| semantically_equal(left, right))
        }
        (JsValue::Object(left), JsValue::Object(right)) => objects_equal(left, right),
        _ => false,
    }
}

fn normalized_number_bits(value: f64) -> u64 {
    const SIGNLESS_MASK: u64 = 0x7fff_ffff_ffff_ffff;

    let bits = value.to_bits();
    if value.is_nan() {
        f64::NAN.to_bits()
    } else if bits & SIGNLESS_MASK == 0 {
        0
    } else {
        bits
    }
}

fn objects_equal(expected: &JsObject, actual: &JsObject) -> bool {
    expected.len() == actual.len()
        && expected.iter().all(|(key, expected_value)| {
            actual
                .get(key.as_str())
                .is_some_and(|actual_value| semantically_equal(expected_value, actual_value))
        })
}

fuzz_target!(|input: Input| {
    #[cfg(fuzzing)]
    let _collect_engine_garbage = CollectEngineGarbage;
    let expected = input.value;
    let runtime = JsRuntime::builder()
        .with_global("input", expected.clone())
        .with_fn("echo", |value: JsValue| value)
        .build();
    assert!(
        runtime.is_ok(),
        "a bounded public JsValue should be a valid runtime global: {:?}",
        runtime.as_ref().err()
    );
    let Ok(mut runtime) = runtime else {
        return;
    };

    let actual = runtime.eval("echo(input)");
    assert!(
        actual.is_ok(),
        "a bounded public JsValue should cross the host boundary: {:?}",
        actual.as_ref().err()
    );
    let Ok(actual) = actual else {
        return;
    };

    assert!(
        semantically_equal(&expected, &actual),
        "value changed across the JS boundary\nexpected: {expected:?}\nactual: {actual:?}"
    );

    // serde round-trip; `undefined` lowers to `null` by design (unit)
    let serialized = JsValue::try_from(Serde(actual.clone()));
    assert!(
        serialized.is_ok(),
        "a bounded public JsValue should serialize: {:?}",
        serialized.as_ref().err()
    );
    let Ok(serialized) = serialized else {
        return;
    };
    let lowered = lower_undefined(&actual);
    assert!(
        semantically_equal(&lowered, &serialized),
        "value changed through the serde serializer\nexpected: {lowered:?}\nactual: {serialized:?}"
    );

    let deserialized = serialized.deserialize_into::<JsValue>();
    assert!(
        deserialized.is_ok(),
        "a serialized JsValue should deserialize: {:?}",
        deserialized.as_ref().err()
    );
    let Ok(deserialized) = deserialized else {
        return;
    };
    assert!(
        semantically_equal(&serialized, &deserialized),
        "value changed through the serde deserializer\nexpected: {serialized:?}\nactual: {deserialized:?}"
    );
});

/// The serde layer maps `Undefined` to unit, which round-trips as `Null`.
fn lower_undefined(value: &JsValue) -> JsValue {
    match value {
        JsValue::Undefined => JsValue::Null,
        JsValue::Array(arr) => JsValue::Array(arr.iter().map(lower_undefined).collect()),
        JsValue::Object(obj) => JsValue::Object(
            obj.iter()
                .map(|(key, value)| (key.clone(), lower_undefined(value)))
                .collect(),
        ),
        other => other.clone(),
    }
}
