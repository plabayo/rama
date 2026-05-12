use super::*;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};

fn round_trip<T>(value: &T) -> T
where
    T: Serialize + for<'de> Deserialize<'de> + fmt::Debug + PartialEq,
{
    let msg = to_xpc_message(value).unwrap();
    let got: T = from_xpc_message(msg).unwrap();
    got
}

#[test]
fn primitives_round_trip() {
    assert!(round_trip(&true));
    assert!(!round_trip(&false));
    assert_eq!(round_trip(&42i64), 42i64);
    assert_eq!(round_trip(&u64::MAX), u64::MAX);
    assert_eq!(round_trip(&1.5f64), 1.5f64);
    assert_eq!(round_trip(&"hello".to_owned()), "hello".to_owned());
}

#[test]
fn option_round_trip() {
    let none: Option<i64> = None;
    let some: Option<i64> = Some(7);
    assert_eq!(round_trip(&none), none);
    assert_eq!(round_trip(&some), some);
}

#[test]
fn vec_round_trip() {
    let v = vec![1i64, 2, 3];
    assert_eq!(round_trip(&v), v);
}

#[test]
fn struct_round_trip() {
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Settings {
        enabled: bool,
        label: String,
        count: i64,
    }

    let s = Settings {
        enabled: true,
        label: "test".to_owned(),
        count: -5,
    };
    assert_eq!(round_trip(&s), s);

    // Verify the XpcMessage shape is a Dictionary
    let msg = to_xpc_message(&s).unwrap();
    assert!(matches!(msg, XpcMessage::Dictionary(_)));
}

#[test]
fn nested_struct_round_trip() {
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Inner {
        x: i64,
    }
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Outer {
        inner: Inner,
        tags: Vec<String>,
    }
    let o = Outer {
        inner: Inner { x: 99 },
        tags: vec!["a".to_owned(), "b".to_owned()],
    };
    assert_eq!(round_trip(&o), o);
}

#[test]
fn unit_enum_round_trip() {
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    enum Color {
        Red,
        Green,
        Blue,
    }
    assert_eq!(round_trip(&Color::Red), Color::Red);
    assert_eq!(round_trip(&Color::Blue), Color::Blue);
}

#[test]
fn newtype_variant_round_trip() {
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    enum Msg {
        Text(String),
        Count(i64),
    }
    let msg = Msg::Text("hello".to_owned());
    let xpc = to_xpc_message(&msg).unwrap();
    // Should be Dictionary with one key
    if let XpcMessage::Dictionary(ref d) = xpc {
        assert!(d.contains_key("Text"));
    } else {
        panic!("expected Dictionary, got {xpc:?}");
    }
    assert_eq!(from_xpc_message::<Msg>(xpc).unwrap(), msg);
}

#[test]
fn map_key_must_be_string() {
    let mut m: BTreeMap<i64, String> = BTreeMap::new();
    m.insert(1, "one".to_owned());
    to_xpc_message(&m).unwrap_err();
}

#[test]
fn bytes_round_trip() {
    let data: Vec<u8> = vec![0, 1, 2, 255];
    let xpc = to_xpc_message(&data).unwrap();
    // Vec<u8> serializes as a seq of integers, not bytes
    // (serde does not call serialize_bytes for Vec<u8> by default)
    let got: Vec<u8> = from_xpc_message(xpc).unwrap();
    assert_eq!(got, data);
}
