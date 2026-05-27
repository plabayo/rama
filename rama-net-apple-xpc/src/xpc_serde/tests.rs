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
fn xpc_uuid_round_trips_as_uuid_variant() {
    use crate::XpcUuid;

    let bytes: [u8; 16] = std::array::from_fn(|i| (i as u8).wrapping_mul(17).wrapping_add(3));
    let uuid = XpcUuid(bytes);

    let msg = to_xpc_message(&uuid).expect("serialize");
    assert!(
        matches!(msg, XpcMessage::Uuid(b) if b == bytes),
        "XpcUuid must serialize as XpcMessage::Uuid, got {msg:?}",
    );

    let back: XpcUuid = from_xpc_message(msg).expect("deserialize");
    assert_eq!(back, uuid);
}

#[test]
fn xpc_uuid_accepts_data_of_16_bytes_on_deser() {
    use crate::XpcUuid;

    let bytes = vec![7u8; 16];
    let msg = XpcMessage::Data(bytes.clone());
    let uuid: XpcUuid = from_xpc_message(msg).expect("deserialize Data->Uuid");
    assert_eq!(uuid.0, bytes.as_slice());
}

#[test]
fn xpc_uuid_rejects_non_uuid_input() {
    use crate::XpcUuid;
    let err = from_xpc_message::<XpcUuid>(XpcMessage::Null).unwrap_err();
    assert!(err.to_string().to_lowercase().contains("uuid"));
}

#[test]
fn xpc_uuid_nested_in_struct_round_trips() {
    use crate::XpcUuid;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct WithUuid {
        id: XpcUuid,
        name: String,
    }

    let v = WithUuid {
        id: XpcUuid([0xAB; 16]),
        name: "alice".to_owned(),
    };

    let msg = to_xpc_message(&v).expect("serialize");
    // The outer dictionary holds an XpcMessage::Uuid for the `id` field.
    if let XpcMessage::Dictionary(ref map) = msg {
        assert!(matches!(map.get("id"), Some(XpcMessage::Uuid(_))));
    } else {
        panic!("expected Dictionary, got {msg:?}");
    }

    let back: WithUuid = from_xpc_message(msg).expect("deserialize");
    assert_eq!(back, v);
}

#[test]
fn xpc_uuid_inside_vec_round_trips() {
    use crate::XpcUuid;
    let v = vec![XpcUuid([1; 16]), XpcUuid([2; 16]), XpcUuid([3; 16])];
    let back: Vec<XpcUuid> = round_trip(&v);
    assert_eq!(back, v);
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
