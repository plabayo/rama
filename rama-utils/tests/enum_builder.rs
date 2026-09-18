mod nested {
    rama_utils::macros::enums::enum_builder! {
        @Bytes
        pub enum ByteEnum {
            Known => b"known",
        }
    }

    rama_utils::macros::enums::enum_builder! {
        @U16
        pub enum NumberEnum {
            Known => 7,
        }
    }
}

#[test]
fn bytes_enum_expands_without_caller_imports() {
    let unknown = nested::ByteEnum::from("unknown");
    assert_eq!(unknown.as_bytes(), b"unknown");

    let encoded = serde_json::to_vec(&unknown).unwrap();
    assert_eq!(
        serde_json::from_slice::<nested::ByteEnum>(&encoded).unwrap(),
        unknown
    );
}

#[test]
fn numeric_enum_expands_without_caller_imports() {
    let known = nested::NumberEnum::from(7);
    assert_eq!(known, nested::NumberEnum::Known);
    assert_eq!(known.variant_name(), "Known");
    assert_eq!(nested::NumberEnum::from(8).variant_name(), "8");
}
