mod nested {
    rama_utils::macros::enums::enum_builder! {
        @Bytes
        pub enum ByteEnum {
            Known => b"known",
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
