mod nested {
    rama_utils::macros::enums::enum_builder! {
        /// Strict enums are not `Copy` by default; a caller can opt in.
        #[derive(Copy)]
        @String
        #[strict]
        pub enum StrictEnum {
            Known => "known" | "alias",
            Other => "other",
        }
    }

    rama_utils::macros::enums::enum_builder! {
        @Bytes
        #[strict]
        pub enum StrictByteEnum {
            Known => b"known",
        }
    }

    rama_utils::macros::enums::enum_builder! {
        @U16
        #[strict]
        pub enum StrictNumberEnum {
            Small => 1,
            Large => 300,
        }
    }

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

    rama_utils::macros::enums::enum_builder! {
        @String
        pub enum TextEnum {
            Known => "known" | "alias",
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

#[test]
fn lenient_string_enum_matches_owned_strings_exactly() {
    use nested::TextEnum;

    // A borrowed string matches ignoring ASCII case and surrounding whitespace.
    for s in ["known", "KNOWN", " known ", "Alias"] {
        assert_eq!(TextEnum::from(s), TextEnum::Known, "{s:?}");
        assert_eq!(s.parse::<TextEnum>().unwrap(), TextEnum::Known, "{s:?}");
    }
    // An owned string only matches a value exactly.
    assert_eq!(TextEnum::from("known".to_owned()), TextEnum::Known);
    assert_eq!(TextEnum::from("alias".to_owned()), TextEnum::Known);
    for s in ["KNOWN", " known "] {
        assert_eq!(
            TextEnum::from(s.to_owned()),
            TextEnum::Unknown(s.into()),
            "{s:?}"
        );
    }
}

#[test]
fn strict_string_enum_expands_without_caller_imports() {
    use nested::StrictEnum;

    assert_eq!("known".parse::<StrictEnum>(), Ok(StrictEnum::Known));
    assert_eq!("ALIAS".parse::<StrictEnum>(), Ok(StrictEnum::Known));
    assert_eq!(StrictEnum::try_from("other"), Ok(StrictEnum::Other));
    assert_eq!(StrictEnum::strict_parse("nope"), None);

    let error = "nope".parse::<StrictEnum>().unwrap_err();
    assert_eq!(error.enum_name(), "StrictEnum");
    assert_eq!(error.to_string(), "unknown StrictEnum value");

    let known = StrictEnum::Known;
    let copied = known;
    assert_eq!(known.as_str(), "known");
    assert_eq!(copied.to_string(), "known");
    assert_eq!(known.as_static_str(), "known");
    assert_eq!(known.as_smol_str(), "known");

    assert_eq!(serde_json::to_string(&known).unwrap(), "\"known\"");
    assert_eq!(
        serde_json::from_str::<StrictEnum>("\"alias\"").unwrap(),
        known
    );
    let error = serde_json::from_str::<StrictEnum>("\"nope\"").unwrap_err();
    assert!(
        error.to_string().contains("unknown StrictEnum value"),
        "{error}"
    );
}

#[test]
fn strict_bytes_enum_expands_without_caller_imports() {
    use nested::StrictByteEnum;

    assert_eq!(
        StrictByteEnum::try_from(&b"known"[..]),
        Ok(StrictByteEnum::Known)
    );
    assert_eq!(StrictByteEnum::try_from("known"), Ok(StrictByteEnum::Known));
    assert_eq!("known".parse::<StrictByteEnum>(), Ok(StrictByteEnum::Known));
    let error = StrictByteEnum::try_from("nope").unwrap_err();
    assert_eq!(error.enum_name(), "StrictByteEnum");

    let known = StrictByteEnum::Known;
    assert_eq!(known.as_bytes(), b"known");
    assert_eq!(known.try_as_str(), Some("known"));
    assert_eq!(Vec::<u8>::from(&known), b"known");
    assert_eq!(known.to_string(), "known");

    let encoded = serde_json::to_vec(&known).unwrap();
    assert_eq!(
        serde_json::from_slice::<StrictByteEnum>(&encoded).unwrap(),
        known
    );
    serde_json::from_str::<StrictByteEnum>("[110,111]").unwrap_err();
}

#[test]
fn strict_numeric_enum_expands_without_caller_imports() {
    use nested::StrictNumberEnum;

    assert_eq!(StrictNumberEnum::try_from(300), Ok(StrictNumberEnum::Large));
    let error = StrictNumberEnum::try_from(2).unwrap_err();
    assert_eq!(error.to_string(), "unknown StrictNumberEnum value");

    assert_eq!(u16::from(StrictNumberEnum::Large), 300);
    assert!(StrictNumberEnum::Small < StrictNumberEnum::Large);
    assert_eq!(StrictNumberEnum::Large.variant_name(), "Large");
    assert_eq!(StrictNumberEnum::Large.to_string(), "Large (0x012c)");
    assert_eq!(format!("{:x}", StrictNumberEnum::Large), "12c");

    assert_eq!(
        serde_json::to_string(&StrictNumberEnum::Small).unwrap(),
        "1"
    );
    assert_eq!(
        serde_json::from_str::<StrictNumberEnum>("300").unwrap(),
        StrictNumberEnum::Large
    );
    serde_json::from_str::<StrictNumberEnum>("2").unwrap_err();
}
