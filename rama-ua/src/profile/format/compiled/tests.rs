use super::*;

const EMBEDDED: &[u8] = include_bytes!("../embed_profiles.bin");

fn frame(set: &impl Serialize) -> Vec<u8> {
    let mut output = MAGIC.to_vec();
    let mut encoder = zstd::Encoder::new(&mut output, 1).unwrap();
    encoder
        .write_all(&postcard::to_allocvec(set).unwrap())
        .unwrap();
    encoder.finish().unwrap();
    output
}

#[test]
fn embedded_set_round_trips_exactly() {
    let profiles = decode_compiled_profiles(EMBEDDED).unwrap();
    assert!(!profiles.is_empty());
    let encoded = encode_compiled_profiles(&profiles).unwrap();
    assert!(is_compiled_profile_set(&encoded));
    // Deterministic output: re-encoding the embedded analysis reproduces the file.
    assert_eq!(encoded, EMBEDDED);
    let decoded = decode_compiled_profiles(&encoded).unwrap();
    assert_eq!(
        serde_json::to_value(&decoded).unwrap(),
        serde_json::to_value(&profiles).unwrap()
    );
    assert_eq!(
        try_load_compiled_profiles(EMBEDDED).unwrap().len(),
        profiles.len()
    );
}

#[test]
fn foreign_stale_empty_and_corrupt_sets_are_refused() {
    decode_compiled_profiles(b"not a profile set").unwrap_err();
    decode_compiled_profiles(&EMBEDDED[MAGIC.len()..]).unwrap_err();
    let profiles = decode_compiled_profiles(EMBEDDED).unwrap();
    // A well-formed set from another classifier revision is refused by that check alone.
    let current = frame(&CompiledProfileSet {
        classifier_revision: PROFILE_CLASSIFIER_REVISION,
        profiles: &profiles[..1],
    });
    assert_eq!(decode_compiled_profiles(&current).unwrap().len(), 1);
    let stale = frame(&CompiledProfileSet {
        classifier_revision: PROFILE_CLASSIFIER_REVISION - 1,
        profiles: &profiles[..1],
    });
    let error = decode_compiled_profiles(&stale).unwrap_err();
    assert!(error.to_string().contains("classifier revision"), "{error}");
    let empty = frame(&CompiledProfileSet {
        classifier_revision: PROFILE_CLASSIFIER_REVISION,
        profiles: Vec::<AnalyzedProfile>::new(),
    });
    let error = decode_compiled_profiles(&empty).unwrap_err();
    assert!(error.to_string().contains("profiles"), "{error}");
    encode_compiled_profiles(&[]).unwrap_err();
    let mut corrupt = EMBEDDED.to_vec();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    decode_compiled_profiles(&corrupt).unwrap_err();
    decode_compiled_profiles(&EMBEDDED[..EMBEDDED.len() / 2]).unwrap_err();
}
