use super::*;
use crate::profile::capture::joint::{JointCapture, JointCaptureLimits};

const EMBEDDED: &[u8] = include_bytes!("../embed_profiles.bin");

fn frame(set: &impl Serialize) -> Vec<u8> {
    let encoded = postcard::to_allocvec(set).unwrap();
    let mut output = MAGIC.to_vec();
    let mut encoder = zstd::Encoder::new(&mut output, 1).unwrap();
    encoder
        .set_pledged_src_size(Some(encoded.len() as u64))
        .unwrap();
    encoder.write_all(&encoded).unwrap();
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

#[test]
fn sets_without_a_content_size_are_refused() {
    let profiles = decode_compiled_profiles(EMBEDDED).unwrap();
    let mut unsized_frame = MAGIC.to_vec();
    let mut encoder = zstd::Encoder::new(&mut unsized_frame, 1).unwrap();
    encoder
        .write_all(
            &postcard::to_allocvec(&CompiledProfileSet {
                classifier_revision: PROFILE_CLASSIFIER_REVISION,
                profiles: &profiles[..1],
            })
            .unwrap(),
        )
        .unwrap();
    encoder.finish().unwrap();
    let error = decode_compiled_profiles(&unsized_frame).unwrap_err();
    assert!(error.to_string().contains("content size"), "{error}");
}

fn shares_buffer(inner: &[u8], outer: &[u8]) -> bool {
    let range = outer.as_ptr_range();
    range.contains(&inner.as_ptr()) && inner.len() <= outer.len()
}

#[test]
fn components_held_by_a_joint_capture_are_stored_once_and_share_its_bytes() {
    let profiles = decode_compiled_profiles(EMBEDDED).unwrap();
    let mut shared = 0;
    for profile in &profiles {
        let joints: Vec<&CanonicalValue> = profile
            .scopes
            .iter()
            .filter(|scope| scope.observations.domain == CanonicalDomain::Joint)
            .flat_map(|scope| {
                scope
                    .observations
                    .variants
                    .iter()
                    .map(|variant| &variant.value)
            })
            .collect();
        for scope in profile.scopes.iter() {
            if scope.observations.domain == CanonicalDomain::Joint {
                continue;
            }
            for variant in scope.observations.variants.iter() {
                assert!(!variant.value.bytes.is_empty());
                if joints
                    .iter()
                    .any(|joint| shares_buffer(&variant.value.bytes, &joint.bytes))
                {
                    shared += 1;
                }
            }
        }
    }
    assert!(shared > 1000, "components share joint buffers: {shared}");

    // Repeats travel as an id alone, so the stored set is far smaller than its values.
    let plain = postcard::to_allocvec(&CompiledProfileSet {
        classifier_revision: PROFILE_CLASSIFIER_REVISION,
        profiles: &profiles,
    })
    .unwrap();
    let compact = postcard::to_allocvec(&CompiledProfileSet {
        classifier_revision: PROFILE_CLASSIFIER_REVISION,
        profiles: &without_repeated_values(&profiles),
    })
    .unwrap();
    assert!(
        compact.len() * 4 < plain.len() * 3,
        "{} of {}",
        compact.len(),
        plain.len()
    );
}

#[test]
fn a_repeat_of_an_unknown_value_is_refused() {
    let profiles = decode_compiled_profiles(EMBEDDED).unwrap();
    let mut profile = without_repeated_values(&profiles[..1]).remove(0);
    let value = &mut profile.scopes[0].structure;
    value.id = ValueId([0xee; 32]);
    value.bytes = Bytes::new();
    let error = decode_compiled_profiles(&frame(&CompiledProfileSet {
        classifier_revision: PROFILE_CLASSIFIER_REVISION,
        profiles: vec![profile],
    }))
    .unwrap_err();
    assert!(error.to_string().contains("value reference"), "{error}");
}

#[test]
fn trusted_slot_split_matches_validated_joint_decoding() {
    let profiles = decode_compiled_profiles(EMBEDDED).unwrap();
    let mut joints = 0;
    for variant in profiles
        .iter()
        .flat_map(|profile| profile.scopes.iter())
        .filter(|scope| scope.observations.domain == CanonicalDomain::Joint)
        .flat_map(|scope| scope.observations.variants.iter())
    {
        let split = joint_slot_values(&variant.value).unwrap();
        let validated =
            JointCapture::from_canonical(&variant.value, JointCaptureLimits::default()).unwrap();
        assert_eq!(split.len(), validated.slots.len());
        for (split, slot) in split.iter().zip(validated.slots.iter()) {
            assert_eq!(split.id, slot.value.id);
            assert_eq!(split.bytes, slot.value.bytes);
            assert!(shares_buffer(&split.bytes, &variant.value.bytes));
        }
        joints += 1;
    }
    assert!(joints > 1000);
}
