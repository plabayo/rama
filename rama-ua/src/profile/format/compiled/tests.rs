use super::*;
#[cfg(feature = "tls")]
use crate::profile::capture::joint::{JointCapture, JointCaptureLimits};
use crate::profile::{analysis::capture::VariantValue, replay::request::CompactCapture};

const EMBEDDED: &[u8] = include_bytes!("../embed_profiles.bin");

fn frame(set: &impl Serialize) -> Vec<u8> {
    let encoded = postcard::to_allocvec(set).unwrap();
    let mut output = MAGIC.to_vec();
    output.push(FORMAT_VERSION);
    let mut encoder = zstd::Encoder::new(&mut output, 1).unwrap();
    encoder
        .set_pledged_src_size(Some(encoded.len() as u64))
        .unwrap();
    encoder.write_all(&encoded).unwrap();
    encoder.finish().unwrap();
    output
}

fn compiled(profiles: &[AnalyzedProfile]) -> Vec<CompiledProfile> {
    profiles
        .iter()
        .map(|profile| compile_profile(profile).unwrap())
        .collect()
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
fn compact_captures_rebuild_their_canonical_bytes_and_share_a_field_table() {
    let profiles = decode_compiled_profiles(EMBEDDED).unwrap();
    let mut compact = 0;
    for profile in &profiles {
        let mut first: Option<&CompactCapture> = None;
        for scope in profile.scopes.iter() {
            let compactable = (scope.flow.is_some()
                && scope.observations.domain == CanonicalDomain::Joint)
                || scope.observations.domain == CanonicalDomain::Headers;
            for variant in scope.observations.variants.iter() {
                let VariantValue::Compact(capture) = &variant.value else {
                    assert!(!compactable, "request and header captures load compact");
                    continue;
                };
                // `canonical` checks the rebuilt bytes hash to the stored id.
                let rebuilt = capture.canonical().unwrap();
                assert_eq!(rebuilt.id, variant.value.id());
                let first = *first.get_or_insert(capture);
                assert!(first.shares_fields_with(capture));
                compact += 1;
            }
        }
    }
    assert!(compact > 10_000, "{compact}");
}

#[test]
fn foreign_stale_empty_and_corrupt_sets_are_refused() {
    decode_compiled_profiles(b"not a profile set").unwrap_err();
    decode_compiled_profiles(&EMBEDDED[MAGIC.len()..]).unwrap_err();
    let profiles = decode_compiled_profiles(EMBEDDED).unwrap();
    // A well-formed set from another classifier revision is refused by that check alone.
    let current = frame(&CompiledProfileSet {
        classifier_revision: PROFILE_CLASSIFIER_REVISION,
        profiles: compiled(&profiles[..1]),
    });
    assert_eq!(decode_compiled_profiles(&current).unwrap().len(), 1);
    let mut previous = current;
    previous[MAGIC.len()] = FORMAT_VERSION - 1;
    assert!(is_compiled_profile_set(&previous));
    let error = decode_compiled_profiles(&previous).unwrap_err();
    assert!(error.to_string().contains("format version"), "{error}");
    let stale = frame(&CompiledProfileSet {
        classifier_revision: PROFILE_CLASSIFIER_REVISION - 1,
        profiles: compiled(&profiles[..1]),
    });
    let error = decode_compiled_profiles(&stale).unwrap_err();
    assert!(error.to_string().contains("classifier revision"), "{error}");
    let empty = frame(&CompiledProfileSet {
        classifier_revision: PROFILE_CLASSIFIER_REVISION,
        profiles: Vec::<CompiledProfile>::new(),
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
    unsized_frame.push(FORMAT_VERSION);
    let mut encoder = zstd::Encoder::new(&mut unsized_frame, 1).unwrap();
    encoder
        .write_all(
            &postcard::to_allocvec(&CompiledProfileSet {
                classifier_revision: PROFILE_CLASSIFIER_REVISION,
                profiles: compiled(&profiles[..1]),
            })
            .unwrap(),
        )
        .unwrap();
    encoder.finish().unwrap();
    let error = decode_compiled_profiles(&unsized_frame).unwrap_err();
    assert!(error.to_string().contains("content size"), "{error}");
}

#[test]
fn compact_and_repeated_values_shrink_the_stored_set() {
    let profiles = decode_compiled_profiles(EMBEDDED).unwrap();
    // Canonical captures serialize in full, as archives store them.
    let plain = postcard::to_allocvec(&CompiledProfileSet {
        classifier_revision: PROFILE_CLASSIFIER_REVISION,
        profiles: &profiles,
    })
    .unwrap();
    let stored = postcard::to_allocvec(&CompiledProfileSet {
        classifier_revision: PROFILE_CLASSIFIER_REVISION,
        profiles: without_repeated_values(compiled(&profiles)),
    })
    .unwrap();
    assert!(
        stored.len() * 2 < plain.len(),
        "{} of {}",
        stored.len(),
        plain.len()
    );
}

#[test]
fn a_repeat_of_an_unknown_value_is_refused() {
    let profiles = decode_compiled_profiles(EMBEDDED).unwrap();
    let mut profile = without_repeated_values(compiled(&profiles[..1])).remove(0);
    let value = &mut profile.analysis.scopes[0].structure;
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
fn one_id_stored_with_different_bytes_is_refused() {
    let profiles = decode_compiled_profiles(EMBEDDED).unwrap();
    let mut set = without_repeated_values(compiled(&profiles[..2]));
    let stored = |value: &&mut CanonicalValue| !value.bytes.is_empty();
    let id = set[0].values_mut().into_iter().find(stored).unwrap().id;
    let value = set[1].values_mut().into_iter().find(stored).unwrap();
    assert_ne!(value.id, id);
    value.id = id;
    let error = decode_compiled_profiles(&frame(&CompiledProfileSet {
        classifier_revision: PROFILE_CLASSIFIER_REVISION,
        profiles: set,
    }))
    .unwrap_err();
    assert!(error.to_string().contains("conflicting value"), "{error}");
}

#[cfg(feature = "tls")]
fn shares_buffer(inner: &[u8], outer: &[u8]) -> bool {
    let range = outer.as_ptr_range();
    range.contains(&inner.as_ptr()) && inner.len() <= outer.len()
}

// Validating the embedded TLS slots needs TLS support; the split itself does not.
#[cfg(feature = "tls")]
#[test]
fn trusted_slot_split_matches_validated_joint_decoding() {
    let profiles = decode_compiled_profiles(EMBEDDED).unwrap();
    let mut joints = 0;
    for value in profiles
        .iter()
        .flat_map(|profile| profile.scopes.iter())
        .filter(|scope| scope.observations.domain == CanonicalDomain::Joint)
        .flat_map(|scope| scope.observations.variants.iter())
        .filter_map(|variant| variant.value.as_canonical())
    {
        let split = joint_slot_values(value).unwrap();
        let validated = JointCapture::from_canonical(value, JointCaptureLimits::default()).unwrap();
        assert_eq!(split.len(), validated.slots.len());
        for (split, slot) in split.iter().zip(validated.slots.iter()) {
            assert_eq!(split.id, slot.value.id);
            assert_eq!(split.bytes, slot.value.bytes);
            assert!(shares_buffer(&split.bytes, &value.bytes));
        }
        joints += 1;
    }
    assert!(joints > 100, "{joints}");
}
