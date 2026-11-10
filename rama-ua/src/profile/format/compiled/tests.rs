use super::{
    compact::{CompiledCapture, CompiledHeaders},
    wire::{ValueRole, WireCapture, WireValue, for_each_value},
    *,
};
#[cfg(feature = "tls")]
use crate::profile::capture::joint::{JointCapture, JointCaptureLimits, joint_slot_values};
use crate::profile::{
    analysis::{
        capture::{CaptureOrderPath, VariantValue},
        profile::ProfileAnalysisLimits,
    },
    capture::completeness::ProfileCaptureCompleteness,
    format::canonical::{CanonicalDomain, ValueId},
    replay::{connection::H3SettingsReplayEvidence, request::CompactCapture},
};

const EMBEDDED: &[u8] = include_bytes!("../embed_profiles.bin");

fn compiled(profiles: &[AnalyzedProfile]) -> WireSet {
    let profiles: Vec<_> = profiles.iter().map(retained).collect();
    compile_set(&profiles).unwrap()
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
fn loaded_ids_are_the_digests_of_what_they_name() {
    let limit = ProfileAnalysisLimits::default().metadata_bytes;
    for profile in decode_compiled_profiles(EMBEDDED).unwrap() {
        assert_eq!(profile.key.canonical(limit).unwrap().id, profile.id);
        for scope in profile.scopes.iter() {
            assert_eq!(scope.context.canonical(limit).unwrap().id, scope.id);
            assert_eq!(scope.observations.scope, scope.id);
            assert_eq!(scope.context.profile, profile.id);
            assert_eq!(
                scope.context.flow,
                scope
                    .flow
                    .as_ref()
                    .map(|flow| flow.canonical(limit).unwrap().id)
            );
            assert_eq!(scope.context.structure, scope.structure.id);
            for value in scope
                .observations
                .variants
                .iter()
                .filter_map(|variant| variant.value.as_canonical())
                .chain([&scope.structure])
            {
                let domain = value.domain_tag(value.bytes.len()).unwrap();
                value.verify(domain, value.bytes.len()).unwrap();
            }
        }
    }
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
    assert!(compact > 0);
}

#[test]
fn exports_whose_ids_do_not_follow_their_bytes_are_refused() {
    let mut profiles = decode_compiled_profiles(EMBEDDED).unwrap();
    profiles.truncate(1);
    encode_compiled_profiles(&profiles).unwrap();
    let mut scope_id = profiles.clone();
    scope_id[0].scopes[0].id = ValueId([0xee; 32]);
    let error = encode_compiled_profiles(&scope_id).unwrap_err();
    assert!(error.to_string().contains("round trip"), "{error}");
    let mut structure = profiles;
    structure[0].scopes[0].structure.id = ValueId([0xee; 32]);
    let error = encode_compiled_profiles(&structure).unwrap_err();
    assert!(error.to_string().contains("round trip"), "{error}");
}

#[test]
fn foreign_stale_empty_and_corrupt_sets_are_refused() {
    decode_compiled_profiles(b"not a profile set").unwrap_err();
    decode_compiled_profiles(&EMBEDDED[MAGIC.len()..]).unwrap_err();
    let profiles = decode_compiled_profiles(EMBEDDED).unwrap();
    // A well-formed set from another classifier revision is refused by that check alone.
    let mut set = compiled(&profiles[..1]);
    let current = frame(&set).unwrap();
    assert_eq!(decode_compiled_profiles(&current).unwrap().len(), 1);
    let mut previous = current;
    previous[MAGIC.len()] = FORMAT_VERSION - 1;
    assert!(is_compiled_profile_set(&previous));
    let error = decode_compiled_profiles(&previous).unwrap_err();
    assert!(error.to_string().contains("format version"), "{error}");
    set.classifier_revision = PROFILE_CLASSIFIER_REVISION - 1;
    let error = decode_compiled_profiles(&frame(&set).unwrap()).unwrap_err();
    assert!(error.to_string().contains("classifier revision"), "{error}");
    set.classifier_revision = PROFILE_CLASSIFIER_REVISION;
    set.profiles.clear();
    let error = decode_compiled_profiles(&frame(&set).unwrap()).unwrap_err();
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
        .write_all(&postcard::to_allocvec(&compiled(&profiles[..1])).unwrap())
        .unwrap();
    encoder.finish().unwrap();
    let error = decode_compiled_profiles(&unsized_frame).unwrap_err();
    assert!(error.to_string().contains("content size"), "{error}");
}

#[test]
fn compact_and_repeated_values_shrink_the_stored_set() {
    let profiles = decode_compiled_profiles(EMBEDDED).unwrap();
    // Canonical captures serialize in full, as archives store them.
    let plain = postcard::to_allocvec(&profiles).unwrap();
    let stored = postcard::to_allocvec(&compiled(&profiles)).unwrap();
    assert!(
        stored.len() * 2 < plain.len(),
        "{} of {}",
        stored.len(),
        plain.len()
    );
}

#[test]
fn references_to_unknown_values_or_slots_are_refused() {
    let profiles = decode_compiled_profiles(EMBEDDED).unwrap();
    let refused = |edit: &dyn Fn(&mut WireSet)| {
        let mut set = compiled(&profiles[..1]);
        edit(&mut set);
        let error = decode_compiled_profiles(&frame(&set).unwrap()).unwrap_err();
        assert!(error.to_string().contains("value reference"), "{error}");
    };
    refused(&|set| set.profiles[0].scopes[0].structure = WireValue::Stored(u32::MAX));
    // The first stored value is a scope structure, never a joint capture.
    refused(&|set| set.profiles[0].scopes[0].structure = WireValue::Slot { joint: 0, slot: 0 });
    refused(&|set| {
        let mut stored = 0;
        let mut joint = None;
        for_each_value(set, |role, value| {
            if let WireValue::Bytes(_) = value {
                if role == ValueRole::Joint && joint.is_none() {
                    joint = Some(stored);
                }
                stored += 1;
            }
            Ok(())
        })
        .unwrap();
        set.profiles[0].scopes[0].structure = WireValue::Slot {
            joint: joint.unwrap(),
            slot: u32::MAX,
        };
    });
}

#[test]
fn compact_plans_beyond_the_header_limits_are_refused_at_load() {
    let profiles = decode_compiled_profiles(EMBEDDED).unwrap();
    let edited = |edit: &dyn Fn(&mut CompiledHeaders)| {
        let mut set = compiled(&profiles[..1]);
        let index = set.profiles[0]
            .scopes
            .iter()
            .flat_map(|scope| scope.observations.variants.iter())
            .find_map(|variant| match &variant.value {
                WireCapture::Compact {
                    capture:
                        CompiledCapture::Request {
                            headers: Some(index),
                            ..
                        },
                    ..
                } => Some(*index),
                _ => None,
            })
            .unwrap();
        edit(&mut set.headers[index as usize]);
        decode_compiled_profiles(&frame(&set).unwrap())
    };
    let error = edited(&|headers| {
        let first = headers.fields[0];
        headers.fields = vec![first; 32_768].into();
    })
    .unwrap_err();
    assert!(
        error.to_string().contains("compact header fields"),
        "{error}"
    );
    edited(&|headers| headers.completeness = ProfileCaptureCompleteness::Incomplete.tag())
        .unwrap_err();
    edited(&|_headers| {}).unwrap();
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

#[test]
fn compiled_http3_settings_keep_the_samples_their_replay_evidence_needs() {
    let mut derived = 0;
    for profile in decode_compiled_profiles(EMBEDDED).unwrap() {
        for scope in profile.scopes.iter() {
            let observations = &scope.observations;
            let ruled = observations.orders.iter().any(|order| {
                order.path == CaptureOrderPath::Http3Settings && order.evidence.derived.is_some()
            });
            if observations.domain != CanonicalDomain::Order || !ruled {
                continue;
            }
            for variant in observations.variants.iter() {
                let selected = variant.value.canonical().unwrap();
                if H3SettingsReplayEvidence::from_analysis(observations, &selected)
                    .unwrap()
                    .is_some()
                {
                    derived += 1;
                }
            }
        }
    }
    assert!(derived > 0);
}
