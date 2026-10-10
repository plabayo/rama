use super::*;
use crate::profile::ProfileKey;
use rama_utils::octets::kib;

fn entry(client: &str) -> ProfileArchiveEntry {
    ProfileArchiveEntry {
        evidence: ProfileEvidence {
            format_version: 1,
            profile: ProfileKey::new(client).canonical(kib(16)).unwrap(),
            scopes: Box::default(),
        },
        sampler_seed: [3; 32],
    }
}

fn bytes(entries: &[ProfileArchiveEntry]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"format_version":1,"profiles":entries})).unwrap()
}

#[test]
fn archive_round_trip_uses_evidence_and_ignores_claimed_capabilities() {
    let compiled = entry("library")
        .analyze(false, 100, 14, ProfileAnalysisLimits::default())
        .unwrap();
    let mut input = serde_json::json!({"format_version":1,"profiles":[compiled]});
    input["profiles"][0]["analysis"]["components"]["h3"] = serde_json::json!([999]);
    input["profiles"][0]["analysis"]["horizon"] = serde_json::json!(999);
    let loaded = load_profile_archive(
        &serde_json::to_vec(&input).unwrap(),
        false,
        100,
        14,
        ProfileArchiveLimits::default(),
    )
    .unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].analysis.key.client.as_ref(), "library");
    assert!(loaded[0].analysis.components.h3.is_none());
    assert_eq!(loaded[0].analysis.horizon, 14);
    assert_eq!(loaded[0].sampler_seed, [3; 32]);
}

#[test]
fn archive_rejects_duplicates_bounds_formats_and_trailing_data_atomically() {
    let one = entry("library");
    let input = bytes(std::slice::from_ref(&one));
    for limits in [
        ProfileArchiveLimits {
            bytes: input.len() - 1,
            ..ProfileArchiveLimits::default()
        },
        ProfileArchiveLimits {
            profiles: 0,
            ..ProfileArchiveLimits::default()
        },
    ] {
        load_profile_archive(&input, false, 100, 14, limits).unwrap_err();
    }
    load_profile_archive(
        &bytes(&[one.clone(), one]),
        false,
        100,
        14,
        ProfileArchiveLimits::default(),
    )
    .unwrap_err();
    for input in [
        b"{}".as_slice(),
        b"{\"format_version\":2,\"profiles\":[]}",
        b"{\"format_version\":1,\"profiles\":[],\"profiles\":[]}",
        b"{\"format_version\":1,\"format_version\":1,\"profiles\":[]}",
        b"{\"format_version\":1,\"profiles\":[]} {}",
    ] {
        load_profile_archive(input, false, 100, 14, ProfileArchiveLimits::default()).unwrap_err();
    }
    let mut invalid = entry("invalid");
    invalid.evidence.profile.id.0[0] ^= 1;
    load_profile_archive(
        &bytes(&[entry("valid"), invalid]),
        false,
        100,
        14,
        ProfileArchiveLimits::default(),
    )
    .unwrap_err();
}

#[test]
fn offline_archives_reproduce_their_recorded_window() {
    let input = serde_json::to_vec(&serde_json::json!({"format_version":1,"generated_day":100,"horizon":7,"profiles":[entry("library")]})).unwrap();
    let loaded =
        load_profile_archive_snapshot(&input, false, ProfileArchiveLimits::default()).unwrap();
    assert_eq!(loaded[0].analysis.current_day, 100);
    assert_eq!(loaded[0].analysis.horizon, 7);
    let current =
        load_profile_archive(&input, false, 200, 14, ProfileArchiveLimits::default()).unwrap();
    assert_eq!(current[0].analysis.current_day, 200);
    assert_eq!(current[0].analysis.horizon, 14);
    load_profile_archive_snapshot(
        &bytes(&[entry("library")]),
        false,
        ProfileArchiveLimits::default(),
    )
    .unwrap_err();
    let invalid = serde_json::to_vec(
        &serde_json::json!({"format_version":1,"generated_day":100,"horizon":0,"profiles":[]}),
    )
    .unwrap();
    load_profile_archive_snapshot(&invalid, false, ProfileArchiveLimits::default()).unwrap_err();
}
