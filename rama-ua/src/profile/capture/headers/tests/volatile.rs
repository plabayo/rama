use super::*;
use crate::profile::capture::headers::structure::{
    normalize_header_structure, validate_header_structure,
};

const MARKER: &str = "x-RAMA-custom-header-marker";

fn capture(version: Version, values: &[(&str, &str)]) -> HeaderCapture {
    HeaderCapturePolicy::default()
        .capture(
            ProfileCaptureCompleteness::Complete,
            version,
            &headers(values),
            None,
        )
        .unwrap()
}

fn structure(version: Version, values: &[(&str, &str)]) -> ValueId {
    capture(version, values)
        .structural(&HeaderCapturePolicy::default())
        .unwrap()
        .id
}

/// A capture as stored before the marker was request-owned.
fn legacy_marker_capture(version: Version, marker: &str) -> HeaderCapture {
    let mut captured = capture(version, &[("accept", "*/*"), (MARKER, marker)]);
    captured.fields[1].value = HeaderValueSource::Profile(marker.as_bytes().into());
    captured
}

#[test]
fn fingerprint_marker_value_is_request_owned_and_keeps_its_position() {
    let first = capture(
        Version::HTTP_2,
        &[("accept", "*/*"), (MARKER, "rama-fp1700000000001")],
    );
    assert_eq!(
        first.fields[1].name.as_lower_str(),
        "x-rama-custom-header-marker"
    );
    assert!(matches!(
        first.fields[1].value,
        HeaderValueSource::Request(RequestBinding::Custom)
    ));
    let policy = HeaderCapturePolicy::default();
    let raw = first.canonical(&policy).unwrap();
    assert!(!raw.bytes.windows(7).any(|bytes| bytes == b"rama-fp"));
    let ids: BTreeSet<_> = (0..64)
        .map(|index| {
            structure(
                Version::HTTP_2,
                &[
                    ("accept", "*/*"),
                    (MARKER, &format!("rama-fp17000000{index:05}")),
                ],
            )
        })
        .collect();
    assert_eq!(ids.len(), 1);
    // An explicit profile override keeps the literal for importers that need it.
    let kept = HeaderCapturePolicy {
        overrides: Box::new([HeaderOwnershipOverride {
            name: HeaderName::from_static("x-rama-custom-header-marker"),
            ownership: HeaderOwnership::Profile,
        }]),
        ..HeaderCapturePolicy::default()
    }
    .capture(
        ProfileCaptureCompleteness::Complete,
        Version::HTTP_2,
        &headers(&[(MARKER, "fixed")]),
        None,
    )
    .unwrap();
    assert!(matches!(
        kept.fields[0].value,
        HeaderValueSource::Profile(_)
    ));
}

#[test]
fn stored_marker_literals_still_decode_and_share_one_structure() {
    let policy = HeaderCapturePolicy::default();
    let current = structure(
        Version::HTTP_3,
        &[("accept", "*/*"), (MARKER, "rama-fp1700000000001")],
    );
    let mut legacy_ids = BTreeSet::new();
    for index in 0..16 {
        let legacy = legacy_marker_capture(Version::HTTP_3, &format!("rama-fp{index}"));
        let raw = legacy.canonical(&policy).unwrap();
        let restored = HeaderCapture::from_canonical(&raw, &policy).unwrap();
        legacy_ids.insert(restored.structural(&policy).unwrap().id);
    }
    assert_eq!(legacy_ids, BTreeSet::from([current]));
}

#[test]
fn client_hints_and_language_are_sampled_without_new_structures() {
    let policy = HeaderCapturePolicy::default();
    let mut ids = BTreeSet::new();
    for index in 0..32_u32 {
        let rtt = (index * 50).to_string();
        let downlink = format!("{}.{}", index % 10, index % 7);
        let memory = ["2", "4", "8"][index as usize % 3].to_owned();
        let width = (360 + index).to_string();
        let language = ["en-US,en;q=0.9", "nl-BE,nl;q=0.9", "fr-FR"][index as usize % 3];
        let values = [
            ("accept", "text/html"),
            ("sec-ch-ua-mobile", "?1"),
            ("downlink", downlink.as_str()),
            ("rtt", rtt.as_str()),
            ("ect", ["4g", "3g"][index as usize % 2]),
            ("device-memory", memory.as_str()),
            ("sec-ch-device-memory", memory.as_str()),
            ("dpr", "2.625"),
            ("sec-ch-viewport-width", width.as_str()),
            ("viewport-width", width.as_str()),
            ("sec-ch-viewport-height", width.as_str()),
            ("sec-ch-ua-platform-version", "\"14.0.0\""),
            (
                "sec-ch-ua-model",
                ["\"Pixel 7\"", "\"SM-S918B\""][index as usize % 2],
            ),
            ("accept-language", language),
        ];
        let captured = capture(Version::HTTP_2, &values);
        // Raw captures keep the sampled values for replay.
        let raw = captured.canonical(&policy).unwrap();
        assert!(
            raw.bytes
                .windows(rtt.len())
                .any(|bytes| bytes == rtt.as_bytes())
        );
        ids.insert(captured.structural(&policy).unwrap().id);
    }
    assert_eq!(ids.len(), 1);
}

#[test]
fn distinct_header_shapes_keep_distinct_structures() {
    let base = structure(Version::HTTP_2, &[("accept", "*/*"), ("rtt", "50")]);
    for other in [
        // A stable literal keeps splitting structures.
        structure(Version::HTTP_2, &[("accept", "text/html"), ("rtt", "50")]),
        // Presence of a hint is part of the shape.
        structure(Version::HTTP_2, &[("accept", "*/*")]),
        // Multiplicity of a hint is part of the shape.
        structure(
            Version::HTTP_2,
            &[("accept", "*/*"), ("rtt", "50"), ("rtt", "100")],
        ),
        // So is a stable client hint value.
        structure(
            Version::HTTP_2,
            &[("accept", "*/*"), ("rtt", "50"), ("sec-ch-ua-mobile", "?0")],
        ),
        structure(Version::HTTP_2, &[("accept", "*/*"), (MARKER, "rama-fp1")]),
    ] {
        assert_ne!(base, other);
    }
}

#[test]
fn multiplexed_cookie_field_count_does_not_split_structures() {
    let one = structure(Version::HTTP_3, &[("accept", "*/*"), ("cookie", "a=1")]);
    let three = structure(
        Version::HTTP_3,
        &[
            ("accept", "*/*"),
            ("cookie", "a=1"),
            ("cookie", "b=2"),
            ("cookie", "c=3"),
        ],
    );
    assert_eq!(one, three);
    assert_ne!(one, structure(Version::HTTP_3, &[("accept", "*/*")]));
    // HTTP/1 sends one cookie field; two remain a distinct shape.
    assert_ne!(
        structure(Version::HTTP_11, &[("cookie", "a=1")]),
        structure(Version::HTTP_11, &[("cookie", "a=1"), ("cookie", "b=2")]),
    );
}

#[test]
fn stored_legacy_structures_validate_and_normalize() {
    let policy = HeaderCapturePolicy::default();
    let legacy = legacy_marker_capture(Version::HTTP_2, "rama-fp42");
    let mut polluted = legacy;
    polluted.fields = polluted
        .fields
        .iter()
        .cloned()
        .chain([HeaderOccurrence {
            name: HeaderName::from_static("rtt"),
            occurrence: 0,
            sensitive: false,
            representation: None,
            value: HeaderValueSource::Profile(b"150".as_slice().into()),
        }])
        .collect();
    let stored = polluted.legacy_structural(&policy).unwrap();
    let current = polluted.structural(&policy).unwrap();
    assert_ne!(stored.id, current.id);
    validate_header_structure(&stored, policy.bytes).unwrap();
    stored.validated_domain(policy.bytes).unwrap();
    let normalized = normalize_header_structure(&stored, policy.bytes).unwrap();
    assert_eq!(normalized.bytes, current.bytes);
    assert_eq!(
        normalize_header_structure(&current, policy.bytes)
            .unwrap()
            .bytes,
        current.bytes
    );
}
