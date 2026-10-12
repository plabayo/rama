use rama_http::{HeaderMap, HeaderValue, Method, Version};

use super::*;
use crate::profile::{
    HeaderOccurrence, PreparedRequestProfile, ProfileCaptureCompleteness, ValueId,
};

fn selection(fields: Vec<HeaderOccurrence>) -> RequestSelection {
    selection_for_version(fields, Version::HTTP_11)
}

fn selection_for_version(fields: Vec<HeaderOccurrence>, version: Version) -> RequestSelection {
    let policy = HeaderCapturePolicy::default();
    let headers = HeaderCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        version,
        fields: fields.into(),
    }
    .canonical(&policy)
    .unwrap();
    let capture = JointCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        level: CaptureLevel::Request,
        slots: vec![crate::profile::CapturedSlot {
            kind: CapturedSlotKind::Headers,
            value: headers,
        }]
        .into(),
    }
    .canonical(JointCaptureLimits::default())
    .unwrap();
    RequestSelection {
        profile: ValueId([1; 32]),
        connection_variant: ValueId([2; 32]),
        variant: capture.id,
        draw: crate::profile::DrawKey([3; 32]),
        analysis_revision: 2,
        effective: PreparedRequestProfile {
            scope: ValueId([4; 32]),
            capture,
            flow: FlowKey::Http {
                version,
                method: Method::GET,
                initiator: None,
                fetch: None,
                connection: Default::default(),
            },
        },
    }
}

fn field(name: &'static str, occurrence: u32, value: HeaderValueSource) -> HeaderOccurrence {
    HeaderOccurrence {
        name: HeaderName::from_static(name),
        occurrence,
        sensitive: false,
        representation: None,
        value,
    }
}

fn profile(value: &'static [u8]) -> HeaderValueSource {
    HeaderValueSource::Profile(value.into())
}

#[test]
fn strict_replay_uses_profile_values_and_actual_request_bindings() {
    let selection = selection(vec![
        field("user-agent", 0, profile(b"captured-browser")),
        field(
            "cookie",
            0,
            HeaderValueSource::Request(RequestBinding::Cookie),
        ),
    ]);
    let mut original = HeaderMap::new();
    original.insert("user-agent", HeaderValue::from_static("caller-agent"));
    original.insert("cookie", HeaderValue::from_static("session=secret"));

    let replayed = selection
        .replay_request(&original, ProfilePreservationMode::Strict)
        .unwrap();
    let headers = replayed.headers.unwrap();
    assert_eq!(headers["user-agent"], "captured-browser");
    assert_eq!(headers["cookie"], "session=secret");
    assert!(replayed.report.is_exact());
}

#[test]
fn best_effort_keeps_explicit_overrides_and_reports_every_difference() {
    let selection = selection(vec![field("user-agent", 0, profile(b"captured-browser"))]);
    let mut original = HeaderMap::new();
    original.insert("user-agent", HeaderValue::from_static("caller-agent"));
    original.insert("x-request-owned", HeaderValue::from_static("present"));

    let replayed = selection
        .replay_request(&original, ProfilePreservationMode::BestEffort)
        .unwrap();
    let headers = replayed.headers.unwrap();
    assert_eq!(headers["user-agent"], "caller-agent");
    assert_eq!(headers["x-request-owned"], "present");
    assert_eq!(replayed.report.differences.len(), 2);
    assert!(matches!(
        replayed.report.differences[0],
        ProfilePreservationDifference::CallerValueOverride { .. }
    ));
    assert!(matches!(
        replayed.report.differences[1],
        ProfilePreservationDifference::AppendedCallerField { .. }
    ));
}

#[test]
fn strict_replay_rejects_missing_request_bindings() {
    let missing_binding = selection(vec![field(
        "cookie",
        0,
        HeaderValueSource::Request(RequestBinding::Cookie),
    )]);
    assert!(matches!(
        missing_binding.replay_request(&HeaderMap::new(), ProfilePreservationMode::Strict),
        Err(ProfileReplayError::IncompatibleHeaderShape { .. })
    ));
}

#[test]
fn strict_replay_appends_caller_owned_fields_in_caller_order() {
    let selection = selection(vec![field("accept", 0, profile(b"*/*"))]);
    let mut original = HeaderMap::new();
    original.insert("accept", HeaderValue::from_static("*/*"));
    original.insert("authorization", HeaderValue::from_static("Bearer secret"));
    original.insert("x-api-key", HeaderValue::from_static("secret"));

    let replayed = selection
        .replay_request(&original, ProfilePreservationMode::Strict)
        .unwrap();
    let headers = replayed.headers.unwrap();
    let ordered: Vec<_> = headers
        .ordered_iter()
        .map(|(name, value)| (name.as_str(), value.to_str().unwrap()))
        .collect();
    assert_eq!(
        ordered,
        [
            ("accept", "*/*"),
            ("authorization", "Bearer secret"),
            ("x-api-key", "secret"),
        ]
    );
    assert_eq!(replayed.report.differences.len(), 2);
    assert!(
        replayed
            .report
            .differences
            .iter()
            .all(|difference| matches!(
                difference,
                ProfilePreservationDifference::AppendedCallerField { .. }
            ))
    );
}

#[test]
fn replay_rejects_conflicting_message_framing_in_every_mode() {
    let selection = selection(vec![field(
        "content-length",
        0,
        HeaderValueSource::Request(RequestBinding::Framing),
    )]);
    let mut original = HeaderMap::new();
    original.insert("content-length", HeaderValue::from_static("1"));
    original.insert("transfer-encoding", HeaderValue::from_static("chunked"));
    assert!(matches!(
        selection.replay_request(&original, ProfilePreservationMode::BestEffort),
        Err(ProfileReplayError::Data(ProfileDataError::Invalid(
            "conflicting message framing"
        )))
    ));
}

#[test]
fn split_cookie_profiles_accept_request_owned_pair_counts() {
    for version in [Version::HTTP_2, Version::HTTP_3] {
        let selected = selection_for_version(
            vec![
                field(
                    "cookie",
                    0,
                    HeaderValueSource::Request(RequestBinding::Cookie),
                ),
                field("user-agent", 0, profile(b"captured-browser")),
                field(
                    "cookie",
                    1,
                    HeaderValueSource::Request(RequestBinding::Cookie),
                ),
                field("accept", 0, profile(b"*/*")),
            ],
            version,
        );
        for (input, expected) in [
            ("a=1", vec!["a=1"]),
            ("a=1; b=2", vec!["a=1", "b=2"]),
            ("a=1; b=2; c=3", vec!["a=1", "b=2", "c=3"]),
        ] {
            let mut original = HeaderMap::new();
            let mut value = HeaderValue::from_str(input).unwrap();
            value.set_sensitive(true);
            original.append("cookie", value);
            let replayed = selected
                .replay_request(&original, ProfilePreservationMode::Strict)
                .unwrap();
            assert!(replayed.report.is_exact());
            let headers = replayed.headers.unwrap();
            let cookies: Vec<_> = headers
                .get_all("cookie")
                .iter()
                .map(|value| {
                    assert!(value.is_sensitive());
                    value.to_str().unwrap()
                })
                .collect();
            assert_eq!(cookies, expected);
            let names: Vec<_> = headers
                .ordered_iter()
                .map(|(name, _)| name.as_str())
                .collect();
            assert_eq!(&names[..2], &["cookie", "user-agent"]);
            assert_eq!(names.last(), Some(&"accept"));
        }
        selected
            .replay_request(&HeaderMap::new(), ProfilePreservationMode::Strict)
            .unwrap_err();
    }
}

#[test]
fn joined_cookie_profiles_preserve_caller_pair_order() {
    for version in [Version::HTTP_2, Version::HTTP_3] {
        let selected = selection_for_version(
            vec![field(
                "cookie",
                0,
                HeaderValueSource::Request(RequestBinding::Cookie),
            )],
            version,
        );
        let mut original = HeaderMap::new();
        original.append("cookie", HeaderValue::from_static("b=2"));
        original.append("cookie", HeaderValue::from_static("a=1"));
        let replayed = selected
            .replay_request(&original, ProfilePreservationMode::Strict)
            .unwrap();
        assert!(replayed.report.is_exact());
        let headers = replayed.headers.unwrap();
        assert_eq!(headers.get_all("cookie").iter().count(), 1);
        assert_eq!(headers["cookie"], "b=2; a=1");
    }
}
