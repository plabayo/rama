use rama_http::{HeaderMap, HeaderValue, Method, Version};

use super::*;
use crate::profile::{
    HeaderOccurrence, PreparedRequestProfile, ProfileCaptureCompleteness, ValueId,
};

fn selection(fields: Vec<HeaderOccurrence>) -> RequestSelection {
    let policy = HeaderCapturePolicy::default();
    let headers = HeaderCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        version: Version::HTTP_11,
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
                version: Version::HTTP_11,
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
