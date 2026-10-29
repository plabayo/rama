use rama_core::bytes::Bytes;
use rama_http::{
    HeaderMap, HeaderValue, Method, Version,
    proto::h3::{
        observation::{FieldRepresentation, ObservedFieldRepresentation},
        qpack::{FieldLine, encoding::Representation},
    },
};
use rama_utils::octets::kib;

use super::*;
use crate::profile::{
    capture::{
        completeness::ProfileCaptureCompleteness,
        headers::{HeaderCapture, HeaderCapturePolicy, HeaderOccurrence, HeaderValueSource},
        joint::{CaptureLevel, JointCapture, JointCaptureLimits},
        pseudo_headers::PseudoHeaderCapture,
    },
    format::canonical::ValueId,
    selection::variants::PreparedRequestProfile,
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
        slots: vec![crate::profile::capture::joint::CapturedSlot {
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
        draw: crate::profile::selection::DrawKey([3; 32]),
        analysis_revision: 2,
        effective: PreparedRequestProfile {
            cookie_layout: CookieLayoutEvidence::Unknown,
            scope: ValueId([4; 32]),
            capture: capture.into(),
            flow: FlowKey::Http {
                version,
                method: Method::GET,
                initiator: None,
                fetch: None,
                connection: Default::default(),
            },
            plan: None,
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
fn replay_uses_profile_values_and_actual_request_bindings() {
    let selection = selection(vec![
        field("user-agent", 0, profile(b"captured-browser")),
        field(
            "cookie",
            0,
            HeaderValueSource::Request(RequestBinding::Cookie),
        ),
    ]);
    let mut original = HeaderMap::new();
    original.insert("cookie", HeaderValue::from_static("session=secret"));

    let replayed = selection.replay_request(&original).unwrap();
    let headers = replayed.headers.unwrap();
    assert_eq!(headers["user-agent"], "captured-browser");
    assert_eq!(headers["cookie"], "session=secret");
    assert!(replayed.report.is_exact());
}

#[test]
fn replay_keeps_explicit_overrides_and_reports_every_difference() {
    let selection = selection(vec![field("user-agent", 0, profile(b"captured-browser"))]);
    let mut original = HeaderMap::new();
    original.insert("user-agent", HeaderValue::from_static("caller-agent"));
    original.insert("x-request-owned", HeaderValue::from_static("present"));

    let replayed = selection.replay_request(&original).unwrap();
    let headers = replayed.headers.unwrap();
    assert_eq!(headers["user-agent"], "captured-browser");
    assert_eq!(headers["x-request-owned"], "present");
    assert_eq!(replayed.report.differences.len(), 2);
    assert!(matches!(
        replayed.report.differences[0],
        ProfilePreservationDifference::CallerValueReplaced { .. }
    ));
    assert!(matches!(
        replayed.report.differences[1],
        ProfilePreservationDifference::AppendedCallerField { .. }
    ));
}

#[test]
fn replay_omits_and_reports_missing_request_bindings() {
    let missing_binding = selection(vec![field(
        "cookie",
        0,
        HeaderValueSource::Request(RequestBinding::Cookie),
    )]);
    let replayed = missing_binding.replay_request(&HeaderMap::new()).unwrap();
    assert!(replayed.headers.unwrap().is_empty());
    assert!(matches!(
        replayed.report.differences.as_ref(),
        [ProfilePreservationDifference::MissingRequestBinding {
            binding: RequestBinding::Cookie,
            ..
        }]
    ));
}

#[test]
fn replay_appends_caller_owned_fields_in_caller_order() {
    let selection = selection(vec![field("accept", 0, profile(b"*/*"))]);
    let mut original = HeaderMap::new();
    original.insert("accept", HeaderValue::from_static("*/*"));
    original.insert("authorization", HeaderValue::from_static("Bearer secret"));
    original.insert("x-api-key", HeaderValue::from_static("secret"));

    let replayed = selection.replay_request(&original).unwrap();
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
fn replay_leaves_caller_framing_to_the_http_encoder() {
    let selection = selection(vec![field(
        "content-length",
        0,
        HeaderValueSource::Request(RequestBinding::Framing),
    )]);
    let mut original = HeaderMap::new();
    original.insert("content-length", HeaderValue::from_static("1"));
    original.insert("transfer-encoding", HeaderValue::from_static("chunked"));
    let headers = selection
        .replay_request(&original)
        .unwrap()
        .headers
        .unwrap();
    assert_eq!(headers["content-length"], "1");
    assert_eq!(headers["transfer-encoding"], "chunked");
}

#[test]
fn caller_fields_beyond_capture_policy_never_fail_replay() {
    for version in [Version::HTTP_2, Version::HTTP_3] {
        let selection = selection_for_version(vec![field("accept", 0, profile(b"*/*"))], version);
        let mut original = HeaderMap::new();
        original.insert("connection", HeaderValue::from_static("keep-alive"));
        original.insert("te", HeaderValue::from_static("gzip"));
        for index in 0..300 {
            original.append(
                HeaderName::from_bytes(format!("x-caller-{index}").as_bytes()).unwrap(),
                HeaderValue::from_static("value"),
            );
        }
        original.insert(
            "x-large",
            HeaderValue::from_bytes(&vec![b'a'; kib(80)]).unwrap(),
        );
        let headers = selection
            .replay_request(&original)
            .unwrap()
            .headers
            .unwrap();
        assert_eq!(headers.len(), 304);
        assert_eq!(headers["te"], "gzip");
    }
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
            let replayed = selected.replay_request(&original).unwrap();
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
        let replayed = selected.replay_request(&HeaderMap::new()).unwrap();
        assert!(!replayed.headers.unwrap().contains_key("cookie"));
        assert!(
            replayed
                .report
                .differences
                .iter()
                .all(|difference| matches!(
                    difference,
                    ProfilePreservationDifference::MissingRequestBinding {
                        binding: RequestBinding::Cookie,
                        ..
                    }
                ))
        );
        assert_eq!(replayed.report.differences.len(), 2);
    }
}

#[test]
fn ambiguous_cookie_capture_never_implies_joining() {
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
        let replayed = selected.replay_request(&original).unwrap();
        assert!(matches!(
            replayed.report.differences.as_ref(),
            [ProfilePreservationDifference::UnknownCookieLayout]
        ));
        let headers = replayed.headers.unwrap();
        assert_eq!(
            headers
                .get_all("cookie")
                .iter()
                .map(|v| v.to_str().unwrap())
                .collect::<Vec<_>>(),
            ["b=2", "a=1"]
        );

        let mut supported = selected;
        supported.effective.cookie_layout = CookieLayoutEvidence::Split;
        original.clear();
        original.append("cookie", HeaderValue::from_static("b=2; a=1"));
        let replayed = supported.replay_request(&original).unwrap();
        assert!(replayed.report.is_exact());
        assert_eq!(
            replayed
                .headers
                .unwrap()
                .get_all("cookie")
                .iter()
                .map(|v| v.to_str().unwrap())
                .collect::<Vec<_>>(),
            ["b=2", "a=1"]
        );
    }
}

#[test]
fn captured_qpack_references_select_a_rule_without_replaying_table_indexes() {
    for (wire, expected) in [
        (0x88, FieldSectionBase::FromFieldPreferences),
        (0x13, FieldSectionBase::FromFieldPreferences),
    ] {
        let line = FieldLine::decode(&mut &[wire][..], 4096).unwrap();
        let mut captured = field("x-profile", 0, profile(b"value"));
        captured.representation = Some(ObservedFieldRepresentation::from(&line));
        let selected = selection_for_version(vec![captured], Version::HTTP_3);
        let replayed = selected.replay_request(&HeaderMap::new()).unwrap();
        assert_eq!(replayed.qpack_base, Some(expected));
        assert_eq!(replayed.headers.unwrap()["x-profile"], "value");
    }
    let selected = selection_for_version(
        vec![field("x-profile", 0, profile(b"value"))],
        Version::HTTP_3,
    );
    assert!(
        selected
            .replay_request(&HeaderMap::new())
            .unwrap()
            .qpack_base
            .is_none()
    );
}

#[test]
fn qpack_preferences_follow_emitted_cookie_occurrences() {
    let mut captured = field(
        "cookie",
        0,
        HeaderValueSource::Request(RequestBinding::Cookie),
    );
    let line = FieldLine::LiteralWithLiteralName {
        name: Bytes::from_static(b"cookie"),
        value: Bytes::from_static(b"redacted"),
        name_huffman: false,
        value_huffman: true,
        never_index: true,
    };
    captured.representation = Some(ObservedFieldRepresentation::from(&line));
    captured.sensitive = true;
    let mut selected = selection_for_version(vec![captured], Version::HTTP_3);
    selected.effective.cookie_layout = CookieLayoutEvidence::Split;
    let mut original = HeaderMap::new();
    original.append("cookie", HeaderValue::from_static("a=1; b=2; c=3"));
    let replayed = selected.replay_request(&original).unwrap();
    let headers = replayed.headers.unwrap();
    let preferences = replayed.qpack_headers.unwrap();
    assert_eq!(
        headers
            .get_all("cookie")
            .iter()
            .map(|value| value.as_bytes())
            .collect::<Vec<_>>(),
        [b"a=1", b"b=2", b"c=3"]
    );
    let choices = preferences
        .headers
        .get_all("cookie")
        .iter()
        .collect::<Vec<_>>();
    assert_eq!(choices.len(), 3);
    for choice in choices {
        assert_eq!(choice.name_huffman, Some(false));
        assert_eq!(choice.value_huffman, Some(true));
        assert!(choice.never_index);
    }
}

#[test]
fn qpack_preferences_skip_omitted_bindings() {
    let first = field(
        "x-profile",
        0,
        HeaderValueSource::Request(RequestBinding::Custom),
    );
    let mut second = field("x-profile", 1, profile(b"retained"));
    let line = FieldLine::LiteralWithLiteralName {
        name: Bytes::from_static(b"x-profile"),
        value: Bytes::from_static(b"retained"),
        name_huffman: false,
        value_huffman: false,
        never_index: false,
    };
    second.representation = Some(ObservedFieldRepresentation::from(&line));
    let selected = selection_for_version(vec![first, second], Version::HTTP_3);
    let replayed = selected.replay_request(&HeaderMap::new()).unwrap();
    let headers = replayed.headers.unwrap();
    assert_eq!(headers.len(), 1);
    assert_eq!(headers["x-profile"], "retained");
    let choices = replayed.qpack_headers.unwrap();
    let choices = choices
        .headers
        .get_all("x-profile")
        .iter()
        .collect::<Vec<_>>();
    assert_eq!(choices.len(), 1);
    assert_eq!(choices[0].value_huffman, Some(false));
}

mod bootstrap;

#[test]
fn mixed_qpack_families_select_native_current_field_boundary_preferences() {
    let mut captures = Vec::new();
    for (name, representation, expected) in [
        (
            "x-marker",
            FieldRepresentation::DynamicPostBaseIndex,
            Representation::DynamicIndexAfterBase,
        ),
        (
            "user-agent",
            FieldRepresentation::DynamicIndex,
            Representation::DynamicIndexBeforeBase,
        ),
        (
            "priority",
            FieldRepresentation::LiteralDynamicName,
            Representation::LiteralDynamicNameBeforeBase,
        ),
        (
            "x-post-name",
            FieldRepresentation::LiteralPostBaseName,
            Representation::LiteralDynamicNameAfterBase,
        ),
    ] {
        let mut capture = field(name, 0, profile(b"current"));
        capture.representation = Some(ObservedFieldRepresentation {
            representation,
            index: Some(900),
            name_huffman: false,
            value_huffman: matches!(
                representation,
                FieldRepresentation::LiteralDynamicName | FieldRepresentation::LiteralPostBaseName
            ),
            never_index: false,
        });
        captures.push((capture, name, expected));
    }
    let selected = selection_for_version(
        captures
            .iter()
            .map(|(capture, _, _)| capture.clone())
            .collect(),
        Version::HTTP_3,
    );
    let replayed = selected.replay_request(&HeaderMap::new()).unwrap();
    assert_eq!(
        replayed.qpack_base,
        Some(FieldSectionBase::FromFieldPreferences)
    );
    let preferences = replayed.qpack_headers.unwrap();
    for (_, name, expected) in captures {
        assert_eq!(preferences.headers[name].representation, expected);
        assert_eq!(replayed.headers.as_ref().unwrap()[name], "current");
    }
}
