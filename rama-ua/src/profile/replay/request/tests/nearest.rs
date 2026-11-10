//! A nearest captured flow replays with the caller's own request context.

use super::*;
use crate::profile::{
    capture::{joint::CapturedSlot, pseudo_headers::PseudoHeaderOccurrence},
    model::identity::FetchContext,
};
use rama_http::proto::h2::PseudoHeader;

/// A captured user-activated top-level navigation.
fn navigation_capture(version: Version) -> RequestSelection {
    selection_for_version(
        vec![
            field("sec-fetch-site", 0, profile(b"none")),
            field("sec-fetch-mode", 0, profile(b"navigate")),
            field("sec-fetch-user", 0, profile(b"?1")),
            field("sec-fetch-dest", 0, profile(b"document")),
            field("user-agent", 0, profile(b"captured-browser")),
            field("accept", 0, profile(b"text/html")),
            field("priority", 0, profile(b"u=0, i")),
            field("upgrade-insecure-requests", 0, profile(b"1")),
        ],
        version,
    )
}

fn requested(
    selection: &mut RequestSelection,
    method: Method,
    fetch: Option<FetchContext>,
    flow_match: FlowMatch,
) {
    if let FlowKey::Http {
        method: requested_method,
        initiator,
        fetch: requested_fetch,
        ..
    } = &mut selection.effective.flow
    {
        *requested_method = method;
        *initiator = None;
        *requested_fetch = fetch;
    }
    selection.effective.flow_match = flow_match;
}

fn stylesheet() -> FetchContext {
    FetchContext {
        mode: Some("no-cors".into()),
        site: Some("same-origin".into()),
        destination: Some("style".into()),
        user_activation: None,
    }
}

fn stylesheet_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("user-agent", HeaderValue::from_static("caller"));
    headers.insert("accept", HeaderValue::from_static("text/css,*/*;q=0.1"));
    headers.insert("sec-fetch-site", HeaderValue::from_static("same-origin"));
    headers.insert("sec-fetch-mode", HeaderValue::from_static("no-cors"));
    headers.insert("sec-fetch-dest", HeaderValue::from_static("style"));
    headers.insert("priority", HeaderValue::from_static("u=0"));
    headers
}

fn emitted(headers: &HeaderMap) -> Vec<(&str, &str)> {
    headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.to_str().unwrap()))
        .collect()
}

fn reports_nearest_flow(report: &ProfilePreservationReport) -> bool {
    report
        .differences
        .contains(&ProfilePreservationDifference::LoweredProfileItem {
            item: LoweredProfileItem::NearestFlow,
        })
}

#[test]
fn nearest_flow_for_another_destination_keeps_the_callers_request_context() {
    let mut selection = navigation_capture(Version::HTTP_11);
    requested(
        &mut selection,
        Method::GET,
        Some(stylesheet()),
        FlowMatch::Nearest {
            other_destination: true,
            other_method: false,
        },
    );
    let replayed = selection.replay_request(&stylesheet_headers()).unwrap();
    assert_eq!(
        emitted(&replayed.headers.unwrap()),
        [
            ("sec-fetch-site", "same-origin"),
            ("sec-fetch-mode", "no-cors"),
            ("sec-fetch-dest", "style"),
            ("user-agent", "captured-browser"),
            ("accept", "text/css,*/*;q=0.1"),
            ("priority", "u=0"),
        ]
    );
    assert_eq!(
        replayed.report.differences.as_ref(),
        [
            ProfilePreservationDifference::LoweredProfileItem {
                item: LoweredProfileItem::NearestFlow,
            },
            ProfilePreservationDifference::CallerValueReplaced {
                name: HeaderName::from_static("user-agent"),
                occurrence: 0,
            },
        ]
    );
}

#[test]
fn nearest_flow_for_the_same_destination_keeps_only_the_callers_fetch_metadata() {
    let mut selection = navigation_capture(Version::HTTP_11);
    requested(
        &mut selection,
        Method::GET,
        Some(FetchContext {
            mode: Some("navigate".into()),
            site: Some("same-origin".into()),
            destination: Some("document".into()),
            user_activation: None,
        }),
        FlowMatch::Nearest {
            other_destination: false,
            other_method: false,
        },
    );
    let mut original = HeaderMap::new();
    original.insert("sec-fetch-site", HeaderValue::from_static("same-origin"));
    original.insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
    original.insert("sec-fetch-dest", HeaderValue::from_static("document"));
    original.insert("accept", HeaderValue::from_static("*/*"));
    let replayed = selection.replay_request(&original).unwrap();
    assert_eq!(
        emitted(&replayed.headers.unwrap()),
        [
            ("sec-fetch-site", "same-origin"),
            ("sec-fetch-mode", "navigate"),
            ("sec-fetch-dest", "document"),
            ("user-agent", "captured-browser"),
            ("accept", "text/html"),
            ("priority", "u=0, i"),
            ("upgrade-insecure-requests", "1"),
        ]
    );
    assert!(reports_nearest_flow(&replayed.report));
}

#[test]
fn nearest_flow_without_caller_fetch_metadata_replays_the_captured_context() {
    let mut selection = navigation_capture(Version::HTTP_11);
    requested(
        &mut selection,
        Method::POST,
        None,
        FlowMatch::Nearest {
            other_destination: false,
            other_method: true,
        },
    );
    let replayed = selection.replay_request(&HeaderMap::new()).unwrap();
    let headers = replayed.headers.unwrap();
    assert_eq!(headers["sec-fetch-mode"], "navigate");
    assert_eq!(headers["sec-fetch-user"], "?1");
    assert_eq!(headers["accept"], "text/html");
    assert!(reports_nearest_flow(&replayed.report));
}

#[test]
fn exact_flow_replays_the_captured_context() {
    let mut selection = navigation_capture(Version::HTTP_11);
    requested(
        &mut selection,
        Method::GET,
        Some(stylesheet()),
        FlowMatch::Exact,
    );
    let replayed = selection.replay_request(&stylesheet_headers()).unwrap();
    let headers = replayed.headers.unwrap();
    assert_eq!(headers["sec-fetch-dest"], "document");
    assert_eq!(headers["sec-fetch-user"], "?1");
    assert!(!reports_nearest_flow(&replayed.report));
}

/// An HTTP/3 navigation whose `:method` is the static `:method GET` entry.
fn static_get_capture() -> RequestSelection {
    let line = FieldLine::decode(&mut &[0xd1][..], 4096).unwrap();
    let mut captured = field("sec-fetch-dest", 0, profile(b"document"));
    captured.representation = Some(ObservedFieldRepresentation::from(
        &FieldLine::LiteralWithLiteralName {
            name: Bytes::from_static(b"sec-fetch-dest"),
            value: Bytes::from_static(b"document"),
            name_huffman: false,
            value_huffman: true,
            never_index: false,
        },
    ));
    let mut selection = selection_for_version(vec![captured], Version::HTTP_3);
    let mut joint = JointCapture::from_canonical(
        &selection.effective.capture.canonical().unwrap(),
        JointCaptureLimits::default(),
    )
    .unwrap();
    let pseudo = PseudoHeaderCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        version: Version::HTTP_3,
        fields: [
            PseudoHeader::Method,
            PseudoHeader::Scheme,
            PseudoHeader::Authority,
            PseudoHeader::Path,
        ]
        .into_iter()
        .map(|name| PseudoHeaderOccurrence {
            name,
            representation: (name == PseudoHeader::Method)
                .then(|| ObservedFieldRepresentation::from(&line)),
        })
        .collect(),
    }
    .canonical(4096)
    .unwrap();
    let mut slots = joint.slots.into_vec();
    slots.push(CapturedSlot {
        kind: CapturedSlotKind::PseudoHeaders,
        value: pseudo,
    });
    joint.slots = slots.into();
    selection.effective.set_capture(
        joint
            .canonical(JointCaptureLimits::default())
            .unwrap()
            .into(),
    );
    selection.variant = selection.effective.capture.id();
    selection
}

#[test]
fn nearest_flow_for_another_method_encodes_the_method_natively() {
    let mut selection = static_get_capture();
    requested(&mut selection, Method::PUT, None, FlowMatch::Exact);
    selection.replay_request(&HeaderMap::new()).unwrap_err();

    requested(
        &mut selection,
        Method::PUT,
        None,
        FlowMatch::Nearest {
            other_destination: false,
            other_method: true,
        },
    );
    let replayed = selection.replay_request(&HeaderMap::new()).unwrap();
    let preferences = replayed.qpack_headers.unwrap();
    assert!(
        !preferences
            .pseudo_headers
            .contains_key(&PseudoHeader::Method)
    );
    assert!(preferences.headers.contains_key("sec-fetch-dest"));
    assert!(reports_nearest_flow(&replayed.report));
}

#[test]
fn omitted_context_fields_take_no_qpack_preference() {
    let mut selection = static_get_capture();
    requested(
        &mut selection,
        Method::GET,
        Some(stylesheet()),
        FlowMatch::Nearest {
            other_destination: true,
            other_method: false,
        },
    );
    let replayed = selection.replay_request(&HeaderMap::new()).unwrap();
    assert!(replayed.headers.unwrap().is_empty());
    assert!(replayed.qpack_headers.unwrap().headers.is_empty());
}
