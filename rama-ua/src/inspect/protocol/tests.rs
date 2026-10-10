use super::*;
use crate::{
    inspect::{ProfileExport, tests::store},
    profile::{CanonicalDomain, ProfileAnalysisLimits, UserAgentDatabase},
};
use rama_core::{Layer, Service, extensions::ExtensionsRef, service::service_fn};
use rama_http::{
    Body, Request, Response, Version,
    body::util::BodyExt,
    inspect::capture::{CaptureHttpLayer, ConnectionId},
    proto::{
        h2::PseudoHeader,
        h3::observation::{
            FieldRepresentation, H3ObservationSnapshot, ObservationCompleteness,
            ObservedControlFrame, ObservedFieldRepresentation, ObservedSetting, ObservedUniStream,
        },
    },
};
use rama_net::Protocol;
use rama_quic_proto::{
    Version as QuicVersion,
    capture::{CaptureCompleteness, FirstFlight, ObservedFrame, RawParameter},
    profile::{PaddingPlacement, ParameterId},
};
use std::{collections::BTreeSet, convert::Infallible, sync::Arc};

fn literal() -> ObservedFieldRepresentation {
    ObservedFieldRepresentation {
        representation: FieldRepresentation::LiteralName,
        index: None,
        name_huffman: false,
        value_huffman: true,
        never_index: false,
    }
}

fn observed() -> QuicObservation {
    QuicObservation {
        connection_id: b"connection-canary".to_vec(),
        attempt_id: b"attempt-canary".to_vec(),
        retry_parent: None,
        first_flight: Some(FirstFlight {
            datagram_sizes: vec![1200],
            trailing_bytes: vec![0],
            version: QuicVersion::V1,
            dcid_len: 8,
            scid_len: 0,
            token_len: 0,
            first_packet_number: 0,
            packet_number_len: 1,
            frames: vec![vec![ObservedFrame::Crypto {
                offset: 0,
                len: 100,
            }]],
            padding: PaddingPlacement::Frames,
            coalesced: false,
            parameters: vec![ParameterId(1)],
            chosen_version: None,
            available_versions: vec![],
            packet_numbers: vec![0],
            complete: true,
        }),
        transport_parameters: vec![RawParameter {
            id: ParameterId(1),
            value: vec![1],
        }],
        client_hello_message: b"hello-canary".to_vec(),
        completeness: CaptureCompleteness {
            datagrams: true,
            frames: true,
            client_hello: true,
            transport_parameters: true,
            original_attempt: true,
        },
    }
}

fn h3() -> H3RequestObservation {
    let connection = Arc::new(H3ObservationSnapshot {
        revision: 2,
        streams: vec![ObservedUniStream {
            sequence: 1,
            stream_id: 2,
            stream_type: 0,
            grease: false,
        }],
        control: vec![ObservedControlFrame {
            sequence: 2,
            frame_type: 4,
            length: 3,
            element_id: None,
            value: Box::default(),
        }],
        local_settings: vec![ObservedSetting {
            id: 1,
            value: 4096,
            grease: false,
        }],
        settings_received: true,
        settings: Some(vec![ObservedSetting {
            id: 1,
            value: 4096,
            grease: false,
        }]),
        completeness: ObservationCompleteness {
            settings: true,
            snapshot: true,
            local_settings: true,
            streams: true,
            control: true,
            qpack: true,
            ..ObservationCompleteness::default()
        },
        ..H3ObservationSnapshot::default()
    });
    H3RequestObservation {
        connection,
        fields: vec![literal(); 7],
        fields_complete: true,
        priority: None,
    }
}

fn parts() -> Parts {
    Request::builder()
        .version(Version::HTTP_3)
        .uri("https://example.test/")
        .header("user-agent", "synthetic/1")
        .header("accept", "text/html")
        .header("cookie", "cookie-canary")
        .extension(observed())
        .extension(h3())
        .extension(
            [
                PseudoHeader::Method,
                PseudoHeader::Scheme,
                PseudoHeader::Authority,
                PseudoHeader::Path,
            ]
            .into_iter()
            .collect::<PseudoHeaderOrder>(),
        )
        .body(())
        .unwrap()
        .into_parts()
        .0
}

#[test]
fn bounded_h3_facts_preserve_wire_choices_without_raw_connection_secrets() {
    let parts = parts();
    let metadata = CaptureMetadata::default();
    capture(&parts, &metadata);
    let facts = metadata
        .connection
        .get_ref::<H3ProfileConnection>()
        .unwrap()
        .0
        .as_ref()
        .unwrap();
    assert_eq!(facts.slots.len(), 4);
    assert!(!facts.token_present);
    assert!(facts.client_hello_complete);
    let request = metadata
        .exchange
        .get_ref::<H3ProfileRequest>()
        .unwrap()
        .0
        .as_ref()
        .unwrap();
    assert_eq!(request.len(), 2);
    for slot in facts.slots.iter().chain(request.iter()) {
        for secret in [
            b"connection-canary".as_slice(),
            b"attempt-canary",
            b"hello-canary",
            b"cookie-canary",
        ] {
            assert!(
                !slot
                    .value
                    .bytes
                    .windows(secret.len())
                    .any(|bytes| bytes == secret)
            );
        }
    }
    let pseudo = PseudoHeaderCapture::from_canonical(
        &request[1].value,
        JointCaptureLimits::default().value_bytes,
    )
    .unwrap();
    assert!(
        pseudo
            .fields
            .iter()
            .all(|field| field.representation.unwrap().value_huffman)
    );
    let later = CaptureMetadata {
        connection: metadata.connection.clone(),
        ..CaptureMetadata::default()
    };
    let next = parts;
    next.extensions.insert(H3RequestObservation {
        fields: vec![],
        ..h3()
    });
    capture(&next, &later);
    assert!(std::ptr::eq(
        metadata
            .connection
            .get_ref::<H3ProfileConnection>()
            .unwrap(),
        later.connection.get_ref::<H3ProfileConnection>().unwrap()
    ));
    later
        .exchange
        .get_ref::<H3ProfileRequest>()
        .unwrap()
        .0
        .as_ref()
        .unwrap_err();
}

#[test]
fn incomplete_h3_capture_cannot_become_complete_during_export() {
    for case in 0..4 {
        let parts = parts();
        match case {
            0 => {
                let mut quic = observed();
                quic.completeness.original_attempt = false;
                parts.extensions.insert(quic);
            }
            1 => {
                let mut request = h3();
                let mut snapshot = (*request.connection).clone();
                snapshot.completeness.settings = false;
                request.connection = Arc::new(snapshot);
                parts.extensions.insert(request);
            }
            2 => {
                let mut request = h3();
                request.fields_complete = false;
                parts.extensions.insert(request);
            }
            _ => {
                let mut request = h3();
                request.fields.pop();
                parts.extensions.insert(request);
            }
        }
        let metadata = CaptureMetadata::default();
        capture(&parts, &metadata);
        if case < 2 {
            metadata
                .connection
                .get_ref::<H3ProfileConnection>()
                .unwrap()
                .0
                .as_ref()
                .unwrap_err();
        } else {
            metadata
                .exchange
                .get_ref::<H3ProfileRequest>()
                .unwrap()
                .0
                .as_ref()
                .unwrap_err();
        }
    }
    let parts = parts();
    let mut request = h3();
    let mut snapshot = (*request.connection).clone();
    snapshot.settings_received = false;
    snapshot.settings = None;
    snapshot.control.clear();
    request.connection = Arc::new(snapshot);
    parts.extensions.insert(request);
    let facts = connection(&parts).unwrap();
    assert_eq!(facts.slots.len(), 3);
    assert!(
        !facts
            .slots
            .iter()
            .any(|slot| slot.kind == CapturedSlotKind::Http3Settings)
    );
}

#[tokio::test]
async fn h3_selected_export_counts_one_connection_and_each_request() {
    let store = store(UserAgentDatabase::default());
    let connection = store
        .begin_connection_if_enabled(None, Protocol::HTTPS, None)
        .unwrap();
    let service =
        CaptureHttpLayer::new(Some(store.clone())).layer(service_fn(async |_: Request| {
            Ok::<_, Infallible>(Response::new(Body::empty()))
        }));
    for _ in 0..2 {
        let request = Request::from_parts(parts(), Body::empty());
        request.extensions().insert(ConnectionId(connection));
        service
            .serve(request)
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();
    }
    let details = store.details(2).await.unwrap();
    let current_day = u32::try_from(details.summary.started_at.as_second() / 86_400).unwrap();
    let mut export = ProfileExport::new(&store, &[1, 2].into(), &BTreeSet::new());
    let entry = export
        .next_evidence(current_day, 14, [9; 32], ProfileAnalysisLimits::default())
        .await
        .unwrap()
        .unwrap();
    let analysis = entry
        .analyze(false, current_day, 14, ProfileAnalysisLimits::default())
        .unwrap()
        .analysis;
    let mut connections = 0;
    let mut requests = 0;
    for scope in &analysis.scopes {
        if scope.observations.domain != CanonicalDomain::Joint {
            continue;
        }
        if scope.flow.is_some() {
            requests += scope.observations.counts.total;
        } else {
            connections += scope.observations.counts.total;
        }
    }
    assert_eq!(connections, 1);
    assert_eq!(requests, 2);
    assert!(
        export
            .next_evidence(current_day, 14, [9; 32], ProfileAnalysisLimits::default())
            .await
            .unwrap()
            .is_none()
    );
}
