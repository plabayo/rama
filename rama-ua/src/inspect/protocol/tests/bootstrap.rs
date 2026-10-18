use super::*;
use crate::{
    inspect::protocol::bootstrap::H3ProfileBootstrap,
    profile::{
        capture::http3::bootstrap::{
            H3BootstrapCapture, H3BootstrapLimits, request::H3BootstrapRequest,
        },
        format::canonical::ValueId,
    },
};
use rama_http::{
    HeaderValue,
    proto::h3::observation::{
        InsertionFieldMatch, ObservedEncoderBindings, ObservedEncoderInstruction,
        ObservedInsertionBinding,
    },
};

fn dynamic_head(pending: bool) -> H3RequestObservation {
    let mut request = h3();
    let mut snapshot = (*request.connection).clone();
    snapshot.revision = 3;
    snapshot.streams.push(ObservedUniStream {
        sequence: 3,
        stream_id: 10,
        stream_type: 2,
        grease: false,
    });
    snapshot.encoder_instructions = vec![
        ObservedEncoderInstruction::Capacity { capacity: 4096 },
        ObservedEncoderInstruction::InsertLiteral {
            name_bytes: 10,
            value_bytes: 11,
            name_huffman: false,
            value_huffman: true,
        },
    ];
    snapshot.encoder_bindings = Some(ObservedEncoderBindings {
        stream_id: 0,
        complete: true,
        insertions: vec![ObservedInsertionBinding {
            instruction_index: 1,
            insertion_index: 0,
            field: InsertionFieldMatch::Unique { field_index: 4 },
        }],
    });
    if pending {
        snapshot.settings_received = false;
        snapshot.settings = None;
        snapshot.control.clear();
        snapshot.completeness.settings = false;
    }
    request.connection = Arc::new(snapshot);
    request.first_request = Arc::new(OnceLock::new());
    if !pending {
        request
            .first_request
            .set(request.connection.clone())
            .unwrap();
    }
    request
}

fn request_id(metadata: &CaptureMetadata) -> ValueId {
    let slots = metadata
        .exchange
        .get_ref::<H3ProfileRequest>()
        .unwrap()
        .0
        .as_ref()
        .unwrap();
    JointCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        level: CaptureLevel::Request,
        slots: slots.clone(),
    }
    .canonical(JointCaptureLimits::default())
    .unwrap()
    .id
}

#[test]
fn delayed_settings_keep_the_initial_request_recipe_not_the_later_head() {
    let first = parts();
    let observation = dynamic_head(true);
    let boundary = observation.first_request.clone();
    first.extensions.insert(observation);
    let initial = CaptureMetadata::default();
    capture(&first, &initial);
    assert!(matches!(
        initial
            .connection
            .get_ref::<H3ProfileConnection>()
            .unwrap()
            .facts(),
        Err(ProfileDataError::Incomplete(_))
    ));
    let frozen = initial.connection.get_ref::<H3ProfileBootstrap>().unwrap();
    assert_eq!(
        frozen.0.as_ref().unwrap().request_id(),
        request_id(&initial)
    );

    let mut next = parts();
    next.headers
        .insert("user-agent", HeaderValue::from_static("later/2"));
    let mut later_observation = dynamic_head(false);
    boundary.set(later_observation.connection.clone()).unwrap();
    later_observation.first_request = boundary;
    later_observation.stream_id = 4;
    next.extensions.insert(later_observation);
    let later = CaptureMetadata {
        connection: initial.connection.clone(),
        ..Default::default()
    };
    capture(&next, &later);
    assert_ne!(request_id(&initial), request_id(&later));
    let facts = later
        .connection
        .get_ref::<H3ProfileConnection>()
        .unwrap()
        .facts()
        .unwrap();
    let slots = connection_slots(&facts, &later).unwrap();
    let value = &slots
        .iter()
        .find(|slot| slot.kind == CapturedSlotKind::Http3Bootstrap)
        .unwrap()
        .value;
    let saved = H3BootstrapCapture::from_canonical(value, H3BootstrapLimits::default()).unwrap();
    assert_eq!(saved.request, request_id(&initial));
    assert_eq!(saved.method, first.method);
    assert!(std::ptr::eq(
        frozen,
        later.connection.get_ref::<H3ProfileBootstrap>().unwrap()
    ));
    for secret in [
        b"cookie-canary".as_slice(),
        b"auth-canary",
        b"synthetic/1",
        b"later/2",
    ] {
        assert!(
            !value
                .bytes
                .windows(secret.len())
                .any(|bytes| bytes == secret)
        );
    }
}

#[test]
fn later_requests_cannot_invent_a_missing_initial_recipe() {
    let parts = parts();
    let mut observation = dynamic_head(false);
    observation.stream_id = 4;
    parts.extensions.insert(observation);
    let metadata = CaptureMetadata::default();
    capture(&parts, &metadata);
    assert!(!metadata.connection.contains::<H3ProfileBootstrap>());
    let facts = metadata
        .connection
        .get_ref::<H3ProfileConnection>()
        .unwrap()
        .facts()
        .unwrap();
    connection_slots(&facts, &metadata).unwrap_err();
}

#[test]
fn changed_frozen_associations_cannot_relabel_the_initial_recipe() {
    let first = parts();
    let observation = dynamic_head(true);
    let boundary = observation.first_request.clone();
    first.extensions.insert(observation);
    let initial = CaptureMetadata::default();
    capture(&first, &initial);
    let next = parts();
    let mut changed = dynamic_head(false);
    let mut snapshot = (*changed.connection).clone();
    snapshot.encoder_bindings.as_mut().unwrap().complete = false;
    changed.connection = Arc::new(snapshot);
    boundary.set(changed.connection.clone()).unwrap();
    changed.first_request = boundary;
    changed.stream_id = 4;
    next.extensions.insert(changed);
    let later = CaptureMetadata {
        connection: initial.connection,
        ..Default::default()
    };
    capture(&next, &later);
    let facts = later
        .connection
        .get_ref::<H3ProfileConnection>()
        .unwrap()
        .facts()
        .unwrap();
    connection_slots(&facts, &later).unwrap_err();
}

#[test]
fn bootstrap_reference_does_not_hash_discarded_credentials() {
    let mut ids = Vec::new();
    for value in ["first-secret", "different-secret"] {
        let mut parts = parts();
        parts.headers.remove("accept");
        parts
            .headers
            .insert("cookie", HeaderValue::from_str(value).unwrap());
        parts
            .headers
            .insert("authorization", HeaderValue::from_str(value).unwrap());
        parts.extensions.insert(dynamic_head(false));
        let metadata = CaptureMetadata::default();
        capture(&parts, &metadata);
        let capture = metadata
            .connection
            .get_ref::<H3ProfileBootstrap>()
            .unwrap()
            .0
            .as_ref()
            .unwrap();
        ids.push(capture.request_id());
    }
    assert_eq!(ids[0], ids[1]);
}

#[test]
fn observer_callback_order_does_not_cache_a_missing_bootstrap_recipe() {
    let first = parts();
    first.extensions.insert(dynamic_head(false));
    let mut next = parts();
    next.headers
        .insert("user-agent", HeaderValue::from_static("later/2"));
    let mut observation = dynamic_head(false);
    observation.stream_id = 4;
    next.extensions.insert(observation);
    let initial = CaptureMetadata::default();
    let later = CaptureMetadata {
        connection: initial.connection.clone(),
        ..Default::default()
    };
    capture(&next, &later);
    let facts = later
        .connection
        .get_ref::<H3ProfileConnection>()
        .unwrap()
        .facts()
        .unwrap();
    connection_slots(&facts, &later).unwrap_err();
    capture(&first, &initial);
    let slots = connection_slots(&facts, &later).unwrap();
    let value = &slots
        .iter()
        .find(|slot| slot.kind == CapturedSlotKind::Http3Bootstrap)
        .unwrap()
        .value;
    let bootstrap =
        H3BootstrapCapture::from_canonical(value, H3BootstrapLimits::default()).unwrap();
    assert_eq!(bootstrap.request, request_id(&initial));
    assert_ne!(bootstrap.request, request_id(&later));
}

#[tokio::test]
async fn counted_export_keeps_the_bootstrap_reference_with_its_request_variant() {
    let store = store(UserAgentDatabase::default());
    let connection = store
        .begin_connection_if_enabled(None, Protocol::HTTPS, None)
        .unwrap();
    let service =
        CaptureHttpLayer::new(Some(store.clone())).layer(service_fn(async |_: Request| {
            Ok::<_, Infallible>(Response::new(Body::empty()))
        }));
    let mut expected = None;
    for stream_id in [0, 4] {
        let mut parts = parts();
        let mut observation = dynamic_head(false);
        observation.stream_id = stream_id;
        parts.extensions.insert(observation);
        if stream_id == 0 {
            expected = Some(
                JointCapture {
                    completeness: ProfileCaptureCompleteness::Complete,
                    level: CaptureLevel::Request,
                    slots: request(&parts).unwrap(),
                }
                .canonical(JointCaptureLimits::default())
                .unwrap()
                .id,
            );
        } else {
            parts
                .headers
                .insert("accept", HeaderValue::from_static("application/json"));
        }
        let request = Request::from_parts(parts, Body::empty());
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
    let analysis = export
        .next_evidence(current_day, 14, [9; 32], ProfileAnalysisLimits::default())
        .await
        .unwrap()
        .unwrap()
        .analyze(false, current_day, 14, ProfileAnalysisLimits::default())
        .unwrap()
        .analysis;
    let mut references = Vec::new();
    let mut requests = Vec::new();
    for scope in &analysis.scopes {
        if scope.observations.domain != CanonicalDomain::Joint {
            continue;
        }
        for variant in &scope.observations.variants {
            if scope.flow.is_some() {
                requests.push(variant.value.id);
                continue;
            }
            let joint = JointCapture::from_canonical(&variant.value, JointCaptureLimits::default())
                .unwrap();
            for slot in joint.slots {
                if slot.kind == CapturedSlotKind::Http3Bootstrap {
                    references.push(
                        H3BootstrapCapture::from_canonical(
                            &slot.value,
                            H3BootstrapLimits::default(),
                        )
                        .unwrap()
                        .request,
                    );
                }
            }
        }
    }
    assert_eq!(references, vec![expected.unwrap()]);
    assert!(requests.contains(&references[0]));
    assert_eq!(requests.len(), 2);
}

#[test]
fn bootstrap_reference_rejects_a_capacity_instruction_as_an_insertion() {
    let parts = parts();
    let mut observation = dynamic_head(false);
    let mut snapshot = (*observation.connection).clone();
    snapshot.encoder_bindings.as_mut().unwrap().insertions[0].instruction_index = 0;
    observation.connection = Arc::new(snapshot);
    observation.first_request = Arc::new(OnceLock::from(observation.connection.clone()));
    parts.extensions.insert(observation);
    let metadata = CaptureMetadata::default();
    capture(&parts, &metadata);
    let facts = metadata
        .connection
        .get_ref::<H3ProfileConnection>()
        .unwrap()
        .facts()
        .unwrap();
    connection_slots(&facts, &metadata).unwrap_err();
}

#[test]
fn initial_request_reference_rejects_another_stream_on_capture_and_bind() {
    let parts = parts();
    let observed = dynamic_head(false);
    parts.extensions.insert(observed.clone());
    let joint = JointCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        level: CaptureLevel::Request,
        slots: request(&parts).unwrap(),
    };
    let reference = H3BootstrapRequest::capture(
        &joint,
        &parts.method,
        &observed,
        H3BootstrapLimits::default(),
    )
    .unwrap();
    let mut later = observed.clone();
    later.stream_id = 4;
    H3BootstrapRequest::capture(&joint, &parts.method, &later, H3BootstrapLimits::default())
        .unwrap_err();
    let sequence = H3ClientSequenceCapture::capture_at_request_head(
        &observed.connection,
        H3SequenceCaptureLimits::default(),
    )
    .unwrap();
    let bindings = observed.connection.encoder_bindings.as_ref().unwrap();
    reference.bind(bindings, &sequence).unwrap();
    let mut different = bindings.clone();
    different.stream_id = 4;
    reference.bind(&different, &sequence).unwrap_err();
}

#[tokio::test]
async fn the_first_stored_request_exports_after_native_publication_without_another_request() {
    for dynamic in [false, true] {
        let store = store(UserAgentDatabase::default());
        let connection = store
            .begin_connection_if_enabled(None, Protocol::HTTPS, None)
            .unwrap();
        let service =
            CaptureHttpLayer::new(Some(store.clone())).layer(service_fn(async |_: Request| {
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }));
        let parts = parts();
        let mut observed = if dynamic { dynamic_head(false) } else { h3() };
        let ready = observed.connection.clone();
        let boundary = Arc::new(OnceLock::new());
        observed.first_request = boundary.clone();
        let mut pending = (*ready).clone();
        pending.settings_received = false;
        pending.completeness.settings = false;
        pending.settings = None;
        pending.control.clear();
        observed.connection = Arc::new(pending);
        parts.extensions.insert(observed);
        let expected = JointCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            level: CaptureLevel::Request,
            slots: request(&parts).unwrap(),
        }
        .canonical(JointCaptureLimits::default())
        .unwrap()
        .id;
        let request = Request::from_parts(parts, Body::empty());
        request.extensions().insert(ConnectionId(connection));
        service
            .serve(request)
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();
        let details = store.details(1).await.unwrap();
        let current_day = u32::try_from(details.summary.started_at.as_second() / 86_400).unwrap();
        let mut export = ProfileExport::new(&store, &[1].into(), &BTreeSet::new());
        export
            .next_evidence(current_day, 14, [9; 32], ProfileAnalysisLimits::default())
            .await
            .unwrap_err();
        boundary.set(ready).unwrap();
        let analysis = export
            .next_evidence(current_day, 14, [9; 32], ProfileAnalysisLimits::default())
            .await
            .unwrap()
            .unwrap()
            .analyze(false, current_day, 14, ProfileAnalysisLimits::default())
            .unwrap()
            .analysis;
        let mut connections = 0;
        let mut requests = 0;
        let mut bootstrap = 0;
        for scope in &analysis.scopes {
            if scope.observations.domain != CanonicalDomain::Joint {
                continue;
            }
            if scope.flow.is_some() {
                requests += scope.observations.counts.total;
                continue;
            }
            connections += scope.observations.counts.total;
            for variant in &scope.observations.variants {
                let joint =
                    JointCapture::from_canonical(&variant.value, JointCaptureLimits::default())
                        .unwrap();
                for slot in joint.slots {
                    if slot.kind == CapturedSlotKind::Http3Bootstrap {
                        let captured = H3BootstrapCapture::from_canonical(
                            &slot.value,
                            H3BootstrapLimits::default(),
                        )
                        .unwrap();
                        assert_eq!(captured.request, expected);
                        bootstrap += 1;
                    }
                }
            }
        }
        assert_eq!(connections, 1);
        assert_eq!(requests, 1);
        assert_eq!(bootstrap, usize::from(dynamic));
    }
}
