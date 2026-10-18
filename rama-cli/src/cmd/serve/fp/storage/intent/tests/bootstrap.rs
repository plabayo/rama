//! The real capture/auth/queue path retains the excluded initial navigation.

use super::*;
use crate::cmd::serve::fp::{
    StorageAuthLayer,
    collection::{CollectionClaim, CollectionLease, CollectionOwner},
};
use rama::{
    error::BoxErrorExt,
    extensions::Ingress,
    http::{
        HeaderValue, Version,
        header::COOKIE,
        proto::{
            h2::{PseudoHeader, PseudoHeaderOrder},
            h3::observation::{
                FieldRepresentation, H3RequestObservation, InsertionFieldMatch,
                ObservedEncoderBindings, ObservedEncoderInstruction, ObservedFieldRepresentation,
                ObservedInsertionBinding, ObservedUniStream,
            },
        },
    },
    service::service_fn,
    ua::profile::{
        capture::{
            http3::bootstrap::{H3BootstrapCapture, H3BootstrapLimits},
            joint::CaptureLevel,
        },
        evidence::transaction::IngestionAttempt,
        model::{identity::ConnectionIpFamily, runtime_hints::RequestInitiator},
    },
};
use std::{convert::Infallible, sync::OnceLock};

fn initial_request(connection: &Extensions) -> Request<()> {
    let mut input = request("/report?h3_probe=1");
    *input.version_mut() = Version::HTTP_3;
    input
        .headers_mut()
        .insert("sec-fetch-mode", HeaderValue::from_static("navigate"));
    input
        .headers_mut()
        .insert("sec-fetch-dest", HeaderValue::from_static("document"));
    input.headers_mut().append(
        COOKIE,
        HeaderValue::from_static("rama-storage-auth=private-canary"),
    );
    input
        .headers_mut()
        .insert("x-bootstrap", HeaderValue::from_static("fresh request"));
    input.extensions().insert(
        [
            PseudoHeader::Method,
            PseudoHeader::Authority,
            PseudoHeader::Scheme,
            PseudoHeader::Path,
        ]
        .into_iter()
        .collect::<PseudoHeaderOrder>(),
    );
    input.extensions().insert(Ingress(connection.clone()));
    let info = collector::tests::h3();
    let mut snapshot = (*info.connection).clone();
    snapshot.revision = 3;
    snapshot.streams.push(ObservedUniStream {
        sequence: 3,
        stream_id: 6,
        stream_type: 2,
        grease: false,
    });
    snapshot.encoder_instructions = vec![
        ObservedEncoderInstruction::Capacity { capacity: 4096 },
        ObservedEncoderInstruction::InsertLiteral {
            name_bytes: 11,
            value_bytes: 0,
            name_huffman: false,
            value_huffman: false,
        },
    ];
    snapshot.encoder_bindings = Some(ObservedEncoderBindings {
        stream_id: 0,
        complete: true,
        insertions: vec![ObservedInsertionBinding {
            instruction_index: 1,
            insertion_index: 0,
            field: InsertionFieldMatch::Unique {
                field_index: 4 + input.headers().len() - 1,
            },
        }],
    });
    let snapshot = Arc::new(snapshot);
    let observed = H3RequestObservation {
        stream_id: 0,
        connection: snapshot.clone(),
        first_request: Arc::new(OnceLock::from(snapshot)),
        fields: vec![
            ObservedFieldRepresentation {
                representation: FieldRepresentation::LiteralName,
                index: None,
                name_huffman: false,
                value_huffman: false,
                never_index: false
            };
            4 + input.headers().len()
        ],
        fields_complete: true,
        priority: None,
    };
    input.extensions().insert(observed);
    input
}

pub(super) fn later_request(
    connection: &Extensions,
    source: &H3RequestObservation,
    authorized: bool,
    profile: bool,
) -> Request<()> {
    let mut input = initial_request(connection);
    *input.method_mut() = Method::POST;
    *input.uri_mut() = Uri::parse("/api/fetch/number/1").unwrap();
    input
        .headers_mut()
        .insert("sec-fetch-mode", HeaderValue::from_static("same-origin"));
    input
        .headers_mut()
        .insert("sec-fetch-dest", HeaderValue::from_static("empty"));
    input.headers_mut().remove("x-bootstrap");
    if !authorized {
        input.headers_mut().remove(COOKIE);
    }
    if !profile {
        input
            .headers_mut()
            .insert(USER_AGENT, HeaderValue::from_static("different-client/9"));
    }
    let mut observed = source.clone();
    observed.stream_id = 4;
    observed.fields.truncate(4 + input.headers().len());
    input.extensions().insert(observed);
    input
}

#[tokio::test]
async fn untracked_initial_navigation_is_stored_before_its_exact_bootstrap_connection() {
    for path in [
        "/report?h3_probe=1",
        "/",
        "/untracked-navigation?private=uri-canary",
    ] {
        for (authorized, profile) in [(true, true), (false, true), (true, false)] {
            let (queue, receiver) = queue(8);
            let service = CaptureLayer::new(queue.clone()).into_layer(
                StorageAuthLayer {
                    storage_auth: Some("private-canary".to_owned()),
                }
                .into_layer(service_fn(|input: Request<()>| async {
                    Ok::<_, Infallible>(input)
                })),
            );
            let connection = Extensions::new();
            connection.insert(CollectionLease::default());
            connection.insert(collector::tests::observed());
            let mut first = initial_request(&connection);
            *first.uri_mut() = Uri::parse(path).unwrap();
            let native = first
                .extensions()
                .get_ref::<H3RequestObservation>()
                .unwrap()
                .clone();
            let expected = prepare(&first, &Initiator::Navigator)
                .unwrap()
                .joint
                .canonical(JointCaptureLimits::default())
                .unwrap()
                .id;
            let first = service.serve(first).await.unwrap();
            assert!(first.extensions().contains::<StorageAuthorized>());
            assert_eq!(first.uri().to_string(), path);
            assert!(
                first
                    .extensions()
                    .get_ref::<CaptureIntent>()
                    .unwrap()
                    .0
                    .lock()
                    .is_none()
            );
            let later = service
                .serve(later_request(&connection, &native, authorized, profile))
                .await
                .unwrap();
            let h3 = data::http3_info(later.extensions()).await.unwrap();
            submit(later.extensions(), Some(&h3));
            let records = Arc::new(Mutex::new(Vec::new()));
            worker::run(
                receiver,
                MemorySink(records.clone()),
                store_limits(),
                QueueConfig {
                    capacity: 8,
                    ..QueueConfig::default()
                },
                async {},
                current_day,
                || Ok([8; 12]),
            )
            .await
            .unwrap();
            let records = records.lock();
            assert_eq!(records.len(), if authorized && profile { 3 } else { 2 });
            let request = &records[0].1;
            assert_eq!(request.joint.level, CaptureLevel::Request);
            assert_eq!(
                request
                    .joint
                    .canonical(JointCaptureLimits::default())
                    .unwrap()
                    .id,
                expected
            );
            let Some(FlowKey::Http {
                initiator, fetch, ..
            }) = request.flow.as_ref()
            else {
                panic!("initial request flow")
            };
            assert_eq!(*initiator, Some(RequestInitiator::Navigate));
            assert!(fetch.as_ref().unwrap().user_activation.is_none());
            let safe_request = request
                .joint
                .canonical(JointCaptureLimits::default())
                .unwrap();
            for private in [b"private-canary".as_slice(), b"uri-canary".as_slice()] {
                assert!(
                    !safe_request
                        .bytes
                        .windows(private.len())
                        .any(|part| part == private)
                );
            }
            let connection = &records[1].1;
            assert_eq!(connection.joint.level, CaptureLevel::Connection);
            let slot = connection
                .joint
                .slots
                .iter()
                .find(|slot| slot.kind == CapturedSlotKind::Http3Bootstrap)
                .unwrap();
            let bootstrap =
                H3BootstrapCapture::from_canonical(&slot.value, H3BootstrapLimits::default())
                    .unwrap();
            assert_eq!(bootstrap.request, expected);
            assert_eq!(bootstrap.bindings.stream_id, 0);
            assert_eq!(bootstrap.bindings.insertions.len(), 1);
            assert!(
                !slot
                    .value
                    .bytes
                    .windows(b"private-canary".len())
                    .any(|part| part == b"private-canary")
            );
            assert_eq!(
                queue.counts().invalid_capture,
                if authorized && profile { 0 } else { 1 }
            );
        }
    }
}

#[tokio::test]
async fn untracked_non_navigation_or_post_cannot_replace_initial_get_navigation() {
    for path in ["/report?h3_probe=1", "/", "/untracked-operation"] {
        for (method, mode, destination) in [
            (Method::GET, "cors", "empty"),
            (Method::GET, "navigate", "empty"),
            (Method::GET, "cors", "document"),
            (Method::POST, "navigate", "document"),
        ] {
            let (queue, receiver) = queue(8);
            let service = CaptureLayer::new(queue.clone()).into_layer(
                StorageAuthLayer {
                    storage_auth: Some("private-canary".to_owned()),
                }
                .into_layer(service_fn(|input: Request<()>| async {
                    Ok::<_, Infallible>(input)
                })),
            );
            let connection = Extensions::new();
            connection.insert(CollectionLease::default());
            connection.insert(collector::tests::observed());
            let mut first = initial_request(&connection);
            *first.uri_mut() = Uri::parse(path).unwrap();
            *first.method_mut() = method;
            first
                .headers_mut()
                .insert("sec-fetch-mode", HeaderValue::from_static(mode));
            first
                .headers_mut()
                .insert("sec-fetch-dest", HeaderValue::from_static(destination));
            let native = first
                .extensions()
                .get_ref::<H3RequestObservation>()
                .unwrap()
                .clone();
            let first = service.serve(first).await.unwrap();
            assert!(!first.extensions().contains::<CaptureIntent>());

            // A later eligible request must report the unavailable initial recipe;
            // it cannot acquire the initial request's identity by callback order.
            let later = service
                .serve(later_request(&connection, &native, true, true))
                .await
                .unwrap();
            let h3 = data::http3_info(later.extensions()).await.unwrap();
            submit(later.extensions(), Some(&h3));
            let records = Arc::new(Mutex::new(Vec::new()));
            worker::run(
                receiver,
                MemorySink(records.clone()),
                store_limits(),
                QueueConfig {
                    capacity: 8,
                    ..QueueConfig::default()
                },
                async {},
                current_day,
                || Ok([12; 12]),
            )
            .await
            .unwrap();
            assert!(records.lock().is_empty());
            assert_eq!(queue.counts().invalid_capture, 1);
        }
    }
}

#[derive(Clone, Copy)]
enum WriteOutcome {
    Stored,
    Rejected,
    Unconfirmed,
    Cancelled,
}

struct BootstrapSink {
    outcome: WriteOutcome,
    levels: Arc<Mutex<Vec<CaptureLevel>>>,
    entered: Arc<tokio::sync::Notify>,
}

impl CollectionSink for BootstrapSink {
    async fn maintain(&mut self, _day: u32, _rows: usize) -> Result<(), BoxError> {
        Ok(())
    }

    async fn ingest(
        &mut self,
        _day: u32,
        _attempt: IngestionAttempt,
        capture: &ProfileCapture,
    ) -> Result<bool, IngestFailure> {
        self.levels.lock().push(capture.joint.level);
        self.entered.notify_one();
        match self.outcome {
            WriteOutcome::Stored => Ok(false), // A confirmed idempotent retry is sufficient.
            WriteOutcome::Rejected => Err(IngestFailure::Rejected(BoxError::from_static_str(
                "recipe rejected",
            ))),
            WriteOutcome::Unconfirmed => Err(IngestFailure::Unconfirmed(
                BoxError::from_static_str("recipe uncertain"),
            )),
            WriteOutcome::Cancelled => std::future::pending().await,
        }
    }
}

async fn queued_bootstrap(empty: bool) -> (CollectionQueue, CollectionReceiver) {
    let (queue, receiver) = queue(8);
    let service = CaptureLayer::new(queue.clone()).into_layer(
        StorageAuthLayer {
            storage_auth: Some("private-canary".to_owned()),
        }
        .into_layer(service_fn(|input: Request<()>| async {
            Ok::<_, Infallible>(input)
        })),
    );
    let connection = Extensions::new();
    connection.insert(CollectionLease::default());
    connection.insert(collector::tests::observed());
    let input = if empty {
        empty_initial_request(&connection, false)
    } else {
        initial_request(&connection)
    };
    service.serve(input).await.unwrap();
    (queue, receiver)
}

#[tokio::test]
async fn bootstrap_connection_requires_confirmed_recipe_persistence() {
    for empty in [false, true] {
        bootstrap_persistence(empty).await;
    }
}

async fn bootstrap_persistence(empty: bool) {
    for outcome in [
        WriteOutcome::Stored,
        WriteOutcome::Rejected,
        WriteOutcome::Unconfirmed,
    ] {
        let (queue, receiver) = queued_bootstrap(empty).await;
        let levels = Arc::new(Mutex::new(Vec::new()));
        worker::run(
            receiver,
            BootstrapSink {
                outcome,
                levels: levels.clone(),
                entered: Arc::default(),
            },
            store_limits(),
            QueueConfig {
                capacity: 8,
                ..QueueConfig::default()
            },
            async {},
            current_day,
            || Ok([9; 12]),
        )
        .await
        .unwrap();
        let counts = queue.counts();
        match outcome {
            WriteOutcome::Stored => {
                assert_eq!(
                    *levels.lock(),
                    [CaptureLevel::Request, CaptureLevel::Connection]
                );
                assert_eq!(
                    (counts.confirmed, counts.rejected, counts.unconfirmed),
                    (2, 0, 0)
                );
            }
            WriteOutcome::Rejected => {
                assert_eq!(*levels.lock(), [CaptureLevel::Request]);
                assert_eq!(
                    (counts.confirmed, counts.rejected, counts.unconfirmed),
                    (0, 2, 0)
                );
            }
            WriteOutcome::Unconfirmed => {
                assert_eq!(*levels.lock(), [CaptureLevel::Request; 3]);
                assert_eq!(
                    (counts.confirmed, counts.rejected, counts.unconfirmed),
                    (0, 1, 1)
                );
                assert_eq!(counts.uncertain_attempts, 3);
            }
            WriteOutcome::Cancelled => panic!("unexpected cancelled outcome"),
        }
    }
}

#[tokio::test]
async fn cancelling_a_recipe_write_never_attempts_its_dependent_connection() {
    let (queue, receiver) = queued_bootstrap(false).await;
    let levels = Arc::new(Mutex::new(Vec::new()));
    let entered = Arc::new(tokio::sync::Notify::new());
    let running = tokio::spawn(worker::run(
        receiver,
        BootstrapSink {
            outcome: WriteOutcome::Cancelled,
            levels: levels.clone(),
            entered: entered.clone(),
        },
        store_limits(),
        QueueConfig {
            capacity: 8,
            ..QueueConfig::default()
        },
        std::future::pending(),
        current_day,
        || Ok([10; 12]),
    ));
    tokio::time::timeout(Duration::from_secs(2), entered.notified())
        .await
        .unwrap();
    running.abort();
    assert!(running.await.unwrap_err().is_cancelled());
    assert_eq!(*levels.lock(), [CaptureLevel::Request]);
    let counts = queue.counts();
    assert_eq!(
        (counts.confirmed, counts.rejected, counts.unconfirmed),
        (0, 1, 1)
    );
}

#[tokio::test]
async fn bootstrap_job_rejects_different_recipe_context_or_owner() {
    for change in ["recipe", "context", "profile", "authorization"] {
        let (queue, _receiver) = queue(8);
        let connection = Extensions::new();
        let lease = Arc::new(CollectionLease::default());
        connection.insert_arc(lease.clone());
        connection.insert(collector::tests::observed());
        let first = initial_request(&connection);
        let request = prepare(&first, &Initiator::Navigator).unwrap();
        let h3 = data::http3_info(first.extensions()).await.unwrap();
        let mut captured = collector::connection_capture(
            request.profile.clone(),
            request.connection.clone(),
            Version::HTTP_3,
            first.extensions(),
            Some(&h3),
            Some(&request),
        )
        .unwrap()
        .unwrap();
        let owner = CollectionOwner {
            authorized: false,
            profile: request
                .profile
                .canonical(JointCaptureLimits::default().value_bytes)
                .unwrap()
                .id,
        };
        let permit = match lease.claim(owner) {
            CollectionClaim::Connection(permit) => permit,
            claim => panic!("{claim:?}"),
        };
        let mut submitted_owner = owner;
        match change {
            "recipe" => {
                let slot = captured
                    .joint
                    .slots
                    .iter_mut()
                    .find(|slot| slot.kind == CapturedSlotKind::Http3Bootstrap)
                    .unwrap();
                let mut bootstrap =
                    H3BootstrapCapture::from_canonical(&slot.value, H3BootstrapLimits::default())
                        .unwrap();
                bootstrap.request.0[0] ^= 1;
                slot.value = bootstrap.canonical(H3BootstrapLimits::default()).unwrap();
            }
            "context" => captured.connection.ip_family = Some(ConnectionIpFamily::V6),
            "profile" => submitted_owner.profile.0[0] ^= 1,
            "authorization" => submitted_owner.authorized = true,
            _ => panic!("unknown corruption"),
        }
        queue
            .try_reserve()
            .unwrap()
            .submit(
                submitted_owner,
                current_day().unwrap(),
                request,
                Some((captured, permit)),
            )
            .unwrap_err();
        assert_eq!(queue.counts().invalid_capture, 1, "{change}");
        assert!(matches!(lease.claim(owner), CollectionClaim::Connection(_)));
    }
}

pub(super) fn empty_initial_request(connection: &Extensions, capacity_only: bool) -> Request<()> {
    let input = initial_request(connection);
    let mut observed = input
        .extensions()
        .get_ref::<H3RequestObservation>()
        .unwrap()
        .clone();
    let mut snapshot = (*observed.connection).clone();
    snapshot
        .encoder_instructions
        .truncate(usize::from(capacity_only));
    snapshot
        .encoder_bindings
        .as_mut()
        .unwrap()
        .insertions
        .clear();
    observed.connection = Arc::new(snapshot);
    observed.first_request = Arc::new(OnceLock::from(observed.connection.clone()));
    input.extensions().insert(observed);
    input
}
