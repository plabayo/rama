//! Native first requests remain exact recipes even outside measured page flows.

use super::bootstrap::{empty_initial_request, later_request};
use super::*;
use rama::{
    http::{header::AUTHORIZATION, proto::h3::observation::H3RequestObservation},
    ua::profile::{
        analysis::profile::ProfileAnalysisLimits,
        capture::http3::bootstrap::{H3BootstrapCapture, H3BootstrapLimits},
        evidence::{collector::ProfileEvidenceCollector, transaction::CaptureRunId},
        format::archive::ProfileArchiveEntry,
        model::ua::UserAgentProfile,
        selection::{
            DrawKey, ProfileSeed,
            capabilities::CapabilitySet,
            database::UserAgentDatabase,
            variants::{ProfileSelector, SelectionRequest, VariantPins},
        },
    },
};

#[tokio::test]
async fn unclassified_initial_assets_keep_safe_recipe_and_connection_ownership() {
    for (method, destination) in [
        (Method::GET, "style"),
        (Method::GET, "script"),
        (Method::POST, "empty"),
    ] {
        let (queue, receiver) = queue(8);
        let service = CaptureLayer::new(queue.clone()).into_layer(
            StorageAuthLayer {
                storage_auth: Some("private-canary".to_owned()),
            }
            .into_layer(service_fn(|input: Request<&'static str>| async {
                Ok::<_, Infallible>(input)
            })),
        );
        let ingress = Extensions::new();
        ingress.insert(CollectionLease::default());
        ingress.insert(collector::tests::observed());
        let mut first = empty_initial_request(&ingress, false).map(|_| "body-private-canary");
        *first.uri_mut() = Uri::parse("/assets/first?private=uri-canary").unwrap();
        *first.method_mut() = method.clone();
        first
            .headers_mut()
            .insert("sec-fetch-mode", HeaderValue::from_static("no-cors"));
        first
            .headers_mut()
            .insert("sec-fetch-dest", HeaderValue::from_static(destination));
        first.headers_mut().insert(
            AUTHORIZATION,
            HeaderValue::from_static("auth-private-canary"),
        );
        let mut native = first
            .extensions()
            .get_ref::<H3RequestObservation>()
            .unwrap()
            .clone();
        native
            .fields
            .resize(4 + first.headers().len(), native.fields[0]);
        first.extensions().insert(native.clone());
        let first = service.serve(first).await.unwrap();
        assert_eq!(*first.body(), "body-private-canary");
        assert!(
            first
                .extensions()
                .get_ref::<CaptureIntent>()
                .unwrap()
                .0
                .lock()
                .is_none()
        );
        let info = data::http3_info(first.extensions()).await.unwrap();
        submit(first.extensions(), Some(&info)); // The internal bootstrap-only completion already submitted it.
        let later = later_request(&ingress, &native, true, true).map(|_| "later-body-canary");
        let later = service.serve(later).await.unwrap();
        let info = data::http3_info(later.extensions()).await.unwrap();
        submit(later.extensions(), Some(&info));
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
        assert_eq!(records.len(), 3);
        assert_eq!(
            records
                .iter()
                .map(|(_, capture)| capture.joint.level)
                .collect::<Vec<_>>(),
            [
                CaptureLevel::Request,
                CaptureLevel::Connection,
                CaptureLevel::Request
            ]
        );
        let first = &records[0].1;
        let connection = &records[1].1;
        let first_id = first
            .joint
            .canonical(JointCaptureLimits::default())
            .unwrap()
            .id;
        let slot = connection
            .joint
            .slots
            .iter()
            .find(|slot| slot.kind == CapturedSlotKind::Http3Bootstrap)
            .unwrap();
        let bootstrap =
            H3BootstrapCapture::from_canonical(&slot.value, H3BootstrapLimits::default()).unwrap();
        assert_eq!(bootstrap.request, first_id);
        assert_eq!(bootstrap.method, method);
        assert_eq!(bootstrap.bindings.stream_id, 0);
        assert!(bootstrap.bindings.complete);
        let Some(FlowKey::Http {
            initiator,
            fetch: Some(fetch),
            ..
        }) = first.flow.as_ref()
        else {
            panic!("initial asset context")
        };
        assert!(initiator.is_none());
        assert_eq!(fetch.destination.as_deref(), Some(destination));
        for (_, capture) in records.iter() {
            let value = capture
                .joint
                .canonical(JointCaptureLimits::default())
                .unwrap();
            for private in [
                b"body-private-canary".as_slice(),
                b"auth-private-canary",
                b"private=uri-canary",
            ] {
                assert!(
                    !value
                        .bytes
                        .windows(private.len())
                        .any(|bytes| bytes == private)
                );
            }
        }
        let day = current_day().unwrap();
        let limits = ProfileAnalysisLimits::default();
        let mut evidence = ProfileEvidenceCollector::new(
            &first.profile,
            true,
            CaptureRunId::new(day, [9; 12]),
            [7; 32],
            day,
            limits,
        )
        .unwrap();
        for (_, capture) in records.iter() {
            evidence.observe(day, capture).unwrap();
        }
        let analysis = ProfileArchiveEntry {
            evidence: evidence.finish(),
            sampler_seed: [7; 32],
        }
        .analyze(true, day, 14, limits)
        .unwrap()
        .analysis;
        let database: UserAgentDatabase = [UserAgentProfile::from_captured(analysis)]
            .into_iter()
            .collect();
        let seed = ProfileSeed([1; 32]);
        let key = DrawKey([2; 32]);
        let selected = database
            .select(
                &SelectionRequest {
                    client: ProfileSelector::default(),
                    required: CapabilitySet {
                        h3: true,
                        ..CapabilitySet::default()
                    },
                    flow: first.flow.clone().unwrap(),
                    pins: VariantPins {
                        connection: Some(
                            connection
                                .joint
                                .canonical(JointCaptureLimits::default())
                                .unwrap()
                                .id,
                        ),
                        request: Some(first_id),
                    },
                },
                seed,
                key,
            )
            .unwrap()
            .for_connection_bootstrap(seed, key)
            .unwrap();
        assert_eq!(selected.pins().request, Some(first_id));
    }
}

#[tokio::test]
async fn unclassified_later_or_incomplete_requests_never_claim_initial_recipe() {
    for change in ["later", "fields", "bindings", "version"] {
        let (queue, receiver) = queue(8);
        let service =
            CaptureLayer::new(queue.clone()).into_layer(service_fn(|request: Request<()>| async {
                Ok::<_, Infallible>(request)
            }));
        let ingress = Extensions::new();
        ingress.insert(CollectionLease::default());
        ingress.insert(collector::tests::observed());
        let mut input = empty_initial_request(&ingress, false);
        *input.uri_mut() = Uri::parse("/assets/first").unwrap();
        input
            .headers_mut()
            .insert("sec-fetch-mode", HeaderValue::from_static("no-cors"));
        input
            .headers_mut()
            .insert("sec-fetch-dest", HeaderValue::from_static("style"));
        let mut native = input
            .extensions()
            .get_ref::<H3RequestObservation>()
            .unwrap()
            .clone();
        match change {
            "later" => native.stream_id = 4,
            "fields" => native.fields_complete = false,
            "bindings" => {
                let mut snapshot = (*native.connection).clone();
                snapshot.encoder_bindings.as_mut().unwrap().complete = false;
                native.connection = Arc::new(snapshot);
            }
            "version" => *input.version_mut() = Version::HTTP_2,
            _ => panic!("unknown native fixture change"),
        }
        input.extensions().insert(native);
        let input = service.serve(input).await.unwrap();
        assert!(!input.extensions().contains::<CaptureIntent>(), "{change}");
        assert_eq!(queue.counts().invalid_capture, 0, "{change}");
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
        assert!(records.lock().is_empty(), "{change}");
    }
}

#[tokio::test]
async fn initial_asset_application_error_preserves_safe_native_capture() {
    let (queue, receiver) = queue(4);
    let service = CaptureLayer::new(queue.clone()).into_layer(service_fn(|_: Request<()>| async {
        Err::<(), _>("application-error")
    }));
    let ingress = Extensions::new();
    ingress.insert(CollectionLease::default());
    ingress.insert(collector::tests::observed());
    let mut input = empty_initial_request(&ingress, false);
    *input.uri_mut() = Uri::parse("/assets/first").unwrap();
    input.headers_mut().remove(COOKIE);
    input
        .headers_mut()
        .insert("sec-fetch-mode", HeaderValue::from_static("no-cors"));
    input
        .headers_mut()
        .insert("sec-fetch-dest", HeaderValue::from_static("script"));
    let mut native = input
        .extensions()
        .get_ref::<H3RequestObservation>()
        .unwrap()
        .clone();
    native.fields.truncate(4 + input.headers().len());
    input.extensions().insert(native);
    assert_eq!(service.serve(input).await.unwrap_err(), "application-error");
    let records = Arc::new(Mutex::new(Vec::new()));
    worker::run(
        receiver,
        MemorySink(records.clone()),
        store_limits(),
        QueueConfig {
            capacity: 4,
            ..QueueConfig::default()
        },
        async {},
        current_day,
        || Ok([8; 12]),
    )
    .await
    .unwrap();
    let records = records.lock();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].1.joint.level, CaptureLevel::Request);
    assert_eq!(records[1].1.joint.level, CaptureLevel::Connection);
    assert!(
        records[1]
            .1
            .joint
            .slots
            .iter()
            .any(|slot| slot.kind == CapturedSlotKind::Http3Bootstrap)
    );
}
