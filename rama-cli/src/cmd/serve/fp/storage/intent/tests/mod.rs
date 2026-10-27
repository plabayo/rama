mod bootstrap;
mod initial_request;
mod static_initial;

use super::super::super::{
    StorageAuthLayer,
    collection::CollectionLayer,
    data::{self, DataSource},
    state::State,
};
use super::super::Storage;
use super::super::{
    counted::{IngestFailure, StoreLimits},
    worker::{self, CollectionReceiver, CollectionSink, QueueConfig},
};
use super::*;
use crate::utils::{
    http::HttpVersions,
    http3::{Http3Args, HttpListeners, OBSERVATION_LIMITS},
};
use rama::{
    extensions::Ingress,
    http::{
        Body, HeaderValue, Response, Version,
        client::{EasyHttpWebClient, Http3Connector},
        conn::TargetHttpVersion,
        header::COOKIE,
        proto::h2::{
            PseudoHeader, PseudoHeaderOrder,
            frame::{EarlyFrameStreamContext, Head, Kind, Settings, StreamId},
        },
        server::HttpServer,
    },
    net::{address::SocketAddress, test_utils::client::MockConnectorService},
    quic::{Endpoint, tls::BoringTlsProvider},
    rt::Executor,
    service::service_fn,
    tls::{
        SecureTransport,
        boring::server::TlsAcceptorLayer,
        client::{ServerVerifyMode, TlsClientConfig},
        server::{GeneratedServerAuthConfig, TlsServerConfig},
    },
    ua::profile::{
        capture::{
            headers::{HeaderCapture, HeaderCapturePolicy, HeaderValueSource, RequestBinding},
            joint::{CaptureLevel, CapturedSlotKind},
        },
        evidence::transaction::{IngestionAttempt, IngestionBatchLimits},
    },
    utils::octets::{kib, mib},
};
use std::{convert::Infallible, sync::Arc, time::Duration};
use tokio::{
    sync::oneshot,
    time::{advance, timeout},
};

fn store_limits() -> StoreLimits {
    StoreLimits {
        ingestion: IngestionBatchLimits::default(),
        capture: JointCaptureLimits::default(),
        retained: [32, 32, 64, 128, 64, 2048, mib(4)],
        checkpoint_bytes: kib(16),
    }
}

fn queue(capacity: usize) -> (CollectionQueue, CollectionReceiver) {
    CollectionQueue::new(
        QueueConfig {
            capacity,
            ..QueueConfig::default()
        },
        store_limits(),
    )
    .unwrap()
}

fn request(path: &str) -> Request<()> {
    let request = Request::builder()
        .uri(path)
        .version(Version::HTTP_11)
        .header(USER_AGENT, "unknown-client/7")
        .body(())
        .unwrap();
    request
        .extensions()
        .insert(super::super::super::CleartextConnection);
    request
}

#[test]
fn only_explicit_report_and_api_flows_prepare_observations() {
    for (method, path, expected) in [
        (Method::GET, "/report", true),
        (Method::GET, "/report?h3_probe=1", false),
        (Method::GET, "/report?other=1&h3_probe", false),
        (Method::GET, "/report?other=h3_probe", true),
        (Method::GET, "/consent", false),
        (Method::GET, "/assets/script.js", false),
        (Method::POST, "/report", false),
        (Method::POST, "/api/fetch/number/1", true),
        (Method::GET, "/api/fetch/number/1", false),
        (Method::POST, "/api/xml/number/1", true),
        (Method::GET, "/form", true),
        (Method::POST, "/form", true),
        (Method::GET, "/api/ws", true),
        (Method::CONNECT, "/api/ws", true),
        (Method::GET, "/api/ws-other", false),
    ] {
        assert_eq!(
            initiator(&method, &Uri::parse(path).unwrap()).is_some(),
            expected,
            "{method} {path}"
        );
    }
}

#[tokio::test]
async fn full_queue_rejects_before_optional_capture_validation() {
    let (queue, _receiver) = queue(1);
    let reservation = queue.try_reserve().unwrap();
    let service =
        CaptureLayer::new(queue.clone()).into_layer(service_fn(|request: Request<()>| async {
            Ok::<_, Infallible>(request)
        }));
    let mut input = request("/report");
    input.headers_mut().insert(
        USER_AGENT,
        HeaderValue::from_bytes(&vec![b'x'; kib(8) + 1]).unwrap(),
    );
    let output = service.serve(input).await.unwrap();
    assert!(!output.extensions().contains::<CaptureIntent>());
    let counts = queue.counts();
    assert_eq!(
        (
            counts.queue_full,
            counts.invalid_capture,
            counts.preparation_drops
        ),
        (1, 0, 0)
    );
    drop(reservation);
}

#[tokio::test]
async fn capture_preserves_cookie_occurrences_without_retaining_cookie_values() {
    let (queue, _receiver) = queue(1);
    let service =
        CaptureLayer::new(queue).into_layer(service_fn(|mut request: Request<()>| async {
            // Model the later display/auth redaction which collapses these occurrences.
            request.headers_mut().remove(COOKIE);
            request
                .headers_mut()
                .insert(COOKIE, HeaderValue::from_static("rama-storage-auth=xxx"));
            Ok::<_, Infallible>(request)
        }));
    let mut input = request("/report");
    input.headers_mut().append(
        COOKIE,
        HeaderValue::from_static("rama-storage-auth=private-canary"),
    );
    input
        .headers_mut()
        .append(COOKIE, HeaderValue::from_static("session=another-canary"));
    let output = service.serve(input).await.unwrap();
    let prepared = output
        .extensions()
        .get_ref::<CaptureIntent>()
        .unwrap()
        .0
        .lock()
        .take()
        .unwrap();
    let raw = &prepared.request.joint.slots[0].value;
    let policy = HeaderCapturePolicy {
        bytes: JointCaptureLimits::default().value_bytes,
        ..HeaderCapturePolicy::default()
    };
    let captured = HeaderCapture::from_canonical(raw, &policy).unwrap();
    let cookies: Vec<_> = captured
        .fields
        .iter()
        .filter(|field| field.name == COOKIE)
        .collect();
    assert_eq!(cookies.len(), 2);
    assert!(cookies.iter().all(|field| matches!(
        field.value,
        HeaderValueSource::Request(RequestBinding::Cookie)
    )));
    assert!(!raw.bytes.windows(6).any(|bytes| bytes == b"canary"));
    assert!(
        output
            .extensions()
            .get_ref::<CaptureIntent>()
            .unwrap()
            .0
            .lock()
            .take()
            .is_none()
    );
}

#[tokio::test]
async fn ineligible_routes_never_reserve_even_when_queue_is_full() {
    let (queue, _receiver) = queue(1);
    let reservation = queue.try_reserve().unwrap();
    let service =
        CaptureLayer::new(queue.clone()).into_layer(service_fn(|request: Request<()>| async {
            Ok::<_, Infallible>(request)
        }));
    for path in ["/assets/script.js", "/consent", "/report?h3_probe=1"] {
        let output = service.serve(request(path)).await.unwrap();
        assert!(!output.extensions().contains::<CaptureIntent>());
    }
    assert_eq!(queue.counts().queue_full, 0);
    drop(reservation);
}

#[derive(Clone)]
struct MemorySink(Arc<Mutex<Vec<(IngestionAttempt, ProfileCapture)>>>);
impl CollectionSink for MemorySink {
    async fn maintain(&mut self, _day: u32, _rows: usize) -> Result<(), BoxError> {
        Ok(())
    }

    async fn ingest(
        &mut self,
        _day: u32,
        attempt: IngestionAttempt,
        capture: &ProfileCapture,
    ) -> Result<bool, IngestFailure> {
        self.0.lock().push((attempt, capture.clone()));
        Ok(true)
    }
}

#[tokio::test]
async fn real_auth_layer_runs_after_safe_capture_and_each_intent_submits_once() {
    let (queue, receiver) = queue(2);
    let service = CaptureLayer::new(queue.clone()).into_layer(
        StorageAuthLayer {
            storage_auth: Some("private-canary".to_owned()),
        }
        .into_layer(service_fn(|request: Request<()>| async {
            Ok::<_, Infallible>(request)
        })),
    );
    let connection = Extensions::new();
    connection.insert(CollectionLease::default());
    let mut input = request("/report");
    input.extensions().insert(Ingress(connection));
    input.headers_mut().append(
        COOKIE,
        HeaderValue::from_static("rama-storage-auth=private-canary"),
    );
    input
        .headers_mut()
        .append(COOKIE, HeaderValue::from_static("session=second-canary"));
    let output = service.serve(input).await.unwrap();
    assert!(output.extensions().contains::<StorageAuthorized>());
    assert!(
        !output
            .headers()
            .get(COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("private-canary")
    );
    let day = output
        .extensions()
        .get_ref::<CaptureIntent>()
        .unwrap()
        .0
        .lock()
        .as_ref()
        .unwrap()
        .day;
    submit(output.extensions(), None);
    submit(output.extensions(), None);
    let records = Arc::new(Mutex::new(Vec::new()));
    worker::run(
        receiver,
        MemorySink(records.clone()),
        store_limits(),
        QueueConfig {
            capacity: 2,
            ..QueueConfig::default()
        },
        async {},
        || Ok(day),
        || Ok([1; 12]),
    )
    .await
    .unwrap();
    let records = records.lock();
    assert_eq!(records.len(), 2);
    assert!(records.iter().all(|(record, _)| record.authorized));
    assert_eq!(records[0].0.observation.sequence, 1);
    assert_eq!(records[1].0.observation.sequence, 2);
    assert_eq!(records[0].1.joint.level, CaptureLevel::Connection);
    assert!(records[0].1.joint.slots.is_empty());
    let capture = &records[1].1;
    assert_eq!(capture.joint.level, CaptureLevel::Request);
    let policy = HeaderCapturePolicy {
        bytes: JointCaptureLimits::default().value_bytes,
        ..HeaderCapturePolicy::default()
    };
    let headers = HeaderCapture::from_canonical(&capture.joint.slots[0].value, &policy).unwrap();
    assert_eq!(
        headers
            .fields
            .iter()
            .filter(|field| field.name == COOKIE)
            .count(),
        2
    );
    assert_eq!(queue.counts().confirmed, 2);
    assert_eq!(queue.counts().invalid_capture, 0);
}

#[tokio::test]
async fn dropping_prepared_request_releases_capacity_without_claiming_connection() {
    let (queue, _receiver) = queue(1);
    let service =
        CaptureLayer::new(queue.clone()).into_layer(service_fn(|request: Request<()>| async {
            Ok::<_, Infallible>(request)
        }));
    let output = service.serve(request("/report")).await.unwrap();
    assert!(output.extensions().contains::<CaptureIntent>());
    assert!(queue.try_reserve().is_none());
    drop(output);
    assert_eq!(queue.counts().preparation_drops, 1);
    assert_eq!(queue.counts().confirmed, 0);
    assert_eq!(queue.counts().unconfirmed, 0);
    assert!(queue.try_reserve().is_some());
}

fn h2_request(connection: &Extensions) -> Request<()> {
    let mut input = request("/report");
    *input.version_mut() = Version::HTTP_2;
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
    let settings = Settings::load_observed(
        Head::new(Kind::Settings, 0, StreamId::zero()),
        &[0, 1, 0, 0, 16, 0],
        true,
    )
    .unwrap();
    let mut recorder = EarlyFrameStreamContext::new_recorder();
    recorder.record_settings_frame(&settings);
    input
        .extensions()
        .insert(recorder.freeze_recorder().unwrap());
    input
}

#[tokio::test]
async fn shared_h2_connection_is_submitted_once_and_each_request_gets_an_id() {
    let (queue, receiver) = queue(2);
    let service =
        CaptureLayer::new(queue.clone()).into_layer(service_fn(|request: Request<()>| async {
            Ok::<_, Infallible>(request)
        }));
    let connection = Extensions::new();
    connection.insert(CollectionLease::default());
    let first = service.serve(h2_request(&connection)).await.unwrap();
    let second = service.serve(h2_request(&connection)).await.unwrap();
    let day = first
        .extensions()
        .get_ref::<CaptureIntent>()
        .unwrap()
        .0
        .lock()
        .as_ref()
        .unwrap()
        .day;
    submit(first.extensions(), None);
    submit(second.extensions(), None);
    let records = Arc::new(Mutex::new(Vec::new()));
    worker::run(
        receiver,
        MemorySink(records.clone()),
        store_limits(),
        QueueConfig {
            capacity: 2,
            ..QueueConfig::default()
        },
        async {},
        || Ok(day),
        || Ok([1; 12]),
    )
    .await
    .unwrap();
    let records = records.lock();
    assert_eq!(records.len(), 3);
    assert!(matches!(records[0].1.joint.level, CaptureLevel::Connection));
    assert_eq!(
        records[0].1.joint.slots[0].kind,
        CapturedSlotKind::Http2EarlyFrames
    );
    assert!(
        records[1..]
            .iter()
            .all(|(_, capture)| matches!(capture.joint.level, CaptureLevel::Request))
    );
    assert_eq!(
        records
            .iter()
            .map(|(attempt, _)| attempt.observation.sequence)
            .collect::<Vec<_>>(),
        [1, 2, 3]
    );
    assert_eq!(queue.counts().confirmed, 3);
    assert_eq!(queue.counts().invalid_capture, 0);
}

#[tokio::test]
async fn shared_connection_never_crosses_profiles_and_each_partition_collects_it_once() {
    for change_profile in [false, true] {
        let (queue, receiver) = queue(2);
        let service =
            CaptureLayer::new(queue.clone()).into_layer(service_fn(|request: Request<()>| async {
                Ok::<_, Infallible>(request)
            }));
        let connection = Extensions::new();
        connection.insert(CollectionLease::default());
        let first = service.serve(h2_request(&connection)).await.unwrap();
        let mut input = h2_request(&connection);
        if change_profile {
            input
                .headers_mut()
                .insert(USER_AGENT, HeaderValue::from_static("different-client/7"));
        } else {
            input.extensions().insert(StorageAuthorized);
        }
        let second = service.serve(input).await.unwrap();
        let day = first
            .extensions()
            .get_ref::<CaptureIntent>()
            .unwrap()
            .0
            .lock()
            .as_ref()
            .unwrap()
            .day;
        submit(first.extensions(), None);
        submit(second.extensions(), None);
        let records = Arc::new(Mutex::new(Vec::new()));
        worker::run(
            receiver,
            MemorySink(records.clone()),
            store_limits(),
            QueueConfig {
                capacity: 2,
                ..QueueConfig::default()
            },
            async {},
            || Ok(day),
            || Ok([1; 12]),
        )
        .await
        .unwrap();
        let records = records.lock();
        assert!(
            records
                .iter()
                .all(|(_attempt, capture)| capture.profile.user_agent.as_deref()
                    == Some("unknown-client/7"))
        );
        let partitions: Vec<_> = records
            .iter()
            .map(|(attempt, capture)| (attempt.authorized, capture.joint.level))
            .collect();
        if change_profile {
            assert_eq!(
                partitions,
                [
                    (false, CaptureLevel::Connection),
                    (false, CaptureLevel::Request)
                ]
            );
            assert_eq!(queue.counts().invalid_capture, 1);
        } else {
            // The authorization cookie may arrive after the first request; the
            // authorized partition still records this connection, once.
            assert_eq!(
                partitions,
                [
                    (false, CaptureLevel::Connection),
                    (false, CaptureLevel::Request),
                    (true, CaptureLevel::Connection),
                    (true, CaptureLevel::Request),
                ]
            );
            assert_eq!(queue.counts().invalid_capture, 0);
        }
    }
}

fn runtime_source() -> UserAgentSourceInfo {
    UserAgentSourceInfo {
        device_name: Some("synthetic-device".into()),
        os: Some("TestOS".into()),
        os_version: Some("1".into()),
        browser_name: Some("Browser".into()),
        browser_version: Some("2".into()),
    }
}

#[tokio::test]
async fn runtime_metadata_joins_the_reserved_request_and_is_submitted_once() {
    let (queue, receiver) = queue(1);
    let service =
        CaptureLayer::new(queue.clone()).into_layer(service_fn(|request: Request<()>| async {
            Ok::<_, Infallible>(request)
        }));
    let connection = Extensions::new();
    connection.insert(CollectionLease::default());
    let mut input = request("/api/fetch/number/1");
    *input.method_mut() = Method::POST;
    input.extensions().insert(Ingress(connection));
    let output = service.serve(input).await.unwrap();
    let source = runtime_source();
    attach_runtime(output.extensions(), Some(&source), None);
    let day = output
        .extensions()
        .get_ref::<CaptureIntent>()
        .unwrap()
        .0
        .lock()
        .as_ref()
        .unwrap()
        .day;
    submit(output.extensions(), None);
    // A replayed attachment after submission does not reserve or count again.
    attach_runtime(output.extensions(), Some(&source), None);
    submit(output.extensions(), None);
    let records = Arc::new(Mutex::new(Vec::new()));
    worker::run(
        receiver,
        MemorySink(records.clone()),
        store_limits(),
        QueueConfig {
            capacity: 1,
            ..QueueConfig::default()
        },
        async {},
        || Ok(day),
        || Ok([7; 12]),
    )
    .await
    .unwrap();
    let records = records.lock();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].1.joint.level, CaptureLevel::Connection);
    assert!(records[0].1.joint.slots.is_empty());
    assert_eq!(records[1].1.joint.level, CaptureLevel::Request);
    let slot = records[1]
        .1
        .joint
        .slots
        .iter()
        .find(|slot| slot.kind == CapturedSlotKind::RuntimeMetadata)
        .unwrap();
    let decoded = RuntimeProfileCapture::from_canonical(
        &slot.value,
        JointCaptureLimits::default().value_bytes,
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(decoded.runtime.source_info.unwrap()).unwrap(),
        serde_json::to_value(&source).unwrap()
    );
    assert_eq!(queue.counts().confirmed, 2);
    assert_eq!(queue.counts().invalid_capture, 0);
}

#[tokio::test]
async fn invalid_or_duplicate_runtime_metadata_releases_the_reservation() {
    let (queue, _receiver) = queue(1);
    let service =
        CaptureLayer::new(queue.clone()).into_layer(service_fn(|request: Request<()>| async {
            Ok::<_, Infallible>(request)
        }));
    let output = service.serve(request("/report")).await.unwrap();
    let mut source = runtime_source();
    source.device_name = Some("x".repeat(JointCaptureLimits::default().value_bytes));
    attach_runtime(output.extensions(), Some(&source), None);
    assert!(
        output
            .extensions()
            .get_ref::<CaptureIntent>()
            .unwrap()
            .0
            .lock()
            .is_none()
    );
    assert_eq!(queue.counts().invalid_capture, 1);
    assert_eq!(queue.counts().preparation_drops, 0);
    let output = service.serve(request("/report")).await.unwrap();
    let source = runtime_source();
    attach_runtime(output.extensions(), Some(&source), None);
    attach_runtime(output.extensions(), Some(&source), None);
    assert!(
        output
            .extensions()
            .get_ref::<CaptureIntent>()
            .unwrap()
            .0
            .lock()
            .is_none()
    );
    assert_eq!(queue.counts().invalid_capture, 2);
    assert_eq!(queue.counts().preparation_drops, 0);
    assert!(queue.try_reserve().is_some());
}

#[tokio::test]
async fn metadata_without_an_admitted_intent_never_prepares_or_reserves() {
    let (queue, _receiver) = queue(1);
    let reservation = queue.try_reserve().unwrap();
    let service =
        CaptureLayer::new(queue.clone()).into_layer(service_fn(|request: Request<()>| async {
            Ok::<_, Infallible>(request)
        }));
    let mut source = runtime_source();
    source.device_name = Some("x".repeat(JointCaptureLimits::default().value_bytes));
    for path in ["/report", "/assets/script.js", "/report?h3_probe=1"] {
        let output = service.serve(request(path)).await.unwrap();
        attach_runtime(output.extensions(), Some(&source), None);
        assert!(!output.extensions().contains::<CaptureIntent>());
    }
    assert_eq!(queue.counts().queue_full, 1);
    assert_eq!(queue.counts().invalid_capture, 0);
    drop(reservation);
}

async fn wire_reports(version: Version) -> (CollectionQueue, CollectionReceiver) {
    let (queue, receiver) = queue(8);
    let service = CaptureLayer::new(queue.clone()).into_layer(
        StorageAuthLayer { storage_auth: None }.into_layer(service_fn(
            |request: Request| async move {
                submit(request.extensions(), None);
                Ok::<_, Infallible>(Response::new(Body::empty()))
            },
        )),
    );
    let mut http = HttpServer::auto(Executor::default());
    http.h2_mut().set_observe_early_frames(true);
    let tls = TlsServerConfig::new()
        .try_with_generated_server_auth(GeneratedServerAuthConfig::default())
        .unwrap();
    let tls = if version == Version::HTTP_2 {
        tls.with_alpn_http_2()
    } else {
        tls.with_alpn_http_1()
    };
    let server = CollectionLayer.into_layer(
        TlsAcceptorLayer::new(tls)
            .with_store_client_hello(true)
            .into_layer(http.service(Arc::new(service))),
    );
    let connector = MockConnectorService::new(move || server.clone());
    let tls = TlsClientConfig::default_http().with_server_verify(ServerVerifyMode::Disable);
    let client = EasyHttpWebClient::connector_builder()
        .with_custom_transport_connector(connector)
        .without_dns_connector()
        .without_tls_proxy_support()
        .without_proxy_support()
        .with_tls_support_using_boringssl(tls)
        .with_default_http_connector(Executor::default())
        .with_default_connection_pool()
        .build_client();
    tokio::time::timeout(Duration::from_secs(10), async {
        for path in ["/report", "/report", "/assets/style.css"] {
            let request = Request::builder()
                .uri(format!("https://localhost{path}"))
                .version(version)
                .header(USER_AGENT, "synthetic-wire-client/1")
                .body(Body::empty())
                .unwrap();
            let response = client.serve(request).await.unwrap();
            assert_eq!(response.version(), version);
        }
    })
    .await
    .unwrap();
    (queue, receiver)
}

#[tokio::test]
async fn real_h1_h2_connections_keep_one_tls_tuple_and_one_tuple_per_report() {
    for version in [Version::HTTP_11, Version::HTTP_2] {
        let (queue, receiver) = wire_reports(version).await;
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
            || Ok([5; 12]),
        )
        .await
        .unwrap();
        let records = records.lock();
        assert_eq!(records.len(), 3, "{version:?}: {:?}", queue.counts());
        assert_eq!(
            records
                .iter()
                .filter(|(_, value)| matches!(value.joint.level, CaptureLevel::Connection))
                .count(),
            1
        );
        assert_eq!(
            records
                .iter()
                .filter(|(_, value)| matches!(value.joint.level, CaptureLevel::Request))
                .count(),
            2
        );
        let connection = records
            .iter()
            .find(|(_, value)| matches!(value.joint.level, CaptureLevel::Connection))
            .unwrap();
        assert!(
            connection
                .1
                .joint
                .slots
                .iter()
                .any(|slot| slot.kind == CapturedSlotKind::TcpTls)
        );
        assert_eq!(
            connection
                .1
                .joint
                .slots
                .iter()
                .any(|slot| slot.kind == CapturedSlotKind::Http2EarlyFrames),
            version == Version::HTTP_2
        );
        for (_, request) in records
            .iter()
            .filter(|(_, value)| matches!(value.joint.level, CaptureLevel::Request))
        {
            assert!(
                matches!(&request.flow, Some(FlowKey::Http { version: observed, .. }) if *observed==version)
            );
            assert_eq!(
                request
                    .joint
                    .slots
                    .iter()
                    .any(|slot| slot.kind == CapturedSlotKind::PseudoHeaders),
                version == Version::HTTP_2
            );
        }
        assert_eq!(queue.counts().confirmed, 3);
        assert_eq!(queue.counts().invalid_capture, 0);
    }
}

async fn h3_wire_reports() -> (CollectionQueue, CollectionReceiver) {
    let (queue, receiver) = queue(8);
    let state = Arc::new(State {
        data_source: DataSource::default(),
        probe_http3: false,
        storage: Some(Storage {
            queue: Some(queue.clone()),
        }),
        storage_auth: None,
        geo_db: None,
    });
    let service = CaptureLayer::new(queue.clone()).into_layer(
        StorageAuthLayer { storage_auth: None }.into_layer(service_fn(move |request: Request| {
            let state = state.clone();
            async move {
                data::get_http_info_and_capture(
                    &state,
                    request.headers().clone(),
                    request.extensions(),
                    request.version(),
                    Initiator::Navigator,
                )
                .await
                .unwrap();
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }
        })),
    );
    let tls = TlsServerConfig::new()
        .try_with_generated_server_auth(GeneratedServerAuthConfig::default())
        .unwrap();
    let listeners = HttpListeners::bind_observed(
        Executor::default(),
        SocketAddress::local_ipv4(0),
        "h3".parse::<HttpVersions>().unwrap(),
        Some(&tls),
        &Http3Args {
            h3_bind: None,
            h3_mtu_upper_bound: None,
            h3_bootstrap_bind: None,
        },
    )
    .await
    .unwrap();
    assert!(listeners.tcp.is_none());
    let endpoint = listeners.http3.unwrap();
    let address = endpoint.local_addr().unwrap();
    let mut http = HttpServer::new_http3(Executor::default());
    http.http3_mut().observation = Some(Box::new(OBSERVATION_LIMITS));
    let service = CollectionLayer.into_layer(http.service(Arc::new(service)));
    let server = tokio::spawn({
        let endpoint = endpoint.clone();
        async move {
            let incoming = endpoint.accept().await.unwrap();
            let connection = incoming.await.unwrap();
            service.serve(connection).await
        }
    });
    let client_endpoint = Endpoint::bind_client(Executor::default(), SocketAddress::local_ipv4(0))
        .await
        .unwrap();
    let tls = TlsClientConfig::default_http().with_server_verify(ServerVerifyMode::Disable);
    let h3 = Http3Connector::builder(Executor::default())
        .with_endpoint(client_endpoint.clone())
        .with_tls_config(tls.clone())
        .with_tls_provider(Arc::new(BoringTlsProvider))
        .build()
        .await
        .unwrap();
    let client = EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .without_dns_connector()
        .without_tls_proxy_support()
        .without_proxy_support()
        .with_tls_support_using_boringssl(tls)
        .with_default_http_connector(Executor::default())
        .with_http3_support(h3)
        .with_default_connection_pool()
        .build_client();
    tokio::time::timeout(Duration::from_secs(10), async {
        for path in ["/report", "/report", "/assets/style.css"] {
            let request = Request::builder()
                .uri(format!("https://{address}{path}"))
                .version(Version::HTTP_3)
                .header(USER_AGENT, "synthetic-wire-client/1")
                .body(Body::empty())
                .unwrap();
            request
                .extensions()
                .insert(TargetHttpVersion(Version::HTTP_3));
            let response = client.serve(request).await.unwrap();
            assert_eq!(response.version(), Version::HTTP_3);
        }
    })
    .await
    .unwrap();
    drop(client);
    client_endpoint.close(0_u32, b"test complete");
    endpoint.close(0_u32, b"test complete");
    tokio::time::timeout(Duration::from_secs(10), async {
        client_endpoint.shutdown().await;
        endpoint.shutdown().await;
        // Local endpoint closure terminates the driver after all responses arrived.
        let _closed = server.await.unwrap();
    })
    .await
    .unwrap();
    (queue, receiver)
}

#[tokio::test]
#[ignore = "requires local UDP integration"]
async fn real_h3_connection_captures_one_complete_connection_and_each_report() {
    let (queue, receiver) = h3_wire_reports().await;
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
        || Ok([5; 12]),
    )
    .await
    .unwrap();
    let records = records.lock();
    assert_eq!(records.len(), 3, "{:?}", queue.counts());
    let connections: Vec<_> = records
        .iter()
        .filter(|(_, value)| matches!(value.joint.level, CaptureLevel::Connection))
        .collect();
    assert_eq!(connections.len(), 1);
    let slots: Vec<_> = connections[0]
        .1
        .joint
        .slots
        .iter()
        .map(|slot| slot.kind)
        .collect();
    for kind in [
        CapturedSlotKind::QuicTls,
        CapturedSlotKind::QuicParameters,
        CapturedSlotKind::QuicFirstFlight,
        CapturedSlotKind::Http3Settings,
        CapturedSlotKind::Http3Sequence,
    ] {
        assert!(slots.contains(&kind), "{kind:?}: {slots:?}");
    }
    assert_eq!(queue.counts().confirmed, 3);
    assert_eq!(queue.counts().invalid_capture, 0);
}

#[tokio::test(start_paused = true)]
async fn slow_handler_releases_capture_capacity_without_cancelling_the_response() {
    let (queue, _receiver) = queue(1);
    let (ready_tx, ready_rx) = oneshot::channel();
    let (finish_tx, finish_rx) = oneshot::channel();
    let signals = Mutex::new(Some((ready_tx, finish_rx)));
    let service =
        CaptureLayer::new(queue.clone()).into_layer(service_fn(move |request: Request<()>| {
            let (ready, finish) = signals.lock().take().unwrap();
            async move {
                ready.send(()).unwrap();
                finish.await.unwrap();
                Ok::<_, Infallible>(request)
            }
        }));
    let running = tokio::spawn(async move { service.serve(request("/report")).await.unwrap() });
    ready_rx.await.unwrap();
    assert!(queue.try_reserve().is_none());
    advance(PREPARATION_TIMEOUT).await;
    timeout(Duration::from_secs(1), queue.wait_for_capacity())
        .await
        .unwrap()
        .unwrap();
    assert!(!running.is_finished());
    assert_eq!(queue.counts().preparation_drops, 1);
    finish_tx.send(()).unwrap();
    let output = running.await.unwrap();
    assert!(
        output
            .extensions()
            .get_ref::<CaptureIntent>()
            .unwrap()
            .0
            .lock()
            .is_none()
    );
    assert_eq!(queue.counts().preparation_drops, 1);
}

#[tokio::test]
async fn missing_tls_client_hello_rejects_and_counts_the_connection_capture() {
    for version in [Version::HTTP_11, Version::HTTP_2] {
        let (queue, receiver) = queue(1);
        let service =
            CaptureLayer::new(queue.clone()).into_layer(service_fn(|request: Request<()>| async {
                Ok::<_, Infallible>(request)
            }));
        let connection = Extensions::new();
        connection.insert(CollectionLease::default());
        connection.insert(SecureTransport::default());
        let input = if version == Version::HTTP_2 {
            h2_request(&connection)
        } else {
            let input = request("/report");
            input.extensions().insert(Ingress(connection));
            input
        };
        let output = service.serve(input).await.unwrap();
        let day = output
            .extensions()
            .get_ref::<CaptureIntent>()
            .unwrap()
            .0
            .lock()
            .as_ref()
            .unwrap()
            .day;
        submit(output.extensions(), None);
        assert_eq!(queue.counts().invalid_capture, 1);
        assert!(queue.try_reserve().is_some());
        let records = Arc::new(Mutex::new(Vec::new()));
        worker::run(
            receiver,
            MemorySink(records.clone()),
            store_limits(),
            QueueConfig {
                capacity: 1,
                ..QueueConfig::default()
            },
            async {},
            || Ok(day),
            || Ok([1; 12]),
        )
        .await
        .unwrap();
        assert!(records.lock().is_empty());
        assert_eq!(queue.counts().confirmed, 0);
    }
}

#[tokio::test(start_paused = true)]
async fn upgraded_request_cannot_keep_a_capture_reservation_after_the_deadline() {
    let (queue, _receiver) = queue(1);
    let service =
        CaptureLayer::new(queue.clone()).into_layer(service_fn(|request: Request<()>| async {
            Ok::<_, Infallible>(request)
        }));
    // The upgrade response finishes while its detached WebSocket task retains
    // the request extensions and has not reached collection submission yet.
    let output = service.serve(request("/api/ws")).await.unwrap();
    assert!(queue.try_reserve().is_none());
    advance(PREPARATION_TIMEOUT).await;
    timeout(Duration::from_secs(1), queue.wait_for_capacity())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(queue.counts().preparation_drops, 1);
    submit(output.extensions(), None);
    assert_eq!(queue.counts().invalid_capture, 0);
}

#[tokio::test]
async fn storage_auth_rejects_empty_or_incorrect_cookies() {
    for (configured, supplied, authorized) in [
        (Some(""), "", false),
        (None, "", false),
        (Some("secret"), "secret", true),
        (Some("secret"), "secreu", false),
        (Some("secret"), "secret-longer", false),
        (Some("secret"), "short", false),
    ] {
        let service = StorageAuthLayer {
            storage_auth: configured.map(str::to_owned),
        }
        .into_layer(service_fn(|request: Request<()>| async {
            Ok::<_, Infallible>(request)
        }));
        let mut input = request("/report");
        input.headers_mut().insert(
            COOKIE,
            HeaderValue::try_from(format!("rama-storage-auth={supplied}")).unwrap(),
        );
        let output = service.serve(input).await.unwrap();
        assert_eq!(
            output.extensions().contains::<StorageAuthorized>(),
            authorized
        );
    }
}
