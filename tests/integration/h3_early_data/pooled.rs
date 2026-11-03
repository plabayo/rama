//! The ordinary builder and multiplex pool own early recovery together.

use super::*;
use rama::{
    Service,
    http::{
        StatusCode,
        body::util::CollectOptions,
        client::{EasyHttpConnectorBuilder, Http3Connector, HttpPooledConnectorConfig},
        layer::retry::{RetryBody, early_data::prepare_bodyless},
        proto::ext::early_data::EarlyDataAttempt,
    },
};
use rama_core::{
    error::extra::OpaqueError,
    extensions::{Egress, Extensions},
};
use rama_net::{
    address::HostWithPort,
    client::ConnectorTarget,
    conn::{ConnectionHealth, ConnectionHealthWatcher},
};
use rama_quic::client::SharedQuicEndpoint;
use rama_tls::client::TlsServerAuthentication;
use std::{
    num::NonZeroUsize,
    sync::atomic::{AtomicUsize, Ordering},
};
use tokio::sync::{Notify, mpsc};

fn client_provider(provider: Provider) -> Arc<dyn rama_quic::tls::QuicClientConfigProvider> {
    match provider {
        #[cfg(feature = "boring")]
        Provider::Boring => Arc::new(BoringTlsProvider),
        #[cfg(all(feature = "rustls", any(feature = "ring", feature = "aws-lc")))]
        Provider::Rustls => Arc::new(RustlsTlsProvider::new(Arc::new(
            rustls_crypto::default_provider(),
        ))),
    }
}

fn pooled_request(port: u16) -> Request<Body> {
    let request = Request::builder()
        .uri(format!("https://localhost:{port}/early"))
        .body(Body::empty())
        .unwrap();
    request
        .extensions()
        .insert(ConnectorTarget(HostWithPort::local_ipv4(port)));
    request
}

#[tokio::test]
async fn pooled_client_recovers_425_once_and_admits_other_callers_after_verification() {
    for provider in Provider::enabled() {
        timeout(LIMIT, pooled_recovery(provider, Scenario::Recover425))
            .await
            .unwrap();
    }
}

#[derive(Clone, Copy)]
enum Scenario {
    Recover425,
    CancelEarly,
    RejectTls,
    ReplayPayload,
}

#[tokio::test]
async fn cancelled_early_request_leaves_verified_connection_reusable() {
    for provider in Provider::enabled() {
        timeout(LIMIT, pooled_recovery(provider, Scenario::CancelEarly))
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn pooled_client_recovers_actual_tls_rejection_on_a_confirmed_connection() {
    for provider in Provider::enabled() {
        timeout(LIMIT, pooled_recovery(provider, Scenario::RejectTls))
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn pooled_client_keeps_application_payload_retries_without_sending_early() {
    for provider in Provider::enabled() {
        timeout(LIMIT, pooled_recovery(provider, Scenario::ReplayPayload))
            .await
            .unwrap();
    }
}

async fn pooled_recovery(provider: Provider, scenario: Scenario) {
    let fixture = Fixture::new(provider, Version::V1).await;
    let port = fixture.server.local_addr().unwrap().port();
    let early = Arc::new(AtomicUsize::new(0));
    let processed = Arc::new(AtomicUsize::new(0));
    let early_seen = Arc::new(Notify::new());
    let (connections, mut accepted) = mpsc::unbounded_channel();
    let endpoint = fixture.server.clone();
    let early_count = early.clone();
    let processed_count = processed.clone();
    let payload_attempts = Arc::new(AtomicUsize::new(0));
    let early_notify = early_seen.clone();
    let _serving = Task::spawn(async move {
        let mut handlers = Vec::new();
        while let Some(incoming) = endpoint.accept().await {
            let connection = incoming
                .accept()
                .unwrap()
                .into_0rtt()
                .unwrap_or_else(|_| panic!("server handles"))
                .0;
            connections.send(connection.clone()).unwrap();
            let early = early_count.clone();
            let processed = processed_count.clone();
            let early_seen = early_notify.clone();
            let payload_attempts = payload_attempts.clone();
            handlers.push(Task::spawn(async move {
                let (mut h3, driver) =
                    server::handshake(connection.clone(), Config::default()).unwrap();
                let _driver = Task::spawn(driver.run());
                while let Ok(stream) = h3.accept().await {
                    // In this fixture the packet gate holds ALL server output.
                    // A stream received before release can only carry early bytes.
                    let sent_early = !connection.is_handshake_confirmed();
                    if sent_early {
                        early.fetch_add(1, Ordering::Relaxed);
                        early_seen.notify_one();
                    }
                    let Ok((request, response)) = stream.resolve().await else {
                        continue;
                    };
                    let payload = request.method() == Method::POST;
                    let body = request.into_body().collect().await.unwrap().to_bytes();
                    if payload {
                        assert_eq!(body, "payload");
                        assert!(!sent_early);
                    }
                    let status = if sent_early {
                        StatusCode::TOO_EARLY
                    } else if payload && payload_attempts.fetch_add(1, Ordering::Relaxed) == 0 {
                        StatusCode::SERVICE_UNAVAILABLE
                    } else {
                        processed.fetch_add(1, Ordering::Relaxed);
                        StatusCode::OK
                    };
                    let sent = response
                        .send_response(
                            Response::builder()
                                .status(status)
                                .body(Body::empty())
                                .unwrap(),
                        )
                        .await;
                    if let Err(error) = sent {
                        assert!(
                            sent_early || connection.close_reason().is_some(),
                            "response failed: {error}"
                        );
                        break;
                    }
                }
            }));
        }
    });

    let h3 = Http3Connector::builder(Executor::new())
        .with_endpoints(SharedQuicEndpoint::supplied(
            fixture.client.clone(),
            Executor::new(),
        ))
        .with_tls_provider(client_provider(provider))
        .with_tls_config(fixture.client_tls.clone())
        .with_config(Config {
            max_requests: 1,
            ..early_config()
        })
        .build_lazy()
        .unwrap();
    let rule_calls = Arc::new(AtomicUsize::new(0));
    let application_calls = rule_calls.clone();
    let client = Arc::new(
        EasyHttpConnectorBuilder::new()
            .with_custom_transport_connector(h3)
            .without_dns_connector()
            .without_tls_proxy_support()
            .without_proxy_support()
            .without_tls_support()
            .with_default_http_connector::<RetryBody>(Executor::new())
            .with_connection_pool(HttpPooledConnectorConfig {
                max_connections_per_id: Some(NonZeroUsize::MIN),
                ..HttpPooledConnectorConfig::default()
            })
            .build_client_with_early_data(
                move |request, result: Result<Response, OpaqueError>| {
                    application_calls.fetch_add(1, Ordering::Relaxed);
                    async move {
                        let retry = result.as_ref().is_ok_and(|response| {
                            response.status().is_client_error()
                                || response.status() == StatusCode::SERVICE_UNAVAILABLE
                        });
                        (request, result, retry)
                    }
                },
                |parts: &rama::http::request::Parts, end, hint: &rama::http::body::SizeHint| {
                    if parts.method == Method::POST {
                        Some(CollectOptions::new().with_max_size(1024))
                    } else {
                        prepare_bodyless(parts, end, hint)
                    }
                },
            ),
    );

    let warm = client.serve(pooled_request(port)).await.unwrap();
    assert_eq!(warm.status(), StatusCode::OK);
    assert!(!warm.extensions().contains::<EarlyDataAttempt>());
    let egress = warm
        .extensions()
        .get_ref::<Egress<Extensions>>()
        .unwrap()
        .0
        .clone();
    let health = egress.get_ref::<ConnectionHealthWatcher>().unwrap();
    let mut changes = health.watch();
    warm.into_body().collect().await.unwrap();
    accepted
        .recv()
        .await
        .unwrap()
        .close(0u32, b"warmup complete");
    while health.health() != ConnectionHealth::Broken {
        changes.changed().await.unwrap();
    }

    if matches!(scenario, Scenario::RejectTls) {
        fixture.forget_tickets();
    }
    fixture.gate.hold();
    let first_client = client.clone();
    let first = Task::spawn(async move {
        let mut request = pooled_request(port);
        if matches!(scenario, Scenario::ReplayPayload) {
            *request.method_mut() = Method::POST;
            *request.body_mut() = Body::from("payload");
        }
        let response = first_client.serve(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.extensions().contains::<ForbidEarlyData>(),
            !matches!(scenario, Scenario::ReplayPayload)
        );
        if matches!(scenario, Scenario::ReplayPayload) {
            assert!(!response.extensions().contains::<EarlyDataPermit>());
        }
        assert!(!response.extensions().contains::<EarlyDataAttempt>());
        let egress = response
            .extensions()
            .get_ref::<Egress<Extensions>>()
            .unwrap();
        assert!(egress.0.contains::<TlsServerAuthentication>());
        response.into_body().collect().await.unwrap();
    });
    if !matches!(scenario, Scenario::RejectTls | Scenario::ReplayPayload) {
        timeout(PROBE * 5, early_seen.notified())
            .await
            .expect("pooled request did not send early");
    }
    let resumed_connection = accepted.recv().await.unwrap();
    assert!(!resumed_connection.is_handshake_confirmed());
    let first = if matches!(scenario, Scenario::CancelEarly) {
        drop(first);
        None
    } else {
        Some(first)
    };
    let mut waiters = Vec::new();
    for _ in 0..3 {
        let client = client.clone();
        waiters.push(Task::spawn(async move {
            let response = client.serve(pooled_request(port)).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert!(!response.extensions().contains::<EarlyDataAttempt>());
            let egress = response
                .extensions()
                .get_ref::<Egress<Extensions>>()
                .unwrap();
            assert!(egress.0.contains::<TlsServerAuthentication>());
            response.into_body().collect().await.unwrap();
        }));
    }
    sleep(PROBE).await;
    assert_eq!(
        early.load(Ordering::Relaxed),
        usize::from(!matches!(
            scenario,
            Scenario::RejectTls | Scenario::ReplayPayload
        ))
    );
    assert!(
        accepted.try_recv().is_err(),
        "waiters opened a second connection"
    );
    if let Some(first) = &first {
        assert!(!first.0.as_ref().unwrap().is_finished());
    }
    fixture.gate.release();
    if let Some(first) = first {
        first.join().await;
    }
    for waiter in waiters {
        waiter.join().await;
    }
    // early_data_accepted() is client-only. The held packet gate proved
    // actual early request receipt above; this connection also resumed.
    if matches!(scenario, Scenario::RejectTls) {
        // Initial packets already in flight can create an incoming handle
        // after the rejected attempt closed. Count successful handshakes,
        // not those stale, immediately closed handles.
        let mut confirmed = 0;
        while let Ok(replacement) = accepted.try_recv() {
            if replacement.handshake_confirmed().await.is_ok() {
                confirmed += 1;
            }
        }
        assert_eq!(confirmed, 1, "only one confirmed replacement connection");
    } else {
        assert_eq!(resumed(&resumed_connection), Some(true));
        assert!(
            accepted.try_recv().is_err(),
            "cancelled request did not force a new dial"
        );
    }
    assert_eq!(
        early.load(Ordering::Relaxed),
        usize::from(!matches!(
            scenario,
            Scenario::RejectTls | Scenario::ReplayPayload
        ))
    );
    assert_eq!(
        processed.load(Ordering::Relaxed),
        if matches!(scenario, Scenario::CancelEarly) {
            4
        } else {
            5
        },
        "each completed operation is processed once"
    );
    assert_eq!(
        rule_calls.load(Ordering::Relaxed),
        match scenario {
            Scenario::CancelEarly => 4,
            Scenario::ReplayPayload => 6,
            _ => 5,
        },
        "only ordinary results reach the application rule"
    );
}
