use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use tokio::time::sleep;

use rama_core::{
    Layer, Service,
    extensions::ExtensionsRef,
    futures::future::{join, join_all},
    graceful::Shutdown,
    io::BridgeIo,
    layer::ArcLayer,
    layer::ConsumeErrLayer,
    rt::Executor,
    service::service_fn,
};
use rama_http::{
    HeaderName, HeaderValue,
    body::util::BodyExt as _,
    layer::set_header::{SetRequestHeaderLayer, SetResponseHeaderLayer},
};
use rama_http_types::{
    Body, Request, Response, StatusCode, Version,
    conn::{H2ClientContextParams, PeerH2Settings, TargetHttpVersion},
};
use rama_net::test_utils::client::{MockConnectorService, MockSocket};
use rama_utils::octets::kib;
use tokio_util::sync::CancellationToken;

use crate::proxy::mitm::DefaultErrorResponse;

use super::{
    client::{HttpConnectorLayer, http_connect},
    proxy::mitm::HttpMitmRelay,
    server::HttpServer,
};

#[tokio::test]
async fn test_http11_pipelining() {
    let connector = HttpConnectorLayer::default().into_layer(MockConnectorService::new(|| {
        HttpServer::auto(Executor::default()).service(service_fn(server_svc_fn))
    }));

    let conn = connector
        .serve(create_test_request(Version::HTTP_11))
        .await
        .unwrap()
        .conn;

    // Http 1.1 should pipeline requests. Pipelining is important when trying to send multiple
    // requests on the same connection. This is something we generally don't do, but we do
    // trigger the same problem when we re-use a connection too fast. However triggering that
    // bug consistently has proven very hard so we trigger this one instead. Both of them
    // should be fixed by waiting for conn.isready().await before trying to send data on the connection.
    // For http1.1 this will result in pipelining (http2 will still be multiplexed)
    let start = Instant::now();
    let (res1, res2) = join(
        conn.serve(create_test_request(Version::HTTP_11)),
        conn.serve(create_test_request(Version::HTTP_11)),
    )
    .await;
    let duration = start.elapsed();

    res1.unwrap();
    res2.unwrap();

    assert!(duration > Duration::from_millis(200));
}

#[tokio::test]
async fn test_http2_multiplex() {
    let inflight = Arc::new(AtomicUsize::new(0));
    let max_inflight = Arc::new(AtomicUsize::new(0));

    let connector = HttpConnectorLayer::default().into_layer(MockConnectorService::new({
        let inflight = inflight.clone();
        let max_inflight = max_inflight.clone();
        move || {
            let inflight = inflight.clone();
            let max_inflight = max_inflight.clone();
            HttpServer::auto(Executor::default()).service(service_fn(move |_req: Request| {
                let inflight = inflight.clone();
                let max_inflight = max_inflight.clone();
                async move {
                    let cur = inflight.fetch_add(1, Ordering::SeqCst) + 1;
                    max_inflight.fetch_max(cur, Ordering::SeqCst);
                    sleep(Duration::from_millis(200)).await;
                    inflight.fetch_sub(1, Ordering::SeqCst);
                    Ok::<_, Infallible>(Response::new(Body::from("a random response body")))
                }
            }))
        }
    }));

    let conn = connector
        .serve(create_test_request(Version::HTTP_2))
        .await
        .unwrap()
        .conn;

    let (res1, res2) = join(
        conn.serve(create_test_request(Version::HTTP_2)),
        conn.serve(create_test_request(Version::HTTP_2)),
    )
    .await;

    res1.unwrap();
    res2.unwrap();

    // multiplexed requests overlap in the sleeping handler; a serialized conn never overlaps
    assert_eq!(max_inflight.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn test_http11_handles_4_concurrent_requests() {
    let connector = HttpConnectorLayer::default().into_layer(MockConnectorService::new(|| {
        HttpServer::auto(Executor::default()).service(service_fn(server_svc_fn))
    }));

    let conn = connector
        .serve(create_test_request(Version::HTTP_11))
        .await
        .unwrap()
        .conn;

    let responses =
        join_all((0..4).map(|_| conn.serve(create_test_request(Version::HTTP_11)))).await;

    assert_eq!(responses.len(), 4);
    for response in responses {
        let response = response.unwrap();
        assert_eq!(response.status(), 200);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "a random response body");
    }
}

#[tokio::test]
async fn test_http2_handles_200_concurrent_requests() {
    let connector = HttpConnectorLayer::default().into_layer(MockConnectorService::new(|| {
        HttpServer::auto(Executor::default()).service(service_fn(server_svc_fn))
    }));

    let conn = connector
        .serve(create_test_request(Version::HTTP_2))
        .await
        .unwrap()
        .conn;

    let responses =
        join_all((0..200).map(|_| conn.serve(create_test_request(Version::HTTP_2)))).await;

    assert_eq!(responses.len(), 200);
    for response in responses {
        let response = response.unwrap();
        assert_eq!(response.status(), 200);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "a random response body");
    }
}

async fn server_svc_fn(_: Request) -> Result<Response, Infallible> {
    sleep(Duration::from_millis(100)).await;
    Ok(Response::new(Body::from("a random response body")))
}

async fn mitm_relay_server_svc_fn(req: Request) -> Result<Response, Infallible> {
    assert!(req.headers().contains_key("x-observed-req"));
    let body = req
        .headers()
        .get("x-test-id")
        .and_then(|v| v.to_str().ok())
        .map(|id| format!("a random response body ({id})"))
        .unwrap_or_else(|| "a random response body".to_owned());
    Ok(Response::new(Body::from(body)))
}

async fn mitm_relay_server_close_after_first_request_svc_fn(
    req: Request,
    request_count: Arc<AtomicUsize>,
) -> Result<Response, Infallible> {
    assert!(req.headers().contains_key("x-observed-req"));

    let id = request_count.fetch_add(1, Ordering::SeqCst);
    let mut response = Response::new(Body::from(format!("single response body ({id})")));
    if id == 0 {
        response.headers_mut().insert(
            HeaderName::from_static("connection"),
            HeaderValue::from_static("close"),
        );
    }
    Ok(response)
}

fn create_test_request(version: Version) -> Request {
    Request::builder()
        .uri("https://www.example.com")
        .version(version)
        .body(Body::from("a reandom request body"))
        .unwrap()
}

fn create_test_request_with_id(version: Version, id: usize) -> Request {
    Request::builder()
        .uri("https://www.example.com")
        .version(version)
        .header("x-test-id", id.to_string())
        .body(Body::from(format!("a reandom request body ({id})")))
        .unwrap()
}

async fn test_mitm_relay_roundtrip_inner(version: Version) {
    let (client_stream, relay_ingress_stream) = tokio::io::duplex(kib(16));
    let (relay_egress_stream, server_stream) = tokio::io::duplex(kib(16));

    let token = CancellationToken::new();
    let graceful = Shutdown::new(token.clone().cancelled_owned());
    let cancel_drop_guard = token.drop_guard();

    graceful.spawn_task_fn(async move |guard| {
        HttpServer::auto(Executor::graceful(guard))
            .service(service_fn(mitm_relay_server_svc_fn))
            .serve(MockSocket::new(server_stream))
            .await
            .unwrap();
    });

    graceful.spawn_task_fn(async move |guard| {
        HttpMitmRelay::new(Executor::graceful(guard))
            .with_http_middleware((
                ConsumeErrLayer::trace_as_debug().with_response(DefaultErrorResponse::new()),
                SetRequestHeaderLayer::overriding(
                    HeaderName::from_static("x-observed-req"),
                    HeaderValue::from_static("1"),
                ),
                SetResponseHeaderLayer::overriding(
                    HeaderName::from_static("x-observed-res"),
                    HeaderValue::from_static("1"),
                ),
                ArcLayer::new(),
            ))
            .serve(BridgeIo(
                MockSocket::new(relay_ingress_stream),
                MockSocket::new(relay_egress_stream),
            ))
            .await
            .unwrap();
    });

    let request = create_test_request(version);
    let conn = http_connect(
        MockSocket::new(client_stream),
        request,
        Executor::graceful(graceful.guard()),
    )
    .await
    .unwrap()
    .conn;

    let response = conn.serve(create_test_request(version)).await.unwrap();

    assert!(response.headers().contains_key("x-observed-res"));

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(bytes, "a random response body");

    drop(conn);
    cancel_drop_guard.disarm().cancel();
    let fut = graceful.shutdown();

    fut.await;
}

async fn test_mitm_relay_concurrency_inner(version: Version, n: usize) {
    let (client_stream, relay_ingress_stream) = tokio::io::duplex(kib(16));
    let (relay_egress_stream, server_stream) = tokio::io::duplex(kib(16));

    let token = CancellationToken::new();
    let graceful = Shutdown::new(token.clone().cancelled_owned());
    let cancel_drop_guard = token.drop_guard();

    graceful.spawn_task_fn(async move |guard| {
        HttpServer::auto(Executor::graceful(guard))
            .service(service_fn(mitm_relay_server_svc_fn))
            .serve(MockSocket::new(server_stream))
            .await
            .unwrap();
    });

    graceful.spawn_task_fn(async move |guard| {
        HttpMitmRelay::new(Executor::graceful(guard))
            .with_http_middleware((
                ConsumeErrLayer::trace_as_debug().with_response(DefaultErrorResponse::new()),
                SetRequestHeaderLayer::overriding(
                    HeaderName::from_static("x-observed-req"),
                    HeaderValue::from_static("1"),
                ),
                SetResponseHeaderLayer::overriding(
                    HeaderName::from_static("x-observed-res"),
                    HeaderValue::from_static("1"),
                ),
                ArcLayer::new(),
            ))
            .serve(BridgeIo(
                MockSocket::new(relay_ingress_stream),
                MockSocket::new(relay_egress_stream),
            ))
            .await
            .unwrap();
    });

    let request = create_test_request(version);
    let conn = http_connect(
        MockSocket::new(client_stream),
        request,
        Executor::graceful(graceful.guard()),
    )
    .await
    .unwrap()
    .conn;

    let mut ids = Vec::with_capacity(n);
    let mut futures = Vec::with_capacity(n);
    for id in 0..n {
        ids.push(id);
        futures.push(conn.serve(create_test_request_with_id(version, id)));
    }

    let responses = join_all(futures).await;
    assert_eq!(responses.len(), n);

    for (id, response) in ids.into_iter().zip(responses) {
        let response = response.unwrap();
        assert!(response.headers().contains_key("x-observed-res"));
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(bytes, format!("a random response body ({id})"));
    }

    drop(conn);
    cancel_drop_guard.disarm().cancel();
    graceful.shutdown().await;
}

#[tokio::test]
async fn test_http11_mitm_relay_roundtrip() {
    test_mitm_relay_roundtrip_inner(Version::HTTP_11).await;
}

#[tokio::test]
async fn test_http2_mitm_relay_roundtrip() {
    test_mitm_relay_roundtrip_inner(Version::HTTP_2).await;
}

#[tokio::test]
async fn test_http11_mitm_relay_handles_4_concurrent_requests() {
    test_mitm_relay_concurrency_inner(Version::HTTP_11, 4).await;
}

#[tokio::test]
async fn test_http2_mitm_relay_handles_200_concurrent_requests() {
    test_mitm_relay_concurrency_inner(Version::HTTP_2, 200).await;
}

#[tokio::test]
async fn test_http11_mitm_relay_closes_downstream_after_upstream_close() {
    let (client_stream, relay_ingress_stream) = tokio::io::duplex(kib(16));
    let (relay_egress_stream, server_stream) = tokio::io::duplex(kib(16));

    let token = CancellationToken::new();
    let graceful = Shutdown::new(token.clone().cancelled_owned());
    let cancel_drop_guard = token.drop_guard();
    let request_count = Arc::new(AtomicUsize::new(0));

    graceful.spawn_task_fn({
        let request_count = request_count.clone();
        async move |guard| {
            HttpServer::auto(Executor::graceful(guard))
                .service(service_fn(move |req| {
                    let request_count = request_count.clone();
                    async move {
                        mitm_relay_server_close_after_first_request_svc_fn(req, request_count).await
                    }
                }))
                .serve(MockSocket::new(server_stream))
                .await
                .unwrap();
        }
    });

    graceful.spawn_task_fn(async move |guard| {
        HttpMitmRelay::new(Executor::graceful(guard))
            .with_http_middleware((
                ConsumeErrLayer::trace_as_debug().with_response(DefaultErrorResponse::new()),
                SetRequestHeaderLayer::overriding(
                    HeaderName::from_static("x-observed-req"),
                    HeaderValue::from_static("1"),
                ),
                SetResponseHeaderLayer::overriding(
                    HeaderName::from_static("x-observed-res"),
                    HeaderValue::from_static("1"),
                ),
                ArcLayer::new(),
            ))
            .serve(BridgeIo(
                MockSocket::new(relay_ingress_stream),
                MockSocket::new(relay_egress_stream),
            ))
            .await
            .unwrap();
    });

    let request = create_test_request(Version::HTTP_11);
    let conn = http_connect(
        MockSocket::new(client_stream),
        request,
        Executor::graceful(graceful.guard()),
    )
    .await
    .unwrap()
    .conn;

    let response = conn
        .serve(create_test_request(Version::HTTP_11))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("connection")
            .and_then(|v| v.to_str().ok()),
        Some("close")
    );

    let second = conn.serve(create_test_request(Version::HTTP_11)).await;
    assert!(
        second.is_err(),
        "downstream connection should close after upstream close"
    );

    drop(conn);
    cancel_drop_guard.disarm().cancel();
    graceful.shutdown().await;
}

#[tokio::test]
async fn test_http11_mitm_relay_task_finishes_after_ingress_disconnect() {
    let (client_stream, relay_ingress_stream) = tokio::io::duplex(kib(16));
    let (relay_egress_stream, server_stream) = tokio::io::duplex(kib(16));

    let token = CancellationToken::new();
    let graceful = Shutdown::new(token.clone().cancelled_owned());
    let cancel_drop_guard = token.drop_guard();

    graceful.spawn_task_fn(async move |guard| {
        HttpServer::auto(Executor::graceful(guard))
            .service(service_fn(mitm_relay_server_svc_fn))
            .serve(MockSocket::new(server_stream))
            .await
            .unwrap();
    });

    let (relay_done_tx, relay_done_rx) = tokio::sync::oneshot::channel::<()>();

    graceful.spawn_task_fn(async move |guard| {
        HttpMitmRelay::new(Executor::graceful(guard))
            .with_http_middleware((
                ConsumeErrLayer::trace_as_debug().with_response(DefaultErrorResponse::new()),
                SetRequestHeaderLayer::overriding(
                    HeaderName::from_static("x-observed-req"),
                    HeaderValue::from_static("1"),
                ),
                SetResponseHeaderLayer::overriding(
                    HeaderName::from_static("x-observed-res"),
                    HeaderValue::from_static("1"),
                ),
                ArcLayer::new(),
            ))
            .serve(BridgeIo(
                MockSocket::new(relay_ingress_stream),
                MockSocket::new(relay_egress_stream),
            ))
            .await
            .unwrap();
        _ = relay_done_tx.send(());
    });

    let request = create_test_request(Version::HTTP_11);
    let conn = http_connect(
        MockSocket::new(client_stream),
        request,
        Executor::graceful(graceful.guard()),
    )
    .await
    .unwrap()
    .conn;

    let response = conn
        .serve(create_test_request(Version::HTTP_11))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    _ = response.into_body().collect().await.unwrap();

    drop(conn);

    tokio::time::timeout(std::time::Duration::from_secs(1), relay_done_rx)
        .await
        .expect("relay task should finish after ingress disconnect")
        .expect("relay completion signal");

    cancel_drop_guard.disarm().cancel();
    graceful.shutdown().await;
}

/// Verifies the relay's eager phase-2 path mirrors the upstream's
/// initial h2 SETTINGS onto its own ingress SETTINGS frame.
///
/// Upstream advertises `enable_connect_protocol=true` plus a custom
/// `max_concurrent_streams`. The relay's egress IO carries
/// `TargetHttpVersion(HTTP_2)`, which triggers eager phase-2 init: the
/// relay handshakes egress, captures upstream SETTINGS, and stamps
/// them as `H2ServerContextParams` on the ingress IO. The downstream
/// client reads back the relay's SETTINGS frame via the
/// `PeerH2Settings` response extension and we assert it matches.
#[tokio::test]
async fn test_h2_mitm_relay_mirrors_upstream_settings_connect_on() {
    test_mitm_relay_mirrors_h2_settings_inner(true, 42).await;
}

/// Counterpart of the previous test: upstream does NOT advertise
/// CONNECT and uses a different `max_concurrent_streams`. The relay
/// must not advertise CONNECT downstream, even though earlier
/// (pre-#932) versions did unconditionally.
#[tokio::test]
async fn test_h2_mitm_relay_mirrors_upstream_settings_connect_off() {
    test_mitm_relay_mirrors_h2_settings_inner(false, 7).await;
}

async fn test_mitm_relay_mirrors_h2_settings_inner(
    upstream_enables_connect: bool,
    upstream_max_concurrent_streams: u32,
) {
    let (client_stream, relay_ingress_stream) = tokio::io::duplex(kib(16));
    let (relay_egress_stream, server_stream) = tokio::io::duplex(kib(16));

    let token = CancellationToken::new();
    let graceful = Shutdown::new(token.clone().cancelled_owned());
    let cancel_drop_guard = token.drop_guard();

    // Upstream h2 server configured with the SETTINGS we want the
    // relay to mirror back out to its downstream client.
    graceful.spawn_task_fn(async move |guard| {
        let mut server = HttpServer::auto(Executor::graceful(guard));
        if upstream_enables_connect {
            server.h2_mut().set_enable_connect_protocol();
        }
        server
            .h2_mut()
            .set_max_concurrent_streams(upstream_max_concurrent_streams);
        server
            .service(service_fn(server_svc_fn))
            .serve(MockSocket::new(server_stream))
            .await
            .unwrap();
    });

    // Egress IO carries TargetHttpVersion(HTTP_2) so the relay takes
    // the eager phase-2 branch and actually mirrors. Without this,
    // the relay would fall through to the lazy path and the ingress
    // would keep its server-defaults (no mirror).
    let egress = MockSocket::new(relay_egress_stream);
    egress
        .extensions()
        .insert(TargetHttpVersion(Version::HTTP_2));

    graceful.spawn_task_fn(async move |guard| {
        HttpMitmRelay::new(Executor::graceful(guard))
            .serve(BridgeIo(MockSocket::new(relay_ingress_stream), egress))
            .await
            .unwrap();
    });

    // Client speaks h2 to the relay. The response carries
    // `PeerH2Settings` — i.e. the SETTINGS frame the *relay*
    // advertised. That is what we assert against.
    let request = create_test_request(Version::HTTP_2);
    let conn = http_connect(
        MockSocket::new(client_stream),
        request,
        Executor::graceful(graceful.guard()),
    )
    .await
    .unwrap()
    .conn;

    let response = conn
        .serve(create_test_request(Version::HTTP_2))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let peer = response
        .extensions()
        .get_ref::<PeerH2Settings>()
        .expect("client must observe relay's initial SETTINGS frame");

    if upstream_enables_connect {
        assert_eq!(
            peer.0.config.enable_connect_protocol,
            Some(1),
            "relay must mirror upstream's enable_connect_protocol=1",
        );
    } else {
        // Stricter than `!= Some(1)`: lock in the wire-omission
        // semantics. The mirror produces Some(false) → the ingress h2
        // server's Config has enable_connect_protocol=false (the
        // default) → it is omitted from the initial SETTINGS frame on
        // the wire → the client sees `None` in PeerH2Settings.
        assert_eq!(
            peer.0.config.enable_connect_protocol, None,
            "relay must NOT advertise CONNECT when upstream doesn't",
        );
    }
    assert_eq!(
        peer.0.config.max_concurrent_streams,
        Some(upstream_max_concurrent_streams),
        "relay must mirror upstream's max_concurrent_streams",
    );

    drop(conn);
    cancel_drop_guard.disarm().cancel();
    graceful.shutdown().await;
}

/// Smoke test: when the egress IO carries `H2ClientContextParams` *in
/// addition to* `TargetHttpVersion(HTTP_2)`, the eager-handshake path
/// must read and apply those params (not silently drop them).
///
/// We can't easily observe per-knob
/// effects from the test harness without frame-level upstream hooks,
/// so this asserts the simpler invariant that the full
/// eager → request → response round-trip still succeeds with non-default
/// client params present. Regression guard for the parity issue.
#[tokio::test]
async fn test_h2_mitm_relay_eager_honors_egress_h2_client_params() {
    let (client_stream, relay_ingress_stream) = tokio::io::duplex(kib(16));
    let (relay_egress_stream, server_stream) = tokio::io::duplex(kib(16));

    let token = CancellationToken::new();
    let graceful = Shutdown::new(token.clone().cancelled_owned());
    let cancel_drop_guard = token.drop_guard();

    graceful.spawn_task_fn(async move |guard| {
        HttpServer::auto(Executor::graceful(guard))
            .service(service_fn(server_svc_fn))
            .serve(MockSocket::new(server_stream))
            .await
            .unwrap();
    });

    let egress = MockSocket::new(relay_egress_stream);
    egress
        .extensions()
        .insert(TargetHttpVersion(Version::HTTP_2));
    // Non-default client-side h2 knobs. Values are chosen valid + small
    // enough not to interact with the test harness's frame sizes.
    egress.extensions().insert(H2ClientContextParams {
        max_header_list_size: Some(65_536),
        init_stream_window_size: Some(131_072),
        ..Default::default()
    });

    graceful.spawn_task_fn(async move |guard| {
        HttpMitmRelay::new(Executor::graceful(guard))
            .serve(BridgeIo(MockSocket::new(relay_ingress_stream), egress))
            .await
            .unwrap();
    });

    let request = create_test_request(Version::HTTP_2);
    let conn = http_connect(
        MockSocket::new(client_stream),
        request,
        Executor::graceful(graceful.guard()),
    )
    .await
    .unwrap()
    .conn;

    let response = conn
        .serve(create_test_request(Version::HTTP_2))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    drop(conn);
    cancel_drop_guard.disarm().cancel();
    graceful.shutdown().await;
}

/// Negative test: confirms the four fields we intentionally do NOT
/// mirror (`header_table_size`, `max_frame_size`, `max_header_list_size`,
/// `initial_stream_window_size`) do not propagate from upstream to
/// ingress even when upstream advertises them with non-default values.
/// Locks in the narrowed-mirror policy from #932 review feedback.
#[tokio::test]
async fn test_h2_mitm_relay_does_not_mirror_per_direction_fields() {
    let (client_stream, relay_ingress_stream) = tokio::io::duplex(kib(16));
    let (relay_egress_stream, server_stream) = tokio::io::duplex(kib(16));

    let token = CancellationToken::new();
    let graceful = Shutdown::new(token.clone().cancelled_owned());
    let cancel_drop_guard = token.drop_guard();

    // Upstream configures all four un-mirrored fields to non-default
    // values. The mirror MUST ignore them.
    graceful.spawn_task_fn(async move |guard| {
        let mut server = HttpServer::auto(Executor::graceful(guard));
        server.h2_mut().set_max_frame_size(32_768);
        server.h2_mut().set_max_header_list_size(32_768);
        server.h2_mut().set_header_table_size(8_192);
        server.h2_mut().set_initial_stream_window_size(131_072);
        server
            .service(service_fn(server_svc_fn))
            .serve(MockSocket::new(server_stream))
            .await
            .unwrap();
    });

    let egress = MockSocket::new(relay_egress_stream);
    egress
        .extensions()
        .insert(TargetHttpVersion(Version::HTTP_2));

    graceful.spawn_task_fn(async move |guard| {
        HttpMitmRelay::new(Executor::graceful(guard))
            .serve(BridgeIo(MockSocket::new(relay_ingress_stream), egress))
            .await
            .unwrap();
    });

    let request = create_test_request(Version::HTTP_2);
    let conn = http_connect(
        MockSocket::new(client_stream),
        request,
        Executor::graceful(graceful.guard()),
    )
    .await
    .unwrap()
    .conn;

    let response = conn
        .serve(create_test_request(Version::HTTP_2))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let peer = response
        .extensions()
        .get_ref::<PeerH2Settings>()
        .expect("client must observe relay's initial SETTINGS frame");

    // Upstream's non-default values must NOT propagate to ingress.
    // Each assertion is a separate guard against accidental
    // re-mirroring.
    assert_ne!(
        peer.0.config.max_frame_size,
        Some(32_768),
        "max_frame_size must not be mirrored",
    );
    assert_ne!(
        peer.0.config.max_header_list_size,
        Some(32_768),
        "max_header_list_size must not be mirrored",
    );
    assert_ne!(
        peer.0.config.header_table_size,
        Some(8_192),
        "header_table_size must not be mirrored",
    );
    assert_ne!(
        peer.0.config.initial_window_size,
        Some(131_072),
        "initial_window_size must not be mirrored",
    );

    drop(conn);
    cancel_drop_guard.disarm().cancel();
    graceful.shutdown().await;
}

/// Timeout-path: upstream completes the byte-level handshake (its side
/// of the duplex stays alive) but never sends its initial SETTINGS
/// frame. The eager-init `await_settings` hits the configured timeout,
/// the relay's fail-safe stamps `enable_connect_protocol: Some(false)`
/// on the ingress, overriding the baseline CONNECT-on default.
/// Downstream observes a SETTINGS frame without CONNECT.
#[tokio::test]
async fn test_h2_mitm_relay_timeout_forces_connect_off_via_fail_safe() {
    use tokio::io::AsyncReadExt;

    let (client_stream, relay_ingress_stream) = tokio::io::duplex(kib(16));
    let (relay_egress_stream, mut silent_upstream) = tokio::io::duplex(kib(16));

    let token = CancellationToken::new();
    let graceful = Shutdown::new(token.clone().cancelled_owned());
    let cancel_drop_guard = token.drop_guard();

    // Silent upstream: drains everything; never sends a byte back. The
    // relay's eager `await_settings` will hit the configured timeout.
    graceful.spawn_task_fn(async move |_guard| {
        let mut buf = [0u8; 1024];
        loop {
            match silent_upstream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    });

    let egress = MockSocket::new(relay_egress_stream);
    egress
        .extensions()
        .insert(TargetHttpVersion(Version::HTTP_2));

    graceful.spawn_task_fn(async move |guard| {
        // The relay's `new()` baseline is already CONNECT-on, so any
        // user opt-in via `h2_mut().set_enable_connect_protocol()` is
        // a no-op vs. baseline. The fail-safe must override regardless.
        _ = HttpMitmRelay::new(Executor::graceful(guard))
            .with_eager_peer_settings_timeout(Duration::from_millis(50))
            .serve(BridgeIo(MockSocket::new(relay_ingress_stream), egress))
            .await;
    });

    // Low-level outer h2 to read the relay's SETTINGS without a request.
    let (send_req, conn) =
        rama_http_core::client::conn::http2::Builder::new(Executor::graceful(graceful.guard()))
            .handshake::<_, rama_http::body::util::Empty<rama_core::bytes::Bytes>>(MockSocket::new(
                client_stream,
            ))
            .await
            .expect("downstream h2 handshake against relay must succeed");

    let handle = conn.peer_settings_handle();
    tokio::spawn(async move {
        drop(conn.await);
    });

    let settings = tokio::time::timeout(Duration::from_secs(3), handle.await_settings())
        .await
        .expect("relay SETTINGS must arrive within 3s")
        .expect("relay must send SETTINGS even after eager timeout");

    assert_eq!(
        settings.0.config.enable_connect_protocol, None,
        "fail-safe: relay must NOT advertise CONNECT when upstream times out",
    );

    drop(send_req);
    cancel_drop_guard.disarm().cancel();
    graceful.shutdown().await;
}

/// Spec-faithful `Some(0)` propagation: per RFC 9113 §6.5.2, `0` is a
/// legal `SETTINGS_MAX_CONCURRENT_STREAMS` value. The relay must NOT
/// floor/clamp it — downstream must see exactly what upstream
/// advertised. Locks in the dropped-floor change.
#[tokio::test]
async fn test_h2_mitm_relay_mirrors_zero_max_concurrent_streams() {
    let (client_stream, relay_ingress_stream) = tokio::io::duplex(kib(16));
    let (relay_egress_stream, server_stream) = tokio::io::duplex(kib(16));

    let token = CancellationToken::new();
    let graceful = Shutdown::new(token.clone().cancelled_owned());
    let cancel_drop_guard = token.drop_guard();

    // Upstream advertises max_concurrent_streams=0.
    graceful.spawn_task_fn(async move |guard| {
        let mut server = HttpServer::auto(Executor::graceful(guard));
        server.h2_mut().set_max_concurrent_streams(0);
        server
            .service(service_fn(server_svc_fn))
            .serve(MockSocket::new(server_stream))
            .await
            .unwrap();
    });

    let egress = MockSocket::new(relay_egress_stream);
    egress
        .extensions()
        .insert(TargetHttpVersion(Version::HTTP_2));

    graceful.spawn_task_fn(async move |guard| {
        _ = HttpMitmRelay::new(Executor::graceful(guard))
            .serve(BridgeIo(MockSocket::new(relay_ingress_stream), egress))
            .await;
    });

    // Low-level h2: we don't send a request because the relay's ingress
    // (correctly enforcing max_streams=0) would RST_STREAM it.
    let (send_req, conn) =
        rama_http_core::client::conn::http2::Builder::new(Executor::graceful(graceful.guard()))
            .handshake::<_, rama_http::body::util::Empty<rama_core::bytes::Bytes>>(MockSocket::new(
                client_stream,
            ))
            .await
            .expect("downstream h2 handshake against relay must succeed");

    let handle = conn.peer_settings_handle();
    tokio::spawn(async move {
        drop(conn.await);
    });

    let settings = tokio::time::timeout(Duration::from_secs(3), handle.await_settings())
        .await
        .expect("relay SETTINGS must arrive within 3s")
        .expect("relay must send SETTINGS");

    assert_eq!(
        settings.0.config.max_concurrent_streams,
        Some(0),
        "RFC 9113 §6.5.2: Some(0) is legal and MUST be propagated as-is",
    );

    drop(send_req);
    cancel_drop_guard.disarm().cancel();
    graceful.shutdown().await;
}
