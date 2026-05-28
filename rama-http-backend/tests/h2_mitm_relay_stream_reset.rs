//! Regression e2e for an upstream HTTP/2 `RST_STREAM` flowing through the
//! [`HttpMitmRelay`].
//!
//! Issue: when an upstream resets a single h2 stream (e.g. a WebSocket
//! stream a server tears down with `RST_STREAM`), the relay must fail ONLY
//! that ingress stream — surfacing a per-stream `502` — and leave the shared
//! ingress h2 connection (and every sibling stream) untouched. The earlier
//! behavior escalated a stream-scoped reset into `close_ingress.cancel()`,
//! which sends a connection-level `GOAWAY` and tears down all siblings.
//!
//! The fix lives in `serve_relay_request`'s error arm
//! (`egress_error_is_stream_scoped` → return a `502` instead of cancelling
//! the ingress). That arm is only reached when the egress client error
//! actually propagates as an `Err` — which is exactly the production wiring
//! (`http_relay_middleware` has `Error = BoxError` and no top-level
//! `ConsumeErrLayer` over the egress client). This test reproduces that by
//! using an error-propagating middleware (NOT the `DefaultMiddleware`'s
//! `ConsumeErrLayer`, which would swallow the reset into a `502` *before*
//! the fix's code path and so would pass even on the buggy code).
//!
//! Wiring (all in-memory, no sockets):
//!
//!   client ──duplex──▶ relay(ingress h2) ──relay──▶ egress h2 ──duplex──▶ upstream
//!
//! The upstream is a hand-rolled low-level `rama_http_core::h2::server` so it
//! can deterministically `send_reset` exactly one stream while answering the
//! rest with `200 OK`.
//!
//! This file lives under `tests/` so it exercises only the public API and
//! touches no existing source.

use rama_core::{
    Service, futures::future::join_all, graceful::Shutdown, io::BridgeIo, layer::ArcLayer,
    rt::Executor,
};
use rama_http::{
    HeaderName, HeaderValue,
    layer::set_header::{SetRequestHeaderLayer, SetResponseHeaderLayer},
};
use rama_http_core::h2::{Reason, server as h2_server};
use rama_http_types::{Body, Request, Response, StatusCode, Version};
use rama_net::test_utils::client::MockSocket;
use tokio_util::sync::CancellationToken;

use rama_http_backend::{client::http_connect, proxy::mitm::HttpMitmRelay};

/// Header used to tag each request so the upstream can decide, per stream,
/// whether to reset it.
const TEST_ID_HEADER: &str = "x-test-id";
/// The single stream the upstream will `RST_STREAM`.
const RESET_ID: &str = "3";
/// Number of concurrent ingress streams in the batch.
const CONCURRENCY: usize = 6;

#[tokio::test]
async fn http2_mitm_relay_stream_reset_does_not_tear_down_ingress() {
    let (client_stream, relay_ingress_stream) = tokio::io::duplex(64 * 1024);
    let (relay_egress_stream, server_stream) = tokio::io::duplex(64 * 1024);

    let token = CancellationToken::new();
    let graceful = Shutdown::new(token.clone().cancelled_owned());
    let cancel_drop_guard = token.drop_guard();

    // Build an h2 request tagged with `id` so the upstream can pick which
    // stream to reset. A closure (rather than a free fn) so its
    // infallible-in-practice `.unwrap()` stays inside the `#[test]` context.
    let make_h2_request = |id: &str| -> Request {
        Request::builder()
            .uri("https://upstream.example/resource")
            .version(Version::HTTP_2)
            .header(TEST_ID_HEADER, id)
            .body(Body::empty())
            .unwrap()
    };

    // ── Upstream: low-level h2 server that resets exactly one stream. ──
    graceful.spawn_task_fn(async move |guard| {
        let _guard = guard;
        let mut conn = h2_server::handshake(MockSocket::new(server_stream))
            .await
            .expect("upstream h2 handshake");

        while let Some(accepted) = conn.accept().await {
            // Connection wound down (client/relay gone) — stop.
            let Ok((request, mut respond)) = accepted else {
                break;
            };

            let is_reset_target = request
                .headers()
                .get(TEST_ID_HEADER)
                .and_then(|v| v.to_str().ok())
                == Some(RESET_ID);

            if is_reset_target {
                // Stream-scoped teardown: the shared connection and its
                // sibling streams are unaffected by this frame.
                respond.send_reset(Reason::CANCEL);
            } else {
                let response = Response::builder()
                    .status(StatusCode::OK)
                    .header("x-upstream", "ok")
                    .body(())
                    .unwrap();
                // end_of_stream = true: an empty-body 200 is enough; we only
                // assert status + provenance headers. A send error here just
                // means the peer already went away for this stream — ignore.
                let _send = respond.send_response(response, true);
            }
        }
    });

    // ── Relay: MITM relay with an ERROR-PROPAGATING middleware. ──
    // Deliberately omit `ConsumeErrLayer` so a reset reaches
    // `serve_relay_request`'s `Err` arm — the fix's code path. `ArcLayer`
    // boxes the egress client to `Error = BoxError` (still `Into<BoxError>`)
    // without consuming errors, mirroring the production relay middleware.
    graceful.spawn_task_fn(async move |guard| {
        HttpMitmRelay::new(Executor::graceful(guard))
            .with_http_middleware((
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

    // ── Client: open one ingress h2 connection, fan out a batch. ──
    let conn = http_connect(
        MockSocket::new(client_stream),
        make_h2_request("0"),
        Executor::graceful(graceful.guard()),
    )
    .await
    .expect("client h2 connect to relay")
    .conn;

    let ids: Vec<String> = (0..CONCURRENCY).map(|i| i.to_string()).collect();
    let responses = join_all(ids.iter().map(|id| conn.serve(make_h2_request(id)))).await;
    assert_eq!(responses.len(), CONCURRENCY);

    for (id, response) in ids.iter().zip(responses) {
        // No ingress stream may hard-error: a hard error here is the GOAWAY
        // symptom the fix prevents.
        let response = response.unwrap_or_else(|err| {
            panic!("ingress stream {id} hard-errored (GOAWAY symptom): {err}")
        });

        if id == RESET_ID {
            assert_eq!(
                response.status(),
                StatusCode::BAD_GATEWAY,
                "the RST_STREAM'd stream must surface as a per-stream 502"
            );
            // The 502 is the relay's synthesized DefaultErrorResponse, not a
            // transport failure leaking through.
            assert!(
                response.headers().contains_key("x-proxy-framework-name"),
                "the per-stream failure must be the relay's DefaultErrorResponse"
            );
        } else {
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "sibling stream {id} must survive the peer RST_STREAM"
            );
            assert_eq!(
                response
                    .headers()
                    .get("x-upstream")
                    .and_then(|v| v.to_str().ok()),
                Some("ok"),
                "sibling stream {id} must carry the real upstream response"
            );
        }
    }

    // ── Strongest assertion: the ingress connection is still usable. ──
    // A connection-level GOAWAY would have closed it; a fresh request on the
    // SAME `conn` must still round-trip after the sibling reset.
    let post_reset = conn
        .serve(make_h2_request("999"))
        .await
        .expect("ingress h2 connection must remain open after a sibling RST_STREAM");
    assert_eq!(post_reset.status(), StatusCode::OK);
    assert_eq!(
        post_reset
            .headers()
            .get("x-upstream")
            .and_then(|v| v.to_str().ok()),
        Some("ok"),
    );

    drop(conn);
    cancel_drop_guard.disarm().cancel();
    graceful.shutdown().await;
}
