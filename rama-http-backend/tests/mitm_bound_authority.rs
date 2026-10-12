//! Trusted interception origins are checked before and after HTTP middleware.

#![expect(clippy::unwrap_used, reason = "invalid fixtures fail the regression")]

use rama_core::{
    Service,
    extensions::ExtensionsRef,
    graceful::Shutdown,
    io::BridgeIo,
    layer::{ArcLayer, MapInputLayer},
    matcher::match_fn,
    rt::Executor,
    service::service_fn,
};
use rama_http::{
    Body, HeaderValue, Request, Response, StatusCode, Version, conn::TargetHttpVersion,
    header::HOST, layer::validate_request::BoundAuthority,
};
use rama_http_backend::{client::http_connect, proxy::mitm::HttpMitmRelay, server::HttpServer};
use rama_net::test_utils::client::MockSocket;
use rama_utils::octets::kib;
use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

fn request(version: Version, authority: &str, action: &str) -> Request {
    Request::builder()
        .uri(format!("https://{authority}/resource"))
        .version(version)
        .header(HOST, authority)
        .header("x-test-action", action)
        .body(Body::empty())
        .unwrap()
}

async fn check_relay(version: Version, eager: bool) {
    timeout(Duration::from_secs(5), async {
        let (client, ingress) = tokio::io::duplex(kib(64));
        let (egress, upstream) = tokio::io::duplex(kib(64));
        let token = CancellationToken::new();
        let graceful = Shutdown::new(token.clone().cancelled_owned());
        let cancel = token.drop_guard();
        let seen = Arc::new(AtomicUsize::new(0));
        let allowed = Arc::new(AtomicBool::new(true));

        let upstream_seen = seen.clone();
        graceful.spawn_task_fn(async move |guard| {
            HttpServer::auto(Executor::graceful(guard))
                .serve(
                    MockSocket::new(upstream),
                    service_fn(move |_: Request| {
                        upstream_seen.fetch_add(1, Ordering::SeqCst);
                        async { Ok::<_, Infallible>(Response::new(Body::empty())) }
                    }),
                )
                .await
                .unwrap();
        });

        let policy_allowed = allowed.clone();
        let middleware_allowed = allowed.clone();
        graceful.spawn_task_fn(async move |guard| {
            let egress = MockSocket::new(egress);
            if eager {
                egress
                    .extensions()
                    .insert(TargetHttpVersion(Version::HTTP_2));
            }
            HttpMitmRelay::new(Executor::graceful(guard))
                .with_bound_authority(BoundAuthority::https(
                    "origin.example:443".parse().unwrap(),
                    match_fn(move |_: &Request| policy_allowed.load(Ordering::SeqCst)),
                ))
                .with_http_middleware((
                    MapInputLayer::new(move |mut req: Request| {
                        match req
                            .headers()
                            .get("x-test-action")
                            .and_then(|v| v.to_str().ok())
                        {
                            Some("repair") => {
                                *req.uri_mut() = "https://origin.example/resource".parse().unwrap();
                                req.headers_mut()
                                    .insert(HOST, HeaderValue::from_static("origin.example"));
                            }
                            Some("rewrite") => {
                                *req.uri_mut() =
                                    "https://elsewhere.example/resource".parse().unwrap();
                                req.headers_mut()
                                    .insert(HOST, HeaderValue::from_static("elsewhere.example"));
                            }
                            Some("revoke") => {
                                middleware_allowed.store(false, Ordering::SeqCst);
                            }
                            _ => (),
                        }
                        req
                    }),
                    ArcLayer::new(),
                ))
                .serve(BridgeIo(MockSocket::new(ingress), egress))
                .await
                .unwrap();
        });
        let conn = http_connect(
            MockSocket::new(client),
            request(version, "origin.example", "none"),
            Executor::graceful(graceful.guard()),
        )
        .await
        .unwrap()
        .conn;

        // A middleware rewrite cannot legitimise an original foreign authority.
        // Rejections on either side of middleware leave the upstream count intact.
        for (authority, action, permit, status, expected) in [
            (
                "elsewhere.example",
                "repair",
                true,
                StatusCode::MISDIRECTED_REQUEST,
                0,
            ),
            ("origin.example", "none", true, StatusCode::OK, 1),
            (
                "origin.example:444",
                "none",
                true,
                StatusCode::MISDIRECTED_REQUEST,
                1,
            ),
            (
                "origin.example",
                "rewrite",
                true,
                StatusCode::MISDIRECTED_REQUEST,
                1,
            ),
            (
                "origin.example",
                "revoke",
                true,
                StatusCode::MISDIRECTED_REQUEST,
                1,
            ),
            (
                "origin.example",
                "none",
                false,
                StatusCode::MISDIRECTED_REQUEST,
                1,
            ),
            ("origin.example", "none", true, StatusCode::OK, 2),
        ] {
            allowed.store(permit, Ordering::SeqCst);
            let response = conn
                .serve(request(version, authority, action))
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                status,
                "{version:?} {authority} {action}"
            );
            assert_eq!(seen.load(Ordering::SeqCst), expected);
            drop(response);
        }
        drop(conn);
        cancel.disarm().cancel();
        graceful.shutdown().await;
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn http1_relay_checks_bound_authority_before_and_after_middleware() {
    check_relay(Version::HTTP_11, false).await;
}

#[tokio::test(start_paused = true)]
async fn http2_relay_checks_bound_authority_before_and_after_middleware() {
    check_relay(Version::HTTP_2, false).await;
    check_relay(Version::HTTP_2, true).await;
}
