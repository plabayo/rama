//! An HTTP/1 connection is served until the transport an upgrade hands out closes, so the
//! layers serving the connection, such as a concurrency limit, hold it for that long.

#![expect(
    clippy::unwrap_used,
    reason = "Integration fixtures fail immediately at the failing setup or assertion"
)]

use std::{convert::Infallible, sync::Arc, time::Duration};

use rama_core::{ServiceInput, graceful::WeakScope, service::service_fn};
use rama_http::io::upgrade::handle_upgrade;
use rama_http_backend::server::HttpServer;
use rama_http_types::{Body, Request, Response, StatusCode, header};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    sync::Notify,
    time::timeout,
};

const UPGRADE_REQUEST: &[u8] =
    b"GET / HTTP/1.1\r\nHost: a\r\nConnection: upgrade\r\nUpgrade: test\r\n\r\n";

/// Upgrades every request and keeps the upgraded transport until `release` is notified.
fn upgrading_service(
    release: Arc<Notify>,
) -> impl rama_core::Service<Request, Output = Response, Error = Infallible> + Clone {
    service_fn(move |req: Request| {
        let release = release.clone();
        async move {
            let upgrade = handle_upgrade(&req);
            tokio::spawn(async move {
                let upgraded = upgrade.await.unwrap();
                release.notified().await;
                drop(upgraded);
            });
            Ok::<_, Infallible>(
                Response::builder()
                    .status(StatusCode::SWITCHING_PROTOCOLS)
                    .header(header::CONNECTION, "upgrade")
                    .header(header::UPGRADE, "test")
                    .body(Body::empty())
                    .unwrap(),
            )
        }
    })
}

#[tokio::test]
async fn http1_connection_is_served_while_upgraded() {
    for auto in [false, true] {
        let release = Arc::new(Notify::new());
        let (mut client, server_io) = tokio::io::duplex(4096);
        let svc = upgrading_service(release.clone());
        let serving = tokio::spawn(async move {
            if auto {
                HttpServer::auto(WeakScope::detached())
                    .serve(ServiceInput::new(server_io), svc)
                    .await
            } else {
                HttpServer::new_http1(WeakScope::detached())
                    .serve(ServiceInput::new(server_io), svc)
                    .await
            }
        });

        client.write_all(UPGRADE_REQUEST).await.unwrap();
        let mut head = vec![0; 1024];
        let n = client.read(&mut head).await.unwrap();
        assert!(head[..n].starts_with(b"HTTP/1.1 101"), "auto={auto}");

        // the upgraded transport is alive, so the connection is still being served
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!serving.is_finished(), "auto={auto}");

        release.notify_one();
        timeout(Duration::from_secs(5), serving)
            .await
            .expect("served past the upgraded transport")
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn http1_connection_without_upgrade_ends_with_the_connection() {
    let (mut client, server_io) = tokio::io::duplex(4096);
    let svc = service_fn(async |_: Request| Ok::<_, Infallible>(Response::new(Body::empty())));
    let serving = tokio::spawn(async move {
        HttpServer::new_http1(WeakScope::detached())
            .serve(ServiceInput::new(server_io), svc)
            .await
    });
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"));
    timeout(Duration::from_secs(5), serving)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
