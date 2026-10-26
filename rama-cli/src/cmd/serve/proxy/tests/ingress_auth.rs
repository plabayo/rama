use rama::{http::header::PROXY_AUTHORIZATION, net::user::Basic};

use super::*;
use crate::cmd::serve::proxy::with_proxy_auth;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_ingress_requires_the_proxy_credential_and_never_forwards_it() {
    let (origin, origin_task) = spawn_credential_reporting_origin().await;
    let bind = loopback_bind_address().to_string();
    let cli = TestCli::parse_from([
        "test",
        "--bind",
        bind.as_str(),
        "--protocol",
        "http,https,socks5",
        "--proxy-auth",
        "john:secret",
    ]);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown = rama::graceful::Shutdown::new(async move {
        _ = shutdown_rx.await;
    });
    let (proxy, _inspector) = start_proxy(shutdown.guard(), cli.proxy).await;

    for (scheme, tunnel) in [
        ("http", false),
        ("http", true),
        ("https", false),
        ("https", true),
        ("socks5h", false),
    ] {
        let label = format!("{scheme} tunnel={tunnel}");
        for credential in ["", "john:wrong@", "jane:secret@"] {
            let result = fetch(origin, &format!("{scheme}://{credential}{proxy}"), tunnel).await;
            let forward = !tunnel && scheme != "socks5h";
            match result {
                // A plain forward request gets the proxy's 407 back as its response.
                Ok((status, _)) => assert_eq!(
                    status,
                    StatusCode::PROXY_AUTHENTICATION_REQUIRED,
                    "{label} {credential:?}"
                ),
                // CONNECT and SOCKS5 fail to establish the tunnel.
                Err(error) => assert!(!forward, "{label} {credential:?}: {error:?}"),
            }
        }
        let (status, body) = fetch(origin, &format!("{scheme}://john:secret@{proxy}"), tunnel)
            .await
            .unwrap_or_else(|error| panic!("{label}: {error:?}"));
        assert_eq!(status, StatusCode::OK, "{label}");
        assert_eq!(body, "no credential", "{label}");
    }

    shutdown_proxy(shutdown_tx, shutdown).await;
    origin_task.abort();
}

#[tokio::test]
async fn the_shared_dashboard_keeps_its_own_token_auth() {
    let dashboard: SocketAddress = "127.0.0.1:8080".parse().unwrap();
    let service = with_proxy_auth(
        service_fn(|request: Request| async move {
            let seen = request.headers().contains_key(PROXY_AUTHORIZATION);
            Ok::<_, Infallible>(Response::new(Body::from(if seen {
                "credential leaked"
            } else {
                "served"
            })))
        }),
        Some("john:secret".parse::<Basic>().unwrap()),
        Some(dashboard),
    );
    let dashboard_request = with_local_address(
        Request::builder()
            .uri("/")
            .header("host", "127.0.0.1:8080")
            .body(Body::empty())
            .unwrap(),
        "127.0.0.1:8080",
    );
    let response = service.serve(dashboard_request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let proxied = with_local_address(
        Request::builder()
            .uri("http://origin.test/")
            .body(Body::empty())
            .unwrap(),
        "127.0.0.1:8080",
    );
    let response = service.serve(proxied).await.unwrap();
    assert_eq!(response.status(), StatusCode::PROXY_AUTHENTICATION_REQUIRED);

    let authorized = with_local_address(
        Request::builder()
            .uri("http://origin.test/")
            .header(PROXY_AUTHORIZATION, "Basic am9objpzZWNyZXQ=")
            .body(Body::empty())
            .unwrap(),
        "127.0.0.1:8080",
    );
    let response = service.serve(authorized).await.unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, "served");
}
