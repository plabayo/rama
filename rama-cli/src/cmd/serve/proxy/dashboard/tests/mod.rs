use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64;
use rama::{
    http::{
        HeaderMap, HeaderName, HeaderValue, Method, Version, inspect::capture::CaptureMetadata,
        ws::inspect::CapturedWebSocketMessage,
    },
    net::{Protocol, address::ProxyAddress},
    ua::profile::UserAgentDatabase,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::*;
use crate::cmd::serve::proxy::capture::{CaptureHttpLayer, StoredRecord};

fn test_state_with_limits(connections: usize, exchanges: usize) -> DashboardState {
    test_state_with_upstream(
        connections,
        exchanges,
        &UpstreamProxyConfig::new(None, false, &[]).unwrap(),
    )
}

fn test_state_with_upstream(
    connections: usize,
    exchanges: usize,
    upstream: &UpstreamProxyConfig,
) -> DashboardState {
    let ua_db = Arc::new(UserAgentDatabase::try_embedded().unwrap());
    DashboardState::new(
        crate::cmd::serve::proxy::capture::test_store(connections, exchanges, kib_u64(1), ua_db)
            .unwrap(),
        HarController::default(),
        Vec::new(),
        Arc::new(SocketOptions::default_tcp()),
        upstream,
        MitmPolicy::try_new(&[], &[]).unwrap(),
    )
    .unwrap()
}

pub(super) fn test_state() -> DashboardState {
    test_state_with_limits(8, 8)
}

pub(super) async fn capture_request_for_replay(state: &DashboardState, uri: &str) {
    let capture = CaptureHttpLayer::new(Some(state.capture.clone())).into_layer(
        rama::service::service_fn(async |request: Request| {
            request.into_body().collect().await.unwrap();
            Ok::<_, Infallible>(Response::new(Body::empty()))
        }),
    );
    capture
        .serve(
            Request::builder()
                .uri(uri)
                .header("proxy-authorization", "Basic captured-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap();
}

async fn read_http_head(stream: &mut tokio::net::TcpStream) -> String {
    let mut request = Vec::new();
    let mut buffer = [0; kib(1)];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut buffer).await.unwrap();
        assert_ne!(read, 0, "HTTP request ended before its headers");
        request.extend_from_slice(&buffer[..read]);
    }
    String::from_utf8(request).unwrap()
}

fn test_headers(values: impl IntoIterator<Item = (impl AsRef<str>, impl AsRef<str>)>) -> HeaderMap {
    values
        .into_iter()
        .map(|(name, value)| {
            (
                name.as_ref().parse::<HeaderName>().unwrap(),
                HeaderValue::from_bytes(value.as_ref().as_bytes()).unwrap(),
            )
        })
        .collect()
}

fn test_details(records: Vec<StoredRecord>) -> InspectorDetails {
    let metadata = CaptureMetadata::default();
    InspectorDetails {
        http: CaptureDetails {
            summary: HttpExchangeSummary {
                decision: None,
                id: 1,
                connection_id: 1,
                connection_display_id: 1,
                started_at: "1970-01-01T00:00:00Z".parse().unwrap(),
                method: Method::GET,
                http_version: Version::HTTP_11,
                url: "http://example.test".parse().unwrap(),
                endpoint: Some("example.test".parse().unwrap()),
                protocol: Protocol::HTTP,
                user_agent: None,
                status: Some(StatusCode::OK),
                active: false,
                response_started_at: None,
                completed_at: None,
                request_bytes: 0,
                response_bytes: 0,
                request_truncated: false,
                response_truncated: false,
                ja4h: None,
                metadata: metadata.clone(),
            },
            records,
            connection: None,
            metadata,
        },
        websocket: WebSocketDetails {
            messages: Vec::new(),
            page: 0,
            total: 0,
            replay_active: false,
        },
    }
}

async fn assert_replay_forward_proxy_auth(
    configured_credential: Option<&str>,
    forward_proxy_auth: bool,
    expected_authorization: Option<&str>,
) {
    let listener = rama::tcp::server::TcpListener::bind_address(
        rama::net::address::SocketAddress::local_ipv4(0),
        Executor::default(),
    )
    .await
    .unwrap();
    let proxy_address = listener.local_addr().unwrap();
    let (observed_tx, mut observed_rx) = tokio::sync::mpsc::channel(1);
    let proxy_task = tokio::spawn(listener.serve(
        rama::http::server::HttpServer::auto(Executor::default()).service(
            rama::service::service_fn(move |request: Request| {
                let observed_tx = observed_tx.clone();
                async move {
                    observed_tx
                        .send((
                            request.uri().to_string(),
                            request
                                .headers()
                                .get_all(rama::http::header::PROXY_AUTHORIZATION)
                                .iter()
                                .map(|value| value.to_str().unwrap().to_owned())
                                .collect::<Vec<_>>(),
                        ))
                        .await
                        .unwrap();
                    Ok::<_, Infallible>(Response::new(Body::from("replayed")))
                }
            }),
        ),
    ));
    let mut proxy: ProxyAddress = format!("http://{proxy_address}").parse().unwrap();
    proxy.credential = configured_credential.map(|credential| {
        rama::net::user::ProxyCredential::Basic(
            rama::net::user::Basic::try_from(credential).unwrap(),
        )
    });
    let upstream = UpstreamProxyConfig::new(Some(proxy), false, &[])
        .unwrap()
        .with_forward_proxy_auth(forward_proxy_auth);
    let state = test_state_with_upstream(8, 8, &upstream);
    capture_request_for_replay(&state, "http://origin.example/replay").await;

    assert_eq!(replay_captured(&state, 1).await.unwrap(), 200);
    assert_eq!(
        observed_rx.recv().await.unwrap(),
        (
            "http://origin.example/replay".to_owned(),
            expected_authorization
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        )
    );
    proxy_task.abort();
}

mod controller;
mod exports;
mod navigation;
mod render;
mod replay;
