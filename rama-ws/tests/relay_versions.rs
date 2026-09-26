//! The WebSocket MITM relay across HTTP versions, including HTTP/3 Extended CONNECT (RFC 9220).
//!
//! The upstream adapts the relayed request to its own version, as a Rama client would, and the
//! [`ResponseVersionAdapter`] translates its answer back for the ingress version.

#![expect(
    clippy::expect_used,
    reason = "integration tests use expectation messages to identify failed stages"
)]

use parking_lot::Mutex;
use rama_core::{
    Layer, Service, ServiceInput, bytes::Bytes, error::BoxError, extensions::ExtensionsRef as _,
    rt::Executor, service::service_fn,
};
use rama_http::{
    Body, Method, Request, Response, StatusCode, Version,
    body::util::BodyExt as _,
    headers::{self, HeaderMapExt as _, SecWebSocketAccept, SecWebSocketKey},
    io::upgrade::{self, Upgraded},
    layer::{
        upgrade::mitm::HttpUpgradeMitmRelayLayer,
        version_adapter::{ResponseVersionAdapter, adapt_request_version},
    },
    proto::ext::Protocol,
};
use rama_ws::{
    AsyncWebSocket, Message,
    handshake::{
        matcher::HttpWebSocketRelayServiceRequestMatcher,
        mitm::{
            WebSocketRelayDirection, WebSocketRelayInput, WebSocketRelayIoService,
            WebSocketRelayMessage, WebSocketRelayOutput, WebSocketRelayService,
        },
    },
    protocol::Role,
};
use std::{convert::Infallible, sync::Arc};

async fn tag_relay_message(input: WebSocketRelayInput) -> Result<WebSocketRelayOutput, Infallible> {
    let WebSocketRelayInput {
        direction,
        message,
        extensions,
    } = input;
    let message = match (direction, message) {
        (WebSocketRelayDirection::Ingress, WebSocketRelayMessage::Text(text)) => {
            WebSocketRelayMessage::Text(text.as_str().to_uppercase().into())
        }
        (WebSocketRelayDirection::Egress, WebSocketRelayMessage::Text(text)) => {
            WebSocketRelayMessage::Text(format!("relayed-{text}").into())
        }
        (_, message) => message,
    };
    Ok(WebSocketRelayOutput {
        messages: vec![message],
        extensions,
    })
}

/// A WebSocket handshake request in the form `version` uses.
fn websocket_request(version: Version) -> Request {
    let mut request = Request::new(Body::empty());
    *request.version_mut() = version;
    *request.uri_mut() = "ws://example.test/socket".parse().expect("request URI");
    if version >= Version::HTTP_2 {
        *request.method_mut() = Method::CONNECT;
        request.extensions().insert(Protocol::WEBSOCKET);
    } else {
        request
            .headers_mut()
            .typed_insert(headers::Upgrade::websocket());
        request
            .headers_mut()
            .typed_insert(headers::Connection::upgrade());
        request
            .headers_mut()
            .typed_insert(SecWebSocketKey::random());
    }
    request
        .headers_mut()
        .typed_insert(headers::SecWebSocketVersion::V13);
    request
}

async fn assert_relay(ingress: Version, egress: Version) {
    let (client_io, ingress_io) = tokio::io::duplex(16 * 1024);
    let (egress_io, server_io) = tokio::io::duplex(16 * 1024);
    let (ingress_pending, ingress_upgrade) = upgrade::pending();
    ingress_pending.fulfill(Upgraded::new(ServiceInput::new(ingress_io), Bytes::new()));
    let (egress_pending, egress_upgrade) = upgrade::pending();
    egress_pending.fulfill(Upgraded::new(ServiceInput::new(egress_io), Bytes::new()));
    let egress_upgrade = Arc::new(Mutex::new(Some(egress_upgrade)));

    // The egress peer: adapts the relayed request to its version and accepts it there.
    let upstream = service_fn(move |mut request: Request| {
        let egress_upgrade = egress_upgrade.clone();
        async move {
            adapt_request_version(&mut request, egress)?;
            assert_eq!(request.version(), egress);
            let mut response = Response::new(Body::empty());
            *response.version_mut() = egress;
            if egress >= Version::HTTP_2 {
                assert_eq!(request.method(), Method::CONNECT);
                assert_eq!(
                    request.extensions().get_ref::<Protocol>(),
                    Some(&Protocol::WEBSOCKET)
                );
                *response.status_mut() = StatusCode::OK;
            } else {
                let key = request
                    .headers()
                    .typed_get::<SecWebSocketKey>()
                    .expect("an HTTP/1.1 upgrade carries a key");
                *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
                let headers = response.headers_mut();
                headers.typed_insert(headers::Upgrade::websocket());
                headers.typed_insert(headers::Connection::upgrade());
                headers.typed_insert(SecWebSocketAccept::try_from(key).expect("accept"));
            }
            response
                .extensions()
                .insert(egress_upgrade.lock().take().expect("one upstream upgrade"));
            Ok::<_, BoxError>(response)
        }
    });
    let relay =
        WebSocketRelayIoService::new(WebSocketRelayService::new(service_fn(tag_relay_message)));
    let service = HttpUpgradeMitmRelayLayer::new(
        Executor::default(),
        HttpWebSocketRelayServiceRequestMatcher::new(relay),
    )
    .into_layer(ResponseVersionAdapter::new(upstream));

    let request = websocket_request(ingress);
    request.extensions().insert(ingress_upgrade);
    let response = service.serve(request).await.expect("relay handshake");
    // The ingress sees its own version's acceptance.
    if ingress >= Version::HTTP_2 {
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "{ingress:?} -> {egress:?}"
        );
    } else {
        assert_eq!(
            response.status(),
            StatusCode::SWITCHING_PROTOCOLS,
            "{ingress:?} -> {egress:?}"
        );
    }
    response
        .into_body()
        .collect()
        .await
        .expect("consume upgrade response body");

    let mut client =
        AsyncWebSocket::from_raw_socket(ServiceInput::new(client_io), Role::Client, None).await;
    let mut server =
        AsyncWebSocket::from_raw_socket(ServiceInput::new(server_io), Role::Server, None).await;
    client
        .send_message(Message::text("hello"))
        .await
        .expect("client send");
    assert_eq!(
        server.recv_message().await.expect("server receive"),
        Message::text("HELLO")
    );
    server
        .send_message(Message::text("world"))
        .await
        .expect("server send");
    assert_eq!(
        client.recv_message().await.expect("client receive"),
        Message::text("relayed-world")
    );
}

#[tokio::test]
async fn relays_bridge_http3_with_every_http_version() {
    for (ingress, egress) in [
        (Version::HTTP_3, Version::HTTP_3),
        (Version::HTTP_3, Version::HTTP_2),
        (Version::HTTP_3, Version::HTTP_11),
        (Version::HTTP_2, Version::HTTP_3),
        (Version::HTTP_11, Version::HTTP_3),
    ] {
        assert_relay(ingress, egress).await;
    }
}
