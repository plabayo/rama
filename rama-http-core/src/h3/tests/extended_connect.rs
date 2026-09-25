//! Extended CONNECT negotiation (RFC 9220, RFC 8441 §3–§4) over real QUIC connections.

use super::{LIMIT, Pair};
use crate::h3::{
    client,
    connection::Config,
    qpack::{Encoder, EncoderConfig},
    server,
};
use rama_core::{
    bytes::BytesMut,
    extensions::ExtensionsRef as _,
    futures::FutureExt as _,
    rt::{Executor, spawn},
};
use rama_http::io::upgrade::handle_upgrade;
use rama_http_types::{
    Body, Method, Request, Response, StatusCode,
    body::util::BodyExt as _,
    proto::{
        ext::Protocol,
        h3::{Code, FrameHeader, FrameType, PseudoHeader, PseudoHeaderOrder},
    },
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

fn extended_connect_server() -> Config {
    Config {
        extended_connect: true,
        ..Config::default()
    }
}

fn extended_connect(uri: &str, protocol: Protocol) -> Request<Body> {
    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(uri)
        .header("x-app", "kept")
        .body(Body::empty())
        .unwrap();
    request.extensions().insert(protocol);
    request
}

#[tokio::test]
async fn custom_token_round_trip_exposes_tunnel_after_success() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::new(None, None).await;
        let (mut client, client_driver) =
            client::handshake::<Body>(pair.client.clone(), Config::default(), Executor::new())
                .unwrap();
        let (mut server, server_driver) =
            server::handshake(pair.server.clone(), extended_connect_server()).unwrap();
        spawn(client_driver.run());
        spawn(server_driver.run());
        let serve = spawn(async move {
            let (request, response) = server.accept().await.unwrap().resolve().await.unwrap();
            assert_eq!(request.method(), Method::CONNECT);
            assert_eq!(
                request.extensions().get_ref::<Protocol>(),
                Some(&Protocol::from_static("x-custom.v1"))
            );
            assert_eq!(request.uri().to_string(), "https://localhost/chat?room=1");
            assert_eq!(request.headers()["x-app"], "kept");
            let order: Vec<_> = request
                .extensions()
                .get_ref::<PseudoHeaderOrder>()
                .unwrap()
                .iter()
                .collect();
            assert!(order.contains(&PseudoHeader::Protocol), "{order:?}");
            let upgrade = handle_upgrade(&request);
            response
                .send_response(Response::new(Body::empty()))
                .await
                .unwrap();
            let mut tunnel = upgrade.await.unwrap();
            let mut received = [0; 4];
            tunnel.read_exact(&mut received).await.unwrap();
            assert_eq!(&received, b"ping");
            tunnel.write_all(b"pong").await.unwrap();
            tunnel.shutdown().await.unwrap();
            let mut rest = Vec::new();
            tunnel.read_to_end(&mut rest).await.unwrap();
            assert!(rest.is_empty());
        });
        let response = client
            .send_request(extended_connect(
                "https://localhost/chat?room=1",
                Protocol::from_static("x-custom.v1"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let mut tunnel = handle_upgrade(&response).await.unwrap();
        tunnel.write_all(b"ping").await.unwrap();
        tunnel.flush().await.unwrap();
        let mut received = Vec::new();
        tunnel.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"pong");
        tunnel.shutdown().await.unwrap();
        serve.await.unwrap();
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn refused_without_server_setting_and_opens_no_stream() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::in_memory(None, None).await;
        let (mut client, client_driver) =
            client::handshake::<Body>(pair.client.clone(), Config::default(), Executor::new())
                .unwrap();
        let (mut server, server_driver) =
            server::handshake(pair.server.clone(), Config::default()).unwrap();
        spawn(client_driver.run());
        spawn(server_driver.run());
        // Any request that does reach the server is answered, so a missing local gate fails
        // on the assertions below instead of waiting for the watchdog.
        let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        spawn({
            let accepted = accepted.clone();
            async move {
                while let Ok(stream) = server.accept().await {
                    accepted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if let Ok((_request, response)) = stream.resolve().await {
                        let mut refused = Response::new(Body::empty());
                        *refused.status_mut() = StatusCode::BAD_REQUEST;
                        _ = response.send_response(refused).await;
                    }
                }
            }
        });
        for _ in 0..3 {
            let error = client
                .send_request(extended_connect(
                    "https://localhost/chat",
                    Protocol::WEBSOCKET,
                ))
                .await
                .map(|response| response.status())
                .unwrap_err();
            assert_eq!(error.code(), Code::H3_MESSAGE_ERROR);
        }
        // Refused requests must not consume even one stream ID.
        let (send, recv) = pair.client.open_bi().await.unwrap();
        assert_eq!(u64::from(send.id()), 0);
        assert_eq!(accepted.load(std::sync::atomic::Ordering::SeqCst), 0);
        drop((send, recv, client));
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn protocol_on_other_methods_fails_locally_without_a_stream() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::in_memory(None, None).await;
        let (mut client, driver) =
            client::handshake::<Body>(pair.client.clone(), Config::default(), Executor::new())
                .unwrap();
        let request = Request::builder()
            .uri("https://localhost/chat")
            .body(Body::empty())
            .unwrap();
        request.extensions().insert(Protocol::WEBSOCKET);
        let error = client
            .send_request(request)
            .now_or_never()
            .expect("local validation needs no peer traffic")
            .unwrap_err();
        assert_eq!(error.code(), Code::H3_MESSAGE_ERROR);
        let (send, recv) = pair.client.open_bi().await.unwrap();
        assert_eq!(u64::from(send.id()), 0);
        drop((send, recv, client, driver));
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn client_waits_for_late_settings_before_opening_a_stream() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::new(None, None).await;
        let (mut client, client_driver) =
            client::handshake::<Body>(pair.client.clone(), Config::default(), Executor::new())
                .unwrap();
        let (mut server, server_driver) =
            server::handshake(pair.server.clone(), extended_connect_server()).unwrap();
        spawn(client_driver.run());
        let mut request = spawn(async move {
            let response = client
                .send_request(extended_connect(
                    "https://localhost/late",
                    Protocol::WEBSOCKET,
                ))
                .await
                .unwrap();
            (client, response)
        });
        // Without the server's control stream no request stream may be opened.
        tokio::task::yield_now().await;
        assert!((&mut request).now_or_never().is_none());
        assert!(pair.server.accept_bi().now_or_never().is_none());
        spawn(server_driver.run());
        let (accepted, response) = server.accept().await.unwrap().resolve().await.unwrap();
        assert_eq!(accepted.uri().request_target(), "/late");
        response
            .send_response(Response::new(Body::empty()))
            .await
            .unwrap();
        let (_client, response) = request.await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn unsuccessful_response_keeps_its_body_and_offers_no_tunnel() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::new(None, None).await;
        let (mut client, client_driver) =
            client::handshake::<Body>(pair.client.clone(), Config::default(), Executor::new())
                .unwrap();
        let (mut server, server_driver) =
            server::handshake(pair.server.clone(), extended_connect_server()).unwrap();
        spawn(client_driver.run());
        spawn(server_driver.run());
        let serve = spawn(async move {
            for _ in 0..2 {
                let (_request, response) = server.accept().await.unwrap().resolve().await.unwrap();
                response
                    .send_response(
                        Response::builder()
                            .status(StatusCode::NOT_IMPLEMENTED)
                            .body(Body::from("unsupported protocol"))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
            }
            server
        });
        // A second request proves the refused stream released its admission.
        for _ in 0..2 {
            let response = client
                .send_request(extended_connect(
                    "https://localhost/",
                    Protocol::from_static("unknown"),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
            handle_upgrade(&response).await.unwrap_err();
            assert_eq!(
                response.into_body().collect().await.unwrap().to_bytes(),
                "unsupported protocol"
            );
        }
        drop(serve.await.unwrap());
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn server_treats_unadvertised_protocol_as_malformed() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::in_memory(None, None).await;
        let (mut server, server_driver) =
            server::handshake(pair.server.clone(), Config::default()).unwrap();
        spawn(server_driver.run());
        let (mut send, _recv) = pair.client.open_bi().await.unwrap();
        let id = u64::from(send.id());
        let fields = Encoder::before_peer_settings(EncoderConfig::default())
            .encode(
                id,
                [
                    (":method", "CONNECT"),
                    (":protocol", "websocket"),
                    (":scheme", "https"),
                    (":authority", "localhost"),
                    (":path", "/chat"),
                ],
            )
            .unwrap();
        let mut frame = BytesMut::new();
        FrameHeader::new(FrameType::HEADERS, fields.len() as u64)
            .encode(&mut frame)
            .unwrap();
        frame.extend_from_slice(&fields);
        send.write_chunk(frame.freeze()).await.unwrap();
        let error = server
            .accept()
            .await
            .unwrap()
            .resolve()
            .await
            .map(|_| ())
            .unwrap_err();
        assert_eq!(error.code(), Code::H3_MESSAGE_ERROR);
        assert_eq!(
            send.stopped().await.unwrap().map(u64::from),
            Some(Code::H3_MESSAGE_ERROR.value())
        );
        pair.close().await;
    })
    .await
    .unwrap();
}

/// RFC 9297 §3.2: Capsule messages must not carry Content-Length; a successful CONNECT keeps
/// the received field visible (ignored for framing, RFC 9110 §9.3.6) so validation rejects it.
#[tokio::test]
async fn capsule_validation_sees_content_length_on_successful_connect() {
    use rama_http::{
        datagram::handshake::{
            CapsuleHandshakeError, prepare_capsule_request, validate_capsule_response,
        },
        io::upgrade::OnMalformedMessage,
    };
    use rama_http_types::{Version, header};
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::in_memory(None, None).await;
        let (mut client, client_driver) =
            client::handshake::<Body>(pair.client.clone(), Config::default(), Executor::new())
                .unwrap();
        // The server engine only supplies SETTINGS; its request streams are answered raw.
        let (_server, server_driver) =
            server::handshake(pair.server.clone(), extended_connect_server()).unwrap();
        spawn(client_driver.run());
        spawn(server_driver.run());
        let token = Protocol::from_static("x-capsule");
        let lengths: [&[&str]; 5] = [&["0"], &["5"], &["invalid"], &["0", "0"], &[]];
        for values in lengths {
            let mut request = Request::builder()
                .version(Version::HTTP_3)
                .uri("https://localhost/capsules")
                .body(Body::empty())
                .unwrap();
            prepare_capsule_request(&mut request, token.clone()).unwrap();
            let serve = async {
                let (mut send, mut recv) = pair.server.accept_bi().await.unwrap();
                let id = u64::from(send.id());
                // Consume the request HEADERS frame before answering.
                recv.read_chunk(usize::MAX, true).await.unwrap().unwrap();
                let mut fields = vec![(":status", "200"), ("capsule-protocol", "?1")];
                fields.extend(values.iter().map(|value| ("content-length", *value)));
                let encoded = Encoder::before_peer_settings(EncoderConfig::default())
                    .encode(id, fields)
                    .unwrap();
                let mut frame = BytesMut::new();
                FrameHeader::new(FrameType::HEADERS, encoded.len() as u64)
                    .encode(&mut frame)
                    .unwrap();
                frame.extend_from_slice(&encoded);
                send.write_chunk(frame.freeze()).await.unwrap();
                (send, recv)
            };
            let (response, (send, _recv)) = tokio::join!(client.send_request(request), serve);
            let response = response.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let result = validate_capsule_response(Version::HTTP_3, &token, &response);
            let tunnel = handle_upgrade(&response).await.unwrap();
            if values.is_empty() {
                result.unwrap();
                continue;
            }
            assert_eq!(
                result,
                Err(CapsuleHandshakeError::ForbiddenField(
                    header::CONTENT_LENGTH
                )),
                "{values:?}"
            );
            // The malformed message resets only its own stream.
            tunnel
                .extensions()
                .get_ref::<OnMalformedMessage>()
                .unwrap()
                .call();
            assert_eq!(
                send.stopped().await.unwrap().map(u64::from),
                Some(Code::H3_MESSAGE_ERROR.value()),
                "{values:?}"
            );
        }
        pair.close().await;
    })
    .await
    .unwrap();
}
