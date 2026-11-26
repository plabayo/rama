//! The WebSocket client handshake forms over real HTTP/1.1 and HTTP/2 engines, with the
//! version a connection negotiated by ALPN (or none), as the server observes them.
//! HTTP/3 and version selection by advertisement are covered by the `rama` integration tests.
#![expect(
    clippy::expect_used,
    clippy::panic,
    reason = "integration tests use expectation messages to identify failed stages"
)]

use parking_lot::Mutex;
use rama_core::{
    Layer as _, Service, ServiceInput,
    error::BoxError,
    extensions::{Extensions, ExtensionsRef as _},
    graceful::WeakScope,
    layer::ConsumeErrLayer,
    rt::spawn,
    service::service_fn,
};
use rama_http::{
    Body, HeaderValue, Method, Request, Response, StatusCode, Version,
    conn::{FallbackHttpVersion, TargetHttpVersion},
    header,
    headers::{HeaderMapExt as _, SecWebSocketKey, SecWebSocketProtocol},
    layer::version_adapter::RequestVersionAdapter,
    proto::ext::Protocol,
    service::client::blocking::Client as BlockingClient,
};
use rama_http_backend::{client::http_connect, server::HttpServer};
use rama_net::client::{ConnectionError, EstablishedClientConnection};
use rama_ws::{
    Message,
    handshake::{
        client::{
            BlockingHttpClientWebSocketExt as _, ClientWebSocket, HandshakeError,
            HttpClientWebSocketExt as _, ResponseValidateError, WebSocketRequestBuilder,
        },
        server::{ECHO_SERVICE_SUB_PROTOCOL_DEFAULT, WebSocketAcceptor},
    },
};
use std::{sync::Arc, time::Duration};
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(20);
const URI: &str = "wss://localhost/socket";

/// The handshake request as the server received it.
#[derive(Debug, Clone)]
struct Seen {
    method: Method,
    version: Version,
    protocol: Option<Protocol>,
    key: Option<HeaderValue>,
    upgrades: usize,
}

/// How the in-memory connection behaves.
#[derive(Clone, Copy, Debug)]
struct Peer {
    /// The version TLS ALPN selected, `None` when none was negotiated.
    negotiated: Option<Version>,
    /// The version the server speaks.
    server: Version,
    /// Whether an HTTP/2 server enables Extended CONNECT.
    extended_connect: bool,
}

const H1: Peer = Peer {
    negotiated: Some(Version::HTTP_11),
    server: Version::HTTP_11,
    extended_connect: false,
};
const H2: Peer = Peer {
    negotiated: Some(Version::HTTP_2),
    server: Version::HTTP_2,
    extended_connect: true,
};
const H2_WITHOUT_EXTENDED_CONNECT: Peer = Peer {
    extended_connect: false,
    ..H2
};
const NO_ALPN: Peer = Peer {
    negotiated: None,
    ..H1
};

type Seens = Arc<Mutex<Vec<Seen>>>;

/// A client stack as an HTTP client builds it: connect, adapt the request to the
/// connection's version, send.
fn client(
    peer: Peer,
    seen: Seens,
) -> impl Service<Request, Output = Response, Error = BoxError> + Clone {
    let connector = service_fn(move |request: Request| {
        let seen = seen.clone();
        async move {
            let scope = WeakScope::detached();
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);
            let echo = ConsumeErrLayer::trace_as_debug().into_layer(
                WebSocketAcceptor::new()
                    .with_per_message_deflate()
                    .into_echo_service(),
            );
            let service = service_fn(move |request: Request| {
                seen.lock().push(Seen {
                    method: request.method().clone(),
                    version: request.version(),
                    protocol: request.extensions().get_ref::<Protocol>().cloned(),
                    key: request.headers().get(header::SEC_WEBSOCKET_KEY).cloned(),
                    upgrades: request.headers().get_all(header::UPGRADE).iter().count(),
                });
                let echo = echo.clone();
                async move { echo.serve(request).await }
            });
            spawn({
                let scope = scope.clone();
                async move {
                    if peer.server == Version::HTTP_2 {
                        let mut server = HttpServer::new_h2(scope);
                        if peer.extended_connect {
                            server.h2_mut().set_enable_connect_protocol();
                        }
                        _ = server.serve(ServiceInput::new(server_io), service).await;
                    } else {
                        _ = HttpServer::new_http1(scope)
                            .serve(ServiceInput::new(server_io), service)
                            .await;
                    }
                }
            });
            let io = ServiceInput::new(client_io);
            if let Some(version) = peer.negotiated {
                io.extensions().insert(TargetHttpVersion(version));
            }
            http_connect::<_, _, Body>(io, request, scope)
                .await
                .map_err(|err| ConnectionError::from(BoxError::from(err)))
        }
    });
    let connector = Arc::new(RequestVersionAdapter::new(connector));
    service_fn(move |request: Request| {
        let connector = connector.clone();
        async move {
            let EstablishedClientConnection { input, conn } = connector.serve(request).await?;
            conn.serve(input).await
        }
    })
}

#[derive(Clone, Copy, Debug)]
enum Form {
    H1,
    H2,
    Auto,
}

/// Handshake in `form` offering the echo subprotocol and permessage-deflate.
async fn handshake(
    peer: Peer,
    form: Form,
    extensions: Extensions,
    key: Option<SecWebSocketKey>,
) -> (Result<ClientWebSocket, HandshakeError>, Vec<Seen>) {
    let seen = Seens::default();
    let client = client(peer, seen.clone());
    let builder = match form {
        Form::H1 => client.websocket(URI),
        Form::H2 => client.websocket_h2(URI),
        Form::Auto => client.websocket_auto(URI),
    };
    let result = timeout(
        LIMIT,
        builder
            .with_protocols(SecWebSocketProtocol::new(ECHO_SERVICE_SUB_PROTOCOL_DEFAULT))
            .with_per_message_deflate()
            .maybe_with_key(key)
            .handshake(extensions),
    )
    .await
    .expect("handshake time");
    let seen = seen.lock().clone();
    (result, seen)
}

/// The negotiated subprotocol and extension hold, messages round trip and close is clean.
async fn assert_established(socket: Result<ClientWebSocket, HandshakeError>, context: &str) {
    let mut socket = socket.unwrap_or_else(|err| panic!("{context}: {err:?}"));
    assert_eq!(socket.accepted_protocol(), Some("echo"), "{context}");
    assert!(
        socket
            .response()
            .headers
            .contains_key(header::SEC_WEBSOCKET_EXTENSIONS),
        "{context}"
    );
    for message in [Message::text("text"), Message::binary(vec![7; 4096])] {
        socket.send_message(message.clone()).await.expect("send");
        let echoed = timeout(LIMIT, socket.recv_message())
            .await
            .expect("echo time")
            .expect("echo");
        assert_eq!(echoed, message, "{context}");
    }
    socket.close(None).await.expect("close");
    let closed = timeout(LIMIT, socket.recv_message())
        .await
        .expect("close time")
        .expect("close frame");
    assert_eq!(closed, Message::Close(None), "{context}");
}

fn assert_upgrade(seen: &[Seen], context: &str) {
    let [seen] = seen else {
        panic!("{context}: one request: {seen:?}");
    };
    assert_eq!(seen.method, Method::GET, "{context}");
    assert_eq!(seen.version, Version::HTTP_11, "{context}");
    assert_eq!(seen.upgrades, 1, "{context}");
    assert!(seen.key.is_some(), "{context}");
}

fn assert_extended_connect(seen: &[Seen], context: &str) {
    let [seen] = seen else {
        panic!("{context}: one request: {seen:?}");
    };
    assert_eq!(seen.method, Method::CONNECT, "{context}");
    assert_eq!(seen.version, Version::HTTP_2, "{context}");
    assert_eq!(seen.protocol, Some(Protocol::WEBSOCKET), "{context}");
    assert_eq!(seen.upgrades, 0, "{context}");
    assert!(seen.key.is_none(), "{context}");
}

fn fallback(version: Version) -> Extensions {
    let extensions = Extensions::new();
    extensions.insert(FallbackHttpVersion(version));
    extensions
}

#[tokio::test]
async fn h1_and_h2_forms_complete_on_their_version() {
    for (peer, form, upgrade) in [
        (H1, Form::H1, true),
        (NO_ALPN, Form::H1, true),
        (H2, Form::H2, false),
    ] {
        let context = format!("{peer:?} {form:?}");
        let (socket, seen) = handshake(peer, form, Extensions::new(), None).await;
        if upgrade {
            assert_upgrade(&seen, &context);
        } else {
            assert_extended_connect(&seen, &context);
        }
        assert_established(socket, &context).await;
    }
}

#[tokio::test]
async fn auto_follows_the_negotiated_version() {
    let h2_by_fallback = Peer {
        negotiated: None,
        ..H2
    };
    for (peer, extensions, upgrade) in [
        (H1, Extensions::new(), true),
        (H2, Extensions::new(), false),
        (NO_ALPN, Extensions::new(), true),
        // prior knowledge, as for any request carrying this fallback
        (h2_by_fallback, fallback(Version::HTTP_2), false),
    ] {
        let context = format!("{peer:?}");
        let (socket, seen) = handshake(peer, Form::Auto, extensions, None).await;
        if upgrade {
            assert_upgrade(&seen, &context);
        } else {
            assert_extended_connect(&seen, &context);
        }
        assert_established(socket, &context).await;
    }
}

#[tokio::test]
async fn extended_connect_without_peer_support_fails_before_sending() {
    for form in [Form::H2, Form::Auto] {
        let (result, seen) =
            handshake(H2_WITHOUT_EXTENDED_CONNECT, form, Extensions::new(), None).await;
        let Err(HandshakeError::HttpRequestError(err)) = result else {
            panic!("{form:?}: request error: {result:?}");
        };
        let mut chain = Vec::new();
        let mut source: Option<&dyn std::error::Error> = Some(err.as_ref());
        while let Some(err) = source {
            chain.push(err.to_string());
            source = err.source();
        }
        assert!(
            chain
                .iter()
                .any(|err| err.contains("peer did not enable extended CONNECT")),
            "{form:?}: {chain:?}"
        );
        assert!(seen.is_empty(), "{form:?}: {seen:?}");
    }
}

#[tokio::test]
async fn a_caller_key_is_kept_on_upgrade_and_dropped_on_extended_connect() {
    let key = SecWebSocketKey::random();
    let mut scratch = rama_http::HeaderMap::new();
    scratch.typed_insert(&key);
    let sent = scratch[header::SEC_WEBSOCKET_KEY].clone();
    for (peer, kept) in [(H1, true), (H2, false)] {
        let (socket, seen) =
            handshake(peer, Form::Auto, Extensions::new(), Some(key.clone())).await;
        let [seen] = &seen[..] else {
            panic!("{peer:?}: {seen:?}");
        };
        assert_eq!(seen.key.as_ref(), kept.then_some(&sent), "{peer:?}");
        assert_established(socket, &format!("{peer:?}")).await;
    }
}

fn request(version: Version, method: Method) -> Request {
    Request::builder()
        .version(version)
        .method(method)
        .uri(URI)
        .body(Body::empty())
        .expect("request")
}

#[tokio::test]
async fn a_request_form_follows_its_own_version_and_target() {
    let with_upgrade = || {
        let mut request = request(Version::HTTP_11, Method::GET);
        request
            .headers_mut()
            .insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        request
            .headers_mut()
            .insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
        request
    };
    let pinned = || {
        let request = request(Version::HTTP_11, Method::GET);
        request
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_11));
        request
    };
    // (peer, request, Some(upgrade) when it completes, None when it fails unsent)
    let cases: Vec<(&str, Peer, Request, Option<bool>)> = vec![
        (
            "h1 request, no target, h1",
            H1,
            request(Version::HTTP_11, Method::GET),
            Some(true),
        ),
        (
            "h1 request, no target, h2",
            H2,
            request(Version::HTTP_11, Method::GET),
            Some(false),
        ),
        ("h1 request, h1 target, h1", H1, pinned(), Some(true)),
        ("h1 request, h1 target, h2", H2, pinned(), None),
        (
            "h2 request, h2",
            H2,
            request(Version::HTTP_2, Method::CONNECT),
            Some(false),
        ),
        (
            "h1 request with upgrade headers, h1",
            H1,
            with_upgrade(),
            Some(true),
        ),
        (
            "h1 request with upgrade headers, h2",
            H2,
            with_upgrade(),
            Some(false),
        ),
    ];
    for (context, peer, request, outcome) in cases {
        let seen = Seens::default();
        let client = client(peer, seen.clone());
        let result = timeout(
            LIMIT,
            client
                .websocket_with_request(request)
                .with_protocols(SecWebSocketProtocol::new(ECHO_SERVICE_SUB_PROTOCOL_DEFAULT))
                .with_per_message_deflate()
                .handshake(Extensions::new()),
        )
        .await
        .expect("handshake time");
        let seen = seen.lock().clone();
        match outcome {
            Some(true) => assert_upgrade(&seen, context),
            Some(false) => assert_extended_connect(&seen, context),
            None => {
                assert!(result.is_err(), "{context}");
                assert!(seen.is_empty(), "{context}: {seen:?}");
                continue;
            }
        }
        assert_established(result, context).await;
    }
}

#[tokio::test]
async fn a_request_with_a_method_wrong_for_its_form_is_refused() {
    // An upgrade must be a GET: the server answers 400.
    let seen = Seens::default();
    let result = client(H1, seen.clone())
        .websocket_with_request(request(Version::HTTP_11, Method::POST))
        .handshake(Extensions::new())
        .await;
    assert!(
        matches!(
            result,
            Err(HandshakeError::ValidationError(
                ResponseValidateError::UnexpectedStatusCode(StatusCode::BAD_REQUEST)
            ))
        ),
        "{result:?}"
    );
    assert_eq!(seen.lock().len(), 1);

    // `:protocol` only extends CONNECT (RFC 8441 §4): refused before sending.
    let seen = Seens::default();
    let result = client(H2, seen.clone())
        .websocket_with_request(request(Version::HTTP_2, Method::GET))
        .handshake(Extensions::new())
        .await;
    assert!(
        matches!(result, Err(HandshakeError::HttpRequestError(_))),
        "{result:?}"
    );
    assert!(seen.lock().is_empty());
}

/// A layer below the builder, as emulation does, may rewrite the extension offer: the
/// answer is validated against the offer actually sent, and compression then works.
#[tokio::test]
async fn the_offer_sent_is_the_one_validated() {
    for peer in [H1, H2] {
        let seen = Seens::default();
        let inner = client(peer, seen.clone());
        let rewriting = service_fn(move |mut request: Request| {
            let inner = inner.clone();
            async move {
                request.headers_mut().insert(
                    header::SEC_WEBSOCKET_EXTENSIONS,
                    HeaderValue::from_static("permessage-deflate; client_max_window_bits"),
                );
                inner.serve(request).await
            }
        });
        let mut socket = timeout(
            LIMIT,
            rewriting
                .websocket_auto(URI)
                .with_per_message_deflate()
                .handshake(Extensions::new()),
        )
        .await
        .expect("handshake time")
        .unwrap_or_else(|err| panic!("{peer:?}: {err:?}"));
        assert_eq!(
            socket.response().headers[header::SEC_WEBSOCKET_EXTENSIONS],
            "permessage-deflate; client_max_window_bits=15",
            "{peer:?}"
        );
        let message = Message::text("compressible ".repeat(512));
        socket.send_message(message.clone()).await.expect("send");
        let echoed = timeout(LIMIT, socket.recv_message())
            .await
            .expect("echo time")
            .expect("echo");
        assert_eq!(echoed, message, "{peer:?}");
    }
}

#[test]
fn blocking_h1_and_auto_forms_complete() {
    for (peer, auto, upgrade) in [(H1, false, true), (H1, true, true), (H2, true, false)] {
        let context = format!("{peer:?} auto={auto}");
        let seen = Seens::default();
        let client = BlockingClient::try_new(client(peer, seen.clone())).expect("client");
        let builder = if auto {
            client.websocket_auto(URI)
        } else {
            client.websocket(URI)
        };
        let mut socket = builder.try_handshake().expect("handshake");
        let seen = seen.lock().clone();
        if upgrade {
            assert_upgrade(&seen, &context);
        } else {
            assert_extended_connect(&seen, &context);
        }
        socket
            .send_message(Message::text("blocking"))
            .expect("send");
        assert_eq!(
            socket.recv_message().expect("echo"),
            Message::text("blocking"),
            "{context}"
        );
    }
}

#[test]
fn standalone_forms_carry_their_target() {
    for (builder, target) in [
        (WebSocketRequestBuilder::new_h1(URI), Some(Version::HTTP_11)),
        (WebSocketRequestBuilder::new_h2(URI), Some(Version::HTTP_2)),
        (WebSocketRequestBuilder::new_h3(URI), Some(Version::HTTP_3)),
        (WebSocketRequestBuilder::new_auto(URI), None),
    ] {
        let handshake = builder.build_handshake().expect("handshake");
        assert_eq!(
            handshake
                .request
                .extensions()
                .get_ref::<TargetHttpVersion>()
                .map(|target| target.0),
            target
        );
    }
}
