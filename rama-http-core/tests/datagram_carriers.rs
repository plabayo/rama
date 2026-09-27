//! The Capsule Protocol session over HTTP/1.1 Upgrade and HTTP/2 Extended CONNECT, driven by
//! the same version-neutral code (RFC 9297 §3).

#![expect(clippy::unwrap_used, clippy::panic, reason = "test fixtures")]

use parking_lot::Mutex;
use rama_core::{
    ServiceInput, bytes::Bytes, extensions::ExtensionsRef as _, rt::Executor, service::service_fn,
};
use rama_http::{
    Body, Request, Response, StatusCode, Version,
    body::util::BodyExt as _,
    datagram::{
        DatagramTransport, HttpDatagramSession, SessionConfig, SessionError, SessionEvent,
        ViolationPolicy,
        capsule::CapsuleConfig,
        handshake::{
            capsule_response, prepare_capsule_request, validate_capsule_request,
            validate_capsule_response,
        },
    },
    io::upgrade::{OnMalformedMessage, Upgraded, handle_upgrade},
    proto::{
        capsule::{CapsuleHeader, CapsuleType},
        ext::Protocol,
    },
};
use rama_http_core::{body::Incoming, client::conn, server, service::RamaHttpService};
use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    sync::oneshot,
};

const LIMIT: Duration = Duration::from_secs(10);
const TOKEN: Protocol = Protocol::from_static("x-capsule-test");
const CONTROL: CapsuleType = match CapsuleType::new(0x2a) {
    Ok(ty) => ty,
    Err(_) => panic!("valid capsule type"),
};

fn config() -> SessionConfig {
    SessionConfig {
        capsules: CapsuleConfig {
            capsule_types: Box::new([CONTROL]),
            ..CapsuleConfig::default()
        },
        ..SessionConfig::default()
    }
}

/// Echo every datagram and control capsule, then finish when the client does.
async fn echo(upgraded: Upgraded) {
    let mut session = HttpDatagramSession::with_config(upgraded, config());
    loop {
        match session.recv().await {
            Ok(Some(SessionEvent::Datagram { payload, .. })) => {
                session.send_datagram(payload).await.unwrap();
            }
            Ok(Some(SessionEvent::Capsule { ty, value })) => {
                session.send_capsule(ty, value).await.unwrap();
            }
            Ok(Some(event)) => panic!("unexpected {event:?}"),
            Ok(None) => {
                session.close().await.unwrap();
                return;
            }
            // Dropping the session now aborts the stream as malformed.
            Err(SessionError::Malformed(_)) => return,
            Err(error) => panic!("unexpected {error:?}"),
        }
    }
}

fn capsule_service()
-> RamaHttpService<impl rama_core::Service<Request, Output = Response, Error = Infallible> + Clone>
{
    RamaHttpService::new(service_fn(|request: Request| async move {
        let protocol = validate_capsule_request(&request, ViolationPolicy::Ignore).unwrap();
        assert_eq!(protocol, TOKEN);
        let upgrade = handle_upgrade(&request);
        tokio::spawn(async move { echo(upgrade.await.unwrap()).await });
        Ok::<_, Infallible>(capsule_response::<Body>(request.version(), &protocol).unwrap())
    }))
}

/// Ends its own direction first, then finds the peer's data malformed and keeps the tunnel.
fn closing_service()
-> RamaHttpService<impl rama_core::Service<Request, Output = Response, Error = Infallible> + Clone>
{
    RamaHttpService::new(service_fn(|request: Request| async move {
        let protocol = validate_capsule_request(&request, ViolationPolicy::Ignore).unwrap();
        let upgrade = handle_upgrade(&request);
        tokio::spawn(async move {
            let mut config = config();
            config.capsules.max_capsule_size = 8;
            let mut session = HttpDatagramSession::with_config(upgrade.await.unwrap(), config);
            session.close().await.unwrap();
            let error = session.recv().await.unwrap_err();
            assert!(matches!(error, SessionError::Malformed(_)), "{error:?}");
            // Neither a write nor a drop may be needed for the reset.
            std::future::pending::<()>().await;
            drop(session);
        });
        Ok::<_, Infallible>(capsule_response::<Body>(request.version(), &protocol).unwrap())
    }))
}

fn capsule_request(version: Version) -> Request {
    let mut request = Request::builder()
        .version(version)
        .uri("https://proxy.example/capsules")
        .header("host", "proxy.example")
        .body(Body::empty())
        .unwrap();
    prepare_capsule_request(&mut request, TOKEN).unwrap();
    request
}

async fn client_session(version: Version) -> HttpDatagramSession {
    HttpDatagramSession::with_config(client_upgraded(version).await, config())
}

async fn client_upgraded(version: Version) -> Upgraded {
    client_upgraded_with(version, capsule_service()).await
}

async fn client_upgraded_with<S>(version: Version, service: RamaHttpService<S>) -> Upgraded
where
    S: rama_core::Service<Request, Output = Response, Error = Infallible> + Clone,
{
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (client_io, server_io) = (ServiceInput::new(client_io), ServiceInput::new(server_io));
    let response = if version == Version::HTTP_2 {
        tokio::spawn(
            server::conn::http2::Builder::new(Executor::new())
                .with_enable_connect_protocol()
                .serve_connection(server_io, service),
        );
        let (mut sender, connection) = conn::http2::Builder::new(Executor::new())
            .handshake(client_io)
            .await
            .unwrap();
        tokio::spawn(connection);
        sender.send_request(capsule_request(version)).await.unwrap()
    } else {
        tokio::spawn(
            server::conn::http1::Builder::new()
                .serve_connection(server_io, service)
                .with_upgrades(),
        );
        let (mut sender, connection) = conn::http1::handshake(client_io).await.unwrap();
        tokio::spawn(connection.with_upgrades());
        sender.send_request(capsule_request(version)).await.unwrap()
    };
    validate_capsule_response(version, &TOKEN, &response, ViolationPolicy::Ignore).unwrap();
    handle_upgrade(&response).await.unwrap()
}

type Report = Arc<Mutex<Option<oneshot::Sender<Result<Option<SessionEvent>, SessionError>>>>>;

/// Reports the first thing the server's session receives.
fn reporting_service(
    report: Report,
) -> RamaHttpService<impl rama_core::Service<Request, Output = Response, Error = Infallible> + Clone>
{
    RamaHttpService::new(service_fn(move |request: Request| {
        let report = report.clone();
        async move {
            let protocol = validate_capsule_request(&request, ViolationPolicy::Ignore).unwrap();
            let upgrade = handle_upgrade(&request);
            tokio::spawn(async move {
                let mut session =
                    HttpDatagramSession::with_config(upgrade.await.unwrap(), config());
                let first = session.recv().await;
                if let Some(report) = report.lock().take() {
                    _ = report.send(first);
                }
            });
            Ok::<_, Infallible>(capsule_response::<Body>(request.version(), &protocol).unwrap())
        }
    }))
}

#[tokio::test]
async fn capsule_sessions_are_version_neutral() {
    for version in [Version::HTTP_11, Version::HTTP_2] {
        tokio::time::timeout(LIMIT, async {
            let mut session = client_session(version).await;
            assert!(session.native().is_none(), "{version:?}");
            for payload in [&b"one"[..], b"", &[7; 4096]] {
                assert_eq!(
                    session
                        .send_datagram(Bytes::copy_from_slice(payload))
                        .await
                        .unwrap(),
                    DatagramTransport::Capsule
                );
                let Some(SessionEvent::Datagram {
                    payload: echoed, ..
                }) = session.recv().await.unwrap()
                else {
                    panic!("expected echo on {version:?}");
                };
                assert_eq!(&echoed[..], payload);
            }
            session
                .send_capsule(CONTROL, Bytes::from_static(b"control"))
                .await
                .unwrap();
            assert_eq!(
                session.recv().await.unwrap(),
                Some(SessionEvent::Capsule {
                    ty: CONTROL,
                    value: Bytes::from_static(b"control")
                })
            );
            session.close().await.unwrap();
            assert_eq!(session.recv().await.unwrap(), None, "{version:?}");
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn truncated_capsules_close_http1_connections() {
    tokio::time::timeout(LIMIT, async {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (client_io, server_io) = (ServiceInput::new(client_io), ServiceInput::new(server_io));
        tokio::spawn(
            server::conn::http1::Builder::new()
                .serve_connection(server_io, capsule_service())
                .with_upgrades(),
        );
        let (mut sender, connection) = conn::http1::handshake(client_io).await.unwrap();
        tokio::spawn(connection.with_upgrades());
        let mut request = Request::builder()
            .uri("https://proxy.example/capsules")
            .header("host", "proxy.example")
            .body(Body::empty())
            .unwrap();
        prepare_capsule_request(&mut request, TOKEN).unwrap();
        let response = sender.send_request(request).await.unwrap();
        let mut tunnel = handle_upgrade(&response).await.unwrap();
        tunnel.write_all(b"\x00\x05ab").await.unwrap();
        tunnel.shutdown().await.unwrap();
        // RFC 9112 §8: the incomplete message closes the connection without any echo.
        let mut rest = Vec::new();
        _ = tunnel.read_to_end(&mut rest).await;
        assert!(rest.is_empty(), "{rest:?}");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn truncated_capsules_reset_http2_streams_with_protocol_error() {
    tokio::time::timeout(LIMIT, async {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (client_io, server_io) = (ServiceInput::new(client_io), ServiceInput::new(server_io));
        tokio::spawn(
            server::conn::http2::Builder::new(Executor::new())
                .with_enable_connect_protocol()
                .serve_connection(server_io, capsule_service()),
        );
        let (mut sender, connection) = conn::http2::Builder::new(Executor::new())
            .handshake(client_io)
            .await
            .unwrap();
        tokio::spawn(connection);
        let mut request = Request::builder()
            .version(Version::HTTP_2)
            .uri("https://proxy.example/capsules")
            .body(Body::empty())
            .unwrap();
        prepare_capsule_request(&mut request, TOKEN).unwrap();
        let response = sender.send_request(request).await.unwrap();
        let mut tunnel = handle_upgrade(&response).await.unwrap();
        // DATAGRAM type, length 5, only two value bytes, then a clean END_STREAM.
        tunnel.write_all(b"\x00\x05ab").await.unwrap();
        tunnel.shutdown().await.unwrap();
        let mut rest = Vec::new();
        let error = tunnel.read_to_end(&mut rest).await.unwrap_err();
        assert!(
            error.to_string().contains("protocol error")
                || format!("{error:?}").contains("PROTOCOL_ERROR"),
            "{error:?}"
        );
        // The connection survives the stream reset.
        let mut request = Request::builder()
            .version(Version::HTTP_2)
            .uri("https://proxy.example/capsules")
            .body(Body::empty())
            .unwrap();
        prepare_capsule_request(&mut request, TOKEN).unwrap();
        let second = sender.send_request(request).await.unwrap();
        assert!(second.status().is_success());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn malformed_http2_streams_reset_after_local_end_stream() {
    tokio::time::timeout(LIMIT, async {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (client_io, server_io) = (ServiceInput::new(client_io), ServiceInput::new(server_io));
        tokio::spawn(
            server::conn::http2::Builder::new(Executor::new())
                .with_enable_connect_protocol()
                .serve_connection(server_io, closing_service()),
        );
        let (mut sender, connection) = conn::http2::Builder::new(Executor::new())
            .handshake(client_io)
            .await
            .unwrap();
        tokio::spawn(connection);
        let response = sender
            .send_request(capsule_request(Version::HTTP_2))
            .await
            .unwrap();
        let mut tunnel = handle_upgrade(&response).await.unwrap();
        let mut rest = Vec::new();
        tunnel.read_to_end(&mut rest).await.unwrap();
        // A registered capsule above the server's 8 byte limit is malformed at once.
        tunnel.write_all(b"\x2a\x40\x64").await.unwrap();
        // Without the reset these writes stall on flow control and time out.
        let error = loop {
            if let Err(error) = tunnel.write_all(&[0; 1024]).await {
                break error;
            }
            tokio::task::yield_now().await;
        };
        assert!(format!("{error:?}").contains("PROTOCOL_ERROR"), "{error:?}");
    })
    .await
    .unwrap();
}

/// Accepts the handshake only when the capsule validator does (the default `Ignore` policy).
fn validating_service()
-> RamaHttpService<impl rama_core::Service<Request, Output = Response, Error = Infallible> + Clone>
{
    RamaHttpService::new(service_fn(|request: Request| async move {
        let Ok(protocol) = validate_capsule_request(&request, ViolationPolicy::Ignore) else {
            let mut refused = Response::new(Body::empty());
            *refused.status_mut() = StatusCode::BAD_REQUEST;
            return Ok::<_, Infallible>(refused);
        };
        let upgrade = handle_upgrade(&request);
        tokio::spawn(async move { echo(upgrade.await.unwrap()).await });
        Ok(capsule_response::<Body>(request.version(), &protocol).unwrap())
    }))
}

/// RFC 9112 §6.3: request content precedes an upgrade; it is never read as capsules.
#[tokio::test]
async fn http1_upgrades_with_request_content_are_refused() {
    let head = "GET /capsules HTTP/1.1\r\nhost: proxy.example\r\nconnection: upgrade\r\n\
                upgrade: x-capsule-test\r\ncapsule-protocol: ?1\r\n";
    // A DATAGRAM capsule "hi" hidden where request content would be.
    for (framing, content, switches) in [
        ("content-length: 0\r\n", "", true),
        ("", "", true),
        ("content-length: 4\r\n", "\x00\x02hi", false),
        (
            "transfer-encoding: chunked\r\n",
            "4\r\n\x00\x02hi\r\n0\r\n\r\n",
            false,
        ),
        (
            "expect: 100-continue\r\ncontent-length: 4\r\n",
            "\x00\x02hi",
            false,
        ),
    ] {
        tokio::time::timeout(LIMIT, async {
            let (mut client_io, server_io) = tokio::io::duplex(64 * 1024);
            tokio::spawn(
                server::conn::http1::Builder::new()
                    .serve_connection(ServiceInput::new(server_io), validating_service())
                    .with_upgrades(),
            );
            client_io
                .write_all(format!("{head}{framing}\r\n{content}").as_bytes())
                .await
                .unwrap();
            let mut response = vec![0; 1024];
            let read = client_io.read(&mut response).await.unwrap();
            let response = String::from_utf8_lossy(&response[..read]).into_owned();
            let status = if switches { "101" } else { "400" };
            assert!(
                response.contains(&format!("HTTP/1.1 {status}")),
                "{framing:?}: {response}"
            );
            if switches {
                // Capsules start after the empty line: the echo proves they are parsed.
                client_io.write_all(b"\x00\x02hi").await.unwrap();
                let mut echo = [0; 4];
                client_io.read_exact(&mut echo).await.unwrap();
                assert_eq!(&echo, b"\x00\x02hi");
            }
        })
        .await
        .unwrap();
    }
}

/// Refuses the first request with a body, then serves capsule sessions.
fn refuse_once_service()
-> RamaHttpService<impl rama_core::Service<Request, Output = Response, Error = Infallible> + Clone>
{
    let served = Arc::new(AtomicUsize::new(0));
    RamaHttpService::new(service_fn(move |request: Request| {
        let served = served.clone();
        async move {
            let protocol = validate_capsule_request(&request, ViolationPolicy::Ignore).unwrap();
            if served.fetch_add(1, Ordering::Relaxed) == 0 {
                return Ok::<_, Infallible>(
                    Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .body(Body::from("denied"))
                        .unwrap(),
                );
            }
            let upgrade = handle_upgrade(&request);
            tokio::spawn(async move { echo(upgrade.await.unwrap()).await });
            Ok(capsule_response::<Body>(request.version(), &protocol).unwrap())
        }
    }))
}

async fn echoes(upgraded: Upgraded) {
    let mut session = HttpDatagramSession::with_config(upgraded, config());
    session
        .send_datagram(Bytes::from_static(b"after"))
        .await
        .unwrap();
    assert!(matches!(
        session.recv().await.unwrap(),
        Some(SessionEvent::Datagram { payload, .. }) if payload == "after"
    ));
}

/// A refused Extended CONNECT or Upgrade is an ordinary response with its body.
async fn refused_then_served(response: Response<Incoming>, version: Version) {
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    validate_capsule_response(version, &TOKEN, &response, ViolationPolicy::Ignore).unwrap_err();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, "denied", "the refusal keeps its body");
}

#[tokio::test]
async fn refused_capsule_requests_leave_the_connection_reusable() {
    tokio::time::timeout(LIMIT, async {
        // HTTP/2: the refused stream ends; the next Extended CONNECT uses the same connection.
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        tokio::spawn(
            server::conn::http2::Builder::new(Executor::new())
                .with_enable_connect_protocol()
                .serve_connection(ServiceInput::new(server_io), refuse_once_service()),
        );
        let (mut sender, connection) = conn::http2::Builder::new(Executor::new())
            .handshake(ServiceInput::new(client_io))
            .await
            .unwrap();
        tokio::spawn(connection);
        let refused = sender
            .send_request(capsule_request(Version::HTTP_2))
            .await
            .unwrap();
        refused_then_served(refused, Version::HTTP_2).await;
        for _ in 0..2 {
            let response = sender
                .send_request(capsule_request(Version::HTTP_2))
                .await
                .unwrap();
            validate_capsule_response(Version::HTTP_2, &TOKEN, &response, ViolationPolicy::Ignore)
                .unwrap();
            echoes(handle_upgrade(&response).await.unwrap()).await;
        }

        // HTTP/1.1: a refusal is an ordinary response; the connection stays open for the next.
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        tokio::spawn(
            server::conn::http1::Builder::new()
                .serve_connection(ServiceInput::new(server_io), refuse_once_service())
                .with_upgrades(),
        );
        let (mut sender, connection) = conn::http1::handshake(ServiceInput::new(client_io))
            .await
            .unwrap();
        tokio::spawn(connection.with_upgrades());
        let refused = sender
            .send_request(capsule_request(Version::HTTP_11))
            .await
            .unwrap();
        refused_then_served(refused, Version::HTTP_11).await;
        sender.ready().await.unwrap();
        let response = sender
            .send_request(capsule_request(Version::HTTP_11))
            .await
            .unwrap();
        validate_capsule_response(Version::HTTP_11, &TOKEN, &response, ViolationPolicy::Ignore)
            .unwrap();
        echoes(handle_upgrade(&response).await.unwrap()).await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn dropping_a_partial_sender_aborts_every_carrier() {
    for version in [Version::HTTP_11, Version::HTTP_2] {
        tokio::time::timeout(LIMIT, async {
            let (mut sender, mut receiver) = client_session(version).await.split();
            sender
                .start_capsule(CapsuleHeader::new(CONTROL, 4).unwrap())
                .await
                .unwrap();
            sender
                .send_capsule_data(Bytes::from_static(b"x"))
                .await
                .unwrap();
            drop(sender);
            // The retained half ends instead of waiting for the abandoned value.
            receiver.recv().await.unwrap_err();
        })
        .await
        .unwrap_or_else(|_| panic!("{version:?} kept the abandoned capsule open"));
    }
}

#[tokio::test]
async fn peers_observe_the_abort_of_a_partial_sender() {
    for version in [Version::HTTP_11, Version::HTTP_2] {
        tokio::time::timeout(LIMIT, async {
            let (tx, rx) = oneshot::channel();
            let report: Report = Arc::new(Mutex::new(Some(tx)));
            let upgraded = client_upgraded_with(version, reporting_service(report)).await;
            let (mut sender, _receiver) =
                HttpDatagramSession::with_config(upgraded, config()).split();
            sender
                .start_capsule(CapsuleHeader::new(CONTROL, 4).unwrap())
                .await
                .unwrap();
            sender
                .send_capsule_data(Bytes::from_static(b"x"))
                .await
                .unwrap();
            drop(sender);
            // H1 closes the connection (truncation), H2 resets the stream: never a clean end.
            let seen = rx.await.unwrap();
            assert!(seen.is_err(), "{version:?}: {seen:?}");
        })
        .await
        .unwrap_or_else(|_| panic!("{version:?} peer never saw the abort"));
    }
}

#[tokio::test]
async fn http2_malformed_hook_discards_buffered_tunnel_data() {
    tokio::time::timeout(LIMIT, async {
        let mut io = client_upgraded(Version::HTTP_2).await;
        // The echo server returns this control capsule in one DATA frame.
        io.write_all(&[0x2a, 3, b'a', b'b', b'c']).await.unwrap();
        io.flush().await.unwrap();
        assert_eq!(io.read_u8().await.unwrap(), 0x2a);
        io.extensions()
            .get_ref::<OnMalformedMessage>()
            .unwrap()
            .call();
        io.read_u8().await.unwrap_err();
    })
    .await
    .unwrap();
}
