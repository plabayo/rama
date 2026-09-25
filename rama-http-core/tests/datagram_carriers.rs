//! The Capsule Protocol session over HTTP/1.1 Upgrade and HTTP/2 Extended CONNECT, driven by
//! the same version-neutral code (RFC 9297 §3).

#![expect(clippy::unwrap_used, clippy::panic, reason = "test fixtures")]

use rama_core::{ServiceInput, bytes::Bytes, rt::Executor, service::service_fn};
use rama_http::{
    Body, Request, Response, Version,
    datagram::{
        DatagramTransport, HttpDatagramSession, SessionConfig, SessionError, SessionEvent,
        capsule::CapsuleConfig,
        handshake::{
            capsule_response, prepare_capsule_request, validate_capsule_request,
            validate_capsule_response,
        },
    },
    io::upgrade::{Upgraded, handle_upgrade},
    proto::{capsule::CapsuleType, ext::Protocol},
};
use rama_http_core::{client::conn, server, service::RamaHttpService};
use std::{convert::Infallible, time::Duration};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

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
        let protocol = validate_capsule_request(&request).unwrap();
        assert_eq!(protocol, TOKEN);
        let upgrade = handle_upgrade(&request);
        tokio::spawn(async move { echo(upgrade.await.unwrap()).await });
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
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (client_io, server_io) = (ServiceInput::new(client_io), ServiceInput::new(server_io));
    let response = if version == Version::HTTP_2 {
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
        sender.send_request(capsule_request(version)).await.unwrap()
    } else {
        tokio::spawn(
            server::conn::http1::Builder::new()
                .serve_connection(server_io, capsule_service())
                .with_upgrades(),
        );
        let (mut sender, connection) = conn::http1::handshake(client_io).await.unwrap();
        tokio::spawn(connection.with_upgrades());
        sender.send_request(capsule_request(version)).await.unwrap()
    };
    validate_capsule_response(version, &TOKEN, &response).unwrap();
    HttpDatagramSession::with_config(handle_upgrade(&response).await.unwrap(), config())
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
