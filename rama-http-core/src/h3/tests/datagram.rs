//! HTTP/3 datagrams (RFC 9297 §2.1) through the public session, over real QUIC connections.

use super::{LIMIT, Pair};
use crate::h3::{
    DatagramLimits, Error as H3Error, client,
    connection::Config,
    server::{self, Connection as ServerConnection},
};
use rama_core::{
    bytes::{Bytes, BytesMut},
    extensions::ExtensionsRef as _,
    futures::FutureExt as _,
    rt::{Executor, spawn},
};
use rama_http::{
    datagram::{
        DatagramTransport, HttpDatagramSession, NativeDatagrams, NativeSendError, SessionError,
        SessionEvent,
    },
    io::upgrade::{Upgraded, handle_upgrade},
};
use rama_http_types::{
    Body, Method, Request, Response, StatusCode,
    proto::{
        ext::Protocol,
        h3::{Code, QuarterStreamId, VarInt},
    },
};
use rama_quic_proto::coding::Codec as _;
use std::{
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const TOKEN: Protocol = Protocol::from_static("x-datagram-test");

fn server_config(datagrams: Option<DatagramLimits>) -> Config {
    Config {
        extended_connect: true,
        datagrams,
        ..Config::default()
    }
}

async fn start(pair: &Pair, server: Config) -> (client::SendRequest<Body>, ServerConnection) {
    let (client, client_driver) =
        client::handshake::<Body>(pair.client.clone(), Config::default(), Executor::new()).unwrap();
    let (server, server_driver) = server::handshake(pair.server.clone(), server).unwrap();
    spawn(client_driver.run());
    spawn(server_driver.run());
    (client, server)
}

fn connect(protocol: Protocol) -> Request<Body> {
    let request = Request::builder()
        .method(Method::CONNECT)
        .uri("https://localhost/datagrams")
        .body(Body::empty())
        .unwrap();
    request.extensions().insert(protocol);
    request
}

/// Open one Extended CONNECT tunnel and return both upgraded ends.
async fn tunnel(
    client: &mut client::SendRequest<Body>,
    server: &mut ServerConnection,
    protocol: Protocol,
) -> (Upgraded, Upgraded) {
    let accept = async {
        let (request, response) = server.accept().await.unwrap().resolve().await.unwrap();
        let upgrade = handle_upgrade(&request);
        response
            .send_response(Response::new(Body::empty()))
            .await
            .unwrap();
        upgrade.await.unwrap()
    };
    let (response, server_io) = tokio::join!(client.send_request(connect(protocol)), accept);
    let response = response.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    (handle_upgrade(&response).await.unwrap(), server_io)
}

async fn sessions(
    client: &mut client::SendRequest<Body>,
    server: &mut ServerConnection,
) -> (HttpDatagramSession, HttpDatagramSession) {
    let (client_io, server_io) = tunnel(client, server, TOKEN).await;
    (
        HttpDatagramSession::new(client_io),
        HttpDatagramSession::new(server_io),
    )
}

/// Native sending needs both SETTINGS; observe it rather than sleeping.
async fn native_ready(session: &HttpDatagramSession) -> usize {
    loop {
        if let Some(max) = session
            .native()
            .and_then(|native| native.channel().max_payload_size())
        {
            return max;
        }
        // A short virtual-time step keeps paused runtimes able to advance timers.
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

async fn wait_pending(server: &ServerConnection, count: usize) {
    while server.shared().pending_datagram_count() != count {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

fn raw_datagram(stream: u64, payload: &[u8]) -> Bytes {
    let mut datagram = BytesMut::new();
    QuarterStreamId::new(stream / 4)
        .unwrap()
        .encode(&mut datagram);
    datagram.extend_from_slice(payload);
    datagram.freeze()
}

fn native(payload: &'static [u8]) -> Option<SessionEvent> {
    Some(SessionEvent::Datagram {
        payload: Bytes::from_static(payload),
        transport: DatagramTransport::Native,
    })
}

#[tokio::test]
async fn native_datagrams_round_trip_beside_reliable_capsules() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::new(None, None).await;
        let (mut client, mut server) = start(&pair, server_config(Some(Default::default()))).await;
        let (mut client_session, mut server_session) = sessions(&mut client, &mut server).await;
        let max = native_ready(&client_session).await;
        assert!(max >= 1000, "{max}");
        native_ready(&server_session).await;
        assert_eq!(
            client_session
                .send_datagram(Bytes::from_static(b"ping"))
                .await
                .unwrap(),
            DatagramTransport::Native
        );
        assert_eq!(server_session.recv().await.unwrap(), native(b"ping"));
        server_session
            .send_datagram(Bytes::from_static(b""))
            .await
            .unwrap();
        assert_eq!(client_session.recv().await.unwrap(), native(b""));
        // Oversized native payloads fail instead of silently becoming reliable. The limit
        // follows the path MTU, so use a payload no QUIC DATAGRAM frame can carry.
        let error = client_session
            .send_datagram(Bytes::from(vec![0; 100_000]))
            .await
            .unwrap_err();
        assert!(
            matches!(
                error,
                SessionError::Native(NativeSendError::TooLarge { .. })
            ),
            "{error:?}"
        );
        let client_native = client_session.native().cloned().unwrap();
        client_session.close().await.unwrap();
        assert_eq!(server_session.recv().await.unwrap(), None);
        // The local send side is closed: nothing may follow (RFC 9297 §2.1).
        assert_eq!(client_native.channel().max_payload_size(), None);
        assert_eq!(
            client_native
                .channel()
                .send(Bytes::from_static(b"late"), Default::default()),
            Err(NativeSendError::Unavailable)
        );
        client_session
            .send_datagram(Bytes::from_static(b"late"))
            .await
            .unwrap_err();
        server_session.close().await.unwrap();
        assert_eq!(client_session.recv().await.unwrap(), None);
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn capsules_carry_datagrams_when_the_peer_disables_them() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::new(None, None).await;
        let (mut client, mut server) = start(&pair, server_config(None)).await;
        let (mut client_session, mut server_session) = sessions(&mut client, &mut server).await;
        // The server never advertised SETTINGS_H3_DATAGRAM and publishes no carrier.
        assert!(server_session.native().is_none());
        let native = client_session.native().expect("client associates");
        assert_eq!(native.channel().max_payload_size(), None);
        assert_eq!(
            client_session
                .send_datagram(Bytes::from_static(b"reliable"))
                .await
                .unwrap(),
            DatagramTransport::Capsule
        );
        assert_eq!(
            server_session.recv().await.unwrap(),
            Some(SessionEvent::Datagram {
                payload: Bytes::from_static(b"reliable"),
                transport: DatagramTransport::Capsule,
            })
        );
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn concurrent_sessions_receive_only_their_own_datagrams() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::new(None, None).await;
        let (mut client, mut server) = start(&pair, server_config(Some(Default::default()))).await;
        let mut pairs = Vec::new();
        for _ in 0..8 {
            pairs.push(sessions(&mut client, &mut server).await);
        }
        for (client_session, server_session) in &pairs {
            native_ready(client_session).await;
            native_ready(server_session).await;
        }
        for (index, (client_session, _)) in pairs.iter_mut().enumerate() {
            for _ in 0..4 {
                client_session
                    .send_datagram(Bytes::from(vec![index as u8]))
                    .await
                    .unwrap();
            }
        }
        for (index, (_, server_session)) in pairs.iter_mut().enumerate() {
            // Loss is possible on real UDP; any datagram received must be this session's.
            let Some(SessionEvent::Datagram { payload, .. }) =
                tokio::time::timeout(Duration::from_secs(5), server_session.recv())
                    .await
                    .unwrap()
                    .unwrap()
            else {
                panic!("expected datagram");
            };
            assert_eq!(&payload[..], [index as u8]);
        }
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn stalled_session_drops_its_oldest_datagrams_without_blocking_others() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::in_memory(None, None).await;
        let limits = DatagramLimits {
            queue_len: 4,
            ..DatagramLimits::default()
        };
        let (mut client, mut server) = start(&pair, server_config(Some(limits))).await;
        let (mut stalled_client, stalled_server) = sessions(&mut client, &mut server).await;
        let (mut active_client, mut active_server) = sessions(&mut client, &mut server).await;
        for session in [
            &stalled_client,
            &stalled_server,
            &active_client,
            &active_server,
        ] {
            native_ready(session).await;
        }
        for index in 0..16u8 {
            stalled_client
                .send_datagram(Bytes::from(vec![index]))
                .await
                .unwrap();
            // Deliver one at a time so the in-memory path cannot reorder or drop them.
            active_client
                .send_datagram(Bytes::from(vec![index]))
                .await
                .unwrap();
            let Some(SessionEvent::Datagram { payload, .. }) = active_server.recv().await.unwrap()
            else {
                panic!("expected datagram");
            };
            assert_eq!(&payload[..], [index]);
        }
        let (_, mut receiver) = stalled_server.split();
        assert_eq!(receiver.dropped_datagrams(), 12);
        for expected in 12..16u8 {
            let Some(SessionEvent::Datagram { payload, .. }) = receiver.recv().await.unwrap()
            else {
                panic!("expected datagram");
            };
            assert_eq!(&payload[..], [expected], "the newest datagrams are kept");
        }
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn datagrams_arriving_before_the_request_head_are_adopted() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::in_memory(None, None).await;
        let (mut client, mut server) = start(&pair, server_config(Some(Default::default()))).await;
        // The request will open stream 0; its datagram overtakes the HEADERS.
        pair.client
            .send_datagram(raw_datagram(0, b"early"))
            .unwrap();
        wait_pending(&server, 1).await;
        let (_client_io, server_io) = tunnel(&mut client, &mut server, TOKEN).await;
        assert_eq!(server.shared().pending_datagram_count(), 0);
        let mut session = HttpDatagramSession::new(server_io);
        assert_eq!(session.recv().await.unwrap(), native(b"early"));
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn datagrams_on_requests_without_datagram_semantics_abort_them() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::in_memory(None, None).await;
        let (mut client, mut server) = start(&pair, server_config(Some(Default::default()))).await;
        // Ordinary GET on stream 0: detected when the server decodes the request head.
        pair.client.send_datagram(raw_datagram(0, b"x")).unwrap();
        wait_pending(&server, 1).await;
        let serve = async {
            let error = server
                .accept()
                .await
                .unwrap()
                .resolve()
                .await
                .map(|_| ())
                .unwrap_err();
            assert_eq!(error.code(), Code::H3_DATAGRAM_ERROR);
        };
        let request = Request::builder()
            .uri("https://localhost/")
            .body(Body::empty())
            .unwrap();
        let (response, ()) = tokio::join!(client.send_request(request), serve);
        assert_eq!(response.unwrap_err().code(), Code::H3_DATAGRAM_ERROR);

        // A WebSocket tunnel (RFC 9220) defines no datagrams either: aborted while open.
        let (mut client_io, mut server_io) =
            tunnel(&mut client, &mut server, Protocol::WEBSOCKET).await;
        assert!(
            client_io
                .extensions()
                .get_ref::<NativeDatagrams>()
                .is_none()
        );
        pair.client.send_datagram(raw_datagram(4, b"y")).unwrap();
        wait_pending(&server, 1).await;
        let mut byte = [0; 1];
        server_io.read(&mut byte).await.unwrap_err();
        client_io.read(&mut byte).await.unwrap_err();
        // The connection itself stays usable.
        let (_client_io, _server_io) = tunnel(&mut client, &mut server, TOKEN).await;
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn malformed_datagram_prefixes_are_connection_errors() {
    let oversized = {
        let mut datagram = BytesMut::new();
        VarInt::from_u64(1 << 60).unwrap().encode(&mut datagram);
        datagram.freeze()
    };
    for (datagram, code) in [
        (Bytes::new(), Code::H3_DATAGRAM_ERROR),
        (oversized, Code::H3_DATAGRAM_ERROR),
        // Far beyond the client bidirectional stream limit (SHOULD, RFC 9297 §2.1).
        (raw_datagram(4 * 1_000_000, b""), Code::H3_ID_ERROR),
    ] {
        tokio::time::timeout(LIMIT, async {
            let pair = Pair::in_memory(None, None).await;
            let (_client, _server) = start(&pair, server_config(Some(Default::default()))).await;
            pair.client.send_datagram(datagram).unwrap();
            let reason = pair.client.closed().await;
            let rama_quic::ConnectionError::ApplicationClosed(close) = reason else {
                panic!("unexpected {reason:?}");
            };
            assert_eq!(close.error_code.into_inner(), code.value());
            pair.close().await;
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn datagrams_after_the_stream_closed_are_dropped() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::in_memory(None, None).await;
        let (mut client, mut server) = start(&pair, server_config(Some(Default::default()))).await;
        let (mut client_session, mut server_session) = sessions(&mut client, &mut server).await;
        native_ready(&client_session).await;
        let server_native = server_session.native().cloned().unwrap();
        client_session.close().await.unwrap();
        assert_eq!(server_session.recv().await.unwrap(), None);
        // A misbehaving peer keeps sending on the finished stream.
        pair.client.send_datagram(raw_datagram(0, b"late")).unwrap();
        // A later request proves the connection processed and survived it.
        let (_a, _b) = sessions(&mut client, &mut server).await;
        assert_eq!(server.shared().pending_datagram_count(), 0);
        while server_native.channel().dropped() == 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let mut cx = Context::from_waker(Waker::noop());
        assert_eq!(
            server_native.channel().poll_recv(&mut cx),
            Poll::Ready(None),
            "datagrams after the receive side closed are dropped"
        );
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn sessions_continue_through_graceful_shutdown_and_end_with_the_connection() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::in_memory(None, None).await;
        let (mut client, mut server) = start(&pair, server_config(Some(Default::default()))).await;
        let (mut client_session, mut server_session) = sessions(&mut client, &mut server).await;
        native_ready(&client_session).await;
        server.shutdown().unwrap();
        while !client.is_draining() {
            tokio::task::yield_now().await;
        }
        client_session
            .send_datagram(Bytes::from_static(b"draining"))
            .await
            .unwrap();
        assert_eq!(server_session.recv().await.unwrap(), native(b"draining"));
        // A pending receive wakes when the connection goes away.
        let recv = spawn(async move { client_session.recv().await });
        pair.server.close(VarInt::from_u32(0x100), b"done");
        let result = recv.await.unwrap();
        assert!(!matches!(result, Ok(Some(_))), "{result:?}");
        assert!(client.send_request(connect(TOKEN)).now_or_never().is_some());
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn lost_datagrams_do_not_stall_the_session() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::impaired().await;
        let (mut client, mut server) = start(&pair, server_config(Some(Default::default()))).await;
        let (mut client_session, mut server_session) = sessions(&mut client, &mut server).await;
        native_ready(&client_session).await;
        let [client_faults, _] = pair.datagram_faults.as_ref().unwrap();
        client_faults.drop_next(1);
        client_session
            .send_datagram(Bytes::from_static(b"lost"))
            .await
            .unwrap();
        // Send the next datagram only after the first packet was lost, not coalesced with it.
        while client_faults.stats().dropped == 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        client_session
            .send_datagram(Bytes::from_static(b"kept"))
            .await
            .unwrap();
        assert_eq!(server_session.recv().await.unwrap(), native(b"kept"));
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn truncated_capsules_reset_http3_streams_as_malformed() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::in_memory(None, None).await;
        let (mut client, mut server) = start(&pair, server_config(None)).await;
        let (mut client_io, server_io) = tunnel(&mut client, &mut server, TOKEN).await;
        let mut session = HttpDatagramSession::new(server_io);
        client_io.write_all(b"\x00\x05ab").await.unwrap();
        client_io.shutdown().await.unwrap();
        let error = session.recv().await.unwrap_err();
        assert!(matches!(error, SessionError::Malformed(_)), "{error:?}");
        let mut rest = Vec::new();
        let error = client_io.read_to_end(&mut rest).await.unwrap_err();
        let error = error
            .get_ref()
            .and_then(|error| error.downcast_ref::<H3Error>())
            .copied()
            .expect("h3 error");
        assert_eq!(error.code(), Code::H3_MESSAGE_ERROR);
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn datagram_floods_do_not_starve_request_streams() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::new(None, None).await;
        let (mut client, mut server) = start(&pair, server_config(Some(Default::default()))).await;
        // A claimed but never-read association absorbs the flood.
        let (_client_io, _server_io) = tunnel(&mut client, &mut server, TOKEN).await;
        let flood = {
            let connection = pair.client.clone();
            spawn(async move {
                let datagram = raw_datagram(0, &[0; 512]);
                loop {
                    if connection.send_datagram(datagram.clone()).is_err() {
                        return;
                    }
                    tokio::task::yield_now().await;
                }
            })
        };
        let serve = spawn(async move {
            for _ in 0..5 {
                let (_request, response) = server.accept().await.unwrap().resolve().await.unwrap();
                response
                    .send_response(Response::new(Body::from("ok")))
                    .await
                    .unwrap();
            }
            server
        });
        for _ in 0..5 {
            let request = Request::builder()
                .uri("https://localhost/")
                .body(Body::empty())
                .unwrap();
            let response = client.send_request(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
        let server = serve.await.unwrap();
        // The flood was bounded by the association queue and the connection budget.
        assert!(server.shared().pending_datagram_count() <= DatagramLimits::default().pending_len);
        flood.abort();
        pair.close().await;
    })
    .await
    .unwrap();
}
