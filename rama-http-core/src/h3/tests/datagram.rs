//! HTTP/3 datagrams (RFC 9297 §2.1) through the public session, over real QUIC connections.

use super::{LIMIT, Pair};
use crate::h3::{
    DatagramConfig, DatagramLimits, Error as H3Error, client,
    connection::Config,
    qpack::{Encoder, EncoderConfig},
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
        DatagramTransport, HttpDatagramSession, NativeDatagrams, NativeRecvError, NativeSendError,
        SessionError, SessionEvent, ViolationPolicy,
    },
    io::upgrade::{OnMalformedMessage, OnUpstreamError, Upgraded, handle_upgrade},
};
use rama_http_types::{
    Body, Method, Request, Response, StatusCode,
    body::util::BodyExt as _,
    proto::{
        capsule::CapsuleType,
        ext::{HttpDatagrams, Protocol},
        h3::{Code, FrameHeader, FrameType, QuarterStreamId, VarInt},
    },
};
use rama_quic_proto::coding::Codec as _;
use std::{
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const TOKEN: Protocol = Protocol::from_static("x-datagram-test");
const POLICIES: [ViolationPolicy; 2] = [ViolationPolicy::Ignore, ViolationPolicy::Reject];

fn datagrams(limits: DatagramLimits, violations: ViolationPolicy) -> Option<DatagramConfig> {
    Some(DatagramConfig { limits, violations })
}

fn server_config(datagrams: Option<DatagramConfig>) -> Config {
    Config {
        extended_connect: true,
        datagrams,
        ..Config::default()
    }
}

async fn start(pair: &Pair, server: Config) -> (client::SendRequest<Body>, ServerConnection) {
    start_both(pair, Config::default(), server).await
}

async fn start_both(
    pair: &Pair,
    client: Config,
    server: Config,
) -> (client::SendRequest<Body>, ServerConnection) {
    let (client, client_driver) =
        client::handshake::<Body>(pair.client.clone(), client, Executor::new()).unwrap();
    let (server, server_driver) = server::handshake(pair.server.clone(), server).unwrap();
    spawn(client_driver.run());
    spawn(server_driver.run());
    (client, server)
}

fn connect(protocol: Protocol, declared: bool) -> Request<Body> {
    let request = Request::builder()
        .method(Method::CONNECT)
        .uri("https://localhost/datagrams")
        .body(Body::empty())
        .unwrap();
    request.extensions().insert(protocol);
    if declared {
        request.extensions().insert(HttpDatagrams);
    }
    request
}

fn accepted(declared: bool) -> Response<Body> {
    let response = Response::new(Body::empty());
    if declared {
        response.extensions().insert(HttpDatagrams);
    }
    response
}

/// Open one Extended CONNECT tunnel, each side declaring datagrams as given.
async fn tunnel_with(
    client: &mut client::SendRequest<Body>,
    server: &mut ServerConnection,
    protocol: Protocol,
    client_declares: bool,
    server_declares: bool,
) -> (Upgraded, Upgraded) {
    let accept = async {
        let (request, response) = server.accept().await.unwrap().resolve().await.unwrap();
        let upgrade = handle_upgrade(&request);
        response
            .send_response(accepted(server_declares))
            .await
            .unwrap();
        upgrade.await.unwrap()
    };
    let (response, server_io) = tokio::join!(
        client.send_request(connect(protocol, client_declares)),
        accept
    );
    let response = response.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    (handle_upgrade(&response).await.unwrap(), server_io)
}

async fn tunnel(
    client: &mut client::SendRequest<Body>,
    server: &mut ServerConnection,
    protocol: Protocol,
) -> (Upgraded, Upgraded) {
    tunnel_with(client, server, protocol, true, true).await
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

/// Wait until the transport reports a closed send side through the native channel.
async fn native_closed(native: &NativeDatagrams) {
    loop {
        match native
            .channel()
            .send(Bytes::from_static(b"probe"), Default::default())
        {
            Err(NativeSendError::Closed) => return,
            Ok(()) => tokio::time::sleep(Duration::from_millis(1)).await,
            Err(error) => panic!("unexpected {error:?}"),
        }
    }
}

async fn wait_pending(server: &ServerConnection, count: usize) {
    while server.shared().datagram_demux().pending_len() != count {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

async fn wait_drops(server: &ServerConnection, done: impl Fn(crate::h3::DatagramDrops) -> bool) {
    while !done(server.datagram_drops()) {
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

fn get() -> Request<Body> {
    Request::builder()
        .uri("https://localhost/")
        .body(Body::empty())
        .unwrap()
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
        assert_eq!(
            client_native
                .channel()
                .send(Bytes::from_static(b"late"), Default::default()),
            Err(NativeSendError::Closed)
        );
        assert!(matches!(
            client_session
                .send_datagram(Bytes::from_static(b"late"))
                .await,
            Err(SessionError::SendClosed)
        ));
        // The reverse direction keeps working after the half-close.
        server_session
            .send_datagram(Bytes::from_static(b"reverse"))
            .await
            .unwrap();
        assert_eq!(client_session.recv().await.unwrap(), native(b"reverse"));
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
        let (mut client, mut server) = start(
            &pair,
            server_config(datagrams(limits, ViolationPolicy::Ignore)),
        )
        .await;
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
        assert_eq!(server.shared().datagram_demux().pending_len(), 0);
        let mut session = HttpDatagramSession::new(server_io);
        assert_eq!(session.recv().await.unwrap(), native(b"early"));
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn datagrams_on_requests_without_datagram_semantics_follow_the_policy() {
    for policy in POLICIES {
        tokio::time::timeout(LIMIT, async {
            let pair = Pair::in_memory(None, None).await;
            let config = server_config(datagrams(DatagramLimits::default(), policy));
            let (mut client, mut server) = start(&pair, config).await;
            // Ordinary GET on stream 0: its datagram overtakes the HEADERS.
            pair.client.send_datagram(raw_datagram(0, b"x")).unwrap();
            wait_pending(&server, 1).await;
            let serve = async {
                let result = server.accept().await.unwrap().resolve().await;
                if policy == ViolationPolicy::Reject {
                    let error = result.map(|_| ()).unwrap_err();
                    assert_eq!(error.code(), Code::H3_DATAGRAM_ERROR);
                } else {
                    let (_request, response) = result.unwrap();
                    response
                        .send_response(Response::new(Body::from("ok")))
                        .await
                        .unwrap();
                }
            };
            let (response, ()) = tokio::join!(client.send_request(get()), serve);
            match policy {
                ViolationPolicy::Reject => {
                    assert_eq!(response.unwrap_err().code(), Code::H3_DATAGRAM_ERROR);
                }
                _ => assert_eq!(response.unwrap().status(), StatusCode::OK),
            }
            assert_eq!(server.datagram_drops().no_semantics, 1, "{policy:?}");

            // A token alone never implies datagrams: an undeclared WebSocket tunnel.
            let (mut client_io, mut server_io) =
                tunnel_with(&mut client, &mut server, Protocol::WEBSOCKET, false, false).await;
            for io in [&client_io, &server_io] {
                assert!(io.extensions().get_ref::<NativeDatagrams>().is_none());
            }
            pair.client.send_datagram(raw_datagram(4, b"y")).unwrap();
            wait_drops(&server, |drops| drops.no_semantics == 2).await;
            let mut byte = [0; 1];
            if policy == ViolationPolicy::Reject {
                // Aborted by the driver while nobody polls the tunnel.
                client_io.read(&mut byte).await.unwrap_err();
                server_io.read(&mut byte).await.unwrap_err();
            } else {
                client_io.write_all(b"z").await.unwrap();
                client_io.flush().await.unwrap();
                server_io.read_exact(&mut byte).await.unwrap();
                assert_eq!(&byte, b"z");
            }
            // The connection itself stays usable.
            let (_client_io, _server_io) = tunnel(&mut client, &mut server, TOKEN).await;
            pair.close().await;
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn servers_declare_semantics_on_their_response() {
    for policy in POLICIES {
        // A zero queue discards every payload: the violation is still observed.
        for queue_len in [0, 4] {
            tokio::time::timeout(LIMIT, async {
                let pair = Pair::in_memory(None, None).await;
                let limits = DatagramLimits {
                    queue_len,
                    ..DatagramLimits::default()
                };
                let (mut client, mut server) =
                    start(&pair, server_config(datagrams(limits, policy))).await;
                let arrived = |server: &ServerConnection, count: u64, bytes: usize| {
                    if queue_len == 0 {
                        server.datagram_drops().queue_full == count
                    } else {
                        server.shared().datagram_demux().buffered() == bytes
                    }
                };
                // Declared by the client only; the slow server answers without declaring.
                let (response, server_io) =
                    tokio::join!(client.send_request(connect(TOKEN, true)), async {
                        let (request, response) =
                            server.accept().await.unwrap().resolve().await.unwrap();
                        pair.client
                            .send_datagram(raw_datagram(0, b"early"))
                            .unwrap();
                        wait_drops(&server, |_| arrived(&server, 1, 5)).await;
                        let upgrade = handle_upgrade(&request);
                        match response.send_response(accepted(false)).await {
                            Ok(()) => upgrade.await.ok(),
                            Err(_) => None,
                        }
                    });
                assert_eq!(server.shared().datagram_demux().buffered(), 0);
                if policy == ViolationPolicy::Reject {
                    // Aborted before the response left, whatever the queue kept.
                    assert_eq!(response.unwrap_err().code(), Code::H3_DATAGRAM_ERROR);
                } else {
                    let mut client_io = handle_upgrade(&response.unwrap()).await.unwrap();
                    let mut server_io = server_io.unwrap();
                    assert!(
                        server_io
                            .extensions()
                            .get_ref::<NativeDatagrams>()
                            .is_none()
                    );
                    client_io.write_all(b"z").await.unwrap();
                    client_io.flush().await.unwrap();
                    let mut byte = [0; 1];
                    server_io.read_exact(&mut byte).await.unwrap();
                    assert!(
                        server.datagram_drops().no_semantics + server.datagram_drops().queue_full
                            >= 1
                    );
                }
                // A declared response keeps datagrams that arrived while it was pending.
                let (response, server_io) =
                    tokio::join!(client.send_request(connect(TOKEN, true)), async {
                        let (request, response) =
                            server.accept().await.unwrap().resolve().await.unwrap();
                        pair.client.send_datagram(raw_datagram(4, b"held")).unwrap();
                        wait_drops(&server, |_| arrived(&server, 2, 4)).await;
                        let upgrade = handle_upgrade(&request);
                        response.send_response(accepted(true)).await.unwrap();
                        upgrade.await.unwrap()
                    });
                assert_eq!(response.unwrap().status(), StatusCode::OK);
                if queue_len > 0 {
                    let mut session = HttpDatagramSession::new(server_io);
                    assert_eq!(session.recv().await.unwrap(), native(b"held"));
                }
                pair.close().await;
            })
            .await
            .unwrap();
        }
    }
}

#[tokio::test]
async fn refused_extended_connects_lose_their_client_declaration() {
    for policy in POLICIES {
        tokio::time::timeout(LIMIT, async {
            let pair = Pair::in_memory(None, None).await;
            let client_config = Config {
                datagrams: datagrams(DatagramLimits::default(), policy),
                ..Config::default()
            };
            let (mut client, mut server) = start_both(
                &pair,
                client_config,
                server_config(Some(DatagramConfig::default())),
            )
            .await;
            let serve = async {
                let (_request, response) = server.accept().await.unwrap().resolve().await.unwrap();
                let mut refused = Response::new(Body::from("refused"));
                *refused.status_mut() = StatusCode::FORBIDDEN;
                response.send_response(refused).await.unwrap();
            };
            let (response, ()) = tokio::join!(client.send_request(connect(TOKEN, true)), serve);
            let response = response.unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            // The remaining response body carries no datagrams.
            pair.server.send_datagram(raw_datagram(0, b"x")).unwrap();
            while client.datagram_drops().no_semantics == 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            let body = response.into_body().collect().await;
            match policy {
                ViolationPolicy::Reject => assert!(body.is_err()),
                _ => assert_eq!(&body.unwrap().to_bytes()[..], b"refused"),
            }
            let (_client_io, _server_io) = tunnel(&mut client, &mut server, TOKEN).await;
            pair.close().await;
        })
        .await
        .unwrap();
    }
}

/// A raw server stream answering one Extended CONNECT with `200`.
async fn raw_accept(pair: &Pair) -> (rama_quic::SendStream, rama_quic::RecvStream) {
    let (mut send, mut recv) = pair.server.accept_bi().await.unwrap();
    let id = u64::from(send.id());
    recv.read_chunk(usize::MAX, true).await.unwrap().unwrap();
    let encoded = Encoder::before_peer_settings(EncoderConfig::default())
        .encode(id, vec![(":status", "200")])
        .unwrap();
    let mut frame = BytesMut::new();
    FrameHeader::new(FrameType::HEADERS, encoded.len() as u64)
        .encode(&mut frame)
        .unwrap();
    frame.extend_from_slice(&encoded);
    send.write_chunk(frame.freeze()).await.unwrap();
    (send, recv)
}

#[tokio::test]
async fn native_sends_follow_the_transport_without_writer_polls() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::in_memory(None, None).await;
        // The engine only supplies SETTINGS; the request stream is served raw.
        let (mut client, _server) =
            start(&pair, server_config(Some(DatagramConfig::default()))).await;
        let (response, (_send, mut recv)) =
            tokio::join!(client.send_request(connect(TOKEN, true)), raw_accept(&pair));
        let session = HttpDatagramSession::new(handle_upgrade(&response.unwrap()).await.unwrap());
        native_ready(&session).await;
        // Split halves and a clone; the writer is never polled again.
        let clone = session.native().cloned().unwrap();
        let (mut sender, _receiver) = session.split();
        clone
            .channel()
            .send(Bytes::from_static(b"open"), Default::default())
            .unwrap();
        recv.stop(VarInt::from_u32(0x33)).unwrap();
        native_closed(&clone).await;
        assert!(matches!(
            sender.send_datagram(Bytes::from_static(b"stopped")).await,
            Err(SessionError::Native(NativeSendError::Closed))
        ));
        // Other requests on the connection are unaffected.
        let (response, _raw) =
            tokio::join!(client.send_request(connect(TOKEN, true)), raw_accept(&pair));
        let other = HttpDatagramSession::new(handle_upgrade(&response.unwrap()).await.unwrap());
        other
            .native()
            .unwrap()
            .channel()
            .send(Bytes::from_static(b"other"), Default::default())
            .unwrap();
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn local_ends_close_native_sending_for_every_holder() {
    for end in ["fin", "malformed", "upstream", "drop", "connection"] {
        tokio::time::timeout(LIMIT, async {
            let pair = Pair::in_memory(None, None).await;
            let (mut client, mut server) =
                start(&pair, server_config(Some(DatagramConfig::default()))).await;
            let (client_io, _server_io) = tunnel(&mut client, &mut server, TOKEN).await;
            let native = client_io
                .extensions()
                .get_ref::<NativeDatagrams>()
                .cloned()
                .unwrap();
            let malformed = client_io
                .extensions()
                .get_ref::<OnMalformedMessage>()
                .cloned();
            let upstream = client_io.extensions().get_ref::<OnUpstreamError>().cloned();
            let mut session = HttpDatagramSession::new(client_io);
            native_ready(&session).await;
            match end {
                "fin" => session.close().await.unwrap(),
                "malformed" => malformed.unwrap().call(),
                "upstream" => upstream.unwrap().call(),
                "drop" => drop(session),
                _ => pair.client.close(VarInt::from_u32(0), b"gone"),
            }
            assert_eq!(
                native
                    .channel()
                    .send(Bytes::from_static(b"after"), Default::default()),
                Err(NativeSendError::Closed),
                "{end}"
            );
            pair.close().await;
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn released_streams_never_hold_datagrams() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::in_memory(None, None).await;
        let (mut client, mut server) =
            start(&pair, server_config(Some(DatagramConfig::default()))).await;
        let serve = async {
            let (_request, response) = server.accept().await.unwrap().resolve().await.unwrap();
            response
                .send_response(Response::new(Body::from("ok")))
                .await
                .unwrap();
        };
        let (response, ()) = tokio::join!(client.send_request(get()), serve);
        drop(response.unwrap());
        while server.shared().datagram_demux().slot_count() != 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        // Stream 0 is below the watermark: silently dropped, never pending.
        pair.client.send_datagram(raw_datagram(0, b"late")).unwrap();
        wait_drops(&server, |drops| drops.unknown_stream == 1).await;
        assert_eq!(server.shared().datagram_demux().pending_len(), 0);
        // A future stream is still held, and late traffic for a released one never evicts it.
        pair.client
            .send_datagram(raw_datagram(8, b"early"))
            .unwrap();
        wait_pending(&server, 1).await;
        pair.client
            .send_datagram(raw_datagram(0, b"later"))
            .unwrap();
        wait_drops(&server, |drops| drops.unknown_stream == 2).await;
        wait_pending(&server, 1).await;
        pair.close().await;
        while server.shared().datagram_demux().buffered() != 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn malformed_datagram_prefixes_follow_the_policy() {
    let oversized = {
        let mut datagram = BytesMut::new();
        VarInt::from_u64(1 << 60).unwrap().encode(&mut datagram);
        datagram.freeze()
    };
    for policy in POLICIES {
        for (datagram, code) in [
            (Bytes::new(), Code::H3_DATAGRAM_ERROR),
            (oversized.clone(), Code::H3_DATAGRAM_ERROR),
            // Far beyond the client bidirectional stream limit (SHOULD, RFC 9297 §2.1).
            (raw_datagram(4 * 1_000_000, b""), Code::H3_ID_ERROR),
        ] {
            tokio::time::timeout(LIMIT, async {
                let pair = Pair::in_memory(None, None).await;
                let config = server_config(datagrams(DatagramLimits::default(), policy));
                let (mut client, mut server) = start(&pair, config).await;
                pair.client.send_datagram(datagram).unwrap();
                if policy == ViolationPolicy::Reject {
                    let reason = pair.client.closed().await;
                    let rama_quic::ConnectionError::ApplicationClosed(close) = reason else {
                        panic!("unexpected {reason:?}");
                    };
                    assert_eq!(close.error_code.into_inner(), code.value());
                } else {
                    wait_drops(&server, |drops| drops.invalid_id + drops.beyond_limit == 1).await;
                    let (_client_io, _server_io) = tunnel(&mut client, &mut server, TOKEN).await;
                }
                pair.close().await;
            })
            .await
            .unwrap();
        }
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
        assert_eq!(server.shared().datagram_demux().pending_len(), 0);
        while server_native.channel().dropped() == 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let mut cx = Context::from_waker(Waker::noop());
        assert_eq!(
            server_native.channel().poll_recv(&mut cx),
            Poll::Ready(Ok(None)),
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
        assert!(
            client
                .send_request(connect(TOKEN, true))
                .now_or_never()
                .is_some()
        );
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
        {
            let demux = server.shared().datagram_demux();
            assert!(demux.pending_len() <= DatagramLimits::default().pending_len);
            assert!(demux.buffered() <= DatagramLimits::default().max_buffered_bytes);
        }
        flood.abort();
        pair.close().await;
    })
    .await
    .unwrap();
}

/// The peer's error code on an aborted request stream.
async fn stream_error(io: &mut Upgraded) -> Code {
    let mut byte = [0; 1];
    let error = io.read(&mut byte).await.unwrap_err();
    error
        .get_ref()
        .and_then(|error| error.downcast_ref::<H3Error>())
        .copied()
        .expect("h3 error")
        .code()
}

#[tokio::test]
async fn rejected_violations_abort_unpolled_requests_in_both_roles() {
    // No buffering at all: eligibility is decided without any retained payload.
    let limits = DatagramLimits {
        queue_len: 0,
        pending_len: 0,
        max_buffered_bytes: 0,
    };
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::in_memory(None, None).await;
        let strict = || Config {
            extended_connect: true,
            datagrams: datagrams(limits.clone(), ViolationPolicy::Reject),
            ..Config::default()
        };
        let (mut client, mut server) = start_both(&pair, strict(), strict()).await;
        // Server role: a datagram for an undeclared tunnel nobody polls.
        let (mut client_io, mut server_io) =
            tunnel_with(&mut client, &mut server, Protocol::WEBSOCKET, false, false).await;
        pair.client.send_datagram(raw_datagram(0, b"x")).unwrap();
        assert_eq!(stream_error(&mut client_io).await, Code::H3_DATAGRAM_ERROR);
        server_io.read(&mut [0; 1]).await.unwrap_err();
        // Client role, likewise.
        let (mut client_io, mut server_io) =
            tunnel_with(&mut client, &mut server, Protocol::WEBSOCKET, false, false).await;
        pair.server.send_datagram(raw_datagram(4, b"y")).unwrap();
        assert_eq!(stream_error(&mut server_io).await, Code::H3_DATAGRAM_ERROR);
        client_io.read(&mut [0; 1]).await.unwrap_err();
        assert_eq!(server.datagram_drops().no_semantics, 1);
        assert_eq!(client.datagram_drops().no_semantics, 1);
        // Later requests, control and QPACK keep working.
        for _ in 0..2 {
            let (mut a, mut b) = tunnel(&mut client, &mut server, TOKEN).await;
            a.write_all(b"ok").await.unwrap();
            a.flush().await.unwrap();
            let mut buf = [0; 2];
            b.read_exact(&mut buf).await.unwrap();
        }
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn refused_connects_remember_datagrams_routed_before_the_response() {
    for queue_len in [0, 4] {
        tokio::time::timeout(LIMIT, async {
            let pair = Pair::in_memory(None, None).await;
            let limits = DatagramLimits {
                queue_len,
                ..DatagramLimits::default()
            };
            let client_config = Config {
                datagrams: datagrams(limits, ViolationPolicy::Reject),
                ..Config::default()
            };
            let (mut client, mut server) = start_both(
                &pair,
                client_config,
                server_config(Some(DatagramConfig::default())),
            )
            .await;
            let observer = client.clone();
            let serve = async {
                let (_request, response) = server.accept().await.unwrap().resolve().await.unwrap();
                pair.server
                    .send_datagram(raw_datagram(0, b"early"))
                    .unwrap();
                // Routed to the client's claimed slot, retained or discarded, before the 403.
                while observer.datagram_drops().queue_full == 0
                    && observer.shared().datagram_demux().buffered() == 0
                {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                let mut refused = Response::new(Body::from("refused"));
                *refused.status_mut() = StatusCode::FORBIDDEN;
                _ = response.send_response(refused).await;
            };
            let (response, ()) = tokio::join!(client.send_request(connect(TOKEN, true)), serve);
            let rejected = match response {
                Err(_) => true,
                Ok(response) => response.into_body().collect().await.is_err(),
            };
            assert!(rejected, "queue_len={queue_len}");
            let (_client_io, _server_io) = tunnel(&mut client, &mut server, TOKEN).await;
            pair.close().await;
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn local_abort_hooks_end_both_directions_at_once() {
    for malformed in [true, false] {
        tokio::time::timeout(LIMIT, async {
            let pair = Pair::in_memory(None, None).await;
            let (mut client, mut server) =
                start(&pair, server_config(Some(DatagramConfig::default()))).await;
            let (mut client_io, mut server_io) = tunnel(&mut client, &mut server, TOKEN).await;
            let native = server_io
                .extensions()
                .get_ref::<NativeDatagrams>()
                .cloned()
                .unwrap();
            // Reliable bytes and a native datagram already buffered on the server side.
            client_io.write_all(b"abc").await.unwrap();
            client_io.flush().await.unwrap();
            assert_eq!(server_io.read_u8().await.unwrap(), b'a');
            pair.client
                .send_datagram(raw_datagram(0, b"queued"))
                .unwrap();
            while server.shared().datagram_demux().buffered() != 6 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            let (code, upstream) = if malformed {
                let hook = server_io
                    .extensions()
                    .get_ref::<OnMalformedMessage>()
                    .cloned();
                hook.unwrap().call();
                (Code::H3_MESSAGE_ERROR, false)
            } else {
                let hook = server_io.extensions().get_ref::<OnUpstreamError>().cloned();
                hook.unwrap().call();
                (Code::H3_CONNECT_ERROR, true)
            };
            // Native receiving ends without any reliable read, discarding what was queued.
            assert_eq!(server.shared().datagram_demux().buffered(), 0);
            let mut cx = Context::from_waker(Waker::noop());
            assert_eq!(
                native.channel().poll_recv(&mut cx),
                Poll::Ready(Err(NativeRecvError::Aborted(code.value()))),
                "upstream={upstream}"
            );
            // Newly arriving datagrams are dropped, not delivered.
            let before = server.datagram_drops().receive_closed;
            pair.client.send_datagram(raw_datagram(0, b"late")).unwrap();
            wait_drops(&server, |drops| drops.receive_closed > before).await;
            assert_eq!(
                native.channel().poll_recv(&mut cx),
                Poll::Ready(Err(NativeRecvError::Aborted(code.value())))
            );
            assert_eq!(server.shared().datagram_demux().buffered(), 0);
            // Buffered reliable bytes are not served after the abort.
            assert_eq!(stream_error(&mut server_io).await, code);
            let (_a, _b) = tunnel(&mut client, &mut server, TOKEN).await;
            pair.close().await;
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn connection_loss_is_never_reported_as_a_peer_reset() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::in_memory(None, None).await;
        let (mut client, mut server) =
            start(&pair, server_config(Some(DatagramConfig::default()))).await;
        let (_client_io, mut server_io) = tunnel(&mut client, &mut server, TOKEN).await;
        let native = server_io
            .extensions()
            .get_ref::<NativeDatagrams>()
            .cloned()
            .unwrap();
        // Only CONNECTION_CLOSE, without a request FIN or RESET_STREAM.
        pair.client
            .close(VarInt::from_u32(Code::H3_NO_ERROR.value() as u32), b"done");
        _ = pair.server.closed().await;
        _ = server.shared().failed().await;
        let mut cx = Context::from_waker(Waker::noop());
        assert_eq!(
            native.channel().poll_recv(&mut cx),
            Poll::Ready(Err(NativeRecvError::Lost))
        );
        assert_eq!(
            stream_error(&mut server_io).await,
            Code::H3_REQUEST_INCOMPLETE
        );
        for _ in 0..2 {
            assert_eq!(
                native.channel().poll_recv(&mut cx),
                Poll::Ready(Err(NativeRecvError::Lost))
            );
        }
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn peer_resets_keep_the_local_send_direction_open() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::in_memory(None, None).await;
        let (mut client, _server) =
            start(&pair, server_config(Some(DatagramConfig::default()))).await;
        let (response, (mut peer_send, mut peer_recv)) =
            tokio::join!(client.send_request(connect(TOKEN, true)), raw_accept(&pair));
        let mut session =
            HttpDatagramSession::new(handle_upgrade(&response.unwrap()).await.unwrap());
        native_ready(&session).await;
        let native = session.native().cloned().unwrap();
        native
            .channel()
            .send(Bytes::from_static(b"before"), Default::default())
            .unwrap();
        // The peer ends only its own direction.
        peer_send
            .reset(VarInt::from_u32(Code::H3_REQUEST_CANCELLED.value() as u32))
            .unwrap();
        session.recv().await.unwrap_err();
        let mut cx = Context::from_waker(Waker::noop());
        assert_eq!(
            native.channel().poll_recv(&mut cx),
            Poll::Ready(Err(NativeRecvError::Reset(
                Code::H3_REQUEST_CANCELLED.value()
            )))
        );
        native
            .channel()
            .send(Bytes::from_static(b"after"), Default::default())
            .unwrap();
        session
            .send_capsule(
                CapsuleType::new(0x2a).unwrap(),
                Bytes::from_static(b"reverse"),
            )
            .await
            .unwrap();
        // The peer still receives reliable data, possibly split over DATA frames.
        let mut reverse = Vec::new();
        while reverse.len() < 9 {
            assert_eq!(peer_recv.read_u8().await.unwrap(), 0);
            let len = usize::from(peer_recv.read_u8().await.unwrap());
            let start = reverse.len();
            reverse.resize(start + len, 0);
            peer_recv.read_exact(&mut reverse[start..]).await.unwrap();
        }
        assert_eq!(&reverse, b"\x2a\x07reverse");
        for _ in 0..2 {
            let (response, _raw) =
                tokio::join!(client.send_request(connect(TOKEN, true)), raw_accept(&pair));
            assert_eq!(response.unwrap().status(), StatusCode::OK);
        }
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn peer_resets_keep_their_raw_wire_code() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::in_memory(None, None).await;
        let (mut client, _server) =
            start(&pair, server_config(Some(DatagramConfig::default()))).await;
        let (response, (mut peer_send, _peer_recv)) =
            tokio::join!(client.send_request(connect(TOKEN, true)), raw_accept(&pair));
        let mut session =
            HttpDatagramSession::new(handle_upgrade(&response.unwrap()).await.unwrap());
        native_ready(&session).await;
        let native = session.native().cloned().unwrap();
        // An unknown code: H3_NO_ERROR semantics (RFC 9114 §8), yet reported as received.
        peer_send.reset(VarInt::from_u32(0xdead)).unwrap();
        session.recv().await.unwrap_err();
        let mut cx = Context::from_waker(Waker::noop());
        assert_eq!(
            native.channel().poll_recv(&mut cx),
            Poll::Ready(Err(NativeRecvError::Reset(0xdead)))
        );
        native
            .channel()
            .send(Bytes::from_static(b"after"), Default::default())
            .unwrap();
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn local_connection_close_is_reported_as_lost() {
    tokio::time::timeout(LIMIT, async {
        let pair = Pair::in_memory(None, None).await;
        let (mut client, mut server) =
            start(&pair, server_config(Some(DatagramConfig::default()))).await;
        let (_client_io, mut server_io) = tunnel(&mut client, &mut server, TOKEN).await;
        let native = server_io
            .extensions()
            .get_ref::<NativeDatagrams>()
            .cloned()
            .unwrap();
        // This endpoint closes the connection, without a request FIN or RESET_STREAM.
        pair.server
            .close(VarInt::from_u32(Code::H3_NO_ERROR.value() as u32), b"done");
        _ = pair.server.closed().await;
        _ = server.shared().failed().await;
        let mut cx = Context::from_waker(Waker::noop());
        assert_eq!(
            native.channel().poll_recv(&mut cx),
            Poll::Ready(Err(NativeRecvError::Lost))
        );
        assert_eq!(
            stream_error(&mut server_io).await,
            Code::H3_REQUEST_INCOMPLETE
        );
        for _ in 0..2 {
            assert_eq!(
                native.channel().poll_recv(&mut cx),
                Poll::Ready(Err(NativeRecvError::Lost))
            );
        }
        pair.close().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn peer_resets_mid_frame_stay_terminal_for_tunnel_reads() {
    // The reset lands inside a DATA frame, after its header, and at a frame boundary.
    for (wire, readable) in [(&b"\x00\x05x"[..], 1), (b"\x00", 0), (b"\x00\x01x", 1)] {
        tokio::time::timeout(LIMIT, async {
            let pair = Pair::in_memory(None, None).await;
            let (mut client, _server) =
                start(&pair, server_config(Some(DatagramConfig::default()))).await;
            let (response, (mut peer_send, mut peer_recv)) =
                tokio::join!(client.send_request(connect(TOKEN, true)), raw_accept(&pair));
            let mut io = handle_upgrade(&response.unwrap()).await.unwrap();
            peer_send.write_all(wire).await.unwrap();
            for _ in 0..readable {
                assert_eq!(io.read_u8().await.unwrap(), b'x');
            }
            peer_send
                .reset(VarInt::from_u32(Code::H3_REQUEST_CANCELLED.value() as u32))
                .unwrap();
            // Every later read reports the same reset, never a connection frame error.
            for _ in 0..3 {
                assert_eq!(
                    stream_error(&mut io).await,
                    Code::H3_REQUEST_CANCELLED,
                    "{wire:?}"
                );
            }
            // The local send direction still reaches the peer.
            io.write_all(b"reverse").await.unwrap();
            io.flush().await.unwrap();
            let mut reverse = Vec::new();
            while reverse.len() < 7 {
                assert_eq!(peer_recv.read_u8().await.unwrap(), 0);
                let len = usize::from(peer_recv.read_u8().await.unwrap());
                let start = reverse.len();
                reverse.resize(start + len, 0);
                peer_recv.read_exact(&mut reverse[start..]).await.unwrap();
            }
            assert_eq!(&reverse, b"reverse");
            for _ in 0..2 {
                let (response, _raw) =
                    tokio::join!(client.send_request(connect(TOKEN, true)), raw_accept(&pair));
                assert_eq!(response.unwrap().status(), StatusCode::OK);
            }
            pair.close().await;
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn connection_loss_stays_lost_across_repeated_reads() {
    // Either tunnel end, either endpoint closing, clean or unknown code, either read order.
    for server_side in [true, false] {
        for local_close in [true, false] {
            for code in [Code::H3_NO_ERROR.value(), 0x1f0a] {
                for native_first in [true, false] {
                    tokio::time::timeout(LIMIT, async {
                        let pair = Pair::in_memory(None, None).await;
                        let (mut client, mut server) =
                            start(&pair, server_config(Some(DatagramConfig::default()))).await;
                        let (client_io, server_io) =
                            tunnel(&mut client, &mut server, TOKEN).await;
                        let (mut io, _other) = if server_side {
                            (server_io, client_io)
                        } else {
                            (client_io, server_io)
                        };
                        let native = io.extensions().get_ref::<NativeDatagrams>().cloned().unwrap();
                        let (this, peer) = if server_side {
                            (&pair.server, &pair.client)
                        } else {
                            (&pair.client, &pair.server)
                        };
                        let closer = if local_close { this } else { peer };
                        closer.close(VarInt::from_u64(code).unwrap(), b"done");
                        _ = this.closed().await;
                        if server_side {
                            _ = server.shared().failed().await;
                        } else {
                            _ = client.shared().failed().await;
                        }
                        let mut cx = Context::from_waker(Waker::noop());
                        let lost = Poll::Ready(Err(NativeRecvError::Lost));
                        if native_first {
                            assert_eq!(native.channel().poll_recv(&mut cx), lost);
                        }
                        let first = stream_error(&mut io).await;
                        for turn in 0..3 {
                            assert_eq!(
                                native.channel().poll_recv(&mut cx),
                                lost,
                                "server={server_side} local={local_close} code={code:#x} turn={turn}"
                            );
                            // Every reliable read repeats the same loss, never a stream abort.
                            assert_eq!(stream_error(&mut io).await, first);
                        }
                        pair.close().await;
                    })
                    .await
                    .unwrap();
                }
            }
        }
    }
}
