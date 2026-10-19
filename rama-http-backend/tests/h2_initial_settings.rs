//! Initial H2 frames use one native configuration for wire bytes and receiver state.
//! Raw peers deliberately wait on opposite prefaces/settings to expose startup cycles.

#![expect(
    clippy::unwrap_used,
    reason = "raw peer helpers fail immediately on fixture errors"
)]

use rama_core::{
    Service,
    bytes::{Bytes, BytesMut},
    extensions::ExtensionsRef as _,
    io::BridgeIo,
    rt::Executor,
    service::service_fn,
};
use rama_http::{
    Body, Request, Response, Version,
    body::util::BodyExt as _,
    conn::{H2ClientContextParams, H2ServerContextParams, H2SettingsLimits, TargetHttpVersion},
};
use rama_http_backend::{
    client::http2_eager_handshake, proxy::mitm::HttpMitmRelay, server::HttpServer,
};
use rama_http_core::{
    client::conn::http2::Builder as CoreH2ClientBuilder,
    h2::server::inspect_client_initial_settings,
};
use rama_http_types::proto::h2::frame::{
    EarlyFrame, Head, Kind, Setting, SettingId, Settings, StreamId, WindowUpdate,
};
use rama_net::test_utils::client::MockSocket;
use rama_utils::octets::mib_u32;
use std::{convert::Infallible, future::pending, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream},
    time::timeout,
};

const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

fn settings(entries: &[(u16, u32)]) -> Arc<Settings> {
    Arc::new(
        Settings::from_ordered_entries(
            entries
                .iter()
                .map(|(id, value)| Setting {
                    id: SettingId::from(*id),
                    value: *value,
                })
                .collect(),
        )
        .unwrap(),
    )
}

fn window_update(increment: u32) -> Bytes {
    let mut frame = vec![0, 0, 4, 8, 0, 0, 0, 0, 0];
    frame.extend_from_slice(&increment.to_be_bytes());
    Bytes::from(frame)
}

fn encoded(frame: &Settings) -> Bytes {
    let mut bytes = BytesMut::new();
    frame.encode(&mut bytes);
    bytes.freeze()
}

/// Independent raw-byte oracle; it does not use the native Settings decoder.
async fn first_settings(peer: &mut DuplexStream, client: bool) -> Vec<(u16, u32)> {
    if client {
        let mut preface = [0; 24];
        peer.read_exact(&mut preface).await.unwrap();
        assert_eq!(preface, CLIENT_PREFACE);
    }
    let mut header = [0; 9];
    peer.read_exact(&mut header).await.unwrap();
    assert_eq!(header[3], 4, "first frame must be SETTINGS");
    assert_eq!(header[4], 0, "initial settings cannot be an ACK");
    assert_eq!(&header[5..], &[0; 4]);
    let len = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
    assert_eq!(len % 6, 0);
    let mut payload = vec![0; len];
    peer.read_exact(&mut payload).await.unwrap();
    payload
        .as_chunks::<6>()
        .0
        .iter()
        .map(|entry| {
            (
                u16::from_be_bytes([entry[0], entry[1]]),
                u32::from_be_bytes([entry[2], entry[3], entry[4], entry[5]]),
            )
        })
        .collect()
}

#[tokio::test]
async fn whole_frame_contexts_emit_exact_order_duplicates_and_absence_in_both_roles() {
    timeout(Duration::from_secs(5), async {
        for entries in [
            vec![],
            vec![
                (5, 32768),
                (1, 32),
                (1, 64),
                (6, 1048576),
                (4, 0),
                (3, 0),
                (0xa0a1, 9),
            ],
        ] {
            let (io, mut peer) = tokio::io::duplex(65536);
            let io = MockSocket::new(io);
            io.extensions().insert(H2ClientContextParams {
                initial_settings: Some(settings(&entries)),
                ..Default::default()
            });
            let task = tokio::spawn(async move {
                let (_client, _) = http2_eager_handshake::<_, Body>(io, Executor::default())
                    .await
                    .unwrap();
                pending::<()>().await;
            });
            assert_eq!(first_settings(&mut peer, true).await, entries);
            task.abort();

            let (io, mut peer) = tokio::io::duplex(65536);
            let io = MockSocket::new(io);
            io.extensions().insert(H2ServerContextParams {
                initial_settings: Some(settings(&entries)),
                ..Default::default()
            });
            let task = tokio::spawn(async move {
                HttpServer::new_h2(Executor::default())
                    .serve(
                        io,
                        service_fn(|_: Request| async {
                            Ok::<_, Infallible>(Response::new(Body::empty()))
                        }),
                    )
                    .await
                    .unwrap();
            });
            // Native server must emit SETTINGS without waiting for any client input.
            assert_eq!(first_settings(&mut peer, false).await, entries);
            task.abort();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn exact_server_advertisement_drives_real_frame_header_and_stream_limits() {
    timeout(Duration::from_secs(5), async {
        let (client, server) = tokio::io::duplex(262144);
        let server = MockSocket::new(server);
        server.extensions().insert(H2ServerContextParams {
            initial_settings: Some(settings(&[(1, 0), (5, 32768), (6, 131072), (4, 128)])),
            ..Default::default()
        });
        let task = tokio::spawn(async move {
            HttpServer::new_h2(Executor::default())
                .serve(
                    server,
                    service_fn(|request: Request| async {
                        assert_eq!(request.headers()["x-long"].as_bytes().len(), 50000);
                        let data = request.into_body().collect().await.unwrap().to_bytes();
                        assert_eq!(data.as_ref(), &[7; 512]);
                        Ok::<_, Infallible>(Response::new(Body::from(data)))
                    }),
                )
                .await
                .unwrap();
        });
        let request = Request::builder()
            .uri("https://origin.example/test")
            .version(Version::HTTP_2)
            .header("x-long", "h".repeat(50000))
            .body(Body::from(vec![7; 512]))
            .unwrap();
        let (mut sender, connection) = CoreH2ClientBuilder::new(Executor::default())
            .with_observe_peer_settings(true)
            .handshake(MockSocket::new(client))
            .await
            .unwrap();
        let peer = connection.peer_settings_handle();
        let driver = tokio::spawn(async move { connection.await.unwrap() });
        let observed = peer.await_settings().await.unwrap();
        assert_eq!(observed.0.config.max_frame_size, Some(32768));
        let response = sender.send_request(request).await.unwrap();
        assert_eq!(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .as_ref(),
            &[7; 512]
        );
        driver.abort();
        task.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn relay_observes_mandatory_client_settings_without_waiting_for_request_headers() {
    timeout(Duration::from_secs(5), async {
        let downstream = vec![(2, 0), (4, 4194304), (6, 10485760), (1, 8192), (5, 32768)];
        let upstream = vec![(6, 10485760), (3, 100), (5, 32768), (1, 4096), (4, 4194304)];
        let (mut client, ingress) = tokio::io::duplex(65536);
        let (egress, mut origin) = tokio::io::duplex(65536);
        let egress = MockSocket::new(egress);
        egress
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_2));
        let relay = tokio::spawn(async move {
            HttpMitmRelay::new(Executor::default())
                .serve(BridgeIo(MockSocket::new(ingress), egress))
                .await
        });
        let expected = downstream.clone();
        let origin_settings = encoded(&settings(&upstream));
        let origin = tokio::spawn(async move {
            // Origin waits for the client's preface AND SETTINGS before sending any.
            assert_eq!(first_settings(&mut origin, true).await, expected);
            origin.write_all(&origin_settings).await.unwrap();
            pending::<()>().await;
        });
        let client_settings = encoded(&settings(&downstream));
        for byte in CLIENT_PREFACE.iter().chain(client_settings.iter()) {
            client.write_all(&[*byte]).await.unwrap();
            tokio::task::yield_now().await;
        }
        // Client deliberately waits for server SETTINGS before sending HEADERS.
        assert_eq!(first_settings(&mut client, false).await, upstream);
        assert!(!relay.is_finished());
        relay.abort();
        origin.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn native_prefix_preserves_read_ahead_and_short_non_h2_input() {
    timeout(Duration::from_secs(5), async {
        let expected = settings(&[(2, 0), (4, 4194304)]);
        for (later, increment) in [
            (window_update(15_663_105), Some(15_663_105)),
            (window_update(0x8000_0001), Some(1)),
            (window_update(0), None),
            (Bytes::from_static(b"unread later frames"), None),
        ] {
            let (mut peer, io) = tokio::io::duplex(65536);
            let mut all = CLIENT_PREFACE.to_vec();
            all.extend_from_slice(&encoded(&expected));
            all.extend_from_slice(&later);
            peer.write_all(&all).await.unwrap();
            peer.shutdown().await.unwrap();
            let (mut io, observed) = inspect_client_initial_settings(MockSocket::new(io))
                .await
                .unwrap();
            let observed = observed.unwrap();
            assert_eq!(observed.settings.to_literal().unwrap(), *expected);
            assert_eq!(observed.connection_window_increment, increment);
            let mut replay = Vec::new();
            io.read_to_end(&mut replay).await.unwrap();
            assert_eq!(replay, all, "every consumed byte is rewound");
        }

        let (mut peer, io) = tokio::io::duplex(32);
        peer.write_all(b"G").await.unwrap();
        let (mut io, observed) = inspect_client_initial_settings(MockSocket::new(io))
            .await
            .unwrap();
        assert!(observed.is_none());
        peer.shutdown().await.unwrap();
        let mut replay = Vec::new();
        io.read_to_end(&mut replay).await.unwrap();
        assert_eq!(replay, b"G");
    })
    .await
    .unwrap();
}

/// Relay `client_frames` to an origin: what the origin's first SETTINGS hold and the
/// increment of its next frame, when that is a connection WINDOW_UPDATE.
async fn relayed_client_start(
    client_frames: &[Bytes],
    limits: Option<H2SettingsLimits>,
) -> (Vec<(u16, u32)>, Option<u32>) {
    let (mut client, ingress) = tokio::io::duplex(65536);
    let (egress, mut origin) = tokio::io::duplex(65536);
    let egress = MockSocket::new(egress);
    egress
        .extensions()
        .insert(TargetHttpVersion(Version::HTTP_2));
    if let Some(limits) = limits {
        egress.extensions().insert(limits);
    }
    let relay = tokio::spawn(async move {
        HttpMitmRelay::new(Executor::default())
            .serve(BridgeIo(MockSocket::new(ingress), egress))
            .await
    });
    client.write_all(CLIENT_PREFACE).await.unwrap();
    client.write_all(&client_frames.concat()).await.unwrap();
    let settings = first_settings(&mut origin, true).await;
    let mut header = [0; 9];
    origin.read_exact(&mut header).await.unwrap();
    let increment = if header[3] == 8 && header[5..] == [0; 4] {
        let mut payload = [0; 4];
        origin.read_exact(&mut payload).await.unwrap();
        Some(u32::from_be_bytes(payload))
    } else {
        None
    };
    relay.abort();
    (settings, increment)
}

#[tokio::test]
async fn client_settings_are_forwarded_and_lowered_never_refused() {
    timeout(Duration::from_secs(5), async {
        let mut wide = H2SettingsLimits::default();
        wide.header_table_size = 65537;
        for (entries, limits, expected) in [
            // Push stays the client's choice; the relay drops any pushes itself.
            (vec![(4, 65535)], None, vec![(4, 65535)]),
            (vec![(2, 1)], None, vec![(2, 1)]),
            (vec![(2, 0), (1, 65537)], None, vec![(2, 0), (1, 65536)]),
            (
                vec![(2, 0), (1, 65537)],
                Some(wide),
                vec![(2, 0), (1, 65537)],
            ),
            (
                vec![(6, 16777217), (2, 0)],
                None,
                vec![(6, 16777216), (2, 0)],
            ),
        ] {
            let (settings, _) = relayed_client_start(&[encoded(&settings(&entries))], limits).await;
            assert_eq!(settings, expected, "{entries:?}");
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn egress_starts_from_the_clients_initial_connection_credit() {
    timeout(Duration::from_secs(5), async {
        let start = encoded(&settings(&[(2, 0), (4, 6291456)]));
        for (update, expected) in [
            (Some(15_663_105), Some(15_663_105)),
            (Some(u32::MAX >> 1), Some(mib_u32(16))),
            // Without an observed update egress keeps its native 5 MiB window.
            (None, Some(mib_u32(5) - 65_535)),
        ] {
            let mut frames = vec![start.clone()];
            frames.extend(update.map(window_update));
            let (_, increment) = relayed_client_start(&frames, None).await;
            assert_eq!(increment, expected, "{update:?}");
        }
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn prefix_and_upstream_settings_share_one_absolute_deadline() {
    let (mut client, ingress) = tokio::io::duplex(65536);
    let (egress, mut origin) = tokio::io::duplex(65536);
    let egress = MockSocket::new(egress);
    egress
        .extensions()
        .insert(TargetHttpVersion(Version::HTTP_2));
    let relay = tokio::spawn(async move {
        HttpMitmRelay::new(Executor::default())
            .with_eager_peer_settings_timeout(Duration::from_secs(5))
            .serve(BridgeIo(MockSocket::new(ingress), egress))
            .await
    });
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(4)).await;
    client.write_all(CLIENT_PREFACE).await.unwrap();
    client
        .write_all(&encoded(&settings(&[(2, 0)])))
        .await
        .unwrap();
    first_settings(&mut origin, true).await;
    // The silent upstream gets no fresh five-second budget: at the shared
    // deadline the client receives the relay's own SETTINGS instead.
    tokio::time::advance(Duration::from_secs(1)).await;
    let mut header = [0; 9];
    client.read_exact(&mut header).await.unwrap();
    assert_eq!(header[3], 4, "the relay's own SETTINGS reach the client");
    assert!(!relay.is_finished());
    relay.abort();
}

#[tokio::test]
async fn native_prefix_rejects_ack_invalid_values_and_incomplete_observation() {
    timeout(Duration::from_secs(5), async {
        let mut excessive = Vec::new();
        for _ in 0..257 {
            excessive.push((1, 4096));
        }
        let mut malformed_value = vec![0, 0, 6, 4, 0, 0, 0, 0, 0];
        malformed_value.extend_from_slice(&[0, 5, 0, 0, 0, 0]);
        for frame in [
            encoded(&Settings::ack()),
            Bytes::from(malformed_value),
            encoded(&settings(&excessive)),
        ] {
            let (mut peer, io) = tokio::io::duplex(65536);
            peer.write_all(CLIENT_PREFACE).await.unwrap();
            peer.write_all(&frame).await.unwrap();
            inspect_client_initial_settings(MockSocket::new(io))
                .await
                .expect_err("invalid initial SETTINGS must fail");
        }
        let (mut peer, io) = tokio::io::duplex(65536);
        peer.write_all(&CLIENT_PREFACE[..10]).await.unwrap();
        peer.shutdown().await.unwrap();
        inspect_client_initial_settings(MockSocket::new(io))
            .await
            .expect_err("incomplete preface must fail");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn explicit_initial_settings_replace_only_the_replay_leading_frame_and_its_state() {
    timeout(Duration::from_secs(5), async {
        let leading = settings(&[(2, 0), (4, 64)]);
        let explicit = settings(&[(4, 128), (2, 0)]);
        let later = settings(&[(6, 131072)]);
        let (io, mut peer) = tokio::io::duplex(65536);
        let io = MockSocket::new(io);
        io.extensions().insert(H2ClientContextParams {
            initial_settings: Some(explicit.clone()),
            replay_early_frames: Some(
                vec![
                    EarlyFrame::Settings((*leading).clone()),
                    EarlyFrame::WindowUpdate(WindowUpdate::new(StreamId::zero(), 27)),
                    EarlyFrame::Settings((*later).clone()),
                ]
                .into(),
            ),
            ..Default::default()
        });
        let task = tokio::spawn(async move {
            let (client, server_settings) =
                http2_eager_handshake::<_, Body>(io, Executor::default())
                    .await
                    .unwrap();
            server_settings.await_settings().await.unwrap();
            let request = Request::builder()
                .uri("https://origin.example/lifecycle")
                .version(Version::HTTP_2)
                .body(Body::empty())
                .unwrap();
            client
                .serve(request)
                .await
                .unwrap()
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
        });
        assert_eq!(first_settings(&mut peer, true).await, [(4, 128), (2, 0)]);
        let (kind, flags, stream, payload) = read_frame(&mut peer).await;
        assert_eq!((kind, flags, stream), (8, 0, 0));
        assert_eq!(payload, 27u32.to_be_bytes());
        peer.write_all(&encoded(&Settings::default()))
            .await
            .unwrap();
        peer.write_all(&encoded(&Settings::ack())).await.unwrap();
        let mut request_stream = None;
        let mut later_seen = false;
        let mut credit_count = 1;
        while request_stream.is_none() || !later_seen {
            let (kind, flags, stream, payload) = read_frame(&mut peer).await;
            match kind {
                4 if flags == 0 => {
                    assert_eq!(stream, 0);
                    assert_eq!(payload, &encoded(&later)[9..]);
                    assert!(!later_seen, "later SETTINGS replayed more than once");
                    later_seen = true;
                    peer.write_all(&encoded(&Settings::ack())).await.unwrap();
                }
                1 => request_stream = Some(stream),
                8 if stream == 0 => credit_count += 1,
                4 if flags == 1 => assert!(payload.is_empty()),
                _ => panic!("unexpected startup frame {kind}/{flags}/{stream}"),
            }
        }
        assert_eq!(credit_count, 1, "initial credit must not be emitted twice");
        let stream = StreamId::from(request_stream.unwrap());
        let mut response = BytesMut::new();
        Head::new(Kind::Headers, 4, stream).encode(1, &mut response);
        response.extend_from_slice(&[0x88]); // independently encoded :status 200
        Head::new(Kind::Data, 1, stream).encode(96, &mut response);
        response.extend_from_slice(&[7; 96]);
        peer.write_all(&response).await.unwrap();
        // This fits explicit B's window128 but exceeds discarded A's window64.
        assert_eq!(task.await.unwrap().as_ref(), &[7; 96]);
    })
    .await
    .unwrap();
}

async fn read_frame(peer: &mut DuplexStream) -> (u8, u8, u32, Vec<u8>) {
    let mut header = [0; 9];
    peer.read_exact(&mut header).await.unwrap();
    let len = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
    let mut payload = vec![0; len];
    peer.read_exact(&mut payload).await.unwrap();
    (
        header[3],
        header[4],
        u32::from_be_bytes(header[5..].try_into().unwrap()) & 0x7fff_ffff,
        payload,
    )
}
