//! Native HTTP/2 preferences must survive pool checkout as well as first handshake.

#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "raw peer helpers fail immediately on fixture errors"
)]

use std::{
    io::ErrorKind,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use rama_core::{Service, extensions::ExtensionsRef as _, rt::Executor, service::service_fn};
use rama_http_backend::client::{
    HttpConnectRequestAdapter, HttpConnector, HttpPooledConnectorConfig,
};
use rama_http_types::{
    Body, Request, Version,
    body::util::BodyExt as _,
    conn::H2ClientContextParams,
    proto::h2::frame::{
        EarlyFrame, EarlyFrameStreamContext, Head, Kind, Setting, Settings, StreamId,
    },
};
use rama_net::{
    client::{ConnectRequest, ConnectionError, EstablishedClientConnection},
    test_utils::client::MockSocket,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream, duplex},
    sync::{Mutex, mpsc},
    task::JoinSet,
    time::timeout,
};

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

fn literal(entries: &[(u16, u32)]) -> Arc<Settings> {
    Arc::new(
        Settings::from_ordered_entries(
            entries
                .iter()
                .map(|(id, value)| Setting::new(*id, *value))
                .collect(),
        )
        .unwrap(),
    )
}

fn observed_settings(entries: &[(u16, u32)]) -> Arc<Settings> {
    let payload: Vec<u8> = entries
        .iter()
        .flat_map(|(id, value)| id.to_be_bytes().into_iter().chain(value.to_be_bytes()))
        .collect();
    Arc::new(
        Settings::load_observed(
            Head::new(Kind::Settings, 0, StreamId::zero()),
            &payload,
            true,
        )
        .unwrap(),
    )
}

fn frame_bytes(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(9 + payload.len());
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
    bytes.extend_from_slice(&[kind, flags]);
    bytes.extend_from_slice(&stream.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

/// Deliberately independent of the native SETTINGS/HPACK decoder.
async fn read_frame(peer: &mut DuplexStream) -> Option<(u8, u8, u32, Vec<u8>)> {
    let mut header = [0; 9];
    match peer.read_exact(&mut header).await {
        Ok(_) => (),
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset | ErrorKind::BrokenPipe
            ) =>
        {
            return None;
        }
        Err(error) => panic!("raw H2 read failed: {error}"),
    }
    let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
    let stream = u32::from_be_bytes(header[5..9].try_into().unwrap()) & 0x7fff_ffff;
    let mut payload = vec![0; length];
    peer.read_exact(&mut payload).await.unwrap();
    Some((header[3], header[4], stream, payload))
}

async fn raw_origin(
    mut peer: DuplexStream,
    id: usize,
    receipts: mpsc::UnboundedSender<(usize, Vec<(u16, u32)>)>,
) {
    let mut preface = [0; 24];
    peer.read_exact(&mut preface).await.unwrap();
    assert_eq!(preface, PREFACE);
    let (kind, flags, stream, payload) = read_frame(&mut peer).await.unwrap();
    assert_eq!((kind, flags, stream), (4, 0, 0));
    assert_eq!(payload.len() % 6, 0);
    let settings = payload
        .as_chunks::<6>()
        .0
        .iter()
        .map(|entry| {
            (
                u16::from_be_bytes(entry[..2].try_into().unwrap()),
                u32::from_be_bytes(entry[2..].try_into().unwrap()),
            )
        })
        .collect();
    receipts.send((id, settings)).unwrap();
    peer.write_all(&frame_bytes(4, 0, 0, &[])).await.unwrap();
    peer.write_all(&frame_bytes(4, 1, 0, &[])).await.unwrap();

    while let Some((kind, flags, stream, payload)) = read_frame(&mut peer).await {
        match kind {
            1 => {
                assert_ne!(flags & 4, 0, "small GET header block fits one frame");
                assert_ne!(flags & 1, 0, "fixture GET has no body");
                // HPACK static-table :status 200; body identifies the physical connection.
                peer.write_all(&frame_bytes(1, 4, stream, &[0x88]))
                    .await
                    .unwrap();
                peer.write_all(&frame_bytes(0, 1, stream, id.to_string().as_bytes()))
                    .await
                    .unwrap();
            }
            4 if flags & 1 == 0 => peer.write_all(&frame_bytes(4, 1, 0, &[])).await.unwrap(),
            6 if flags & 1 == 0 => peer
                .write_all(&frame_bytes(6, 1, 0, &payload))
                .await
                .unwrap(),
            7 => return,
            _ => (),
        }
    }
}

#[tokio::test]
async fn native_h2_wire_preferences_partition_actual_pool_connections_by_value() {
    timeout(Duration::from_secs(10), async {
        let connections = Arc::new(AtomicUsize::new(0));
        let tasks = Arc::new(Mutex::new(JoinSet::new()));
        let (receipts, mut observed) = mpsc::unbounded_channel();
        let transport = service_fn({
            let connections = connections.clone();
            let tasks = tasks.clone();
            move |input: ConnectRequest| {
                let id = connections.fetch_add(1, Ordering::Relaxed);
                let tasks = tasks.clone();
                let receipts = receipts.clone();
                async move {
                    let (client, peer) = duplex(65536);
                    tasks.lock().await.spawn(raw_origin(peer, id, receipts));
                    Ok::<_, ConnectionError>(EstablishedClientConnection {
                        input,
                        conn: MockSocket::new(client),
                    })
                }
            }
        });
        let connector = HttpConnectRequestAdapter::new(
            HttpPooledConnectorConfig {
                idle_timeout: None,
                ..Default::default()
            }
            .build_connector(HttpConnector::<_, Body>::new(transport, Executor::new())),
        );

        let first = vec![(2, 0), (4, 65535), (6, 1048576)];
        let reordered = vec![(6, 1048576), (2, 0), (4, 65535)];
        let repeated = vec![(2, 0), (0xa0a1, 7), (1, 32), (1, 64), (4, 65535)];
        let changed_unknown = vec![(2, 0), (0xa0a1, 8), (1, 32), (1, 64), (4, 65535)];
        let exact = |entries: &[(u16, u32)]| H2ClientContextParams {
            initial_settings: Some(literal(entries)),
            ..Default::default()
        };
        let replay = |entries: &[(u16, u32)]| H2ClientContextParams {
            replay_early_frames: Some([EarlyFrame::Settings((*literal(entries)).clone())].into()),
            ..Default::default()
        };
        let mut replay_with_ignored_legacy = replay(&first);
        let mut recorder = EarlyFrameStreamContext::new_recorder();
        recorder.record_settings_frame(&literal(&reordered));
        replay_with_ignored_legacy.early_frames = recorder.freeze_recorder();
        let cases = [
            (None, 0, None),
            (Some(H2ClientContextParams::default()), 0, None),
            (Some(exact(&first)), 1, Some(first.clone())),
            (Some(exact(&first)), 1, None),
            (Some(exact(&reordered)), 2, Some(reordered.clone())),
            (Some(exact(&repeated)), 3, Some(repeated.clone())),
            (
                Some(H2ClientContextParams {
                    initial_settings: Some(observed_settings(&repeated)),
                    ..Default::default()
                }),
                3,
                None,
            ),
            (Some(exact(&changed_unknown)), 4, Some(changed_unknown)),
            (Some(exact(&first)), 1, None),
            (
                Some(H2ClientContextParams {
                    header_table_size: Some(0),
                    ..Default::default()
                }),
                5,
                None,
            ),
            (
                Some(H2ClientContextParams {
                    header_table_size: Some(0),
                    ..Default::default()
                }),
                5,
                None,
            ),
            (
                Some(H2ClientContextParams {
                    header_table_size: Some(1),
                    ..Default::default()
                }),
                6,
                None,
            ),
            (Some(replay(&first)), 7, Some(first.clone())),
            (Some(replay_with_ignored_legacy), 7, None),
            (Some(replay(&reordered)), 8, Some(reordered)),
            (
                Some(H2ClientContextParams {
                    max_send_buf_size: Some(1024),
                    initial_max_send_streams: Some(4),
                    ..Default::default()
                }),
                0,
                None,
            ),
        ];
        let mut next_connection = 0;
        for (params, expected_connection, expected_settings) in cases {
            let request = Request::builder()
                .uri("http://origin.test/pool")
                .version(Version::HTTP_2)
                .body(Body::empty())
                .unwrap();
            if let Some(params) = params {
                request.extensions().insert(params);
            }
            let established = connector.serve(request).await.unwrap();
            let response = established.conn.serve(established.input).await.unwrap();
            assert_eq!(response.version(), Version::HTTP_2);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(body.as_ref(), expected_connection.to_string().as_bytes());

            if expected_connection == next_connection {
                let (id, entries) = observed.recv().await.unwrap();
                assert_eq!(id, expected_connection);
                if let Some(expected) = expected_settings {
                    assert_eq!(entries, expected);
                }
                if id == 5 {
                    assert!(entries.contains(&(1, 0)));
                }
                if id == 6 {
                    assert!(entries.contains(&(1, 1)));
                }
                next_connection += 1;
            }
            assert_eq!(connections.load(Ordering::Relaxed), next_connection);
        }
        assert_eq!(next_connection, 9);
        drop(connector);
        let mut tasks = tasks.lock().await;
        tasks.abort_all();
        while let Some(result) = tasks.join_next().await {
            if let Err(error) = result {
                assert!(error.is_cancelled(), "raw peer failed: {error}");
            }
        }
    })
    .await
    .unwrap();
}
