//! HTTP Datagrams (RFC 9297): capsule decoding and skipping, native demultiplexing as the
//! number of sessions grows, and a stalled session's effect on its neighbours, over real
//! HTTP/3 on localhost.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "benchmark setup and protocol assertions"
)]

use rama::{
    bytes::{Bytes, BytesMut},
    extensions::ExtensionsRef as _,
    http::{
        Body, Method, Request, Response, StatusCode,
        core::h3::{client, connection::Config, server},
        datagram::{
            HttpDatagramSession, SessionEvent,
            capsule::{CapsuleConfig, CapsuleDecoder, CapsuleEvent, encode_capsule},
        },
        io::upgrade::{Upgraded, handle_upgrade},
        proto::{
            capsule::CapsuleType,
            ext::{HttpDatagrams, Protocol},
        },
    },
    net::{address::SocketAddress, tls::ApplicationProtocol},
    quic::{Endpoint, TransportConfig, tls::TlsOptions},
    rt::Executor,
    tls::{
        client::TlsClientConfig,
        server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
    },
    utils::octets::{kib, mib},
};
use std::{sync::Arc, time::Duration};
use tokio::runtime::Runtime;

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    divan::main();
}

const TOKEN: Protocol = Protocol::from_static("x-datagram-bench");
const CAPSULES: usize = 256;
const PAYLOAD: usize = 64;
const LOST: Duration = Duration::from_secs(5);

/// `CAPSULES` DATAGRAM capsules of `PAYLOAD` bytes each.
fn datagram_capsules() -> Bytes {
    let capsule = encode_capsule(CapsuleType::DATAGRAM, &[7; PAYLOAD]).unwrap();
    let mut stream = BytesMut::with_capacity(capsule.len() * CAPSULES);
    for _ in 0..CAPSULES {
        stream.extend_from_slice(&capsule);
    }
    stream.freeze()
}

/// Decode a stream of DATAGRAM capsules fed in `chunk`-sized pieces.
#[divan::bench(args = [1, 16, 1400, kib(64)])]
fn capsule_decode(bencher: divan::Bencher, chunk: usize) {
    let stream = datagram_capsules();
    bencher
        .counter(divan::counter::BytesCount::new(stream.len()))
        .bench(|| {
            let mut decoder = CapsuleDecoder::new(CapsuleConfig::default());
            let mut received = 0;
            let mut offset = 0;
            while offset < stream.len() {
                let end = (offset + chunk).min(stream.len());
                decoder.feed(stream.slice(offset..end)).unwrap();
                offset = end;
                while let Some(event) = decoder.poll().unwrap() {
                    if let CapsuleEvent::Datagram(payload) = event {
                        received += 1;
                        divan::black_box(payload);
                    }
                }
            }
            assert_eq!(received, CAPSULES);
        });
}

/// Skip one unknown 1 MiB capsule fed in `chunk`-sized pieces: nothing is buffered.
#[divan::bench(args = [1400, kib(16)])]
fn capsule_skip(bencher: divan::Bencher, chunk: usize) {
    let unknown = encode_capsule(CapsuleType::new(0x2d).unwrap(), &vec![0; mib(1)]).unwrap();
    bencher
        .counter(divan::counter::BytesCount::new(unknown.len()))
        .bench(|| {
            let mut decoder = CapsuleDecoder::new(CapsuleConfig::default());
            let mut offset = 0;
            while offset < unknown.len() {
                let end = (offset + chunk).min(unknown.len());
                decoder.feed(unknown.slice(offset..end)).unwrap();
                offset = end;
                assert!(decoder.poll().unwrap().is_none());
            }
            decoder.finish().unwrap();
        });
}

/// A client and server HTTP/3 connection over localhost UDP, with Extended CONNECT and
/// native datagrams.
struct Connection {
    rt: Runtime,
    client: client::SendRequest<Body>,
    server: server::Connection,
    client_endpoint: Endpoint,
    server_endpoint: Endpoint,
}

impl Connection {
    fn new() -> Self {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (client, server, client_endpoint, server_endpoint) = rt.block_on(async {
            let auth = ServerAuthData::new_generated(GeneratedServerAuthConfig::default()).unwrap();
            let client_tls = TlsClientConfig::new()
                .try_with_server_trust_anchors(auth.cert_chain.clone())
                .unwrap()
                .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
            let server_tls = TlsServerConfig::new()
                .with_server_auth(auth)
                .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
            let config = Config {
                extended_connect: true,
                max_requests: 1024,
                ..Config::default()
            };
            let mut transport = TransportConfig::default();
            config.configure_transport(&mut transport).unwrap();
            let transport = Arc::new(transport);
            let mut server_config =
                rama::quic::ServerConfig::try_from_rama_tls(&server_tls, TlsOptions::default())
                    .unwrap();
            server_config.set_transport_config(transport.clone());
            let mut client_config =
                rama::quic::ClientConfig::try_from_rama_tls(&client_tls, TlsOptions::default())
                    .unwrap();
            client_config.set_transport_config(transport);
            let bind = SocketAddress::local_ipv4(0);
            let server_endpoint = Endpoint::build(Executor::new())
                .with_server_config(server_config)
                .bind_address(bind)
                .await
                .unwrap();
            let accept = tokio::spawn({
                let endpoint = server_endpoint.clone();
                let config = config.clone();
                async move {
                    let connection = endpoint.accept().await.unwrap().await.unwrap();
                    let (server, driver) = server::handshake(connection, config).unwrap();
                    tokio::spawn(driver.run());
                    server
                }
            });
            let client_endpoint = Endpoint::build(Executor::new())
                .bind_address(bind)
                .await
                .unwrap();
            let connection = client_endpoint
                .connect_with(
                    client_config,
                    server_endpoint.local_addr().unwrap(),
                    "localhost",
                )
                .unwrap()
                .await
                .unwrap();
            let (client, driver) =
                client::handshake::<Body>(connection, config, Executor::new()).unwrap();
            tokio::spawn(driver.run());
            let server = accept.await.unwrap();
            (client, server, client_endpoint, server_endpoint)
        });
        Self {
            rt,
            client,
            server,
            client_endpoint,
            server_endpoint,
        }
    }

    /// Open a session; both sides declare datagram semantics.
    fn session(&mut self) -> (HttpDatagramSession, HttpDatagramSession) {
        let (client, server) = (&mut self.client, &mut self.server);
        let (client_io, server_io) = self.rt.block_on(async {
            let request = Request::builder()
                .method(Method::CONNECT)
                .uri("https://localhost/datagrams")
                .body(Body::empty())
                .unwrap();
            request.extensions().insert(TOKEN);
            request.extensions().insert(HttpDatagrams);
            let accept = async {
                let (request, response) = server.accept().await.unwrap().resolve().await.unwrap();
                let upgrade = handle_upgrade(&request);
                let accepted = Response::new(Body::empty());
                accepted.extensions().insert(HttpDatagrams);
                response.send_response(accepted).await.unwrap();
                upgrade.await.unwrap()
            };
            let (response, server_io): (_, Upgraded) =
                tokio::join!(client.send_request(request), accept);
            let response = response.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            (handle_upgrade(&response).await.unwrap(), server_io)
        });
        let client = HttpDatagramSession::new(client_io);
        // Native sending needs both SETTINGS; observe it rather than assuming.
        self.rt.block_on(async {
            while client
                .native()
                .and_then(|native| native.channel().max_payload_size())
                .is_none()
            {
                tokio::task::yield_now().await;
            }
        });
        (client, HttpDatagramSession::new(server_io))
    }

    /// Echo every datagram of `session` until it ends.
    fn echo(&self, mut session: HttpDatagramSession) {
        self.rt.spawn(async move {
            while let Ok(Some(event)) = session.recv().await {
                if let SessionEvent::Datagram { payload, .. } = event
                    && session.send_datagram(payload).await.is_err()
                {
                    return;
                }
            }
        });
    }

    fn close(self) {
        self.rt.block_on(async {
            self.client_endpoint.close(0u32, b"benchmark complete");
            self.server_endpoint.close(0u32, b"benchmark complete");
            tokio::join!(
                self.client_endpoint.shutdown(),
                self.server_endpoint.shutdown()
            );
        });
    }
}

/// Round trip one native datagram through the echo of each session.
async fn round_trip(sessions: &mut [HttpDatagramSession], payload: &Bytes) {
    for session in sessions.iter_mut() {
        session.send_datagram(payload.clone()).await.unwrap();
    }
    for session in sessions.iter_mut() {
        // Unreliable even on localhost: fail loudly instead of hanging on a lost one.
        let echoed = tokio::time::timeout(LOST, session.recv())
            .await
            .expect("a datagram was lost on localhost")
            .unwrap();
        assert!(matches!(echoed, Some(SessionEvent::Datagram { .. })));
    }
}

/// One native round trip on one session while `sessions` sessions share the connection.
#[divan::bench(args = [1, 16, 256], sample_count = 20)]
fn native_round_trip(bencher: divan::Bencher, sessions: usize) {
    let mut connection = Connection::new();
    let mut idle = Vec::with_capacity(sessions);
    for _ in 0..sessions {
        let (client, server) = connection.session();
        connection.echo(server);
        idle.push(client);
    }
    let mut active = idle.split_off(sessions - 1);
    let payload = Bytes::from(vec![42; PAYLOAD]);
    bencher.bench_local(|| connection.rt.block_on(round_trip(&mut active, &payload)));
    drop((active, idle));
    connection.close();
}

/// A native round trip on every one of `sessions` sessions.
#[divan::bench(args = [16, 256], sample_count = 20)]
fn native_fan_out(bencher: divan::Bencher, sessions: usize) {
    let mut connection = Connection::new();
    let mut active = Vec::with_capacity(sessions);
    for _ in 0..sessions {
        let (client, server) = connection.session();
        connection.echo(server);
        active.push(client);
    }
    let payload = Bytes::from(vec![42; PAYLOAD]);
    bencher
        .counter(divan::counter::ItemsCount::new(sessions))
        .bench_local(|| connection.rt.block_on(round_trip(&mut active, &payload)));
    drop(active);
    connection.close();
}

/// A round trip beside a neighbour receiving a burst per iteration that it never reads
/// (its queue stays full and drops) or that is drained as it arrives.
#[divan::bench(args = [false, true], sample_count = 20)]
fn beside_a_flooded_neighbour(bencher: divan::Bencher, stalled: bool) {
    const BURST: usize = 64;
    let mut connection = Connection::new();
    let (client, server) = connection.session();
    connection.echo(server);
    let mut active = [client];
    let (mut neighbour, mut unread) = connection.session();
    if !stalled {
        connection
            .rt
            .spawn(async move { while let Ok(Some(_)) = unread.recv().await {} });
    } else {
        // Held unread: the server keeps it registered with a full queue.
        connection.rt.spawn(async move {
            std::future::pending::<()>().await;
            drop(unread);
        });
    }
    let payload = Bytes::from(vec![42; PAYLOAD]);
    bencher.bench_local(|| {
        connection.rt.block_on(async {
            for _ in 0..BURST {
                neighbour.send_datagram(payload.clone()).await.unwrap();
            }
            round_trip(&mut active, &payload).await;
        })
    });
    // The stalled neighbour really was full: its queue displaced datagrams while timing.
    let displaced = connection.server.datagram_drops().queue_full;
    assert_eq!(stalled, displaced > 0, "queue_full = {displaced}");
    drop((active, neighbour));
    connection.close();
}

/// A consumer resuming after a stall: its full queue is drained up to a fresh datagram.
#[divan::bench(sample_count = 20)]
fn stalled_consumer_recovery(bencher: divan::Bencher) {
    // Twice the default per-request queue: the oldest half is displaced.
    const FLOOD: usize = 64;
    let mut connection = Connection::new();
    let (mut sender, mut consumer) = connection.session();
    let payload = Bytes::from(vec![42; PAYLOAD]);
    let marker = Bytes::from(vec![43; PAYLOAD]);
    let mut displaced = 0;
    bencher
        .with_inputs(|| {
            connection.rt.block_on(async {
                for _ in 0..FLOOD - 1 {
                    sender.send_datagram(payload.clone()).await.unwrap();
                }
                sender.send_datagram(marker.clone()).await.unwrap();
                // Everything arrived: kept or displaced, while nobody read.
                displaced += FLOOD as u64 / 2;
                while connection.server.datagram_drops().queue_full < displaced {
                    tokio::task::yield_now().await;
                }
            });
        })
        .bench_local_values(|()| {
            connection.rt.block_on(async {
                let mut drained = 0;
                loop {
                    let event = consumer.recv().await.unwrap().expect("session ended");
                    drained += 1;
                    if matches!(event, SessionEvent::Datagram { payload, .. } if payload == marker)
                    {
                        break;
                    }
                }
                assert_eq!(drained, FLOOD / 2);
            })
        });
    drop((sender, consumer));
    connection.close();
}
