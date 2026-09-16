//! Established, authenticated QUIC loopback throughput and stream-churn baselines.
//!
//! Connections, persistent bulk streams, receive buffers, and warmup are prepared outside
//! measurement. Bulk transfers 1 MiB per stream before an application acknowledgement;
//! RPC opens a new stream for each verified 4 KiB request and response. Cases name
//! connection count and concurrent streams per connection. Byte rates count payload only.
//! Current-thread Divan allocations cover both endpoints and the driver. Multi-thread
//! Divan allocations exclude runtime worker allocations. Both include future orchestration,
//! payload verification, and deadline polling; endpoint shutdown is outside measurement.
//! The inline-app variants poll application futures in one task. The spawned-app variant
//! runs one persistent task per stream on four runtime workers; channel dispatch and
//! completion notifications are measured, while task creation and joining are excluded.
#![expect(clippy::unwrap_used, reason = "benchmark failures must fail the run")]

use divan::{AllocProfiler, black_box, counter::BytesCount};
use rama::{
    futures::future::join_all,
    net::tls::ApplicationProtocol,
    quic::{
        ClientConfig, Connection, Endpoint, RecvStream, SendStream, ServerConfig, tls::TlsOptions,
    },
    rt::Executor,
    tls::{
        client::TlsClientConfig,
        server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
    },
    utils::{collections::smallvec::smallvec, octets},
};
use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};
use tokio::{
    runtime::{Builder, Runtime},
    sync::mpsc,
    time::timeout,
};

#[global_allocator]
static ALLOC: AllocProfiler = AllocProfiler::system();

const CASES: [&str; 4] = [
    "1conn_1stream",
    "1conn_16streams",
    "16conns_1stream",
    "16conns_16streams",
];
const ALPN: &[u8] = b"rama-quic/transport-bench";
const DEADLINE: Duration = Duration::from_secs(30);
const BULK_BYTES: usize = octets::mib(1);
const CHUNK: [u8; octets::kib(16)] = [0x5a; octets::kib(16)];
const REQUEST: [u8; octets::kib(4)] = [0x3c; octets::kib(4)];
const RESPONSE: [u8; octets::kib(4)] = [0xc3; octets::kib(4)];

fn main() {
    divan::main();
}

#[expect(
    clippy::unreachable,
    reason = "Divan supplies only the declared benchmark cases"
)]
fn shape(case: &str) -> (usize, usize) {
    match case {
        "1conn_1stream" => (1, 1),
        "1conn_16streams" => (1, 16),
        "16conns_1stream" => (16, 1),
        "16conns_16streams" => (16, 16),
        _ => unreachable!("unknown benchmark case"),
    }
}

struct Loopback {
    runtime: Runtime,
    client: Endpoint,
    server: Endpoint,
    connections: Vec<(Connection, Connection)>,
}

impl Loopback {
    fn new(connection_count: usize, threaded: bool) -> Self {
        let mut builder = if threaded {
            let mut builder = Builder::new_multi_thread();
            builder.worker_threads(4);
            builder
        } else {
            Builder::new_current_thread()
        };
        let runtime = builder.enable_all().build().unwrap();
        let auth = ServerAuthData::new_generated(GeneratedServerAuthConfig::default()).unwrap();
        let server_tls = TlsServerConfig::new()
            .with_alpn(smallvec![ApplicationProtocol::from(ALPN)])
            .with_server_auth(auth.clone());
        let client_tls = TlsClientConfig::new()
            .with_alpn(smallvec![ApplicationProtocol::from(ALPN)])
            .try_with_server_trust_anchors([auth.cert_chain.last().unwrap().clone()])
            .unwrap();
        let server_config =
            ServerConfig::try_from_rama_tls(&server_tls, TlsOptions::default()).unwrap();
        let client_config =
            ClientConfig::try_from_rama_tls(&client_tls, TlsOptions::default()).unwrap();
        let (client, server, connections) = runtime.block_on(async {
            timeout(DEADLINE, async {
                let server = Endpoint::build(Executor::new())
                    .with_server_config(server_config)
                    .bind_address(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
                    .await
                    .unwrap();
                let client = Endpoint::build(Executor::new())
                    .bind_address(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
                    .await
                    .unwrap();
                let mut connections = Vec::with_capacity(connection_count);
                for _ in 0..connection_count {
                    let connecting = client
                        .connect_with(
                            client_config.clone(),
                            server.local_addr().unwrap(),
                            "localhost",
                        )
                        .unwrap();
                    let (client_connection, server_connection) =
                        tokio::join!(async { connecting.await.unwrap() }, async {
                            server.accept().await.unwrap().await.unwrap()
                        },);
                    for connection in [&client_connection, &server_connection] {
                        assert_eq!(
                            connection
                                .handshake_data()
                                .unwrap()
                                .application_layer_protocol,
                            Some(ApplicationProtocol::from(ALPN))
                        );
                    }
                    connections.push((client_connection, server_connection));
                }
                (client, server, connections)
            })
            .await
            .unwrap()
        });
        Self {
            runtime,
            client,
            server,
            connections,
        }
    }
}

impl Drop for Loopback {
    fn drop(&mut self) {
        self.client.close(0u32.into(), b"benchmark done");
        self.server.close(0u32.into(), b"benchmark done");
        self.runtime.block_on(async {
            timeout(DEADLINE, async {
                tokio::join!(self.client.wait_idle(), self.server.wait_idle());
            })
            .await
            .unwrap();
        });
    }
}

struct BulkStream {
    client_send: SendStream,
    client_recv: RecvStream,
    server_send: SendStream,
    server_recv: RecvStream,
    received: Vec<u8>,
}

impl BulkStream {
    async fn new(client: &Connection, server: &Connection) -> Self {
        let (client_stream, server_stream) = tokio::join!(
            async {
                let (mut send, mut recv) = client.open_bi().await.unwrap();
                send.write_all(b"S").await.unwrap();
                let mut ready = [0];
                recv.read_exact(&mut ready).await.unwrap();
                assert_eq!(ready, *b"R");
                (send, recv)
            },
            async {
                let (mut send, mut recv) = server.accept_bi().await.unwrap();
                let mut start = [0];
                recv.read_exact(&mut start).await.unwrap();
                assert_eq!(start, *b"S");
                send.write_all(b"R").await.unwrap();
                (send, recv)
            },
        );
        Self {
            client_send: client_stream.0,
            client_recv: client_stream.1,
            server_send: server_stream.0,
            server_recv: server_stream.1,
            received: vec![0; CHUNK.len()],
        }
    }

    async fn transfer(&mut self) {
        tokio::join!(
            async {
                for _ in 0..BULK_BYTES / CHUNK.len() {
                    self.client_send.write_all(black_box(&CHUNK)).await.unwrap();
                }
                let mut ack = [0];
                self.client_recv.read_exact(&mut ack).await.unwrap();
                assert_eq!(ack, *b"A");
            },
            async {
                for _ in 0..BULK_BYTES / CHUNK.len() {
                    self.server_recv
                        .read_exact(&mut self.received)
                        .await
                        .unwrap();
                    assert_eq!(self.received.as_slice(), CHUNK);
                }
                self.server_send.write_all(b"A").await.unwrap();
            },
        );
    }
}

struct RpcLane {
    client: Connection,
    server: Connection,
    request: Vec<u8>,
    response: Vec<u8>,
}

impl RpcLane {
    async fn exchange(&mut self) {
        tokio::join!(
            async {
                let (mut send, mut recv) = self.client.open_bi().await.unwrap();
                send.write_all(black_box(&REQUEST)).await.unwrap();
                send.finish().unwrap();
                recv.read_exact(&mut self.response).await.unwrap();
                assert_eq!(self.response.as_slice(), RESPONSE);
                assert_eq!(recv.read(&mut [0]).await.unwrap(), None);
            },
            async {
                let (mut send, mut recv) = self.server.accept_bi().await.unwrap();
                recv.read_exact(&mut self.request).await.unwrap();
                assert_eq!(self.request.as_slice(), REQUEST);
                assert_eq!(recv.read(&mut [0]).await.unwrap(), None);
                send.write_all(black_box(&RESPONSE)).await.unwrap();
                send.finish().unwrap();
            },
        );
    }
}

fn bulk(bencher: divan::Bencher, case: &str, threaded: bool) {
    let (connection_count, stream_count) = shape(case);
    let loopback = Loopback::new(connection_count, threaded);
    let mut streams = loopback.runtime.block_on(async {
        timeout(DEADLINE, async {
            let mut streams = Vec::with_capacity(connection_count * stream_count);
            for (client, server) in &loopback.connections {
                for _ in 0..stream_count {
                    streams.push(BulkStream::new(client, server).await);
                }
            }
            streams
        })
        .await
        .unwrap()
    });
    let mut transfer = || {
        loopback.runtime.block_on(async {
            timeout(
                DEADLINE,
                join_all(streams.iter_mut().map(BulkStream::transfer)),
            )
            .await
            .unwrap();
        });
    };
    transfer();
    bencher
        .counter(BytesCount::new(
            connection_count * stream_count * BULK_BYTES,
        ))
        .bench_local(transfer);
    drop(streams);
}

fn rpc(bencher: divan::Bencher, case: &str, threaded: bool) {
    let (connection_count, stream_count) = shape(case);
    let loopback = Loopback::new(connection_count, threaded);
    let mut lanes = Vec::with_capacity(connection_count * stream_count);
    for (client, server) in &loopback.connections {
        for _ in 0..stream_count {
            lanes.push(RpcLane {
                client: client.clone(),
                server: server.clone(),
                request: vec![0; REQUEST.len()],
                response: vec![0; RESPONSE.len()],
            });
        }
    }
    let mut exchange = || {
        loopback.runtime.block_on(async {
            timeout(DEADLINE, join_all(lanes.iter_mut().map(RpcLane::exchange)))
                .await
                .unwrap();
        });
    };
    exchange();
    bencher
        .counter(BytesCount::new(
            connection_count * stream_count * (REQUEST.len() + RESPONSE.len()),
        ))
        .bench_local(exchange);
}

#[divan::bench(args = CASES, sample_count = 10, sample_size = 1)]
fn persistent_bulk_current_thread_whole_pipeline(bencher: divan::Bencher, case: &str) {
    bulk(bencher, case, false);
}

#[divan::bench(args = CASES, sample_count = 10, sample_size = 1)]
fn persistent_bulk_multi_thread_inline_apps_worker_allocations_excluded(
    bencher: divan::Bencher,
    case: &str,
) {
    bulk(bencher, case, true);
}

#[divan::bench(args = CASES, sample_count = 30, sample_size = 1)]
fn stream_churn_rpc_current_thread_whole_pipeline(bencher: divan::Bencher, case: &str) {
    rpc(bencher, case, false);
}

#[divan::bench(args = CASES, sample_count = 30, sample_size = 1)]
fn stream_churn_rpc_multi_thread_inline_apps_worker_allocations_excluded(
    bencher: divan::Bencher,
    case: &str,
) {
    rpc(bencher, case, true);
}

#[divan::bench(args = CASES, sample_count = 10, sample_size = 1)]
fn persistent_bulk_multi_thread_spawned_apps_worker_allocations_excluded(
    bencher: divan::Bencher,
    case: &str,
) {
    let (connection_count, stream_count) = shape(case);
    let lane_count = connection_count * stream_count;
    let loopback = Loopback::new(connection_count, true);
    let (commands, workers, mut completed) = loopback.runtime.block_on(async {
        timeout(DEADLINE, async {
            let (completion, completed) = mpsc::channel(lane_count);
            let mut commands = Vec::with_capacity(lane_count);
            let mut workers = Vec::with_capacity(lane_count);
            for (client, server) in &loopback.connections {
                for _ in 0..stream_count {
                    let mut stream = BulkStream::new(client, server).await;
                    let (command, mut requested) = mpsc::channel::<()>(1);
                    let completion = completion.clone();
                    workers.push(tokio::spawn(async move {
                        while requested.recv().await.is_some() {
                            stream.transfer().await;
                            completion.send(()).await.unwrap();
                        }
                    }));
                    commands.push(command);
                }
            }
            (commands, workers, completed)
        })
        .await
        .unwrap()
    });
    let mut transfer = || {
        loopback.runtime.block_on(async {
            timeout(DEADLINE, async {
                for command in &commands {
                    command.send(()).await.unwrap();
                }
                for _ in 0..lane_count {
                    completed.recv().await.unwrap();
                }
            })
            .await
            .unwrap();
        });
    };
    transfer();
    bencher
        .counter(BytesCount::new(lane_count * BULK_BYTES))
        .bench_local(transfer);
    drop(commands);
    loopback.runtime.block_on(async {
        for worker in timeout(DEADLINE, join_all(workers)).await.unwrap() {
            worker.unwrap();
        }
    });
}
