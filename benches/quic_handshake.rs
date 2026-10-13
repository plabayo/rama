//! QUIC server handshake cost with a fixed certificate versus certificates issued per
//! ClientHello (the dynamic issuer and the in-memory CA, both with a warm cache).
//!
//! Each iteration is one client handshake on loopback against a serving endpoint, closed
//! once established. Issued cases add the ClientHello read before accepting and the cache
//! hit; `in_memory_ca_cold` issues a fresh leaf for every handshake. The `split` cases offer
//! enough ALPN protocols for the ClientHello to span two Initial packets.
//!
//! `established_rtt` measures request/response round trips on established connections while
//! other clients handshake with the same server endpoint at a paced rate, which shows how much
//! handshake work delays datagram routing for connections that are already up: `idle` without
//! handshakes, `churn_p256` with a trickle of cheap ones, and the `pressure` cases with as many
//! admitted handshakes as the server sustains comfortably for a P-256, RSA-2048 and RSA-4096
//! certificate, served on the endpoint's own runtime as `Endpoint::serve` does. The `offloaded`
//! cases accept the same RSA floods on a runtime of their own, so only the endpoint couples
//! that handshake work to the established traffic. Round trips are issued every 500 µs and
//! timed from their scheduled start (the `lat` percentiles); `rtt` times each from its actual
//! start. The server runs on four workers and the flood on its own runtime, so every build does
//! the same handshake work. After each case one line on stderr also gives the handshake rate
//! achieved against its target with the setup time and failures of those handshakes, the
//! server's admission decisions (every flood attempt should be accepted, none retried or
//! refused), and how busy the server and flood workers were, all over the measured window.
//!
//! ```sh
//! cargo bench --bench quic_handshake --features quic,boring,crypto
//! ```
#![expect(clippy::unwrap_used, reason = "benchmark failures must fail the run")]

use std::{
    convert::Infallible,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use parking_lot::Mutex;

use rama::{
    crypto::cert::{CertificateAuthorityData, CertificateKeyKind, LeafCertRequest},
    error::BoxError,
    net::tls::ApplicationProtocol,
    quic::{
        ClientConfig, Connection, Endpoint, EndpointStats, RecvStream, SendStream, ServerConfig,
        tls::{BoringTlsProvider, TlsOptions},
    },
    rt::Executor,
    service::service_fn,
    tls::{
        boring::server::{
            BoringServerConfigExt as _, CacheKind, ServerCertIssuerData, ServerCertIssuerKind,
        },
        client::TlsClientConfig,
        server::{
            CertificateIssuanceContext, DynamicCertIssuer, LeafCertConfig, SelfSignedCaConfig,
            ServerAuthData, TlsServerConfig,
        },
    },
    utils::collections::smallvec::SmallVec,
};
use tokio::{
    runtime::{Builder, Runtime},
    time::{MissedTickBehavior, interval_at, timeout},
};

mod bench_alloc;

const ALPN: &[u8] = b"rama-quic/handshake-bench";
const DEADLINE: Duration = Duration::from_secs(30);
/// Established-connection workloads (see [`load`]).
const LOADS: [&str; 7] = [
    "idle",
    "churn_p256",
    "pressure_p256",
    "pressure_rsa2048",
    "pressure_rsa4096",
    "offloaded_rsa2048",
    "offloaded_rsa4096",
];
/// Established connections the measured round trips rotate over.
const ESTABLISHED: usize = 8;
/// When the flood starts, after its clients have bound their endpoints.
const FLOOD_START: Duration = Duration::from_millis(100);
/// Round trips run under the flood before measuring.
const WARMUP_ROUND_TRIPS: usize = 500;
/// Measured round trips are issued on this schedule and timed from their scheduled start, so
/// a stall also counts against the probes it held up rather than only the one it hit.
const PROBE_INTERVAL: Duration = Duration::from_micros(500);
const SERVER_WORKERS: usize = 4;
const FLOOD_WORKERS: usize = 4;
const PING: [u8; 64] = [0x5a; 64];
const CASES: [&str; 7] = [
    "fixed",
    "fixed_split",
    "dynamic_issuer",
    "dynamic_issuer_split",
    "in_memory_ca",
    "in_memory_ca_split",
    "in_memory_ca_cold",
];

fn main() {
    divan::main();
}

/// Hands out one pre-issued certificate for every name.
struct PreIssued(ServerAuthData);

impl DynamicCertIssuer for PreIssued {
    async fn issue_cert(
        &self,
        _context: CertificateIssuanceContext,
    ) -> Result<ServerAuthData, BoxError> {
        Ok(self.0.clone())
    }
}

fn alpn(split: bool) -> SmallVec<[ApplicationProtocol; 2]> {
    let padding = if split { 24 } else { 0 };
    (0..padding)
        .map(|n: u8| ApplicationProtocol::from(vec![b'a' + n % 26; 96]))
        .chain([ApplicationProtocol::from(ALPN)])
        .collect()
}

struct Loopback {
    runtime: Runtime,
    client: Endpoint,
    client_config: ClientConfig,
    server: SocketAddr,
}

impl Loopback {
    fn new(case: &str) -> Self {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        let ca = CertificateAuthorityData::generate(SelfSignedCaConfig::default()).unwrap();
        let leaf = ServerAuthData::new_issued_by(&ca, Default::default()).unwrap();
        let base = TlsServerConfig::new().with_alpn(alpn(false));
        let server_tls = match case.trim_end_matches("_split").trim_end_matches("_cold") {
            "fixed" => base.with_server_auth(leaf),
            "dynamic_issuer" => base.with_cert_issuer(ServerCertIssuerData::new(PreIssued(leaf))),
            _ => base.with_cert_issuer(
                ServerCertIssuerData::new(ServerCertIssuerKind::ProvidedCa {
                    ca: CertificateAuthorityData::try_new(
                        ca.certificate_chain().to_vec(),
                        ca.private_key().clone_key(),
                    )
                    .unwrap(),
                    leaf: LeafCertConfig::default(),
                })
                .with_cache_kind(if case.ends_with("_cold") {
                    CacheKind::Disabled
                } else {
                    CacheKind::default()
                }),
            ),
        };
        let client_tls = TlsClientConfig::new()
            .with_alpn(alpn(case.ends_with("_split")))
            .try_with_server_trust_anchors([ca.certificate_chain()[0].clone()])
            .unwrap();
        let options = TlsOptions::default();
        let server_config =
            ServerConfig::try_from_rama_tls_with_provider(&server_tls, options, &BoringTlsProvider)
                .unwrap();
        let client_config =
            ClientConfig::try_from_rama_tls_with_provider(&client_tls, options, &BoringTlsProvider)
                .unwrap();
        let (client, server) = runtime.block_on(async {
            let server = Endpoint::build(Executor::new())
                .with_server_config(server_config)
                .bind_address(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
                .await
                .unwrap();
            let addr = server.local_addr().unwrap();
            tokio::spawn(server.serve(
                Executor::new(),
                service_fn(async |connection: Connection| {
                    _ = connection.closed().await;
                    Ok::<_, Infallible>(())
                }),
            ));
            let client = Endpoint::build(Executor::new())
                .bind_address(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
                .await
                .unwrap();
            (client, addr)
        });
        let loopback = Self {
            runtime,
            client,
            client_config,
            server,
        };
        // Warm the issuer caches, so the issued cases measure a cache hit.
        loopback.handshake();
        loopback
    }

    fn handshake(&self) {
        self.runtime.block_on(async {
            let connection = timeout(
                DEADLINE,
                self.client
                    .connect_with(self.client_config.clone(), self.server, "localhost")
                    .unwrap(),
            )
            .await
            .unwrap()
            .unwrap();
            connection.close(0u32, b"done");
        });
    }
}

#[divan::bench(args = CASES, sample_count = 200)]
fn handshake(bencher: divan::Bencher, case: &str) {
    let loopback = Loopback::new(case);
    bencher.bench_local(|| loopback.handshake());
}

/// One established-connection workload: the server certificate key, the paced handshake rate
/// of the flood, how many clients handshake at once (each on its own endpoint), and whether
/// the server accepts the flood on a runtime of its own.
struct Load {
    key: CertificateKeyKind,
    rate: f64,
    clients: usize,
    offloaded: bool,
}

fn load(case: &str) -> Load {
    let (key, rate, clients) = match case.trim_start_matches("offloaded_") {
        "churn_p256" => (CertificateKeyKind::EcP256, 100.0, 4),
        "pressure_p256" => (CertificateKeyKind::EcP256, 800.0, 32),
        "pressure_rsa2048" | "rsa2048" => (CertificateKeyKind::Rsa2048, 400.0, 32),
        "pressure_rsa4096" | "rsa4096" => (CertificateKeyKind::Rsa4096, 100.0, 32),
        // `idle`: no flood.
        _ => (CertificateKeyKind::EcP256, 0.0, 0),
    };
    Load {
        key,
        rate,
        clients,
        offloaded: case.starts_with("offloaded_"),
    }
}

/// What the flood achieved: the setup time of each completed handshake, and failed attempts.
#[derive(Default)]
struct FloodStats {
    completed: Mutex<Vec<Duration>>,
    failed: AtomicU64,
}

/// Established connections on a server endpoint that other clients flood with handshakes.
struct Flooded {
    measure: Runtime,
    streams: Vec<(SendStream, RecvStream)>,
    _connections: Vec<Connection>,
    server: Endpoint,
    stop: Arc<AtomicBool>,
    flood_stats: Arc<FloodStats>,
    server_rt: Option<Runtime>,
    /// Where offloaded handshakes run.
    handshakes: Option<Runtime>,
    flood: Option<Runtime>,
}

/// Counters read at both ends of the measured window.
struct Snapshot {
    at: Instant,
    completed: usize,
    failed: u64,
    server: EndpointStats,
    server_busy: Duration,
    flood_busy: Duration,
}

impl Flooded {
    fn new(case: &str) -> Self {
        let load = load(case);
        let ca = CertificateAuthorityData::generate(SelfSignedCaConfig::default()).unwrap();
        let leaf = ServerAuthData::new_issued_by(
            &ca,
            LeafCertRequest {
                config: LeafCertConfig {
                    key_kind: load.key,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
        let server_tls = TlsServerConfig::new()
            .with_alpn(alpn(false))
            .with_server_auth(leaf);
        let client_tls = TlsClientConfig::new()
            .with_alpn(alpn(false))
            .try_with_server_trust_anchors([ca.certificate_chain()[0].clone()])
            .unwrap();
        let options = TlsOptions::default();
        let server_config =
            ServerConfig::try_from_rama_tls_with_provider(&server_tls, options, &BoringTlsProvider)
                .unwrap();
        let client_config =
            ClientConfig::try_from_rama_tls_with_provider(&client_tls, options, &BoringTlsProvider)
                .unwrap();

        let server_rt = Builder::new_multi_thread()
            .worker_threads(SERVER_WORKERS)
            .enable_all()
            .build()
            .unwrap();
        let handshakes = load.offloaded.then(|| {
            Builder::new_multi_thread()
                .worker_threads(SERVER_WORKERS)
                .enable_all()
                .build()
                .unwrap()
        });
        let offload = handshakes.as_ref().map(|runtime| runtime.handle().clone());
        let server = server_rt.block_on(async {
            let server = Endpoint::build(Executor::new())
                .with_server_config(server_config)
                .bind_address(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
                .await
                .unwrap();
            match offload {
                None => {
                    tokio::spawn(server.clone().serve(Executor::new(), service_fn(echo)));
                }
                // The established connections are accepted here and the flood on the other
                // runtime, so only the endpoint couples their handshake work to this traffic.
                Some(offload) => {
                    let accepting = server.clone();
                    tokio::spawn(async move {
                        let mut accepted = 0;
                        while let Some(incoming) = accepting.accept().await {
                            accepted += 1;
                            let serve = async move {
                                if let Ok(connection) = incoming.await {
                                    _ = echo(connection).await;
                                }
                            };
                            if accepted <= ESTABLISHED {
                                tokio::spawn(serve);
                            } else {
                                offload.spawn(serve);
                            }
                        }
                    });
                }
            }
            server
        });
        let addr = server.local_addr().unwrap();

        let measure = Builder::new_current_thread().enable_all().build().unwrap();
        let (connections, streams) = measure.block_on(async {
            let client = Endpoint::build(Executor::new())
                .bind_address(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
                .await
                .unwrap();
            let mut connections = Vec::with_capacity(ESTABLISHED);
            let mut streams = Vec::with_capacity(ESTABLISHED);
            for _ in 0..ESTABLISHED {
                let connection = timeout(
                    DEADLINE,
                    client
                        .connect_with(client_config.clone(), addr, "localhost")
                        .unwrap(),
                )
                .await
                .unwrap()
                .unwrap();
                let (mut send, mut recv) = connection.open_bi().await.unwrap();
                // One round trip makes the stream known to the server before measuring.
                round_trip(&mut send, &mut recv).await;
                connections.push(connection);
                streams.push((send, recv));
            }
            (connections, streams)
        });

        let stop = Arc::new(AtomicBool::new(false));
        let flood_stats = Arc::new(FloodStats::default());
        let flood = (load.clients > 0).then(|| {
            let flood = Builder::new_multi_thread()
                .worker_threads(FLOOD_WORKERS)
                .enable_all()
                .build()
                .unwrap();
            // Each client handshakes once per period, the clients spread evenly over it, so
            // attempts arrive at the paced rate rather than in bursts of every client at once.
            let period = Duration::from_secs_f64(load.clients as f64 / load.rate);
            let first = tokio::time::Instant::now() + FLOOD_START;
            for client in 0..load.clients {
                let stop = stop.clone();
                let flood_stats = flood_stats.clone();
                let config = client_config.clone();
                let start = first + period.mul_f64(client as f64 / load.clients as f64);
                flood.spawn(async move {
                    let client = Endpoint::build(Executor::new())
                        .bind_address(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0))
                        .await
                        .unwrap();
                    let mut pace = interval_at(start, period);
                    pace.set_missed_tick_behavior(MissedTickBehavior::Delay);
                    while !stop.load(Ordering::Relaxed) {
                        pace.tick().await;
                        let started = Instant::now();
                        let connection =
                            match client.connect_with(config.clone(), addr, "localhost") {
                                Ok(connecting) => timeout(DEADLINE, connecting).await.ok(),
                                Err(_) => None,
                            };
                        match connection {
                            Some(Ok(connection)) => {
                                flood_stats.completed.lock().push(started.elapsed());
                                connection.close(0u32, b"done");
                            }
                            _ => {
                                flood_stats.failed.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                });
            }
            flood
        });
        let mut flooded = Self {
            measure,
            streams,
            _connections: connections,
            server,
            stop,
            flood_stats,
            server_rt: Some(server_rt),
            handshakes,
            flood,
        };
        // Let the flood reach its steady rate, then warm the measured path under it.
        if flooded.flood.is_some() {
            thread::sleep(Duration::from_secs(1));
        }
        for next in 0..WARMUP_ROUND_TRIPS {
            let Self {
                measure, streams, ..
            } = &mut flooded;
            let (send, recv) = &mut streams[next % ESTABLISHED];
            measure.block_on(round_trip(send, recv));
        }
        flooded
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot {
            at: Instant::now(),
            completed: self.flood_stats.completed.lock().len(),
            failed: self.flood_stats.failed.load(Ordering::Relaxed),
            server: self.server.stats(),
            server_busy: self
                .server_rt
                .iter()
                .chain(&self.handshakes)
                .map(busy)
                .sum(),
            flood_busy: self.flood.as_ref().map(busy).unwrap_or_default(),
        }
    }
}

impl Drop for Flooded {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(flood) = self.flood.take() {
            flood.shutdown_timeout(Duration::from_secs(1));
        }
        if let Some(handshakes) = self.handshakes.take() {
            handshakes.shutdown_timeout(Duration::from_secs(1));
        }
        if let Some(server) = self.server_rt.take() {
            server.shutdown_timeout(Duration::from_secs(1));
        }
    }
}

/// Time the runtime's workers spent polling tasks, summed over the workers.
fn busy(runtime: &Runtime) -> Duration {
    let metrics = runtime.metrics();
    (0..metrics.num_workers())
        .map(|worker| metrics.worker_total_busy_duration(worker))
        .sum()
}

async fn round_trip(send: &mut SendStream, recv: &mut RecvStream) {
    let mut pong = [0u8; PING.len()];
    send.write_all(&PING).await.unwrap();
    recv.read_exact(&mut pong).await.unwrap();
    assert_eq!(pong, PING);
}

/// Echo every bidirectional stream until the connection ends.
async fn echo(connection: Connection) -> Result<(), Infallible> {
    while let Ok((mut send, mut recv)) = connection.accept_bi().await {
        tokio::spawn(async move {
            while let Ok(Some(chunk)) = recv.read_chunk(usize::MAX, true).await {
                if send.write_all(&chunk.bytes).await.is_err() {
                    return;
                }
            }
        });
    }
    Ok(())
}

/// The value at percentile `per_mille` (tenths of a percent) of sorted `values`, in µs.
fn percentile(values: &[Duration], per_mille: usize) -> u128 {
    values
        .get(values.len().saturating_sub(1) * per_mille / 1000)
        .map_or(0, Duration::as_micros)
}

#[divan::bench(args = LOADS, sample_count = 20_000, sample_size = 1)]
fn established_rtt(bencher: divan::Bencher, case: &str) {
    let mut flooded = Flooded::new(case);
    let mut latencies = Vec::with_capacity(32_768);
    let mut rtts = Vec::with_capacity(32_768);
    let mut next = 0;
    let before = flooded.snapshot();
    let mut schedule = Instant::now();
    bencher
        .with_inputs(|| {
            schedule += PROBE_INTERVAL;
            // A probe that an earlier stall delayed past its slot starts at once.
            if let Some(wait) = schedule.checked_duration_since(Instant::now()) {
                thread::sleep(wait);
            }
            schedule
        })
        .bench_local_values(|scheduled| {
            let Flooded {
                measure, streams, ..
            } = &mut flooded;
            let (send, recv) = &mut streams[next % ESTABLISHED];
            next += 1;
            let begin = Instant::now();
            measure.block_on(round_trip(send, recv));
            rtts.push(begin.elapsed());
            latencies.push(scheduled.elapsed());
        });
    let after = flooded.snapshot();
    latencies.sort_unstable();
    rtts.sort_unstable();
    let mut handshakes =
        flooded.flood_stats.completed.lock()[before.completed..after.completed].to_vec();
    handshakes.sort_unstable();
    let window = after.at.duration_since(before.at).as_secs_f64();
    let load = load(case);
    let (server, base) = (after.server, before.server);
    eprintln!(
        "established_rtt[{case}] lat_p50_us={} lat_p90_us={} lat_p95_us={} lat_p99_us={} \
         lat_p999_us={} lat_max_us={} rtt_p50_us={} rtt_p95_us={} rtt_p99_us={} rtt_p999_us={} \
         probes={} hs_per_s={:.1} \
         hs_target={:.0} hs_failed={} hs_p50_us={} hs_p99_us={} accepted={} retried={} \
         refused={} expired={} server_busy_pct={:.0} flood_busy_pct={:.0} window_s={:.2}",
        percentile(&latencies, 500),
        percentile(&latencies, 900),
        percentile(&latencies, 950),
        percentile(&latencies, 990),
        percentile(&latencies, 999),
        percentile(&latencies, 1000),
        percentile(&rtts, 500),
        percentile(&rtts, 950),
        percentile(&rtts, 990),
        percentile(&rtts, 999),
        latencies.len(),
        handshakes.len() as f64 / window,
        load.rate,
        after.failed - before.failed,
        percentile(&handshakes, 500),
        percentile(&handshakes, 990),
        server.accepted_handshakes - base.accepted_handshakes,
        server.retried_under_load - base.retried_under_load,
        server.refused_at_limit + server.refused_per_source + server.refused_unvalidated
            - base.refused_at_limit
            - base.refused_per_source
            - base.refused_unvalidated,
        server.expired_incoming - base.expired_incoming,
        100.0
            * after
                .server_busy
                .saturating_sub(before.server_busy)
                .as_secs_f64()
            / window,
        100.0
            * after
                .flood_busy
                .saturating_sub(before.flood_busy)
                .as_secs_f64()
            / window,
        window,
    );
}
