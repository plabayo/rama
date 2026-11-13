//! End-to-end loopback comparison. Run explicitly in release mode; never a CI timing gate.
//! Same native UDP transports, demux, TLS and relay in every case. Only optional migration routing, policy watching and
//! the number of port changes differ. Setup/handshake is excluded and cases rotate per round.
use super::*;
use rama_net::{address::SocketAddress, stream::Socket as _};
use rama_udp::{DatagramDemux, DemuxConfig, UdpPacketSocket, proxy::DatagramToProxyBridge};
use std::time::Instant;

#[derive(Clone, Copy)]
struct Scenario {
    migration: bool,
    policy: bool,
    connections: usize,
    rebinds: usize,
    reuse_peer: bool,
}

struct Sample {
    steady_mib_s: f64,
    total_mib_s: f64,
    requests_ms: Vec<f64>,
    migrations_ms: Vec<f64>,
    ingress_mtu: u16,
}

#[derive(Clone)]
struct ObservedRelay {
    connections: Arc<Mutex<Vec<Connection>>>,
    policy: Option<crate::proxy::QuicMigrationLayer>,
}

impl Service<BridgeIo<Connection, Connection>> for ObservedRelay {
    type Output = ();
    type Error = BoxError;

    async fn serve(&self, input: BridgeIo<Connection, Connection>) -> Result<(), BoxError> {
        self.connections.lock().push(input.0.clone());
        let relay = QuicRelay::new(VarInt::from_u32(1));
        match &self.policy {
            Some(layer) => layer.layer(relay).serve(input).await,
            None => relay.serve(input).await,
        }
    }
}

async fn exchange(connection: &Connection, bytes: usize) {
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    let payload = vec![0x5a; bytes];
    send.write_all(&payload).await.unwrap();
    send.finish().unwrap();
    assert_eq!(recv.read_to_end(bytes).await.unwrap(), payload);
}

async fn sample(scenario: Scenario) -> Sample {
    let scope = rama_core::graceful::Scope::new();
    let weak_scope = scope.clone_weak();
    let mitm = identity();
    let upstream = untrusted_identity();
    let tls = rama_tls::server::TlsServerConfig::new()
        .with_alpn([ALPN.into()].into_iter().collect())
        .with_server_auth(upstream.clone());
    let origin = Endpoint::build(weak_scope.clone())
        .with_server_config(ServerConfig::try_from_rama_tls(&tls, TlsOptions::default()).unwrap())
        .bind_address(SocketAddress::local_ipv4(0))
        .await
        .unwrap();
    let origin_address = origin.local_addr().unwrap();
    let listener = UdpPacketSocket::bind(SocketAddress::local_ipv4(0))
        .await
        .unwrap();
    let listen = listener.local_addr().unwrap();
    let ingress = QuicMitmIngress::new(
        weak_scope.clone(),
        QuicMitmIngressConfig {
            max_registered_connections: NonZeroUsize::new(scenario.connections).unwrap(),
            max_paths_per_connection: rama_utils::macros::nonzero!(8),
            path_validation_timeout: std::time::Duration::from_secs(5),
            capabilities: None,
        },
    );
    let observed = Arc::new(Mutex::new(Vec::<Connection>::new()));
    let policy = scenario.policy.then(|| {
        crate::proxy::QuicMigrationLayer::new(
            service_fn(|_: crate::proxy::QuicMigrationInput| async {
                Ok::<_, BoxError>(crate::proxy::QuicMigrationDecision::default())
            }),
            crate::proxy::QuicMigrationConfig {
                scope: weak_scope.clone(),
                decision_timeout: Duration::from_secs(5),
                failure_action: crate::proxy::QuicMigrationFailureAction::Close,
                failure_code: VarInt::from_u32(1),
            },
        )
        .with_network_changes(crate::proxy::QuicNetworkChanges::new())
    });
    let relay = QuicMitmRelay::new(
        issuer(&mitm),
        weak_scope.clone(),
        trusting(&upstream),
        VarInt::from_u32(1),
    )
    .maybe_with_migration_ingress(scenario.migration.then(|| ingress.clone()))
    .into_layer(ObservedRelay {
        connections: observed.clone(),
        policy,
    });
    let bridge = PeekQuicClientHelloService::new(
        BoringTlsProvider,
        DatagramToProxyBridge::new(relay, origin_address),
    );
    let routed = bridge.clone().with_router(ingress);
    let associations = service_fn(
        move |socket: rama_udp::DemuxedSocket<rama_udp::UdpPacketSender>| {
            let routed = routed.clone();
            let bridge = bridge.clone();
            async move {
                if scenario.migration {
                    routed.serve(socket).await
                } else {
                    bridge.serve(socket).await
                }
            }
        },
    );
    let demux = DatagramDemux::new(
        listener,
        DemuxConfig {
            associations: NonZeroUsize::new(scenario.connections * 8).unwrap(),
            queue: rama_utils::macros::nonzero!(256),
            idle_timeout: Duration::from_secs(30),
            receive_bytes: rama_utils::macros::nonzero!(65536),
            queued_bytes: NonZeroUsize::new(16 * 1024 * 1024).unwrap(),
        },
    );
    let demux_scope = weak_scope.clone();
    let proxy = tokio::spawn(async move { demux.serve(demux_scope, associations).await });
    let accepting = origin.clone();
    let echo = tokio::spawn(async move {
        while let Some(incoming) = accepting.accept().await {
            tokio::spawn(async move {
                let connection = incoming.await.unwrap();
                while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                    tokio::spawn(async move {
                        let payload = recv.read_to_end(2 * 1024 * 1024).await.unwrap();
                        send.write_all(&payload).await.unwrap();
                        send.finish().unwrap();
                    });
                }
            });
        }
    });
    let config = ClientConfig::try_from_rama_tls(&trusting(&mitm), TlsOptions::default()).unwrap();
    let mut clients = Vec::with_capacity(scenario.connections);
    for _ in 0..scenario.connections {
        let client = Endpoint::build(weak_scope.clone())
            .bind_address(SocketAddress::local_ipv4(0))
            .await
            .unwrap();
        let connection = client
            .connect_with(config.clone(), listen.into(), "localhost")
            .unwrap()
            .await
            .unwrap();
        exchange(&connection, 1024 * 1024).await;
        let port = client.local_addr().unwrap().port();
        let ingress = observed
            .lock()
            .iter()
            .find(|conn| conn.remote_address().port() == port)
            .unwrap()
            .clone();
        clients.push((client, connection, ingress));
    }

    let total = Instant::now();
    let mut steady = Duration::ZERO;
    let mut requests_ms = Vec::new();
    let mut migrations_ms = Vec::new();
    for phase in 0..4 {
        if phase > 0 && phase <= scenario.rebinds {
            let reused = if scenario.reuse_peer {
                let (client, connection, ingress) = &clients[0];
                let previous = SocketAddress::from(client.local_addr().unwrap());
                client
                    .rebind(SocketAddress::local_ipv4(0), Default::default())
                    .await
                    .unwrap();
                exchange(connection, 64).await;
                while ingress.remote_address().port() != client.local_addr().unwrap().port() {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                Some(previous)
            } else {
                None
            };
            let mut moves = tokio::task::JoinSet::new();
            for (index, (client, connection, ingress)) in clients.iter().enumerate() {
                if reused.is_some() && index == 0 {
                    continue;
                }
                let (client, connection, ingress) =
                    (client.clone(), connection.clone(), ingress.clone());
                moves.spawn(async move {
                    let moving = Instant::now();
                    if let Some(previous) = reused.filter(|_| index == 1) {
                        timeout(Duration::from_secs(2), async {
                            loop {
                                match client.rebind(previous, Default::default()).await {
                                    Ok(()) => break,
                                    Err(_) => tokio::time::sleep(Duration::from_millis(1)).await,
                                }
                            }
                        })
                        .await
                        .expect("the first client must release its old port");
                    } else {
                        client
                            .rebind(SocketAddress::local_ipv4(0), Default::default())
                            .await
                            .unwrap();
                    }
                    assert!(
                        timeout(Duration::from_secs(5), exchange(&connection, 64))
                            .await
                            .is_ok(),
                        "migration stalled: client={:?} endpoint={:?} ingress_peer={} ingress={:?}",
                        connection.stats(),
                        client.stats(),
                        ingress.remote_address(),
                        ingress.stats()
                    );
                    let port = client.local_addr().unwrap().port();
                    while ingress.remote_address().port() != port {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                    moving.elapsed().as_secs_f64() * 1000.0
                });
            }
            while let Some(result) = moves.join_next().await {
                migrations_ms.push(result.unwrap());
            }
        }

        let phase_start = Instant::now();
        let mut transfers = tokio::task::JoinSet::new();
        for (_, connection, _) in &clients {
            for _ in 0..4 {
                let conn = connection.clone();
                transfers.spawn(async move {
                    let start = Instant::now();
                    exchange(&conn, 1024 * 1024).await;
                    start.elapsed().as_secs_f64() * 1000.0
                });
            }
        }
        while let Some(result) = transfers.join_next().await {
            requests_ms.push(result.unwrap());
        }
        steady += phase_start.elapsed();
    }
    // Count application bytes in both directions: 4 phases * 4 streams * 1 MiB * 2.
    let total_mib_s = (32.0 * scenario.connections as f64) / total.elapsed().as_secs_f64();
    let steady_mib_s = (32.0 * scenario.connections as f64) / steady.as_secs_f64();
    let ingress_mtu = observed
        .lock()
        .iter()
        .map(|c| c.stats().path.current_mtu)
        .min()
        .unwrap();
    for (client, connection, _) in &clients {
        connection.close(VarInt::from_u32(0), b"bench done");
        client.shutdown_now().await;
    }
    origin.shutdown_now().await;
    proxy.abort();
    drop(proxy.await);
    echo.abort();
    drop(echo.await);
    // Do not let background work from one configuration contaminate the next sample.
    drop((clients, origin, observed));
    scope.abort(rama_core::graceful::Cause::Owner);
    drop(scope);
    weak_scope.drained().await;
    Sample {
        steady_mib_s,
        total_mib_s,
        requests_ms,
        migrations_ms,
        ingress_mtu,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "release-mode native UDP benchmark; prints measured comparisons"]
#[expect(
    clippy::print_stdout,
    reason = "explicit benchmark emits machine-readable measurements"
)]
async fn compare_native_relay_migration() {
    if std::env::var_os("RAMA_MIGRATION_BENCH_TRACE").is_some() {
        let _installed = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_env_filter("rama_quic::driver=debug,rama_quic::proxy=debug,rama_udp=debug")
            .try_init();
    }
    let connections = std::env::var("RAMA_MIGRATION_BENCH_CONNECTIONS")
        .ok()
        .map(|s| s.parse::<usize>().unwrap())
        .unwrap_or(1);
    assert!(connections > 0);
    let cases = [
        Scenario {
            migration: false,
            policy: false,
            connections,
            rebinds: 0,
            reuse_peer: false,
        },
        Scenario {
            migration: true,
            policy: false,
            connections,
            rebinds: 0,
            reuse_peer: false,
        },
        Scenario {
            migration: true,
            policy: false,
            connections,
            rebinds: 1,
            reuse_peer: false,
        },
        Scenario {
            migration: true,
            policy: false,
            connections,
            rebinds: 3,
            reuse_peer: false,
        },
        Scenario {
            migration: true,
            policy: true,
            connections,
            rebinds: 0,
            reuse_peer: false,
        },
    ];
    // Restrict comparisons without spending samples on unrelated migration scenarios.
    let selected = std::env::var("RAMA_MIGRATION_BENCH_CASES")
        .map(|value| {
            value
                .split(',')
                .map(|index| index.trim().parse::<usize>().unwrap())
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|_| (0..cases.len()).collect());
    assert!(!selected.is_empty());
    assert!(selected.iter().all(|&index| index < cases.len()));
    for (position, index) in selected.iter().enumerate() {
        assert!(
            !selected[..position].contains(index),
            "duplicate benchmark case"
        );
    }

    let rounds = std::env::var("RAMA_MIGRATION_BENCH_ROUNDS")
        .ok()
        .map(|s| s.parse::<usize>().unwrap())
        .unwrap_or(9);
    assert!(rounds >= 3);
    for round in 0..=rounds {
        for offset in 0..selected.len() {
            let index = selected[(round + offset) % selected.len()];
            let measured = timeout(Duration::from_secs(60), sample(cases[index]))
                .await
                .unwrap();
            if round == 0 {
                continue;
            } // one full unmeasured warmup per configuration
            println!(
                "MIGRATION_BENCH {{\"case\":{index},\"connections\":{connections},\"round\":{round},\"steady_mib_s\":{},\"total_mib_s\":{},\"requests_ms\":{:?},\"migrations_ms\":{:?},\"ingress_mtu\":{}}}",
                measured.steady_mib_s,
                measured.total_mib_s,
                measured.requests_ms,
                measured.migrations_ms,
                measured.ingress_mtu
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real UDP port reuse; another process can claim the released port"]
async fn retired_peer_tuple_can_move_to_another_independent_connection() {
    timeout(
        Duration::from_secs(15),
        sample(Scenario {
            migration: true,
            policy: false,
            connections: 2,
            rebinds: 1,
            reuse_peer: true,
        }),
    )
    .await
    .unwrap();
}
