//! The CONNECT-UDP ship gate, end to end through the proxy on every carrier: amplification,
//! cancellation, sustained load and flood fairness.

use super::{
    Carrier, DEADLINE, ProxyAuth, QuicTls, Tasks, assert_carrier, echo, http_client,
    masque_proxy_limited, masque_proxy_on, open_tunnel, proxy_address, udp_echo,
};
use rama::{
    Service as _,
    futures::future::join_all,
    graceful::Shutdown,
    net::{
        address::{HostWithPort, ProxyAddress, SocketAddress},
        client::{ConnectRequest, EstablishedClientConnection, ProxyRoute},
        stream::Socket as _,
    },
    proxy::masque::connect_udp::{
        ConnectUdpConnector, ConnectUdpLimits, ConnectUdpSocket, DatagramRate,
        DestinationScopePolicy, MaybeTunneledSocket, PrincipalBudget, TunnelBudget,
    },
    rt::Executor,
    udp::{
        DatagramSenderExt as _, DatagramSocket as _, DatagramSocketExt as _, SendDatagram,
        proxy::UdpConnector,
    },
    utils::{octets::mib, rate::Rate},
};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    net::UdpSocket,
    task::JoinHandle,
    time::{MissedTickBehavior, timeout},
};

/// What a counting target received.
#[derive(Debug, Default)]
struct Received {
    packets: AtomicU64,
    bytes: AtomicU64,
}

impl Received {
    fn packets(&self) -> u64 {
        self.packets.load(Ordering::SeqCst)
    }

    fn bytes(&self) -> u64 {
        self.bytes.load(Ordering::SeqCst)
    }
}

/// How a counting target answers each datagram.
#[derive(Debug, Clone, Copy)]
enum Answer {
    Nothing,
    Echo,
    /// This many copies of it.
    Reflect(usize),
}

/// A loopback UDP target counting what it receives.
async fn counting_target(answer: Answer) -> (SocketAddress, Arc<Received>, Tasks) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = SocketAddress::from(socket.local_addr().unwrap());
    let received = Arc::new(Received::default());
    let counted = received.clone();
    let task = tokio::spawn(async move {
        let mut buffer = vec![0; 65536];
        while let Ok((len, from)) = socket.recv_from(&mut buffer).await {
            counted.packets.fetch_add(1, Ordering::SeqCst);
            counted.bytes.fetch_add(len as u64, Ordering::SeqCst);
            let copies = match answer {
                Answer::Nothing => 0,
                Answer::Echo => 1,
                Answer::Reflect(copies) => copies,
            };
            for _ in 0..copies {
                _ = socket.send_to(&buffer[..len], from).await;
            }
        }
    });
    (address, received, Tasks::new(vec![task], None))
}

/// A proxy for `carrier` with `limits` and `budget`.
async fn proxy_for(
    carrier: Carrier,
    limits: ConnectUdpLimits,
    budget: TunnelBudget,
) -> (ProxyAddress, Tasks) {
    let (proxy, tasks) = masque_proxy_limited(
        None,
        DestinationScopePolicy::allow_private(),
        carrier != Carrier::Http3Capsule,
        ProxyAuth::Anonymous,
        QuicTls::Boring,
        limits,
        Some(budget),
    )
    .await;
    (proxy_address("masque://", proxy), tasks)
}

/// A tunnel for `carrier`, on a client connection of its own.
async fn tunnel(proxy: &ProxyAddress, target: SocketAddress, carrier: Carrier) -> ConnectUdpSocket {
    let socket = open_tunnel(Executor::new(), proxy, target, carrier.version())
        .await
        .unwrap_or_else(|error| panic!("{carrier:?}: {error}"));
    assert_carrier(&socket, carrier);
    socket
}

/// Receive datagrams until none arrives for `quiet`, returning how many did.
async fn drain(socket: &mut ConnectUdpSocket, quiet: Duration) -> u64 {
    let mut buffer = vec![0; 65536];
    let mut count = 0;
    while let Ok(result) = timeout(quiet, socket.recv(&mut buffer)).await {
        result.unwrap();
        count += 1;
    }
    count
}

/// Wait until `done` holds, at most five seconds.
async fn eventually(what: &str, mut done: impl FnMut() -> bool) {
    timeout(Duration::from_secs(5), async {
        while !done() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{what} within 5s"));
}

/// A payload of `len` bytes, cut to what the tunnel carries.
fn payload(socket: &ConnectUdpSocket, len: usize, fill: u8) -> Vec<u8> {
    vec![fill; len.min(socket.max_payload())]
}

/// The proxy sends a target one datagram for each the client sent and not a byte more,
/// empty ones included.
#[tokio::test]
async fn a_target_receives_exactly_what_the_client_sent_on_every_carrier() {
    timeout(DEADLINE, async {
        for carrier in Carrier::ALL {
            let (target, received, _target) = counting_target(Answer::Echo).await;
            let (proxy, _proxy) =
                proxy_for(carrier, ConnectUdpLimits::new(), TunnelBudget::new()).await;
            let mut socket = tunnel(&proxy, target, carrier).await;
            let mut sent = 0;
            for (index, len) in [0, 1, 64, 700, 1200]
                .into_iter()
                .cycle()
                .take(40)
                .enumerate()
            {
                let payload = payload(&socket, len, index as u8);
                sent += payload.len() as u64;
                echo(&mut socket, &payload).await;
            }
            assert_eq!(received.packets(), 40, "{carrier:?}");
            assert_eq!(received.bytes(), sent, "{carrier:?}");
        }
    })
    .await
    .unwrap();
}

/// A target answering every datagram many times over reaches the client only within the
/// tunnel's rate toward the client.
#[tokio::test]
async fn a_reflecting_target_reaches_the_client_only_within_its_rate_on_every_carrier() {
    const COPIES: usize = 50;
    const BURST: u64 = 10;
    timeout(DEADLINE, async {
        let (target, _received, _target) = counting_target(Answer::Reflect(COPIES)).await;
        // Ten packets at once, refilled one per second: the test reads well within one second.
        let limited = TunnelBudget::new().with_to_client(
            DatagramRate::new(Rate::per_sec(1), Rate::per_sec(mib(1) as u64))
                .with_packet_burst(BURST),
        );
        for carrier in Carrier::ALL {
            for (budget, limited) in [(TunnelBudget::new(), false), (limited, true)] {
                let (proxy, _proxy) = proxy_for(carrier, ConnectUdpLimits::new(), budget).await;
                let mut socket = tunnel(&proxy, target, carrier).await;
                let peer = socket.peer_addr().unwrap();
                socket
                    .create_sender()
                    .send(SendDatagram::new(peer, b"reflect me"))
                    .await
                    .unwrap();
                let delivered = drain(&mut socket, Duration::from_millis(300)).await;
                if limited {
                    assert_eq!(delivered, BURST, "{carrier:?}");
                } else {
                    // Without a rate the reflection is the target's to send: well beyond it.
                    assert!(delivered > BURST, "{carrier:?}: {delivered}");
                }
            }
        }
    })
    .await
    .unwrap();
}

/// Only the target reaches the client: anyone else writing to the proxy's egress socket does not.
#[tokio::test]
async fn a_stranger_writing_to_the_egress_socket_never_reaches_the_client_on_every_carrier() {
    timeout(DEADLINE, async {
        let (target, _echo) = udp_echo().await;
        let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for carrier in Carrier::ALL {
            let (proxy, fixture) =
                proxy_for(carrier, ConnectUdpLimits::new(), TunnelBudget::new()).await;
            let mut socket = tunnel(&proxy, target, carrier).await;
            echo(&mut socket, b"answered").await;
            let egress = *fixture
                .proxy
                .as_ref()
                .unwrap()
                .locals
                .lock()
                .last()
                .unwrap();
            for _ in 0..8 {
                stranger
                    .send_to(b"stranger", SocketAddr::from(egress))
                    .await
                    .unwrap();
            }
            // Room for the stranger's datagrams to arrive, had they been forwarded.
            tokio::time::sleep(Duration::from_millis(100)).await;
            echo(&mut socket, b"only the target").await;
            assert_eq!(
                drain(&mut socket, Duration::from_millis(100)).await,
                0,
                "{carrier:?}"
            );
        }
    })
    .await
    .unwrap();
}

/// A tunnel dropped while both directions are busy frees its place and its egress socket.
#[tokio::test]
async fn a_tunnel_dropped_mid_flood_frees_its_place_and_socket_on_every_carrier() {
    timeout(DEADLINE, async {
        let (target, received, _target) = counting_target(Answer::Echo).await;
        for carrier in Carrier::ALL {
            let limits = ConnectUdpLimits::new().with_max_tunnels(1);
            let (proxy, fixture) = proxy_for(carrier, limits.clone(), TunnelBudget::new()).await;
            let egress = fixture.proxy.clone().unwrap();
            let mut socket = tunnel(&proxy, target, carrier).await;
            let before = received.packets();
            let mut sender = socket.create_sender();
            let peer = socket.peer_addr().unwrap();
            let datagram = payload(&socket, 1000, 7);
            let flood = tokio::spawn(async move {
                while sender
                    .send(SendDatagram::new(peer, &datagram))
                    .await
                    .is_ok()
                {
                    tokio::task::yield_now().await;
                }
            });
            let mut buffer = vec![0; 65536];
            // Both ways busy: the target has answered a good deal of the flood.
            while received.packets() < before + 100 {
                timeout(Duration::from_secs(5), socket.recv(&mut buffer))
                    .await
                    .unwrap_or_else(|_| panic!("{carrier:?}: answers within 5s"))
                    .unwrap();
            }
            flood.abort();
            _ = flood.await;
            drop(socket);
            eventually(&format!("{carrier:?}: place freed"), || {
                limits.live_tunnels() == 0
            })
            .await;
            eventually(&format!("{carrier:?}: egress socket closed"), || {
                egress.active() == 0
            })
            .await;
            let mut again = tunnel(&proxy, target, carrier).await;
            echo(&mut again, b"again").await;
        }
    })
    .await
    .unwrap();
}

/// A graceful proxy shutdown ends every live tunnel, frees its place and socket, and finishes.
#[tokio::test]
async fn a_graceful_proxy_shutdown_ends_every_tunnel_on_every_carrier() {
    timeout(DEADLINE, async {
        let (target, _echo) = udp_echo().await;
        for carrier in Carrier::ALL {
            let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
            let shutdown = Shutdown::new(async move {
                _ = stopped.await;
            });
            let limits = ConnectUdpLimits::new();
            let (proxy, fixture) = masque_proxy_on(
                Executor::graceful(shutdown.guard()),
                None,
                DestinationScopePolicy::allow_private(),
                carrier != Carrier::Http3Capsule,
                ProxyAuth::Anonymous,
                QuicTls::Boring,
                limits.clone(),
                Some(TunnelBudget::new()),
            )
            .await;
            let egress = fixture.proxy.clone().unwrap();
            let mut socket = tunnel(&proxy_address("masque://", proxy), target, carrier).await;
            echo(&mut socket, b"before").await;
            assert_eq!(limits.live_tunnels(), 1, "{carrier:?}");

            stop.send(()).unwrap();
            timeout(Duration::from_secs(10), shutdown.shutdown())
                .await
                .unwrap_or_else(|_| panic!("{carrier:?}: shutdown within 10s"));
            assert_eq!(limits.live_tunnels(), 0, "{carrier:?}");
            assert_eq!(egress.active(), 0, "{carrier:?}");
            let mut buffer = [0; 64];
            let ended = timeout(Duration::from_secs(5), socket.recv(&mut buffer))
                .await
                .unwrap_or_else(|_| panic!("{carrier:?}: the tunnel ends within 5s"));
            assert!(ended.is_err(), "{carrier:?}: {ended:?}");
            drop(fixture);
        }
    })
    .await
    .unwrap();
}

/// Round trips of one tunnel: how many were lost and how long each answered one took.
#[derive(Debug, Default)]
struct RoundTrips {
    lost: u64,
    rtts: Vec<Duration>,
}

impl RoundTrips {
    fn merge(&mut self, other: Self) {
        self.lost += other.lost;
        self.rtts.extend(other.rtts);
    }

    fn sent(&self) -> u64 {
        self.lost + self.rtts.len() as u64
    }

    /// The `per_mille`th fastest round trip.
    fn quantile(&self, per_mille: usize) -> Duration {
        let mut rtts = self.rtts.clone();
        rtts.sort_unstable();
        let index = (rtts.len() * per_mille / 1000).min(rtts.len().saturating_sub(1));
        rtts.get(index).copied().unwrap_or_default()
    }
}

/// Echo round trips, one in flight and at most one per `pace`, `count` of them or until
/// `until` passes. A round trip unanswered after `lost_after` is lost; a stale answer arriving
/// late is skipped.
async fn round_trips(
    socket: &mut ConnectUdpSocket,
    len: impl Fn(usize) -> usize,
    count: usize,
    until: Option<Instant>,
    pace: Option<Duration>,
    lost_after: Duration,
) -> RoundTrips {
    let peer = socket.peer_addr().unwrap();
    let mut sender = socket.create_sender();
    let mut buffer = vec![0; 65536];
    let mut trips = RoundTrips::default();
    let mut ticks = pace.map(|pace| {
        let mut ticks = tokio::time::interval(pace);
        ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
        ticks
    });
    for index in 0..count {
        if let Some(ticks) = &mut ticks {
            ticks.tick().await;
        }
        if until.is_some_and(|until| Instant::now() >= until) {
            break;
        }
        // The index leads each payload, so a late answer is told from the current one.
        let mut datagram = payload(socket, len(index).max(4), 0);
        datagram[..4].copy_from_slice(&(index as u32).to_be_bytes());
        let started = Instant::now();
        sender
            .send(SendDatagram::new(peer, &datagram))
            .await
            .unwrap();
        let answered = timeout(lost_after, async {
            loop {
                let metadata = socket.recv(&mut buffer).await.unwrap();
                if buffer[..metadata.len] == datagram[..] {
                    return;
                }
            }
        })
        .await;
        match answered {
            Ok(()) => trips.rtts.push(started.elapsed()),
            Err(_) => trips.lost += 1,
        }
    }
    trips
}

/// Many tunnels on every carrier at once move thousands of datagrams of mixed size; capsules
/// lose none, native datagrams few, and every place and socket is given back afterwards.
#[tokio::test]
async fn sustained_load_on_every_carrier_moves_every_payload_and_frees_everything() {
    const TUNNELS: usize = 8;
    const TRIPS: usize = 250;
    timeout(Duration::from_secs(60), async {
        let (target, received, _target) = counting_target(Answer::Echo).await;
        let lengths = [4, 32, 200, 512, 1200, 64, 900, 8];
        let runs = Carrier::ALL.map(|carrier| async move {
            let limits = ConnectUdpLimits::new()
                .with_max_tunnels(TUNNELS)
                .with_max_tunnels_per_principal(TUNNELS);
            let (proxy, fixture) = proxy_for(carrier, limits.clone(), TunnelBudget::new()).await;
            let egress = fixture.proxy.clone().unwrap();
            let mut sockets = Vec::new();
            for _ in 0..TUNNELS {
                sockets.push(tunnel(&proxy, target, carrier).await);
            }
            let trips = join_all(sockets.iter_mut().map(|socket| {
                round_trips(
                    socket,
                    |index| lengths[index % lengths.len()],
                    TRIPS,
                    None,
                    None,
                    Duration::from_secs(1),
                )
            }))
            .await;
            let mut all = RoundTrips::default();
            for trip in trips {
                all.merge(trip);
            }
            drop(sockets);
            eventually(&format!("{carrier:?}: places freed"), || {
                limits.live_tunnels() == 0
            })
            .await;
            eventually(&format!("{carrier:?}: egress sockets closed"), || {
                egress.active() == 0
            })
            .await;
            // The principal has all its places back.
            let mut again = Vec::new();
            for _ in 0..TUNNELS {
                again.push(tunnel(&proxy, target, carrier).await);
            }
            for socket in &mut again {
                echo(socket, b"again").await;
            }
            (carrier, all, fixture)
        });
        let started = Instant::now();
        let results = join_all(runs).await;
        let elapsed = started.elapsed();
        for (carrier, trips, _fixture) in results {
            let sent = trips.sent();
            assert_eq!(sent, (TUNNELS * TRIPS) as u64, "{carrier:?}");
            if carrier == Carrier::Http3Datagram {
                // Unreliable by design; on loopback with one datagram in flight, rare.
                assert!(trips.lost * 100 <= sent, "{carrier:?}: lost {}", trips.lost);
            } else {
                assert_eq!(trips.lost, 0, "{carrier:?}: capsules are reliable");
            }
            eprintln!(
                "sustained {carrier:?}: {sent} round trips, {} lost, p50 {:?}, p99 {:?}",
                trips.lost,
                trips.quantile(500),
                trips.quantile(990),
            );
        }
        eprintln!(
            "sustained: {} datagrams reached the target in {elapsed:?}",
            received.packets()
        );
    })
    .await
    .unwrap();
}

/// Where a flooding tunnel runs relative to the measured one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flood {
    None,
    /// On a client connection of its own.
    OtherConnection,
    /// On the same client connection (not on HTTP/1.1, whose tunnel takes its connection whole).
    SameConnection,
    /// Another principal's, on a connection of its own, which exhausts that principal's budget.
    OtherPrincipalLimited,
}

/// A flooding tunnel sending `len`-byte datagrams to a silent target as fast as it can until
/// stopped; returns how many it sent.
fn flood(socket: ConnectUdpSocket, len: usize, stop: Arc<AtomicBool>) -> JoinHandle<u64> {
    tokio::spawn(async move {
        let peer = socket.peer_addr().unwrap();
        let mut sender = socket.create_sender();
        let datagram = payload(&socket, len, 9);
        let mut sent = 0;
        while !stop.load(Ordering::Relaxed) {
            if sender
                .send(SendDatagram::new(peer, &datagram))
                .await
                .is_err()
            {
                break;
            }
            sent += 1;
            // Keep the flood from monopolising a current-thread runtime.
            if sent % 32 == 0 {
                tokio::task::yield_now().await;
            }
        }
        drop(socket);
        sent
    })
}

/// The measured tunnel's payload, at most one per millisecond: an interactive tenant, well
/// within the rate a limited principal gets.
const MEASURED_PAYLOAD: usize = 64;
const MEASURED_PACE: Duration = Duration::from_millis(1);
/// How long the measured tunnel waits for an answer before counting it lost.
const LOST_AFTER: Duration = Duration::from_millis(500);
/// The flood's payload, sent as fast as the carrier takes it.
const FLOOD_PAYLOAD: usize = 1000;
/// What every principal may send toward targets in [`Flood::OtherPrincipalLimited`].
const LIMITED_PACKETS: u64 = 2000;
const LIMITED_BURST: u64 = 100;
const LIMITED_BYTES: u64 = 4 * 1024 * 1024;

/// One fairness measurement: the measured tunnel's round trips beside `scenario`, what the
/// flood sent and the sink received, and how long the measured round trips took.
struct Measured {
    trips: RoundTrips,
    flood_sent: u64,
    sink_received: u64,
    elapsed: Duration,
}

/// The measured tunnel's round trips, `count` of them or until `window` passes, beside
/// `scenario`. Every principal may run one tunnel, so the proxy keys each one: the measured
/// tunnel is anonymous, keyed by its client IP, and a flood on another connection is `john`'s.
/// A flood on the same connection is the same client's, which may then run two.
async fn measure(
    carrier: Carrier,
    scenario: Flood,
    count: usize,
    window: Option<Duration>,
) -> Measured {
    let (echo_target, _echo) = udp_echo().await;
    let (sink, sunk, _sink) = counting_target(Answer::Nothing).await;
    let per_principal = if scenario == Flood::SameConnection {
        2
    } else {
        1
    };
    let limits = ConnectUdpLimits::new().with_max_tunnels_per_principal(per_principal);
    let limits = match scenario {
        Flood::OtherPrincipalLimited => limits.with_principal_budget(
            PrincipalBudget::new().with_to_target(
                DatagramRate::new(Rate::per_sec(LIMITED_PACKETS), Rate::per_sec(LIMITED_BYTES))
                    .with_packet_burst(LIMITED_BURST),
            ),
        ),
        _ => limits,
    };
    let (address, fixture) = masque_proxy_limited(
        None,
        DestinationScopePolicy::allow_private(),
        carrier != Carrier::Http3Capsule,
        ProxyAuth::Anonymous,
        QuicTls::Boring,
        limits.clone(),
        // The flood's target never answers: no first-reply allowance stops it.
        Some(TunnelBudget::new().with_unanswered(u64::MAX, u64::MAX)),
    )
    .await;
    let anonymous = proxy_address("masque://", address);
    let john = ProxyAddress::try_from(format!("masque://john:secret@{address}").as_str()).unwrap();
    let (mut measured, flooding) = if scenario == Flood::SameConnection {
        let exec = Executor::new();
        let connector =
            ConnectUdpConnector::new(UdpConnector::new(), http_client(exec.clone()), exec)
                .with_version(carrier.version());
        let mut sockets = Vec::new();
        for target in [echo_target, sink] {
            let request = ConnectRequest::new(HostWithPort::from(target));
            request
                .extensions
                .insert(ProxyRoute::Proxy(anonymous.clone()));
            let EstablishedClientConnection { conn, .. } = connector.serve(request).await.unwrap();
            let MaybeTunneledSocket::Tunneled(socket) = conn else {
                panic!("{carrier:?}: a MASQUE route must tunnel");
            };
            sockets.push(socket);
        }
        let flooding = sockets.pop().unwrap();
        (sockets.pop().unwrap(), Some(flooding))
    } else {
        let measured = tunnel(&anonymous, echo_target, carrier).await;
        let flooding = match scenario {
            Flood::None => None,
            _ => Some(tunnel(&john, sink, carrier).await),
        };
        (measured, flooding)
    };
    // Who runs the tunnels, and on how many carrier connections.
    let principals = if matches!(scenario, Flood::None | Flood::SameConnection) {
        1
    } else {
        2
    };
    assert_eq!(
        limits.tracked_principals(),
        principals,
        "{carrier:?} {scenario:?}"
    );
    if flooding.is_some() {
        let tcp = fixture.tcp_connections.load(Ordering::SeqCst);
        let quic = fixture.endpoint.as_ref().unwrap().open_connections();
        let connections = if scenario == Flood::SameConnection {
            1
        } else {
            2
        };
        let expected = match carrier {
            Carrier::Http1 | Carrier::Http2 => (connections, 0),
            Carrier::Http3Capsule | Carrier::Http3Datagram => (0, connections),
        };
        assert_eq!((tcp, quic), expected, "{carrier:?} {scenario:?}");
    }
    if scenario != Flood::SameConnection {
        // The cap is live: a second anonymous tunnel is refused, so john's tunnel counts
        // against john alone.
        let error = open_tunnel(Executor::new(), &anonymous, echo_target, carrier.version())
            .await
            .expect_err("one tunnel per principal");
        assert!(
            format!("{error:?}").contains("503"),
            "{carrier:?}: {error:?}"
        );
    }
    // Warm up both ways before measuring.
    echo(&mut measured, b"warm").await;
    let stop = Arc::new(AtomicBool::new(false));
    let flooder = flooding.map(|socket| flood(socket, FLOOD_PAYLOAD, stop.clone()));
    let started = Instant::now();
    let trips = round_trips(
        &mut measured,
        |_| MEASURED_PAYLOAD,
        count,
        window.map(|window| started + window),
        Some(MEASURED_PACE),
        LOST_AFTER,
    )
    .await;
    let elapsed = started.elapsed();
    stop.store(true, Ordering::Relaxed);
    let flood_sent = match flooder {
        Some(flooder) => flooder.await.unwrap(),
        None => 0,
    };
    Measured {
        trips,
        flood_sent,
        sink_received: sunk.packets(),
        elapsed,
    }
}

/// The measured round trips beside a flood are all answered on a reliable carrier; native
/// datagrams may lose a few, as every connection reaches the proxy through its one UDP socket.
fn assert_live(carrier: Carrier, scenario: Flood, measured: &Measured, count: usize) {
    assert_eq!(
        measured.trips.sent(),
        count as u64,
        "{carrier:?} {scenario:?}"
    );
    if carrier == Carrier::Http3Datagram {
        assert!(
            measured.trips.lost * 10 <= measured.trips.sent(),
            "{carrier:?} {scenario:?}: lost {} of {}",
            measured.trips.lost,
            measured.trips.sent(),
        );
    } else {
        assert_eq!(measured.trips.lost, 0, "{carrier:?} {scenario:?}");
    }
}

fn report(carrier: Carrier, scenario: Flood, measured: &Measured) {
    eprintln!(
        "fairness {carrier:?} {scenario:?}: p50 {:?} p99 {:?}, {} of {} lost in {:?}, flood {} sent {} received",
        measured.trips.quantile(500),
        measured.trips.quantile(990),
        measured.trips.lost,
        measured.trips.sent(),
        measured.elapsed,
        measured.flood_sent,
        measured.sink_received,
    );
}

/// A tunnel stays live beside another principal's flood on a connection of its own, on every
/// carrier: unlimited, and with every principal's budget set, where the flooding principal
/// exhausts its own budget and the quiet one is never refused.
#[tokio::test]
async fn a_flooding_principal_leaves_another_principals_tunnel_live_on_every_carrier() {
    const TRIPS: usize = 100;
    timeout(DEADLINE, async {
        for carrier in Carrier::ALL {
            let quiet = measure(carrier, Flood::None, TRIPS, None).await;
            assert_live(carrier, Flood::None, &quiet, TRIPS);
            report(carrier, Flood::None, &quiet);

            let flooded = measure(carrier, Flood::OtherConnection, TRIPS, None).await;
            assert!(
                flooded.sink_received >= 100,
                "{carrier:?}: the flood reached its target ({} of {})",
                flooded.sink_received,
                flooded.flood_sent,
            );
            assert_live(carrier, Flood::OtherConnection, &flooded, TRIPS);
            report(carrier, Flood::OtherConnection, &flooded);

            let limited = measure(carrier, Flood::OtherPrincipalLimited, TRIPS, None).await;
            // One burst, then the rate while the flood ran: the measured round trips, and
            // slack for stopping the flood and its last datagrams in flight.
            let flooding_ms = limited.elapsed.as_millis() as u64 + 100;
            let allowed = LIMITED_BURST + LIMITED_PACKETS * flooding_ms / 1000;
            assert!(
                limited.sink_received <= allowed && limited.sink_received < limited.flood_sent,
                "{carrier:?}: john's budget held the flood ({} of {} reached the target, {allowed} allowed)",
                limited.sink_received,
                limited.flood_sent,
            );
            assert_live(carrier, Flood::OtherPrincipalLimited, &limited, TRIPS);
            report(carrier, Flood::OtherPrincipalLimited, &limited);
        }
    })
    .await
    .unwrap();
}

/// The flood fairness and latency table: a measured tunnel's round trips beside each kind of
/// flood, on every carrier. Run with `--ignored --nocapture`; local numbers vary with host load,
/// so it asserts only who runs the tunnels and where.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "a measurement; prints a table"]
async fn measure_flood_fairness_and_latency() {
    const WINDOW: Duration = Duration::from_secs(2);
    eprintln!(
        "measured: {MEASURED_PAYLOAD}-byte echoes, one in flight, at most one per {MEASURED_PACE:?}, \
         lost after {LOST_AFTER:?}, for {WINDOW:?}; flood: {FLOOD_PAYLOAD}-byte datagrams to a \
         silent target as fast as the carrier takes them; limited: every principal \
         {LIMITED_PACKETS} packets (burst {LIMITED_BURST}) and {LIMITED_BYTES} bytes a second toward targets"
    );
    eprintln!(
        "{:<14} {:<22} {:>9} {:>6} {:>6} {:>10} {:>10} {:>10} {:>9} {:>9}",
        "carrier", "flood", "elapsed", "trips", "lost", "p50", "p99", "max", "sent", "sunk"
    );
    for carrier in Carrier::ALL {
        for scenario in [
            Flood::None,
            Flood::OtherConnection,
            Flood::SameConnection,
            Flood::OtherPrincipalLimited,
        ] {
            if scenario == Flood::SameConnection && carrier == Carrier::Http1 {
                continue;
            }
            let measured = measure(carrier, scenario, usize::MAX, Some(WINDOW)).await;
            eprintln!(
                "{:<14} {:<22} {:>9.2?} {:>6} {:>6} {:>10.1?} {:>10.1?} {:>10.1?} {:>9} {:>9}",
                format!("{carrier:?}"),
                format!("{scenario:?}"),
                measured.elapsed,
                measured.trips.sent(),
                measured.trips.lost,
                measured.trips.quantile(500),
                measured.trips.quantile(990),
                measured.trips.quantile(1000),
                measured.flood_sent,
                measured.sink_received,
            );
        }
    }
}
