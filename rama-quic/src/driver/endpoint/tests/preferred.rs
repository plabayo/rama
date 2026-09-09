//! A server that advertises a preferred address, and the sockets it owns for it (RFC 9000 §9.6).

use super::super::*;
use super::lifecycle::{SegmentLog, SentDatagram};
use super::lifecycle::{
    block_segments_for, breakable_socket, configs, endpoint_with, exchange, fail_receiver,
    handshake, recording_socket, unblock_segments, wait_for,
};
use super::{DropObserver, TestSocket, probe_socket};
use rama_udp::UdpSocketConfig;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::Ordering;

fn localhost_v4() -> SocketAddr {
    SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0)
}

/// A server bound to an initial address and advertising a preferred one, with the client's
/// configuration to reach it.
async fn preferring_server() -> (Endpoint, ClientConfig, SocketAddr, SocketAddr) {
    let (client_config, mut server_config) = configs();
    server_config.preferred_address_v4(Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)));
    let server = Endpoint::server(server_config, localhost_v4())
        .await
        .expect("the server binds both addresses");
    let initial = server.local_addr().unwrap();
    let addrs = server.local_addrs();
    assert_eq!(addrs.len(), 2, "the endpoint owns both sockets: {addrs:?}");
    let preferred = addrs
        .into_iter()
        .find(|address| *address != initial)
        .expect("the advertised socket has an address of its own");
    assert_ne!(preferred.port(), 0, "with the port the platform assigned");
    (server, client_config, initial, preferred)
}

/// The client moves to the address the server advertised, and both sides carry data over it.
#[tokio::test]
async fn a_client_moves_to_the_advertised_address_and_data_flows() {
    let (server, client_config, initial, preferred) = preferring_server().await;
    let client = Endpoint::client(localhost_v4())
        .await
        .expect("the client binds");
    let connecting = client
        .connect_with(client_config, initial, "localhost")
        .unwrap();
    let incoming = tokio::time::timeout(Duration::from_secs(5), server.accept())
        .await
        .expect("the attempt arrives")
        .expect("the server is listening");
    let (c, s) = handshake(connecting, incoming).await;
    exchange(&c, &s, b"on the initial address").await;

    wait_for(
        "the client moved to the advertised address",
        Duration::from_secs(5),
        || c.remote_address() == preferred,
    )
    .await;

    // Exact bytes and the stream's end, both ways, over the new path.
    exchange(&c, &s, b"up over the preferred address").await;
    exchange(&s, &c, b"down over the preferred address").await;
    assert_eq!(c.remote_address(), preferred);
    drop((c, s));
    tokio::join!(client.shutdown(), server.shutdown());
}

/// A wildcard listener with a concrete advertised socket. Before the move the server answers from
/// the address the client sent to, which the wildcard socket covers; after it, from the advertised
/// socket. The client's view of the server's address is the source tuple its datagrams carried.
#[tokio::test]
async fn a_wildcard_listener_and_a_concrete_advertised_socket_keep_their_own_tuples() {
    let (client_config, mut server_config) = configs();
    server_config.preferred_address_v4(Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)));
    let server = Endpoint::server(
        server_config,
        SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
    )
    .await
    .expect("the wildcard listener and the advertised socket both bind");
    let listener = server.local_addr().unwrap();
    assert!(listener.ip().is_unspecified(), "the listener is a wildcard");
    let preferred = server
        .local_addrs()
        .into_iter()
        .find(|address| !address.ip().is_unspecified())
        .expect("the advertised socket is concrete");

    // The client sends to a concrete address of ours that the wildcard listener receives on.
    let reachable = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), listener.port());
    let client = Endpoint::client(localhost_v4())
        .await
        .expect("the client binds");
    let connecting = client
        .connect_with(client_config, reachable, "localhost")
        .unwrap();
    let incoming = tokio::time::timeout(Duration::from_secs(5), server.accept())
        .await
        .expect("the attempt arrives")
        .expect("the server is listening");
    let (c, s) = handshake(connecting, incoming).await;
    assert_eq!(
        c.remote_address(),
        reachable,
        "the wildcard listener answered from the address the client sent to"
    );
    exchange(&c, &s, b"through the wildcard listener").await;

    wait_for(
        "the client moved to the advertised address",
        Duration::from_secs(5),
        || c.remote_address() == preferred,
    )
    .await;
    exchange(&c, &s, b"up from the advertised socket").await;
    exchange(&s, &c, b"down from the advertised socket").await;
    drop((c, s));
    tokio::join!(client.shutdown(), server.shutdown());
}

/// A client connecting after another moved away still reaches the listener, and the two
/// connections keep their own paths: the second declines the advertised address, so the two paths
/// are different for as long as both live and each carries its own bytes.
#[tokio::test]
async fn the_listener_still_admits_clients_after_a_move_and_paths_stay_apart() {
    let (client_config, server, initial, preferred) = preferring_server_with_config().await;
    let first = Endpoint::client(localhost_v4()).await.unwrap();
    let (fc, fs) = connect_through(&first, &server, client_config.clone(), initial).await;
    wait_for("the first client moved", Duration::from_secs(5), || {
        fc.remote_address() == preferred
    })
    .await;

    // A second client connects through the original listener, which the move left alone, and
    // declines the advertised address so it stays there.
    let mut declining = client_config;
    declining.set_preferred_address_policy(crate::proto::PreferredAddressPolicy::Decline);
    let second = Endpoint::client(localhost_v4()).await.unwrap();
    let (sc, ss) = connect_through(&second, &server, declining, initial).await;
    assert_eq!(
        sc.remote_address(),
        initial,
        "the second client is answered from the listener"
    );

    // Both carry their own bytes over their own paths, in both directions.
    exchange(&fc, &fs, b"first on the advertised path").await;
    exchange(&fs, &fc, b"back on the advertised path").await;
    exchange(&sc, &ss, b"second on the listener").await;
    exchange(&ss, &sc, b"back on the listener").await;
    assert_eq!(fc.remote_address(), preferred);
    assert_eq!(
        sc.remote_address(),
        initial,
        "the second was never dragged onto the first's path"
    );
    drop((fc, fs, sc, ss));
    tokio::join!(first.shutdown(), second.shutdown(), server.shutdown());
}

/// An IPv6 server advertising an IPv6 preferred address, with an IPv6 client.
#[tokio::test]
async fn an_ipv6_server_advertises_an_ipv6_address() {
    let (client_config, mut server_config) = configs();
    server_config.preferred_address_v6(Some(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0)));
    let server = Endpoint::server(
        server_config,
        SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 0),
    )
    .await
    .expect("both IPv6 sockets bind");
    let initial = server.local_addr().unwrap();
    let preferred = server
        .local_addrs()
        .into_iter()
        .find(|address| *address != initial)
        .expect("the advertised socket has its own address");
    assert!(preferred.is_ipv6());

    let client = Endpoint::client(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 0))
        .await
        .unwrap();
    let (c, s) = connect_through(&client, &server, client_config, initial).await;
    wait_for("the client moved", Duration::from_secs(5), || {
        c.remote_address() == preferred
    })
    .await;
    exchange(&c, &s, b"over IPv6").await;
    exchange(&s, &c, b"and back").await;
    drop((c, s));
    tokio::join!(client.shutdown(), server.shutdown());
}

/// A wildcard preferred address is refused: resolving its port leaves an address no peer can be
/// sent to.
#[tokio::test]
async fn a_wildcard_preferred_address_is_refused() {
    let (_client_config, mut server_config) = configs();
    server_config.preferred_address_v4(Some(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)));
    let error = Endpoint::server(server_config, localhost_v4())
        .await
        .expect_err("a wildcard cannot be advertised");
    assert!(
        matches!(&error, rama_udp::DatagramError::Io(error)
            if error.kind() == io::ErrorKind::InvalidInput),
        "refused as an invalid configuration: {error:?}"
    );
}

/// Shutting down drops the sockets the endpoint owns, the advertised one included.
#[tokio::test]
async fn shutdown_drops_the_advertised_socket() {
    let (client_config, server_config) = configs();
    let server = Endpoint::server(server_config, localhost_v4())
        .await
        .expect("the server binds");
    let observer = Arc::new(DropObserver::default());
    server
        .advertise_socket(probe_socket(&observer, TestSocket::default()))
        .expect("the endpoint takes the advertised socket");
    assert_eq!(server.local_addrs().len(), 2, "it owns both");

    let client = Endpoint::client(localhost_v4()).await.unwrap();
    let initial = server.local_addr().unwrap();
    let (c, s) = connect_through(&client, &server, client_config, initial).await;
    exchange(&c, &s, b"before the shutdown").await;
    drop((c, s));

    tokio::join!(client.shutdown(), server.shutdown());
    assert_eq!(
        observer.drops.load(Ordering::SeqCst),
        1,
        "the advertised socket was dropped"
    );
    assert_eq!(
        observer.under_lock.load(Ordering::SeqCst),
        0,
        "and not while the endpoint lock was held"
    );
}

/// A server bound with no preferred address owns one socket.
#[tokio::test]
async fn a_server_without_a_preferred_address_owns_one_socket() {
    let (_client_config, server_config) = configs();
    let server = Endpoint::server(server_config, localhost_v4())
        .await
        .expect("the server binds");
    assert_eq!(server.local_addrs().len(), 1);
    server.shutdown().await;
}

/// The server and the client configuration for it, plus its two addresses.
async fn preferring_server_with_config() -> (ClientConfig, Endpoint, SocketAddr, SocketAddr) {
    let (server, client_config, initial, preferred) = preferring_server().await;
    (client_config, server, initial, preferred)
}

/// Connect `client` to `server` at `address` and complete the handshake.
async fn connect_through(
    client: &Endpoint,
    server: &Endpoint,
    config: ClientConfig,
    address: SocketAddr,
) -> (
    crate::driver::connection::Connection,
    crate::driver::connection::Connection,
) {
    let connecting = client.connect_with(config, address, "localhost").unwrap();
    let incoming = tokio::time::timeout(Duration::from_secs(5), server.accept())
        .await
        .expect("the attempt arrives")
        .expect("the server is listening");
    handshake(connecting, incoming).await
}

/// Which socket a datagram left by, observed on the wire rather than inferred from the
/// connection's own view of its path. The server's listener and its advertised socket each record
/// what they send, and the advertised one is blocked until the initial leg has been observed, so
/// the move cannot race ahead of it.
#[tokio::test]
async fn the_datagrams_of_each_path_leave_by_that_paths_socket() {
    let (client_config, mut server_config) = configs();
    let (listener, listener_log) = recording_socket();
    let (advertised, advertised_log) = recording_socket();
    let advertised_addr = advertised.local_addr();
    let SocketAddr::V4(advertised_v4) = advertised_addr else {
        panic!("the fixture binds an IPv4 loopback socket");
    };
    server_config.preferred_address_v4(Some(advertised_v4));
    let server = endpoint_with(EndpointConfig::default(), Some(server_config), listener);
    let initial = server.local_addr().unwrap();
    server
        .advertise_socket(advertised)
        .expect("the endpoint takes the advertised socket");

    let client = Endpoint::client(localhost_v4())
        .await
        .expect("the client binds");
    let client_addr = client.local_addr().unwrap();
    // Nothing leaves the advertised socket until this test lets it, so the initial leg is not a
    // race against the move.
    block_segments_for(&advertised_log, SocketAddress::from(client_addr));

    let (c, s) = connect_through(&client, &server, client_config, initial).await;
    exchange(&c, &s, b"on the initial path").await;
    let to_client = |log: &Mutex<SegmentLog>| {
        log.lock()
            .sent
            .iter()
            .filter(|datagram| datagram.destination == SocketAddress::from(client_addr))
            .count()
    };
    assert!(
        to_client(&listener_log) > 0,
        "the listener sent to the client"
    );
    assert_eq!(
        to_client(&advertised_log),
        0,
        "and the advertised socket sent nothing while it was blocked"
    );

    // Let the advertised socket answer: the client's probe is answered from there and it moves.
    unblock_segments(&advertised_log);
    wait_for("the client moved", Duration::from_secs(5), || {
        c.remote_address() == advertised_addr
    })
    .await;
    let listener_before = to_client(&listener_log);
    let advertised_before = to_client(&advertised_log);
    assert!(
        advertised_before > 0,
        "the advertised socket answered on its own path"
    );

    // The traffic that follows leaves by the advertised socket, and the listener sends no more.
    exchange(&c, &s, b"up over the advertised path").await;
    exchange(&s, &c, b"down over the advertised path").await;
    assert!(
        to_client(&advertised_log) > advertised_before,
        "the exchange left by the advertised socket"
    );
    assert_eq!(
        to_client(&listener_log),
        listener_before,
        "and nothing more left by the listener"
    );
    drop((c, s));
    tokio::join!(client.shutdown(), server.shutdown());
}

/// Coverage of a path by a wildcard socket belongs to that socket. When the socket a connection
/// sends from is replaced, the connection asks again rather than sending from a socket that
/// cannot carry the path.
#[tokio::test]
async fn coverage_does_not_survive_the_socket_it_was_established_on() {
    let (client_config, server_config) = configs();
    let server = Endpoint::server(server_config, localhost_v4())
        .await
        .expect("the server binds");
    let initial = server.local_addr().unwrap();

    // The client sends from a wildcard socket, so its path's local address is a concrete address
    // the socket covers rather than the address the socket is bound to.
    let client = Endpoint::bind(
        EndpointConfig::default(),
        None,
        SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
        UdpSocketConfig::default(),
    )
    .await
    .expect("the wildcard client binds");
    let (c, s) = connect_through(&client, &server, client_config, initial).await;
    exchange(&c, &s, b"from the wildcard socket").await;

    // A concrete socket replaces it. The coverage recorded for the old socket says nothing about
    // this one, and the connection keeps working.
    client
        .rebind(localhost_v4(), UdpSocketConfig::default())
        .await
        .expect("the rebind binds");
    exchange(&c, &s, b"after the replacement").await;
    exchange(&s, &c, b"and back").await;
    drop((c, s));
    tokio::join!(client.shutdown(), server.shutdown());
}

/// A socket the endpoint advertised that then fails is not offered to connections still to come,
/// and the connections on it are told to leave it while the listener keeps working.
#[tokio::test]
async fn a_failed_advertised_socket_stops_being_advertised() {
    let (client_config, mut server_config) = configs();
    let (listener, _listener_log) = recording_socket();
    let (advertised, _gate, fault, sent_by_advertised) = breakable_socket(None);
    let advertised_addr = advertised.local_addr();
    let SocketAddr::V4(advertised_v4) = advertised_addr else {
        panic!("the fixture binds an IPv4 loopback socket");
    };
    server_config.preferred_address_v4(Some(advertised_v4));
    let server = endpoint_with(EndpointConfig::default(), Some(server_config), listener);
    let initial = server.local_addr().unwrap();
    server.advertise_socket(advertised).unwrap();
    assert_eq!(
        server.advertised_preferred(),
        vec![advertised_addr],
        "the address is advertised while its socket is usable"
    );

    // Its receive path fails. The endpoint keeps its listener and stops offering the address.
    let sent_before = sent_by_advertised.load(Ordering::SeqCst);
    fail_receiver(&server, &fault);
    wait_for(
        "the advertised address is withdrawn",
        Duration::from_secs(5),
        || server.advertised_preferred().is_empty(),
    )
    .await;
    assert_eq!(
        server.local_addr().unwrap(),
        initial,
        "the listener is untouched"
    );

    // A client connecting now is never told about it, so it stays on the listener.
    let client = Endpoint::client(localhost_v4()).await.unwrap();
    let (c, s) = connect_through(&client, &server, client_config, initial).await;
    exchange(&c, &s, b"only the listener").await;
    exchange(&s, &c, b"and back").await;
    assert_eq!(c.remote_address(), initial);
    assert_eq!(
        sent_by_advertised.load(Ordering::SeqCst),
        sent_before,
        "nothing left by the failed socket"
    );
    drop((c, s));
    tokio::join!(client.shutdown(), server.shutdown());
}
