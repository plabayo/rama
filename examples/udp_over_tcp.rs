//! Tunnel UDP datagrams over a single TCP connection.
//!
//! This example is inspired by [Jon Gjengset](https://github.com/jonhoo)'s
//! [`udp-over-tcp`](https://github.com/jonhoo/udp-over-tcp) crate; full credit
//! for the use case and the wire protocol (UDP datagrams length-prefixed
//! with a `u16` over the TCP side) goes to him.
//!
//! Use cases include reaching a UDP service (e.g. WireGuard, DNS) from a
//! network that only allows outbound TCP.
//!
//! # Pieces
//!
//! - **`udp2tcp`** binds a UDP socket and forwards every datagram over a
//!   single, long-lived TCP connection to a remote `tcp2udp` peer.
//! - **`tcp2udp`** accepts TCP connections and, for each, forwards the
//!   length-framed datagrams to a configured UDP destination.
//!
//! With rama, both sides reduce to:
//!
//! ```text
//! ConnectedUdpFramed  <—— StreamForwardService ——>  Framed<TcpStream, LengthDelimitedCodec>
//! ```
//!
//! Connected UDP sockets give us a `Stream + Sink` over plain bytes with no
//! per-datagram peer-tracking state, so the bridge is a one-liner.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example udp_over_tcp --features=udp,tcp
//! ```
//!
//! # Expected output
//!
//! The example wires up an in-process tunnel and verifies a UDP round-trip
//! through it:
//!
//! ```text
//! tunnel: round-trip ok (5 bytes)
//! tunnel: round-trip ok (5 bytes)
//! tunnel: round-trip ok (5 bytes)
//! done!
//! ```

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "example: panic-on-error is the standard pattern for demos"
)]

use std::net::SocketAddr;
use std::time::Duration;

use rama::{
    Service,
    bytes::Bytes,
    error::BoxError,
    futures::{SinkExt, StreamExt},
    net::address::SocketAddress,
    rt::Executor,
    stream::{
        BytesFreeze, StreamBridge, StreamForwardService,
        codec::{BytesCodec, Framed, LengthDelimitedCodec},
    },
    tcp::{TcpStream, client::default_tcp_connect, server::TcpListener},
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
    udp::{ConnectedUdpFramed, UdpSocket, bind_udp_with_address},
};

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    tracing::subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    // 1. Spin up a UDP "echo target": receives a datagram, sends it back.
    let echo_socket = bind_udp_with_address(SocketAddress::local_ipv4(0)).await?;
    let echo_addr = echo_socket.local_addr()?;
    tokio::spawn(udp_echo(echo_socket));

    // 2. Spin up the `tcp2udp` gateway: TCP listener that forwards each
    //    length-framed UDP datagram to `echo_addr`, and pipes replies back.
    let tcp_gateway_addr = SocketAddress::local_ipv4(0);
    let tcp_listener = TcpListener::bind_address(tcp_gateway_addr, Executor::default()).await?;
    let tcp_gateway_addr = tcp_listener.local_addr()?;
    tokio::spawn(async move {
        tcp_listener
            .serve(rama::service::service_fn(move |stream: TcpStream| {
                tcp2udp_one(stream, echo_addr)
            }))
            .await;
    });

    // 3. Spin up the `udp2tcp` gateway: UDP listener that pipes every
    //    datagram from one local UDP peer over a single TCP connection
    //    to `tcp_gateway_addr`.
    let udp_gateway_local = bind_udp_with_address(SocketAddress::local_ipv4(0)).await?;
    let udp_gateway_local_addr = udp_gateway_local.local_addr()?;
    tokio::spawn(async move {
        if let Err(err) = udp2tcp_run(udp_gateway_local, tcp_gateway_addr).await {
            tracing::error!("udp2tcp gateway exited with error: {err}");
        }
    });

    // 4. Driver: a connected UDP client speaking to the `udp2tcp` gateway.
    //    Anything it sends should come back through the tunnel.
    let client = bind_udp_with_address(SocketAddress::local_ipv4(0)).await?;
    client.connect(udp_gateway_local_addr).await?;
    let mut client = ConnectedUdpFramed::new(client, BytesCodec::new());

    for _ in 0..3 {
        client.send(Bytes::from_static(b"hello")).await?;
        let echoed = tokio::time::timeout(Duration::from_secs(2), client.next())
            .await
            .expect("tunnel round-trip timed out")
            .unwrap()
            .unwrap();
        assert_eq!(&echoed[..], b"hello");
        tracing::info!("tunnel: round-trip ok ({} bytes)", echoed.len());
    }

    tracing::info!("done!");
    Ok(())
}

/// Trivial UDP echo server bound to `socket`.
async fn udp_echo(socket: UdpSocket) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((n, peer)) => {
                if let Err(err) = socket.send_to(&buf[..n], peer).await {
                    tracing::error!("udp echo: send_to error: {err}");
                    return;
                }
            }
            Err(err) => {
                tracing::error!("udp echo: recv error: {err}");
                return;
            }
        }
    }
}

/// `udp2tcp`: bind UDP locally, connect TCP to the remote `tcp2udp` peer,
/// bridge them.
///
/// The UDP socket is `connect()`-ed to the first peer that talks to us
/// so that we get a plain `Stream + Sink` over bytes with no per-datagram
/// addressing state. Replies are routed back to that peer.
async fn udp2tcp_run(udp: UdpSocket, tcp_peer: SocketAddr) -> Result<(), BoxError> {
    // Wait for the first inbound datagram so we know who to pin to.
    let mut peek = [0u8; 1];
    let (_n, first_peer) = udp.peek_from(&mut peek).await?;
    udp.connect(first_peer).await?;

    let udp = ConnectedUdpFramed::new(udp, BytesCodec::new());
    let (tcp, _peer) =
        default_tcp_connect(&Default::default(), tcp_peer.into(), Executor::default()).await?;
    let tcp = Framed::new(
        tcp,
        LengthDelimitedCodec::builder()
            .length_field_type::<u16>()
            .new_codec(),
    );

    StreamForwardService::new()
        .with_idle_timeout(Duration::from_secs(300))
        .serve(StreamBridge::new(
            BytesFreeze::new(udp),
            BytesFreeze::new(tcp),
        ))
        .await?;

    Ok(())
}

/// `tcp2udp`: per inbound TCP connection, bind an ephemeral UDP socket
/// pinned to `udp_dst`, bridge them.
async fn tcp2udp_one(tcp: TcpStream, udp_dst: SocketAddr) -> Result<(), BoxError> {
    let udp = bind_udp_with_address(SocketAddress::local_ipv4(0)).await?;
    udp.connect(udp_dst).await?;
    let udp = ConnectedUdpFramed::new(udp, BytesCodec::new());
    let tcp = Framed::new(
        tcp,
        LengthDelimitedCodec::builder()
            .length_field_type::<u16>()
            .new_codec(),
    );

    StreamForwardService::new()
        .with_idle_timeout(Duration::from_secs(300))
        .serve(StreamBridge::new(
            BytesFreeze::new(tcp),
            BytesFreeze::new(udp),
        ))
        .await?;

    Ok(())
}
