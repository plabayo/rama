//! An example to showcase how one can build an authenticated socks5 UDP Associate proxy server.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example socks5_udp_associate_framed --features=socks5
//! ```
//!
//! # Expected output
//!
//! Not many tools in the wild support socks5 UDP Associate,
//! and thus this is another self-contained example with the server
//! and client combined.

use rama::{
    Context,
    bytes::Bytes,
    net::address::SocketAddress,
    proxy::socks5::{Socks5Acceptor, Socks5Auth},
    proxy::socks5::{
        Socks5Client,
        server::{
            DefaultUdpRelay,
            udp::{RelayDirection, UdpInspectAction},
        },
    },
    tcp::client::default_tcp_connect,
    tcp::server::TcpListener,
    udp::{UdpSocket, codec::BytesCodec},
};

use futures::{FutureExt, SinkExt, StreamExt};
use std::convert::Infallible;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .init();

    let socks5_socket_addr = spawn_socks5_server().await;

    let (proxy_client_stream, _) =
        default_tcp_connect(&Context::default(), socks5_socket_addr.into())
            .await
            .expect("establish connection to socks5 server (from client)");

    let socks5_client =
        Socks5Client::new().with_auth(Socks5Auth::username_password("john", "secret"));

    let udp_binder = socks5_client
        .handshake_udp(proxy_client_stream)
        .await
        .expect("initiate socks5 UDP Associate handshake");

    let udp_server = UdpSocket::bind(SocketAddress::local_ipv4(0))
        .await
        .expect("bind udp server");

    let udp_server_addr: SocketAddress = udp_server
        .local_addr()
        .expect("get local addr of bind udp server")
        .into();

    tracing::info!(%udp_server_addr, "server: socket created");

    tokio::spawn(async move {
        tracing::info!("server: ready");

        let mut fs = udp_server.into_framed(BytesCodec::new());

        let (bytes, client_addr) = fs
            .next()
            .map(|result| result.expect("server read 'ping' bytes"))
            .await
            .expect("server decode 'ping'  bytes");

        assert_eq!(b"ping", &bytes[..]);

        tracing::info!("server: write pong via socks5 proxy to client");

        fs.send((Bytes::from("pong"), client_addr))
            .await
            .expect("server write 'pong' bytes");

        // read something that will never come,
        // so we stay blocked until client drops
        let _ = fs.next().await;
    });

    let udp_socket_relay = udp_binder
        .bind(SocketAddress::local_ipv4(0))
        .await
        .expect("server to be connected");

    let udp_client_addr = udp_socket_relay
        .local_addr()
        .expect("get client udp socket addr");

    tracing::info!(%udp_client_addr, "client: socket created");

    let mut udp_framed_relay = udp_socket_relay.into_framed(BytesCodec::new());

    tracing::info!("client: write ping via socks5 proxy to server");

    udp_framed_relay
        .send((Bytes::from("ping"), udp_server_addr.into()))
        .await
        .expect("client write 'ping'");

    tracing::info!("client: read pong via socks5 proxy from server");

    let (bytes, recv_udp_server_addr) = udp_framed_relay
        .next()
        .map(|result| result.expect("client read 'PONG'"))
        .await
        .expect("client decode 'PONG'");

    assert_eq!(recv_udp_server_addr, udp_server_addr);
    assert_eq!(b"PONG", &bytes[..]);

    tracing::info!("ping-pong (with pong uppercased to PONG) succeeded, bye now!")
}

async fn spawn_socks5_server() -> SocketAddress {
    let tcp_service = TcpListener::bind(SocketAddress::local_ipv4(0))
        .await
        .expect("bind socks5 UDP Associate proxy on open port");

    let bind_addr = tcp_service
        .local_addr()
        .expect("get bind address of socks5 proxy server")
        .into();

    let socks5_acceptor = Socks5Acceptor::new()
        .with_auth(Socks5Auth::username_password("john", "secret"))
        .with_udp_associator(
            DefaultUdpRelay::default()
                .with_bind_interface(SocketAddress::local_ipv4(0))
                .with_sync_inspector(udp_packet_inspect),
        );

    tokio::spawn(tcp_service.serve(socks5_acceptor));

    bind_addr
}

// you do not need an inspector, sync or async,
// to use UDP associate, this is an opt-in feature provided to you.
//
// By default it the relay will just forward all packets unchanged and unconditionally.

fn udp_packet_inspect(
    _ctx: &Context<()>,
    dir: RelayDirection,
    _addr: SocketAddress,
    data: &[u8],
) -> Result<UdpInspectAction, Infallible> {
    match dir {
        RelayDirection::South => Ok(UdpInspectAction::Forward),
        RelayDirection::North => Ok(UdpInspectAction::Modify(data.to_ascii_uppercase().into())),
    }
}
