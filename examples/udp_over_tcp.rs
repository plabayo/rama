//! Tunnel UDP datagrams over a single TCP connection.
//!
//! Inspired by [Jon Gjengset](https://github.com/jonhoo)'s
//! [`udp-over-tcp`](https://github.com/jonhoo/udp-over-tcp) crate;
//! full credit for the use case and the `u16` length-prefix wire
//! protocol on the TCP side goes to him.
//!
//! Use cases: reach a UDP service through a network that only allows
//! outbound TCP (WireGuard through a corporate firewall, etc.).
//!
//! With rama, the entire tunnel is just one helper:
//!
//! ```text
//! ConnectedUdpFramed  <—— StreamForwardService ——>  Framed<TcpStream, LengthDelimitedCodec>
//! ```
//!
//! Both UDP sockets are `connect()`-ed to their configured peers, so
//! the tunnel handles bidirectional traffic between two known
//! endpoints. Each gateway must know its UDP peer at startup.
//!
//! # CLI
//!
//! ```text
//! udp_over_tcp <listen|connect> <tcp_addr> <udp_bind> <udp_peer>
//! ```
//!
//! - `listen` / `connect` — the TCP role this side plays.
//! - `tcp_addr`           — TCP address to bind (listen) or connect to.
//! - `udp_bind`           — local UDP address.
//! - `udp_peer`           — remote UDP peer this side speaks to.
//!
//! Defaults (when omitted): all ports are `0` (kernel-chosen).
//!
//! # Try it with `nc`
//!
//! In four terminals — server side (TCP listener) first, then the
//! client side, then two `nc`'s acting as the two UDP applications:
//!
//! ```sh
//! # TCP listener side: UDP peer is the server-side app (port 9001).
//! cargo run --example udp_over_tcp --features=udp,tcp -- \
//!     listen 127.0.0.1:7878 127.0.0.1:7777 127.0.0.1:9001
//!
//! # TCP connector side: UDP peer is the client-side app (port 9000).
//! cargo run --example udp_over_tcp --features=udp,tcp -- \
//!     connect 127.0.0.1:7878 127.0.0.1:8888 127.0.0.1:9000
//!
//! # Server-side UDP app (on the listener host): listen on 9001.
//! ncat -u -l 9001
//!
//! # Client-side UDP app (on the connector host): send to 8888 from 9000.
//! ncat -u -p 9000 127.0.0.1 8888
//! ```
//!
//! Anything typed into the client `ncat` flows: client `ncat` → 8888
//! (UDP bind of the connector side) → TCP tunnel → 7777 (UDP bind of
//! the listener side) → server `ncat` on 9001. Replies travel back
//! through the tunnel the same way.

use std::net::SocketAddr;

use rama::{
    Service,
    error::BoxError,
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
    init_tracing();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let [m, t, b, p] = args.as_slice() else {
        eprintln!("usage: udp_over_tcp <listen|connect> <tcp_addr> <udp_bind> <udp_peer>");
        std::process::exit(2);
    };
    let mode = m.as_str();
    let tcp_addr: SocketAddr = t.parse()?;
    let udp_bind: SocketAddr = b.parse()?;
    let udp_peer: SocketAddr = p.parse()?;

    let udp = bind_udp_with_address(SocketAddress::from(udp_bind)).await?;
    udp.connect(udp_peer).await?;

    let tcp = match mode {
        "listen" => {
            let listener =
                TcpListener::bind_address(SocketAddress::from(tcp_addr), Executor::default())
                    .await?;
            tracing::info!("tcp listening on {}", listener.local_addr()?);
            let (tcp, peer) = listener.accept().await?;
            tracing::info!("tcp accepted from {peer}");
            tcp
        }
        "connect" => {
            let (tcp, peer) =
                default_tcp_connect(&Default::default(), tcp_addr.into(), Executor::default())
                    .await?;
            tracing::info!("tcp connected to {peer}");
            tcp
        }
        _ => {
            eprintln!("mode must be 'listen' or 'connect'");
            std::process::exit(2);
        }
    };

    bridge(udp, tcp).await
}

/// Bridge a connected UDP socket and a TCP stream using `u16`
/// length-prefix framing on the TCP side. Each UDP datagram is one frame.
async fn bridge(udp: UdpSocket, tcp: TcpStream) -> Result<(), BoxError> {
    let udp = ConnectedUdpFramed::new(udp, BytesCodec::new());
    let tcp = Framed::new(
        tcp,
        LengthDelimitedCodec::builder()
            .length_field_type::<u16>()
            .new_codec(),
    );
    StreamForwardService::default()
        .serve(StreamBridge::new(
            BytesFreeze::new(udp),
            BytesFreeze::new(tcp),
        ))
        .await?;
    Ok(())
}

fn init_tracing() {
    tracing::subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();
}
