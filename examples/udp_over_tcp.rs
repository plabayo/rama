//! Tunnel UDP datagrams over a single TCP connection.
//!
//! Inspired by [Jon Gjengset](https://github.com/jonhoo)'s
//! [`udp-over-tcp`](https://github.com/jonhoo/udp-over-tcp) crate;
//! full credit for the use case and the `u16` length-prefix wire
//! protocol on the TCP side goes to him.
//!
//! With rama, the entire tunnel reduces to one helper:
//!
//! ```text
//! ConnectedUdpFramed  <—— StreamForwardService ——>  Framed<TcpStream, LengthDelimitedCodec>
//! ```
//!
//! Connected UDP sockets expose a `Stream + Sink` over plain bytes with
//! no per-datagram peer-tracking state, so the bridge is a one-liner.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example udp_over_tcp --features=udp,tcp
//! ```

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "example: panic-on-error is the standard pattern for demos"
)]

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

/// Bridge a connected UDP socket with a TCP stream using `u16`
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

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    init_tracing();

    // UDP echo target. Anything that arrives gets sent back to its source.
    let echo = bind_udp_with_address(SocketAddress::local_ipv4(0)).await?;
    let echo_addr = echo.local_addr()?;
    tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        while let Ok((n, peer)) = echo.recv_from(&mut buf).await {
            let _drop = echo.send_to(&buf[..n], peer).await;
        }
    });

    // tcp2udp gateway: each inbound TCP conn gets a fresh UDP socket
    // pinned to `echo_addr`, then bridged.
    let listener =
        TcpListener::bind_address(SocketAddress::local_ipv4(0), Executor::default()).await?;
    let gw_addr = listener.local_addr()?;
    tokio::spawn(async move {
        listener
            .serve(rama::service::service_fn(
                move |tcp: TcpStream| async move {
                    let udp = bind_udp_with_address(SocketAddress::local_ipv4(0)).await?;
                    udp.connect(echo_addr).await?;
                    bridge(udp, tcp).await
                },
            ))
            .await;
    });

    // Driver bound first so we can pre-pin the udp2tcp side to it.
    let driver = bind_udp_with_address(SocketAddress::local_ipv4(0)).await?;
    let driver_addr = driver.local_addr()?;

    // udp2tcp gateway: UDP socket pinned to `driver`, single TCP conn to `gw_addr`.
    let udp2tcp_udp = bind_udp_with_address(SocketAddress::local_ipv4(0)).await?;
    let udp2tcp_addr = udp2tcp_udp.local_addr()?;
    udp2tcp_udp.connect(driver_addr).await?;
    let (tcp, _) =
        default_tcp_connect(&Default::default(), gw_addr.into(), Executor::default()).await?;
    tokio::spawn(bridge(udp2tcp_udp, tcp));

    // Drive: send through the tunnel, expect the echo back.
    driver.connect(udp2tcp_addr).await?;
    let mut driver = ConnectedUdpFramed::new(driver, BytesCodec::new());
    for _ in 0..3 {
        driver.send(Bytes::from_static(b"hello")).await?;
        let echoed = tokio::time::timeout(Duration::from_secs(2), driver.next())
            .await
            .expect("tunnel round-trip timed out")
            .unwrap()
            .unwrap();
        assert_eq!(&echoed[..], b"hello");
        tracing::info!("tunnel: round-trip ok");
    }
    tracing::info!("done!");
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
