//! This example leverages `BytesCodec` to create a UDP client and server which
//! speak a custom protocol, with the client's pings paced by a `PacedSink`.
//!
//! # Run the example
//!
//! ```sh
//! cargo run -p rama-examples --bin udp_codec --features=udp
//! ```
//!
//! # Expected output
//!
//! ```
//! [b] recv: PING
//! [a] recv: PONG
//! [b] recv: PING
//! [a] recv: PONG
//! [b] recv: PING
//! [a] recv: PONG
//! [b] recv: PING
//! [a] recv: PONG
//! [b] recv: PING
//! done!
//! ```
//!
//! The pings arrive rate-paced: 4-byte datagrams against a 16 B/s
//! budget with a 4-byte burst, i.e. one ping per 250ms after the burst.

// rama provides everything out of the box for your primitive UDP needs,
// thanks to the underlying implementation from Tokio

#![expect(
    clippy::unwrap_used,
    reason = "example: panic-on-error is the standard pattern for demos"
)]

use rama::{
    bytes::Bytes,
    error::BoxError,
    futures::{FutureExt, SinkExt, StreamExt},
    net::address::SocketAddress,
    stream::{PacedSink, codec::BytesCodec},
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
    udp::{UdpFramed, bind_udp_with_address},
    utils::rate::Rate,
};

// everything else is provided by the standard library, community crates or tokio

use std::net::SocketAddr;
use std::time::Duration;
use tokio::{io, time};

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

    // pace outgoing pings: their 4 bytes cost against 16 B/s (4 B burst)
    let mut a = PacedSink::new(
        UdpFramed::new(
            bind_udp_with_address(SocketAddress::local_ipv4(0)).await?,
            BytesCodec::new(),
        ),
        Rate::per_sec(16),
    )
    .with_burst(4);
    let mut b = UdpFramed::new(
        bind_udp_with_address(SocketAddress::local_ipv4(0)).await?,
        BytesCodec::new(),
    );

    let b_addr = b.get_ref().local_addr()?;

    let start = std::time::Instant::now();

    // Start off by sending a ping from a to b, afterwards we just print out
    // what they send us and continually send pings
    let a = ping(&mut a, b_addr);

    // The second client we have will receive the pings from `a` and then send
    // back pongs.
    let b = pong(&mut b);

    // Run both futures simultaneously of `a` and `b` sending messages back and forth.
    if let Err(e) = tokio::try_join!(a, b) {
        tracing::error!("an error occurred; error = {e:?}");
    } else {
        // 5 pings against a 4-byte burst: at least 3 paced waits of 250ms
        assert!(start.elapsed() >= Duration::from_millis(700));
        tracing::info!("done!");
    }

    Ok(())
}

async fn ping(
    socket: &mut PacedSink<UdpFramed<BytesCodec>>,
    b_addr: SocketAddr,
) -> Result<(), io::Error> {
    socket.send((Bytes::from(&b"PING"[..]), b_addr)).await?;

    for _ in 0..4usize {
        let (bytes, addr) = socket.next().map(|e| e.unwrap()).await?;

        tracing::info!("[a] recv: {}", String::from_utf8_lossy(&bytes));

        socket.send((Bytes::from(&b"PING"[..]), addr)).await?;
    }

    Ok(())
}

async fn pong(socket: &mut UdpFramed<BytesCodec>) -> Result<(), io::Error> {
    // generous enough to bridge the 250ms gaps between paced pings
    let timeout = Duration::from_millis(500);

    while let Ok(Some(Ok((bytes, addr)))) = time::timeout(timeout, socket.next()).await {
        tracing::info!("[b] recv: {}", String::from_utf8_lossy(&bytes));

        socket.send((Bytes::from(&b"PONG"[..]), addr)).await?;
    }

    Ok(())
}
