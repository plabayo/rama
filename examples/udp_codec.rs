//! This example leverages `BytesCodec` to create a UDP client and server which
//! speak a custom protocol.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example udp_codec --features=udp
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

// rama provides everything out of the box for your primitive UDP needs,
// thanks to the underlying implementation from Tokio
use rama::{
    bytes::Bytes,
    error::BoxError,
    futures::{FutureExt, SinkExt, StreamExt},
    net::address::SocketAddress,
    stream::codec::BytesCodec,
    udp::{UdpFramed, UdpSocket},
};

// everything else is provided by the standard library, community crates or tokio
use std::net::SocketAddr;
use std::time::Duration;
use tokio::{io, time};

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let mut a = UdpSocket::bind(SocketAddress::local_ipv4(0))
        .await?
        .into_framed(BytesCodec::new());
    let mut b = UdpSocket::bind(SocketAddress::local_ipv4(0))
        .await?
        .into_framed(BytesCodec::new());

    let b_addr = b.get_ref().local_addr()?;

    // Start off by sending a ping from a to b, afterwards we just print out
    // what they send us and continually send pings
    let a = ping(&mut a, b_addr);

    // The second client we have will receive the pings from `a` and then send
    // back pongs.
    let b = pong(&mut b);

    // Run both futures simultaneously of `a` and `b` sending messages back and forth.
    match tokio::try_join!(a, b) {
        Err(e) => println!("an error occurred; error = {e:?}"),
        _ => println!("done!"),
    }

    Ok(())
}

async fn ping(socket: &mut UdpFramed<BytesCodec>, b_addr: SocketAddr) -> Result<(), io::Error> {
    socket.send((Bytes::from(&b"PING"[..]), b_addr)).await?;

    for _ in 0..4usize {
        let (bytes, addr) = socket.next().map(|e| e.unwrap()).await?;

        println!("[a] recv: {}", String::from_utf8_lossy(&bytes));

        socket.send((Bytes::from(&b"PING"[..]), addr)).await?;
    }

    Ok(())
}

async fn pong(socket: &mut UdpFramed<BytesCodec>) -> Result<(), io::Error> {
    let timeout = Duration::from_millis(200);

    while let Ok(Some(Ok((bytes, addr)))) = time::timeout(timeout, socket.next()).await {
        println!("[b] recv: {}", String::from_utf8_lossy(&bytes));

        socket.send((Bytes::from(&b"PONG"[..]), addr)).await?;
    }

    Ok(())
}
