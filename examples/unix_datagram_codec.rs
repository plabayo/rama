//! This example leverages `BytesCodec` to create a unix (datagram)
//! pair which speak a custom protocol via bytes frames.
//!
//! Unix datagram sockets can be useful for all kind of local communications,
//! such as Command and Control (C&C) of an otherwise public service,
//! or for a local-first protocol that's not session bound.
//!
//! See the `unix_socket` example for a client-server stream demonstration.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example unix_datagram_codec --features=net
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

#[cfg(unix)]
mod unix_example {
    use rama::{
        bytes::Bytes,
        futures::{FutureExt, SinkExt, StreamExt},
        telemetry::tracing::{self, level_filters::LevelFilter},
        unix::{UnixDatagram, UnixDatagramFramed, UnixSocketAddress, codec::BytesCodec},
    };

    use std::{
        io, process,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };
    use tokio::time;
    use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

    pub(super) async fn run() {
        tracing_subscriber::registry()
            .with(fmt::layer())
            .with(
                EnvFilter::builder()
                    .with_default_directive(LevelFilter::DEBUG.into())
                    .from_env_lossy(),
            )
            .init();

        let path_a = random_tmp_path("rama_example_unix_datagram_a");
        let path_b = random_tmp_path("rama_example_unix_datagram_b");

        let socket_a = UnixDatagram::bind(&path_a).expect("bind unix datagram A");
        let mut socket_framed_a = UnixDatagramFramed::new(socket_a, BytesCodec::new());
        tracing::info!(
            file.path = %path_a,
            "unix Datagram socket A ready for action",
        );

        let socket_b = UnixDatagram::bind(&path_b).expect("bind unix datagram B");
        let mut socket_framed_b = UnixDatagramFramed::new(socket_b, BytesCodec::new());
        tracing::info!(
            file.path = %path_b,
            "unix Datagram socket B ready for action",
        );

        let b_addr: UnixSocketAddress = socket_framed_b
            .get_ref()
            .local_addr()
            .expect("get local addr")
            .into();

        // Start off by sending a ping from a to b, afterwards we just print out
        // what they send us and continually send pings
        let a = ping(&mut socket_framed_a, b_addr);

        // The second client we have will receive the pings from `a` and then send
        // back pongs.
        let b = pong(&mut socket_framed_b);

        // Run both futures simultaneously of `a` and `b` sending messages back and forth.
        match tokio::try_join!(a, b) {
            Err(e) => println!("an error occurred; error = {e:?}"),
            _ => println!("done!"),
        }

        std::fs::remove_file(path_a).expect("delete tmp a");
        std::fs::remove_file(path_b).expect("delete tmp b");
    }

    async fn ping(
        socket: &mut UnixDatagramFramed<BytesCodec>,
        b_addr: UnixSocketAddress,
    ) -> Result<(), io::Error> {
        socket.send((Bytes::from(&b"PING"[..]), b_addr)).await?;

        for _ in 0..4 {
            let (bytes, addr) = socket.next().map(|e| e.unwrap()).await?;

            println!("[a] recv: {}", String::from_utf8_lossy(&bytes));

            socket.send((Bytes::from(&b"PING"[..]), addr)).await?;
        }

        Ok(())
    }

    async fn pong(socket: &mut UnixDatagramFramed<BytesCodec>) -> Result<(), io::Error> {
        let timeout = Duration::from_millis(200);

        while let Ok(Some(Ok((bytes, addr)))) = time::timeout(timeout, socket.next()).await {
            println!("[b] recv: {}", String::from_utf8_lossy(&bytes));

            socket.send((Bytes::from(&b"PONG"[..]), addr)).await?;
        }

        Ok(())
    }

    fn random_tmp_path(prefix: &str) -> String {
        let pid = process::id();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        format!("/tmp/{prefix}_{pid}_{nanos}")
    }
}

#[cfg(unix)]
use unix_example::run;

#[cfg(not(unix))]
async fn run() {
    println!("unix_datagram socket example is a unix-only example, bye now!");
}

#[tokio::main]
async fn main() {
    run().await
}
