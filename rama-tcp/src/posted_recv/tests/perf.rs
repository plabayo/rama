//! Overhead of [`PostedRecv`] against a plain stream: bulk throughput and
//! round-trip latency over loopback. Prints only; run with
//! `--run-ignored=only --no-capture`, preferably in release.

use std::time::{Duration, Instant};

use rama_utils::octets::{kib, mib};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream as TokioTcpStream,
    task::JoinSet,
};

use super::harness::spawn_origin_fn;
use crate::{
    TcpStream,
    posted_recv::{PostedRecv, PostedRecvConfig},
};

#[derive(Debug, Clone, Copy)]
enum Reader {
    Plain,
    Posted(usize, usize),
}

impl Reader {
    const ALL: [Self; 3] = [
        Self::Plain,
        Self::Posted(2, kib(16)),
        Self::Posted(4, kib(64)),
    ];

    async fn connect(self, addr: std::net::SocketAddr) -> Box<dyn Stream> {
        let stream = TokioTcpStream::connect(addr).await.unwrap();
        stream.set_nodelay(true).unwrap();
        match self {
            Self::Plain => Box::new(stream),
            Self::Posted(slots, size) => {
                let config = PostedRecvConfig::new()
                    .with_slots(slots)
                    .with_slot_size(size)
                    .with_max_buffered(kib(64).max(slots * size));
                Box::new(PostedRecv::with_config(TcpStream::new(stream), &config))
            }
        }
    }
}

trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

/// `flows` concurrent flows each receive `per_flow` bytes; returns MiB/s.
async fn throughput(reader: Reader, flows: usize, per_flow: usize) -> f64 {
    let origin = spawn_origin_fn(move |mut stream| async move {
        // The client speaks first, so a dropped handshake cannot leave it
        // waiting forever.
        let mut hello = [0; 1];
        if stream.read_exact(&mut hello).await.is_err() {
            return;
        }
        let chunk = vec![0x5a; kib(64)];
        let mut left = per_flow;
        while left > 0 {
            let n = left.min(chunk.len());
            if stream.write_all(&chunk[..n]).await.is_err() {
                return;
            }
            left -= n;
        }
    })
    .await;
    let addr = origin.addr;
    let started = Instant::now();
    let mut set = JoinSet::new();
    for _ in 0..flows {
        set.spawn(async move {
            let flow = async {
                let mut stream = reader.connect(addr).await;
                stream.write_all(b"!").await.unwrap();
                let mut buf = vec![0; kib(64)];
                let mut total = 0;
                loop {
                    match stream.read(&mut buf).await.unwrap() {
                        0 => break total,
                        n => total += n,
                    }
                }
            };
            let total = tokio::time::timeout(Duration::from_secs(120), flow)
                .await
                .expect("a flow hung");
            assert_eq!(total, per_flow);
        });
    }
    while let Some(done) = set.join_next().await {
        done.unwrap();
    }
    let secs = started.elapsed().as_secs_f64();
    (flows * per_flow) as f64 / (1024.0 * 1024.0) / secs
}

/// Round trips of a 64 byte message; returns (mean, p99).
async fn latency(reader: Reader, rounds: usize) -> (Duration, Duration) {
    let origin = spawn_origin_fn(|stream| async move {
        stream.set_nodelay(true).unwrap();
        let (mut r, mut w) = stream.into_split();
        _ = tokio::io::copy(&mut r, &mut w).await;
    })
    .await;
    let mut stream = reader.connect(origin.addr).await;
    let msg = [7u8; 64];
    let mut back = [0u8; 64];
    let mut samples = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let started = Instant::now();
        stream.write_all(&msg).await.unwrap();
        stream.read_exact(&mut back).await.unwrap();
        samples.push(started.elapsed());
    }
    samples.sort();
    let mean = samples.iter().sum::<Duration>() / rounds as u32;
    (mean, samples[rounds * 99 / 100])
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "benchmark: prints throughput and latency"]
async fn overhead() {
    if !super::harness::characterizing() {
        return;
    }
    for (flows, per_flow) in [(1, mib(1024)), (64, mib(32)), (1000, mib(2))] {
        for reader in Reader::ALL {
            let mibs = throughput(reader, flows, per_flow).await;
            eprintln!("throughput flows={flows} per_flow={per_flow} {reader:?}: {mibs:.0} MiB/s");
        }
    }
    for reader in Reader::ALL {
        let (mean, p99) = latency(reader, 20_000).await;
        eprintln!("latency 64B round trip {reader:?}: mean={mean:?} p99={p99:?}");
    }
}
