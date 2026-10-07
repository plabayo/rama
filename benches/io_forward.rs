//! Throughput of [`IoForwardService`] relaying between two in-memory transports, one direction
//! at a time, as a proxy tunnel does.
//!
//! ```sh
//! cargo bench --bench io_forward --features net
//! ```

#![expect(
    clippy::unwrap_used,
    reason = "bench: panic-on-error is the standard pattern for harnesses"
)]

use divan::counter::BytesCount;
use rama::{Service as _, ServiceInput, io::BridgeIo, net::proxy::IoForwardService, rt::Executor};
use std::sync::Arc;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream, duplex};

fn main() {
    divan::main();
}

/// Bytes relayed per iteration.
const PAYLOAD: usize = 4 << 20;
/// Write sizes: a TLS record and a small interactive frame.
const CHUNK_SIZES: &[usize] = &[16 * 1024, 1024];

/// A relay between `client` and `origin`, running until both ends close.
fn relay(runtime: &tokio::runtime::Runtime) -> (DuplexStream, DuplexStream) {
    let (client, client_side) = duplex(64 * 1024);
    let (origin, origin_side) = duplex(64 * 1024);
    runtime.spawn(async move {
        _ = IoForwardService::new(Executor::new())
            .serve(BridgeIo(
                ServiceInput::new(client_side),
                ServiceInput::new(origin_side),
            ))
            .await;
    });
    (client, origin)
}

/// The client writes `PAYLOAD` bytes in `chunk` sized writes; the origin drains them.
#[divan::bench(args = CHUNK_SIZES, sample_count = 20)]
fn client_to_origin(bencher: divan::Bencher, chunk: usize) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let (mut client, mut origin) = relay(&runtime);
    let payload: Arc<[u8]> = vec![0xAB; chunk].into();
    bencher.counter(BytesCount::new(PAYLOAD)).bench_local(|| {
        runtime.block_on(async {
            let writes = PAYLOAD / chunk;
            let write = async {
                for _ in 0..writes {
                    client.write_all(&payload).await.unwrap();
                }
                client.flush().await.unwrap();
            };
            let read = async {
                let mut buf = vec![0; 64 * 1024];
                let mut total = 0;
                while total < writes * chunk {
                    total += origin.read(&mut buf).await.unwrap();
                }
            };
            tokio::join!(write, read);
        });
    });
}
