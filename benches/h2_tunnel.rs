//! Throughput of an HTTP/2 CONNECT tunnel: bytes written into the client's
//! upgraded IO and drained from the server's upgraded IO over an in-memory
//! duplex connection.
//!
//! ```sh
//! cargo bench --bench h2_tunnel --features http-full
//! ```

#![expect(
    clippy::unwrap_used,
    reason = "bench: panic-on-error is the standard pattern for harnesses"
)]

use std::{convert::Infallible, sync::Arc};

use divan::counter::BytesCount;
use rama::{
    ServiceInput,
    extensions::ExtensionsRef as _,
    http::{
        Body, Method, Request, Response, StatusCode, Version,
        core::{client::conn, server, service::RamaHttpService},
        io::upgrade::{self, OnUpgrade, Upgraded},
    },
    rt::Executor,
    service::service_fn,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
};

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    divan::main();
}

/// Bytes pushed through the tunnel per iteration.
const PAYLOAD: usize = 4 << 20;
/// Write sizes: a TLS record and a small interactive frame.
const CHUNK_SIZES: &[usize] = &[16 * 1024, 1024];

struct Tunnel {
    client: Upgraded,
    server: Upgraded,
    _tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        for task in &self._tasks {
            task.abort();
        }
    }
}

async fn tunnel() -> Tunnel {
    let (tx, mut upgrades) = mpsc::unbounded_channel::<OnUpgrade>();
    let service = service_fn(move |req: Request| {
        let tx = tx.clone();
        async move {
            tx.send(req.extensions().get_ref::<OnUpgrade>().unwrap().clone())
                .unwrap();
            Ok::<_, Infallible>(
                Response::builder()
                    .version(Version::HTTP_2)
                    .status(StatusCode::OK)
                    .body(Body::empty())
                    .unwrap(),
            )
        }
    });
    let (client_io, server_io) = tokio::io::duplex(1 << 20);
    let server_task = tokio::spawn(async move {
        _ = server::conn::http2::Builder::new(Executor::new())
            .serve_connection(ServiceInput::new(server_io), RamaHttpService::new(service))
            .await;
    });
    let (mut sender, connection) = conn::http2::Builder::new(Executor::new())
        .handshake(ServiceInput::new(client_io))
        .await
        .unwrap();
    let client_task = tokio::spawn(async move {
        _ = connection.await;
    });

    let req = Request::builder()
        .method(Method::CONNECT)
        .version(Version::HTTP_2)
        .uri("https://example.test:443")
        .body(Body::empty())
        .unwrap();
    let res = sender.send_request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let client = upgrade::handle_upgrade(&res).await.unwrap();
    let server = upgrades.recv().await.unwrap().await.unwrap();
    Tunnel {
        client,
        server,
        _tasks: vec![server_task, client_task],
    }
}

/// Client writes `PAYLOAD` bytes in `chunk` sized writes, server drains them.
#[divan::bench(args = CHUNK_SIZES, sample_count = 20)]
fn client_to_server(bencher: divan::Bencher, chunk: usize) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let mut tunnel = runtime.block_on(tunnel());
    let payload: Arc<[u8]> = vec![0xABu8; chunk].into();
    bencher.counter(BytesCount::new(PAYLOAD)).bench_local(|| {
        runtime.block_on(async {
            let writes = PAYLOAD / chunk;
            let write = async {
                for _ in 0..writes {
                    tunnel.client.write_all(&payload).await.unwrap();
                }
                tunnel.client.flush().await.unwrap();
            };
            let read = async {
                let mut buf = vec![0u8; 64 * 1024];
                let mut total = 0;
                while total < writes * chunk {
                    total += tunnel.server.read(&mut buf).await.unwrap();
                }
            };
            tokio::join!(write, read);
        })
    });
}
