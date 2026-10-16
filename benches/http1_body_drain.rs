//! HTTP/1 connection reuse when callers drop response bodies unread or
//! partially read, against a raw loopback origin (plain TCP and rustls with
//! ALPN `http/1.1`), with draining of abandoned bodies on and off.
//!
//! ```sh
//! cargo bench --bench http1_body_drain --features http-full,rustls,ring
//! ```
//!
//! Each sample is a sequence of requests on a client and origin reused
//! across samples. After each sample, outside of the timing, the bench waits
//! longer than the drain timeout, so no cleanup carries into the next one.
//! On the one-connection pool, a sample ends in a fully read request, which
//! waits for the drain of the request before it inside the timing. Per case,
//! a `RESULT` line on stderr reports the requests, TCP connections, TLS
//! handshakes, errors and timeouts of the measured samples.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stderr,
    reason = "bench: panic-on-error and print-for-output are the standard patterns for harnesses"
)]

use std::{
    convert::Infallible,
    fmt,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use divan::counter::ItemsCount;
use rama::{
    Layer as _, Service,
    bytes::Bytes,
    error::extra::OpaqueError,
    http::{
        Body, Request, Response, Version,
        body::{StreamingBody as _, util::BodyExt as _},
        client::{EasyHttpWebClient, Http1BodyDrainConfig, HttpPooledConnectorConfig},
    },
    io::Io,
    net::{address::SocketAddress, client::pool::SaturationPolicy, tls::ApplicationProtocol},
    rt::Executor,
    tcp::{client::service::TcpConnector, server::TcpListener},
    tls::{
        client::{ServerVerifyMode, TlsClientConfig},
        rustls,
        server::{GeneratedServerAuthConfig, TlsServerConfig},
    },
    utils::collections::smallvec::smallvec,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

mod bench_alloc;

fn main() {
    divan::main();
}

/// Longer than the default drain timeout (50 ms).
const SETTLE: Duration = Duration::from_millis(60);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const CHUNK: usize = 4 * 1024;
const CLIENT_WORKERS: usize = 2;
const SERVER_WORKERS: usize = 2;
const UNCAPPED_CONCURRENCY: usize = 4;

/// The largest body served, generated once outside of any timing.
static PAYLOAD: LazyLock<Bytes> = LazyLock::new(|| Bytes::from(vec![b'x'; 2 * 1024 * 1024]));

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Consume {
    /// Drop the response after its status.
    Unread,
    /// Read one frame (a chunk of [`CHUNK`] bytes), drop the rest.
    Prefix,
    /// Read the whole body.
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Framing {
    Sized,
    /// Chunks of [`CHUNK`] bytes: a frame never holds the whole body.
    Chunked,
    /// One byte, then the rest 200 ms later: beyond the drain deadline.
    Slow,
}

#[derive(Debug, Clone, Copy)]
struct Workload {
    name: &'static str,
    framing: Framing,
    size: usize,
    consume: Consume,
    requests: usize,
}

impl fmt::Display for Workload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name)
    }
}

const fn workload(
    name: &'static str,
    framing: Framing,
    size: usize,
    consume: Consume,
    requests: usize,
) -> Workload {
    Workload {
        name,
        framing,
        size,
        consume,
        requests,
    }
}

const WORKLOADS: &[Workload] = &[
    workload("unread_2b", Framing::Sized, 2, Consume::Unread, 16),
    workload("unread_4kib", Framing::Sized, 4 * 1024, Consume::Unread, 16),
    workload(
        "unread_64kib",
        Framing::Sized,
        64 * 1024,
        Consume::Unread,
        16,
    ),
    workload(
        "prefix_64kib",
        Framing::Chunked,
        64 * 1024,
        Consume::Prefix,
        16,
    ),
    workload(
        "prefix_512kib",
        Framing::Chunked,
        512 * 1024,
        Consume::Prefix,
        16,
    ),
    workload("full_2b", Framing::Sized, 2, Consume::Full, 16),
    workload("full_4kib", Framing::Sized, 4 * 1024, Consume::Full, 16),
    workload("full_64kib", Framing::Sized, 64 * 1024, Consume::Full, 16),
    workload("empty", Framing::Sized, 0, Consume::Unread, 16),
    workload(
        "unread_2mib_over_budget",
        Framing::Sized,
        2 * 1024 * 1024,
        Consume::Unread,
        16,
    ),
    workload(
        "unread_slow_over_deadline",
        Framing::Slow,
        64 * 1024,
        Consume::Unread,
        4,
    ),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transport {
    Tcp,
    Tls,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pool {
    /// One connection, requests wait for it: recovery against reconnecting.
    One,
    /// No connection limit, [`UNCAPPED_CONCURRENCY`] concurrent requests.
    Uncapped,
}

/// The pool config of a case.
///
/// For a base revision without `http1_body_drain`, remove its line: the
/// harness is otherwise the same.
fn pool_config(pool: Pool, drain: bool) -> HttpPooledConnectorConfig {
    let mut config = HttpPooledConnectorConfig::default();
    if pool == Pool::One {
        config.max_connections_total = std::num::NonZeroUsize::new(1);
        config.saturation_policy = SaturationPolicy::Wait;
    }
    config.http1_body_drain = drain.then(Http1BodyDrainConfig::default);
    config
}

#[derive(Debug, Default)]
struct Stats {
    tcp: AtomicUsize,
    tls: AtomicUsize,
    requests: AtomicUsize,
    errors: AtomicUsize,
    timeouts: AtomicUsize,
    /// Prefix reads that turned out to hold the whole body.
    not_partial: AtomicUsize,
}

impl Stats {
    fn reset(&self) {
        for counter in [
            &self.tcp,
            &self.tls,
            &self.requests,
            &self.errors,
            &self.timeouts,
            &self.not_partial,
        ] {
            counter.store(0, Ordering::SeqCst);
        }
    }
}

/// Counts the connections an inner service is handed.
#[derive(Debug, Clone)]
struct Count<S> {
    inner: S,
    count: Arc<Stats>,
    tls: bool,
}

impl<S, Input> Service<Input> for Count<S>
where
    S: Service<Input>,
    Input: Send + 'static,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
        let counter = if self.tls {
            &self.count.tls
        } else {
            &self.count.tcp
        };
        counter.fetch_add(1, Ordering::Relaxed);
        self.inner.serve(input).await
    }
}

/// A raw HTTP/1 origin answering `/{sized|chunked|slow}/{size}` byte for byte.
#[derive(Debug, Clone)]
struct Origin;

impl<S: Io> Service<S> for Origin {
    type Output = ();
    type Error = Infallible;

    async fn serve(&self, stream: S) -> Result<(), Infallible> {
        let mut stream = std::pin::pin!(stream);
        let mut buf = Vec::with_capacity(1024);
        loop {
            let head_end = loop {
                if let Some(at) = buf.windows(4).position(|window| window == b"\r\n\r\n") {
                    break at + 4;
                }
                let mut chunk = [0u8; 1024];
                match stream.read(&mut chunk).await {
                    Ok(0) | Err(_) => return Ok(()),
                    Ok(read) => buf.extend_from_slice(&chunk[..read]),
                }
            };
            let path = std::str::from_utf8(&buf[..head_end])
                .ok()
                .and_then(|head| head.split(' ').nth(1))
                .unwrap_or("/")
                .to_owned();
            buf.drain(..head_end);
            let mut parts = path.trim_start_matches('/').split('/');
            let framing = parts.next().unwrap_or_default().to_owned();
            let size: usize = parts.next().and_then(|size| size.parse().ok()).unwrap_or(0);
            let body = PAYLOAD.slice(..size);
            let written = match framing.as_str() {
                "chunked" => {
                    let mut out = Vec::with_capacity(size + size / CHUNK * 8 + 64);
                    out.extend_from_slice(b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n");
                    for chunk in body.chunks(CHUNK) {
                        out.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
                        out.extend_from_slice(chunk);
                        out.extend_from_slice(b"\r\n");
                    }
                    out.extend_from_slice(b"0\r\n\r\n");
                    stream.write_all(&out).await
                }
                "slow" => {
                    let head = format!("HTTP/1.1 200 OK\r\ncontent-length: {size}\r\n\r\n");
                    if stream.write_all(head.as_bytes()).await.is_err()
                        || stream.write_all(&body[..1]).await.is_err()
                    {
                        return Ok(());
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    stream.write_all(&body[1..]).await
                }
                _ => {
                    let head = format!("HTTP/1.1 200 OK\r\ncontent-length: {size}\r\n\r\n");
                    match stream.write_all(head.as_bytes()).await {
                        Ok(()) => stream.write_all(&body).await,
                        Err(error) => Err(error),
                    }
                }
            };
            if written.is_err() {
                return Ok(());
            }
        }
    }
}

/// A server runtime, shut down with its tasks and sockets on drop.
struct ServerRuntime(Option<tokio::runtime::Runtime>);

impl Drop for ServerRuntime {
    fn drop(&mut self) {
        if let Some(runtime) = self.0.take() {
            runtime.shutdown_timeout(Duration::from_secs(1));
        }
    }
}

fn spawn_origin(transport: Transport, stats: Arc<Stats>) -> (SocketAddress, ServerRuntime) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(SERVER_WORKERS)
        .enable_all()
        .build()
        .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    // certificates are generated before any timing
    let tls = (transport == Transport::Tls).then(|| {
        TlsServerConfig::new()
            .try_with_generated_server_auth(GeneratedServerAuthConfig::default())
            .expect("self signed")
            .with_alpn_http_1()
    });
    runtime.spawn(async move {
        let listener =
            TcpListener::try_from_std_tcp_listener(listener, Executor::default()).unwrap();
        let origin = Count {
            inner: Origin,
            count: stats.clone(),
            tls: true,
        };
        match tls {
            None => {
                listener
                    .serve(Count {
                        inner: Origin,
                        count: stats,
                        tls: false,
                    })
                    .await;
            }
            Some(config) => {
                listener
                    .serve(Count {
                        inner: rustls::server::TlsAcceptorLayer::new(config).into_layer(origin),
                        count: stats,
                        tls: false,
                    })
                    .await;
            }
        }
    });
    (addr.into(), ServerRuntime(Some(runtime)))
}

fn client(
    pool: Pool,
    drain: bool,
) -> impl Service<Request, Output = Response, Error = OpaqueError> {
    let tls = TlsClientConfig::new()
        .with_alpn(smallvec![ApplicationProtocol::HTTP_11])
        .with_server_verify(ServerVerifyMode::Disable);
    EasyHttpWebClient::connector_builder()
        .with_custom_transport_connector(TcpConnector::new())
        .without_dns_connector()
        .without_tls_proxy_support()
        .without_proxy_support()
        .with_tls_support_using_rustls(tls)
        .with_default_http_connector(Executor::default())
        .with_connection_pool(pool_config(pool, drain))
        .build_client()
}

async fn request(
    client: &impl Service<Request, Output = Response, Error = OpaqueError>,
    uri: &str,
    consume: Consume,
    stats: &Stats,
) {
    let request = Request::builder()
        .version(Version::HTTP_11)
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    let result = tokio::time::timeout(REQUEST_TIMEOUT, async {
        let response = client.serve(request).await?;
        match consume {
            Consume::Unread => drop(response),
            Consume::Prefix => {
                let mut body = response.into_body();
                if let Some(frame) = body.frame().await {
                    frame?;
                }
                if body.is_end_stream() {
                    stats.not_partial.fetch_add(1, Ordering::Relaxed);
                }
            }
            Consume::Full => {
                divan::black_box(response.into_body().collect().await?.to_bytes());
            }
        }
        Ok::<_, rama::error::BoxError>(())
    })
    .await;
    stats.requests.fetch_add(1, Ordering::Relaxed);
    match result {
        Ok(Ok(())) => {}
        Ok(Err(_)) => _ = stats.errors.fetch_add(1, Ordering::Relaxed),
        Err(_) => _ = stats.timeouts.fetch_add(1, Ordering::Relaxed),
    }
}

/// One sample: the workload's requests, then for the one-connection pool a
/// fully read request that waits for the last drain.
async fn sample<C>(client: &C, base: &str, pool: Pool, workload: Workload, stats: &Stats)
where
    C: Service<Request, Output = Response, Error = OpaqueError>,
{
    let framing = match workload.framing {
        Framing::Sized => "sized",
        Framing::Chunked => "chunked",
        Framing::Slow => "slow",
    };
    let uri = format!("{base}/{framing}/{}", workload.size);
    match pool {
        Pool::One => {
            for _ in 0..workload.requests {
                request(client, &uri, workload.consume, stats).await;
            }
            request(client, &format!("{base}/sized/2"), Consume::Full, stats).await;
        }
        Pool::Uncapped => {
            let per_worker = workload.requests.div_ceil(UNCAPPED_CONCURRENCY);
            let workers = (0..UNCAPPED_CONCURRENCY).map(|_| async {
                for _ in 0..per_worker {
                    request(client, &uri, workload.consume, stats).await;
                }
            });
            rama::futures::future::join_all(workers).await;
        }
    }
}

fn run(bencher: divan::Bencher, transport: Transport, pool: Pool, drain: bool, workload: Workload) {
    let stats = Arc::new(Stats::default());
    let (addr, server) = spawn_origin(transport, stats.clone());
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(CLIENT_WORKERS)
        .enable_all()
        .build()
        .unwrap();
    let client = runtime.block_on(async { client(pool, drain) });
    let scheme = match transport {
        Transport::Tcp => "http",
        Transport::Tls => "https",
    };
    let base = format!("{scheme}://{addr}");
    // warm up: connections, TLS session, allocator
    runtime.block_on(async {
        sample(&client, &base, pool, workload, &stats).await;
        tokio::time::sleep(SETTLE).await;
    });
    stats.reset();

    let per_sample = match pool {
        Pool::One => workload.requests + 1,
        Pool::Uncapped => workload.requests.div_ceil(UNCAPPED_CONCURRENCY) * UNCAPPED_CONCURRENCY,
    };
    // reserved up front: recording a sample does not allocate
    let mut timings = Vec::with_capacity(4096);
    bencher
        .counter(ItemsCount::new(per_sample))
        .with_inputs(|| runtime.block_on(async { tokio::time::sleep(SETTLE).await }))
        .bench_local_values(|()| {
            let start = std::time::Instant::now();
            runtime.block_on(sample(&client, &base, pool, workload, &stats));
            timings.push(start.elapsed());
        });

    let mut micros: Vec<f64> = timings
        .iter()
        .map(|timing| timing.as_secs_f64() * 1e6 / per_sample as f64)
        .collect();
    micros.sort_by(f64::total_cmp);
    let mean = micros.iter().sum::<f64>() / micros.len() as f64;
    let stddev = (micros.iter().map(|x| (x - mean).powi(2)).sum::<f64>()
        / (micros.len().max(2) - 1) as f64)
        .sqrt();
    eprintln!(
        "RESULT transport={transport:?} pool={pool:?} drain={drain} workload={} samples={} requests={} tcp_connections={} tls_handshakes={} errors={} timeouts={} not_partial={} us_per_request_median={:.1} mean={mean:.1} stddev={stddev:.1} min={:.1} max={:.1}",
        workload.name,
        micros.len(),
        stats.requests.load(Ordering::SeqCst),
        stats.tcp.load(Ordering::SeqCst),
        stats.tls.load(Ordering::SeqCst),
        stats.errors.load(Ordering::SeqCst),
        stats.timeouts.load(Ordering::SeqCst),
        stats.not_partial.load(Ordering::SeqCst),
        micros[micros.len() / 2],
        micros[0],
        micros[micros.len() - 1],
    );
    // let the last drains end before the client and origin go
    runtime.block_on(async { tokio::time::sleep(SETTLE).await });
    drop(client);
    runtime.shutdown_timeout(Duration::from_secs(1));
    drop(server);
}

macro_rules! cases {
    ($($group:ident => ($transport:ident, $pool:ident)),* $(,)?) => {$(
        mod $group {
            use super::*;

            #[divan::bench(args = WORKLOADS, sample_count = 16, sample_size = 1)]
            fn drain_on(bencher: divan::Bencher, workload: &Workload) {
                run(bencher, Transport::$transport, Pool::$pool, true, *workload);
            }

            #[divan::bench(args = WORKLOADS, sample_count = 16, sample_size = 1)]
            fn drain_off(bencher: divan::Bencher, workload: &Workload) {
                run(bencher, Transport::$transport, Pool::$pool, false, *workload);
            }
        }
    )*};
}

cases! {
    tcp_one_connection => (Tcp, One),
    tcp_uncapped => (Tcp, Uncapped),
    tls_one_connection => (Tls, One),
    tls_uncapped => (Tls, Uncapped),
}
