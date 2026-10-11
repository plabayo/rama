//! gRPC end to end: protobuf over HTTP/2 (prior knowledge, plaintext), many
//! concurrent callers sharing one pooled [`EasyHttpWebClient`], against origins
//! counting the connections they accept. gRPC callers share a few multiplexed
//! connections, so the pool's connect coalescing and stream accounting carry
//! these rows: after the run each prints how many connections its origins
//! accepted.
//!
//! ```sh
//! cargo bench --bench e2e_grpc_client_server --features http-full,grpc,unix
//! ```

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "bench: panic-on-error is the standard pattern for harnesses"
)]
#![allow(
    unreachable_pub,
    clippy::allow_attributes,
    reason = "generated gRPC stubs are exempt from rama's lints"
)]

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread::JoinHandle,
    time::Duration,
};

use rama::{
    Service,
    http::{
        client::EasyHttpWebClient,
        grpc::{Request, Response, Status, protobuf::ProstCodec},
        server::HttpServer,
    },
    net::{address::SocketAddress, uri::Uri},
    rt::Executor,
    service::service_fn,
    tcp::server::TcpListener,
};

mod bench_alloc;

/// A payload to echo, and how many replies a stream sends.
#[derive(Clone, PartialEq, rama::http::grpc::protobuf::prost::Message)]
#[prost(prost_path = "::rama::http::grpc::protobuf::prost")]
pub struct EchoRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub payload: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub replies: u32,
}

#[derive(Clone, PartialEq, rama::http::grpc::protobuf::prost::Message)]
#[prost(prost_path = "::rama::http::grpc::protobuf::prost")]
pub struct EchoResponse {
    #[prost(bytes = "vec", tag = "1")]
    pub payload: Vec<u8>,
}

rama::http::grpc::define_service! {
    package = "rama.bench.echo.v1";
    codec = ProstCodec;

    /// Echoes what it is given.
    service Echo {
        /// Echo the payload once.
        rpc Unary(EchoRequest) -> EchoResponse;
        /// Echo the payload `replies` times.
        rpc ServerStream(EchoRequest) -> stream EchoResponse;
    }
}

struct EchoService;

impl echo_server::Echo for EchoService {
    type ServerStreamStream = rama::stream::Iter<std::vec::IntoIter<Result<EchoResponse, Status>>>;

    async fn unary(&self, request: Request<EchoRequest>) -> Result<Response<EchoResponse>, Status> {
        let payload = request.into_inner().payload;
        Ok(Response::new(EchoResponse { payload }))
    }

    async fn server_stream(
        &self,
        request: Request<EchoRequest>,
    ) -> Result<Response<Self::ServerStreamStream>, Status> {
        let EchoRequest { payload, replies } = request.into_inner();
        let replies: Vec<_> = (0..replies)
            .map(|_| {
                Ok(EchoResponse {
                    payload: payload.clone(),
                })
            })
            .collect();
        Ok(Response::new(rama::stream::iter(replies)))
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Workload {
    /// A 64 byte unary call, [`ROUNDS`] times.
    Small,
    /// A 64 KiB unary call, [`ROUNDS`] times.
    Large,
    /// A 1 KiB call answered by [`STREAMED`] replies, [`ROUNDS`] times.
    Stream,
}

impl Workload {
    const fn payload(self) -> usize {
        match self {
            Self::Small => 64,
            Self::Large => 64 * 1024,
            Self::Stream => 1024,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct LoadParameters {
    workload: Workload,
    /// Concurrent callers, all through one client.
    callers: usize,
    origins: usize,
}

const fn load(workload: Workload, callers: usize, origins: usize) -> LoadParameters {
    LoadParameters {
        workload,
        callers,
        origins,
    }
}

use Workload::{Large, Small, Stream};

/// Low to high pressure: one caller, then bursts far beyond what one
/// connection's streams take, on one origin and spread over several.
const LOAD_MATRIX: [LoadParameters; 10] = [
    load(Small, 1, 1),
    load(Small, 64, 1),
    load(Small, 256, 1),
    load(Small, 1024, 1),
    load(Small, 256, 16),
    load(Small, 1024, 16),
    load(Large, 64, 1),
    load(Large, 256, 16),
    load(Stream, 64, 1),
    load(Stream, 256, 16),
];

/// Calls every caller makes per sample.
const ROUNDS: usize = 16;

/// Replies of a [`Workload::Stream`] call.
const STREAMED: u32 = 16;

const STARTUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Per row: the connections the origins accepted, printed again after the run
/// so they read together, apart from divan's table.
static LOAD_STATS: parking_lot::Mutex<Vec<String>> = parking_lot::Mutex::new(Vec::new());

fn main() {
    #[cfg(unix)]
    {
        _ = rama::unix::utils::raise_nofile(16_384);
    }
    divan::main();
    for line in LOAD_STATS.lock().iter() {
        eprintln!("{line}");
    }
}

/// An origin on its own runtime, counting the connections it accepts. Shut
/// down as it is dropped, so a row's origins do not run into the next row.
struct Origin {
    addr: SocketAddress,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for Origin {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

fn spawn_origin(accepted: Arc<AtomicUsize>) -> Origin {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let thread = std::thread::spawn(move || {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let listener =
                    TcpListener::try_from_std_tcp_listener(listener, Executor::default()).unwrap();
                ready_tx.send(()).unwrap();
                let http = Arc::new(
                    HttpServer::auto(Executor::default())
                        .service(echo_server::EchoServer::new(EchoService)),
                );
                let serve = listener.serve(service_fn(move |stream| {
                    accepted.fetch_add(1, Ordering::Relaxed);
                    let http = http.clone();
                    async move { http.serve(stream).await }
                }));
                tokio::select! {
                    () = serve => {}
                    _ = stopped => {}
                }
            });
    });
    ready_rx
        .recv_timeout(STARTUP_TIMEOUT)
        .expect("origin start");
    Origin {
        addr: addr.into(),
        stop: Some(stop),
        thread: Some(thread),
    }
}

#[divan::bench(args = LOAD_MATRIX, sample_count = 20)]
fn bench_grpc_load(bencher: divan::Bencher, params: LoadParameters) {
    let accepted = Arc::new(AtomicUsize::new(0));
    let origins: Vec<Origin> = (0..params.origins)
        .map(|_| spawn_origin(accepted.clone()))
        .collect();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    // One client for every caller: their calls share its pool.
    let http = EasyHttpWebClient::default();
    let clients: Arc<Vec<_>> = Arc::new(
        origins
            .iter()
            .map(|origin| {
                echo_client::EchoClient::new(
                    http.clone(),
                    Uri::try_from(format!("http://{}", origin.addr)).unwrap(),
                )
            })
            .collect(),
    );
    let payload = vec![0x2a; params.workload.payload()];

    bencher
        .counter(divan::counter::ItemsCount::new(params.callers * ROUNDS))
        .bench_local(|| {
            rt.block_on(async {
                let mut tasks = Vec::with_capacity(params.callers);
                for caller in 0..params.callers {
                    let clients = clients.clone();
                    let mut payload = payload.clone();
                    tasks.push(tokio::spawn(async move {
                        let client = &clients[caller % clients.len()];
                        // Checked: a lost, short or foreign reply fails the run,
                        // each request marked with its caller and round.
                        payload[..8].copy_from_slice(&(caller as u64).to_le_bytes());
                        for round in 0..ROUNDS {
                            payload[8..16].copy_from_slice(&(round as u64).to_le_bytes());
                            let request = Request::new(EchoRequest {
                                payload: payload.clone(),
                                replies: STREAMED,
                            });
                            if params.workload != Workload::Stream {
                                let reply = client.unary(request).await.expect("unary call");
                                assert!(reply.into_inner().payload == payload, "its own echo");
                                continue;
                            }
                            let mut stream = client
                                .server_stream(request)
                                .await
                                .expect("stream call")
                                .into_inner();
                            let mut replies = 0;
                            while let Some(reply) = stream.message().await.expect("a reply") {
                                assert!(reply.payload == payload, "its own reply");
                                replies += 1;
                            }
                            assert_eq!(replies, STREAMED, "every reply");
                        }
                    }));
                }
                for task in tasks {
                    task.await.unwrap();
                }
            });
        });

    let line = format!(
        "grpc load {:?} callers={} origins={}: {} connections accepted, warm-up included",
        params.workload,
        params.callers,
        params.origins,
        accepted.load(Ordering::Relaxed)
    );
    // Now too: a later row failing aborts the run before the summary.
    eprintln!("{line}");
    LOAD_STATS.lock().push(line);
}
