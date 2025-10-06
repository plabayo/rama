#![deny(warnings)]

// TODO: Reimplement parallel for HTTP/1

use std::convert::Infallible;
use std::net::SocketAddr;

use rama::extensions::Extensions;
use rama::futures::future::join_all;
use rama::http::body::util::BodyExt;
use rama::http::{Method, Request, Response};
use rama::rt::Executor;
use tokio::sync::Mutex;

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    // Run registered benchmarks.
    divan::main();
}

type BoxedBody = rama::http::body::util::combinators::BoxBody<bytes::Bytes, Infallible>;

// HTTP1

#[divan::bench]
fn http1_consecutive_x1_empty(b: divan::Bencher) {
    opts().bench(b)
}

#[divan::bench]
fn http1_consecutive_x1_req_10b(b: divan::Bencher) {
    opts()
        .method(Method::POST)
        .request_body(&[b's'; 10])
        .bench(b)
}

#[divan::bench]
fn http1_consecutive_x1_both_100kb(b: divan::Bencher) {
    let body = &[b'x'; 1024 * 100];
    opts()
        .method(Method::POST)
        .request_body(body)
        .response_body(body)
        .bench(b)
}

#[divan::bench]
fn http1_consecutive_x1_both_10mb(b: divan::Bencher) {
    let body = &[b'x'; 1024 * 1024 * 10];
    opts()
        .method(Method::POST)
        .request_body(body)
        .response_body(body)
        .bench(b)
}

#[divan::bench]
fn http1_parallel_x10_empty(b: divan::Bencher) {
    opts().parallel(10).bench(b)
}

#[divan::bench]
fn http1_parallel_x10_req_10mb(b: divan::Bencher) {
    let body = &[b'x'; 1024 * 1024 * 10];
    opts()
        .parallel(10)
        .method(Method::POST)
        .request_body(body)
        .bench(b)
}

#[divan::bench]
fn http1_parallel_x10_req_10kb_100_chunks(b: divan::Bencher) {
    let body = &[b'x'; 1024 * 10];
    opts()
        .parallel(10)
        .method(Method::POST)
        .request_chunks(body, 100)
        .bench(b)
}

#[divan::bench]
fn http1_parallel_x10_res_1mb(b: divan::Bencher) {
    let body = &[b'x'; 1024 * 1024];
    opts().parallel(10).response_body(body).bench(b)
}

#[divan::bench]
fn http1_parallel_x10_res_10mb(b: divan::Bencher) {
    let body = &[b'x'; 1024 * 1024 * 10];
    opts().parallel(10).response_body(body).bench(b)
}

// HTTP2

const HTTP2_MAX_WINDOW: u32 = u32::MAX >> 1;

#[divan::bench]
fn http2_consecutive_x1_empty(b: divan::Bencher) {
    opts().http2().bench(b)
}

#[divan::bench]
fn http2_consecutive_x1_req_10b(b: divan::Bencher) {
    opts()
        .http2()
        .method(Method::POST)
        .request_body(&[b's'; 10])
        .bench(b)
}

#[divan::bench]
fn http2_consecutive_x1_req_100kb(b: divan::Bencher) {
    let body = &[b'x'; 1024 * 100];
    opts()
        .http2()
        .method(Method::POST)
        .request_body(body)
        .bench(b)
}

#[divan::bench]
fn http2_parallel_x10_empty(b: divan::Bencher) {
    opts().http2().parallel(10).bench(b)
}

#[divan::bench]
fn http2_parallel_x10_req_10mb(b: divan::Bencher) {
    let body = &[b'x'; 1024 * 1024 * 10];
    opts()
        .http2()
        .parallel(10)
        .method(Method::POST)
        .request_body(body)
        .http2_stream_window(HTTP2_MAX_WINDOW)
        .http2_conn_window(HTTP2_MAX_WINDOW)
        .bench(b)
}

#[divan::bench]
fn http2_parallel_x10_req_10kb_100_chunks(b: divan::Bencher) {
    let body = &[b'x'; 1024 * 10];
    opts()
        .http2()
        .parallel(10)
        .method(Method::POST)
        .request_chunks(body, 100)
        .bench(b)
}

#[divan::bench]
fn http2_parallel_x10_req_10kb_100_chunks_adaptive_window(b: divan::Bencher) {
    let body = &[b'x'; 1024 * 10];
    opts()
        .http2()
        .parallel(10)
        .method(Method::POST)
        .request_chunks(body, 100)
        .http2_adaptive_window()
        .bench(b)
}

#[divan::bench]
fn http2_parallel_x10_req_10kb_100_chunks_max_window(b: divan::Bencher) {
    let body = &[b'x'; 1024 * 10];
    opts()
        .http2()
        .parallel(10)
        .method(Method::POST)
        .request_chunks(body, 100)
        .http2_stream_window(HTTP2_MAX_WINDOW)
        .http2_conn_window(HTTP2_MAX_WINDOW)
        .bench(b)
}

#[divan::bench]
fn http2_parallel_x10_res_1mb(b: divan::Bencher) {
    let body = &[b'x'; 1024 * 1024];
    opts()
        .http2()
        .parallel(10)
        .response_body(body)
        .http2_stream_window(HTTP2_MAX_WINDOW)
        .http2_conn_window(HTTP2_MAX_WINDOW)
        .bench(b)
}

#[divan::bench]
fn http2_parallel_x10_res_10mb(b: divan::Bencher) {
    let body = &[b'x'; 1024 * 1024 * 10];
    opts()
        .http2()
        .parallel(10)
        .response_body(body)
        .http2_stream_window(HTTP2_MAX_WINDOW)
        .http2_conn_window(HTTP2_MAX_WINDOW)
        .bench(b)
}

// ==== Benchmark Options =====

#[derive(Clone)]
struct Opts {
    http2: bool,
    http2_stream_window: Option<u32>,
    http2_conn_window: Option<u32>,
    http2_adaptive_window: bool,
    parallel_cnt: u32,
    request_method: Method,
    request_body: Option<&'static [u8]>,
    request_chunks: usize,
    response_body: &'static [u8],
}

fn opts() -> Opts {
    Opts {
        http2: false,
        http2_stream_window: None,
        http2_conn_window: None,
        http2_adaptive_window: false,
        parallel_cnt: 1,
        request_method: Method::GET,
        request_body: None,
        request_chunks: 0,
        response_body: b"",
    }
}

impl Opts {
    fn http2(mut self) -> Self {
        self.http2 = true;
        self
    }

    fn http2_stream_window(mut self, sz: impl Into<Option<u32>>) -> Self {
        assert!(!self.http2_adaptive_window);
        self.http2_stream_window = sz.into();
        self
    }

    fn http2_conn_window(mut self, sz: impl Into<Option<u32>>) -> Self {
        assert!(!self.http2_adaptive_window);
        self.http2_conn_window = sz.into();
        self
    }

    fn http2_adaptive_window(mut self) -> Self {
        assert!(self.http2_stream_window.is_none());
        assert!(self.http2_conn_window.is_none());
        self.http2_adaptive_window = true;
        self
    }

    fn method(mut self, m: Method) -> Self {
        self.request_method = m;
        self
    }

    fn request_body(mut self, body: &'static [u8]) -> Self {
        self.request_body = Some(body);
        self
    }

    fn request_chunks(mut self, chunk: &'static [u8], cnt: usize) -> Self {
        assert!(cnt > 0);
        self.request_body = Some(chunk);
        self.request_chunks = cnt;
        self
    }

    fn response_body(mut self, body: &'static [u8]) -> Self {
        self.response_body = body;
        self
    }

    fn parallel(mut self, cnt: u32) -> Self {
        assert!(cnt > 0, "parallel count must be larger than 0");
        self.parallel_cnt = cnt;
        self
    }

    fn bench(self, b: divan::Bencher) {
        use std::sync::Arc;
        // Create a runtime of current thread.
        let rt = Arc::new(
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("rt build"),
        );
        let exec = rt.clone();

        let req_len = self.request_body.map(|b| b.len()).unwrap_or(0) as u64;
        let req_len = if self.request_chunks > 0 {
            req_len * self.request_chunks as u64
        } else {
            req_len
        };

        let addr = spawn_server(&rt, &self);

        enum Client {
            Http1(Mutex<rama::http::core::client::conn::http1::SendRequest<BoxedBody>>),
            Http2(rama::http::core::client::conn::http2::SendRequest<BoxedBody>),
        }

        let client = rt.block_on(async {
            if self.http2 {
                let tcp = tokio::net::TcpStream::connect(&addr).await.unwrap();
                let (tx, conn) =
                    rama::http::core::client::conn::http2::Builder::new(Executor::new())
                        .initial_stream_window_size(self.http2_stream_window)
                        .initial_connection_window_size(self.http2_conn_window)
                        .adaptive_window(self.http2_adaptive_window)
                        .handshake(tcp)
                        .await
                        .unwrap();
                tokio::spawn(conn);
                Client::Http2(tx)
            } else {
                let tcp = tokio::net::TcpStream::connect(&addr).await.unwrap();
                let (tx, conn) = rama::http::core::client::conn::http1::Builder::new()
                    .handshake(tcp)
                    .await
                    .unwrap();
                tokio::spawn(conn);
                Client::Http1(Mutex::new(tx))
            }
        });

        let url: rama::http::Uri = format!("http://{addr}/hello").parse().unwrap();

        let make_request = || {
            let chunk_cnt = self.request_chunks;
            let body = if chunk_cnt > 0 {
                let (mut tx, rx) = futures_channel::mpsc::channel(0);

                let chunk = self
                    .request_body
                    .expect("request_chunks means request_body");
                exec.spawn(async move {
                    use rama::futures::SinkExt;
                    use rama::http::core::body::Frame;
                    for _ in 0..chunk_cnt {
                        tx.send(Ok(Frame::data(bytes::Bytes::from(chunk))))
                            .await
                            .expect("send_data");
                    }
                });
                rama::http::body::util::StreamBody::new(rx).boxed()
            } else if let Some(chunk) = self.request_body {
                rama::http::body::util::Full::new(bytes::Bytes::from(chunk)).boxed()
            } else {
                rama::http::body::util::Empty::new().boxed()
            };
            let mut req = Request::new(body);
            *req.method_mut() = self.request_method.clone();
            *req.uri_mut() = url.clone();
            req
        };

        let shared_client = &client;

        let send_request = async |req| {
            let res = match shared_client {
                Client::Http1(tx) => {
                    let mut tx = tx.lock().await;
                    tx.ready().await.expect("client is ready");
                    tx.send_request(req).await.expect("client wait h1")
                }
                Client::Http2(tx) => {
                    let mut tx = tx.clone();
                    tx.ready().await.expect("client is ready");
                    tx.send_request(req).await.expect("client wait h2")
                }
            };
            let mut body = res.into_body();
            while let Some(_chunk) = body.frame().await {}
        };

        let bytes_per_iter = (req_len + self.response_body.len() as u64) * self.parallel_cnt as u64;
        let b = b.counter(divan::counter::BytesCount::u8(bytes_per_iter as usize));

        if self.parallel_cnt == 1 {
            b.bench_local(|| {
                let req = make_request();
                rt.block_on(send_request(req));
            });
        } else {
            b.bench_local(|| {
                let futs = (0..self.parallel_cnt).map(|_| {
                    let req = make_request();
                    send_request(req)
                });
                // Await all spawned futures becoming completed.
                rt.block_on(join_all(futs));
            });
        }
    }
}

fn spawn_server(rt: &tokio::runtime::Runtime, opts: &Opts) -> SocketAddr {
    use rama::service::service_fn;
    use tokio::net::TcpListener;
    let addr = "127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap();

    let listener = rt.block_on(async { TcpListener::bind(&addr).await.unwrap() });

    let addr = listener.local_addr().unwrap();
    let body = opts.response_body;
    let opts = opts.clone();
    rt.spawn(async move {
        let _ = &opts;
        while let Ok((sock, _)) = listener.accept().await {
            if opts.http2 {
                tokio::spawn(
                    rama::http::core::server::conn::http2::Builder::new(Executor::new())
                        .initial_stream_window_size(opts.http2_stream_window)
                        .initial_connection_window_size(opts.http2_conn_window)
                        .adaptive_window(opts.http2_adaptive_window)
                        .serve_connection(
                            sock,
                            rama::http::core::service::RamaHttpService::new(
                                Extensions::new(),
                                service_fn(move |req: Request| async move {
                                    let mut req_body = req.into_body();
                                    while let Some(_chunk) = req_body.frame().await {}
                                    Ok::<_, std::convert::Infallible>(Response::new(
                                        rama::http::Body::from(body),
                                    ))
                                }),
                            ),
                        ),
                );
            } else {
                tokio::spawn(
                    rama::http::core::server::conn::http1::Builder::new().serve_connection(
                        sock,
                        rama::http::core::service::RamaHttpService::new(
                            Extensions::new(),
                            service_fn(move |req: Request| async move {
                                let mut req_body = req.into_body();
                                while let Some(_chunk) = req_body.frame().await {}
                                Ok::<_, std::convert::Infallible>(Response::new(
                                    rama::http::Body::from(body),
                                ))
                            }),
                        ),
                    ),
                );
            }
        }
    });
    addr
}
