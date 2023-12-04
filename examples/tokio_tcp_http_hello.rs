use std::{convert::Infallible, time::Duration};

use rama::{
    http::server as http,
    http::StatusCode,
    rt::graceful::Shutdown,
    service::{limit::ConcurrentPolicy, Layer, Service},
    state::Extendable,
    stream::layer::BytesRWTrackerHandle,
    tcp::server::TcpListener,
};

use tracing::metadata::LevelFilter;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[rama::rt::main]
async fn main() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .init();

    let shutdown = Shutdown::default();

    shutdown.spawn_task_fn(|guard| async {
        let tcp_listener = TcpListener::bind("127.0.0.1:8080")
            .await
            .expect("bind TCP Listener");
        tracing::info!(
            "listening for incoming TCP connections on {}",
            tcp_listener.local_addr().unwrap()
        );

        tcp_listener.set_ttl(30).expect("set TTL");

        // TODO:
        // - support state passing from tcp listener to stream
        // - find good way to pass state from stream to http

        let mut http_server = http::HttpServer::auto();

        http_server.http1_mut().preserve_header_case(true);
        http_server.h2_mut().adaptive_window(true);

        let web_server = http_server
            .compression()
            .trace()
            .timeout(Duration::from_secs(10))
            .service::<WebServer, _, _, _>(WebServer::new());

        tcp_listener
            .spawn()
            .limit(ConcurrentPolicy::new(2))
            .timeout(Duration::from_secs(30))
            .bytes_tracker()
            .layer(TcpLogLayer)
            .serve_graceful(guard, web_server)
            .await
            .expect("serve incoming TCP connections");
    });

    shutdown
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}

#[derive(Debug, Clone)]
pub struct TcpLogService<S> {
    service: S,
}

impl<S, Stream> Service<Stream> for TcpLogService<S>
where
    S: Service<Stream>,
    Stream: Extendable,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn call(&self, stream: Stream) -> Result<Self::Response, Self::Error> {
        let handle = stream
            .extensions()
            .get::<BytesRWTrackerHandle>()
            .expect("bytes tracker is enabled")
            .clone();

        let result = self.service.call(stream).await;

        tracing::info!(
            "bytes read: {}, bytes written: {}",
            handle.read(),
            handle.written(),
        );

        result
    }
}

pub struct TcpLogLayer;

impl<S> Layer<S> for TcpLogLayer {
    type Service = TcpLogService<S>;

    fn layer(&self, service: S) -> Self::Service {
        TcpLogService { service }
    }
}

type Request = http::Request;
type Response = http::Response<String>;

#[derive(Debug, Clone)]
struct WebServer {
    start_time: std::time::Instant,
}

impl WebServer {
    fn new() -> Self {
        Self {
            start_time: std::time::Instant::now(),
        }
    }

    async fn render_page_fast(&self) -> Response {
        self.render_page(StatusCode::OK, "This was a fast response.")
    }

    async fn render_page_slow(&self) -> Response {
        rama::rt::time::sleep(std::time::Duration::from_secs(5)).await;
        self.render_page(StatusCode::OK, "This was a slow response.")
    }

    async fn render_page_not_found(&self, path: &str) -> Response {
        self.render_page(
            StatusCode::NOT_FOUND,
            format!("The path {} was not found.", path).as_str(),
        )
    }

    fn render_page(&self, status: StatusCode, msg: &str) -> Response {
        hyper::Response::builder()
            .header(hyper::header::CONTENT_TYPE, "text/html")
            .status(status)
            .body(format!(
                r##"<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Rama Http Server Example</title>
    </head>
    <body>
        <h1>Hello!</h1>
        <p>{msg}<p>
        <p>Server has been running {} seconds.</p>
    </body>
</html>
"##,
                self.start_time.elapsed().as_secs()
            ))
            .unwrap()
    }
}

impl Service<Request> for WebServer {
    type Response = Response;
    type Error = Infallible;

    async fn call(&self, request: Request) -> Result<Self::Response, Self::Error> {
        Ok(match request.uri().path() {
            "/fast" => self.render_page_fast().await,
            "/slow" => self.render_page_slow().await,
            path => self.render_page_not_found(path).await,
        })
    }
}
