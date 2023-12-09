use std::{convert::Infallible, time::Duration};

use rama::{
    http::server as http,
    http::StatusCode,
    rt::graceful::Shutdown,
    service::{limit::ConcurrentPolicy, Layer, Service},
    stream::layer::BytesRWTrackerHandle,
    tcp::server::{TcpListener, TcpSocketInfo},
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

        let mut http_server = http::HttpServer::auto();

        http_server.http1_mut().preserve_header_case(true);
        http_server.h2_mut().adaptive_window(true);

        let web_server = http_server
            .compression()
            .trace()
            .timeout(Duration::from_secs(10))
            .layer(HttpLogLayer)
            .service::<WebServer, _, _, _>(WebServer::new());

        tcp_listener
            .spawn()
            .limit(ConcurrentPolicy::new(2))
            .timeout(Duration::from_secs(30))
            .bytes_tracker()
            .serve_graceful(guard, web_server)
            .await
            .expect("serve incoming TCP connections");
    });

    shutdown
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}

type Request = http::Request;
type Response = http::Response<String>;

#[derive(Debug, Clone)]
pub struct HttpLogService<S> {
    service: S,
}

impl<S, Body> Service<Request> for HttpLogService<S>
where
    S: Service<Request, Response = http::Response<Body>>,
    S::Error: std::fmt::Debug,
{
    type Response = S::Response;
    type Error = S::Error;

    async fn call(&self, request: Request) -> Result<Self::Response, Self::Error> {
        let uri = request.uri().clone();

        let handle = request
            .extensions()
            .get::<BytesRWTrackerHandle>()
            .expect("bytes tracker is enabled")
            .clone();

        let tcp_socket_info = request
            .extensions()
            .get::<TcpSocketInfo>()
            .expect("tcp socket info is enabled")
            .clone();

        let result = self.service.call(request).await;
        match &result {
            Ok(response) => {
                tracing::info!(
                    "{} -> {} | {} > status: {} [ bytes read: {} ]",
                    tcp_socket_info.peer_addr,
                    tcp_socket_info
                        .local_addr
                        .map(|addr| addr.to_string())
                        .unwrap_or_default(),
                    uri,
                    response.status(),
                    handle.read(),
                );
            }
            Err(err) => {
                tracing::error!(
                    "{} -> {} | {} > error: {:?} [ bytes read: {} ]",
                    tcp_socket_info.peer_addr,
                    tcp_socket_info
                        .local_addr
                        .map(|addr| addr.to_string())
                        .unwrap_or_default(),
                    uri,
                    err,
                    handle.read(),
                );
            }
        }
        result
    }
}

pub struct HttpLogLayer;

impl<S> Layer<S> for HttpLogLayer {
    type Service = HttpLogService<S>;

    fn layer(&self, service: S) -> Self::Service {
        HttpLogService { service }
    }
}

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
