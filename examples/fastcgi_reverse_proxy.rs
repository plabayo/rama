//! An example of a reverse proxy that accepts HTTP requests and forwards them to a
//! FastCGI backend application, returning the application's response as an HTTP reply.
//!
//! The example spawns two services:
//!
//! 1. A FastCGI application server on `127.0.0.1:62054` that wraps a plain HTTP echo
//!    handler via [`FastCgiHttpService`] — demonstrating that any HTTP service can be
//!    deployed as a FastCGI backend without modification.
//!
//! 2. An HTTP server on `127.0.0.1:62053` that accepts ordinary HTTP requests,
//!    translates them into FastCGI requests via [`FastCgiHttpClient`], and proxies
//!    them to the FastCGI backend.
//!
//! This demonstrates both sides of the HTTP adaptive layer:
//! - [`FastCgiHttpClient`]: HTTP reverse proxy → FastCGI backend (client side).
//! - [`FastCgiHttpService`]: HTTP handler deployed as a FastCGI application (server side).
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example fastcgi_reverse_proxy --features=http-full,fastcgi
//! ```
//!
//! # Expected output
//!
//! The proxy will start and listen on `:62053`. You can use `curl` to interact:
//!
//! ```sh
//! curl -v http://127.0.0.1:62053/hello?foo=bar
//! curl -v -X POST http://127.0.0.1:62053/submit -d 'name=rama'
//! ```
//!
//! Each response is the HTTP request echoed back by the backend handler.

use rama::{
    error::BoxError,
    gateway::fastcgi::{FastCgiClientRequest, FastCgiHttpClient, FastCgiHttpService, FastCgiServer},
    http::{Body, Request, Response, StatusCode, body::util::BodyExt, server::HttpServer},
    net::client::EstablishedClientConnection,
    rt::Executor,
    service::service_fn,
    tcp::server::TcpListener,
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
};
use std::sync::Arc;
use std::time::Duration;

const PROXY_ADDR: &str = "127.0.0.1:62053";
const BACKEND_ADDR: &str = "127.0.0.1:62054";

#[tokio::main]
async fn main() {
    tracing::subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .init();

    let graceful = rama::graceful::Shutdown::default();
    let exec = Executor::graceful(graceful.guard());

    // Spawn the FastCGI backend: a plain HTTP echo handler wrapped in FastCgiHttpService
    // so it can accept FastCGI connections from the proxy.
    {
        let exec = exec.clone();
        let tcp = TcpListener::bind_address(BACKEND_ADDR, exec)
            .await
            .expect("bind fastcgi backend");
        let service = Arc::new(FastCgiServer::new(FastCgiHttpService::new(service_fn(
            echo_http,
        ))));
        graceful.spawn_task(tcp.serve(service));
        tracing::info!("FastCGI backend listening on {BACKEND_ADDR}");
    }

    // Small delay to let the backend bind before the proxy starts sending.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Spawn the HTTP reverse proxy that translates HTTP to FastCGI.
    {
        let exec2 = Executor::graceful(graceful.guard());
        let tcp = TcpListener::bind_address(PROXY_ADDR, exec)
            .await
            .expect("bind http proxy");
        let proxy = Arc::new(FastCgiProxyService::new());
        graceful.spawn_task(tcp.serve(HttpServer::auto(exec2).service(proxy)));
        tracing::info!("HTTP→FastCGI reverse proxy listening on {PROXY_ADDR}");
    }

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}

// ---------------------------------------------------------------------------
// HTTP echo handler (the real backend logic)
// ---------------------------------------------------------------------------

/// A plain HTTP handler that echoes the request back as plain text.
///
/// This is a normal HTTP service — it knows nothing about FastCGI.
/// [`FastCgiHttpService`] wraps it to accept FastCGI connections.
async fn echo_http(req: Request) -> Result<Response, BoxError> {
    let (parts, body) = req.into_parts();
    let body_bytes = body.collect().await?.to_bytes();

    let mut text = format!("=== {} {} ===\n", parts.method, parts.uri);
    for (name, value) in &parts.headers {
        let _ = std::fmt::Write::write_fmt(
            &mut text,
            format_args!("{}: {}\n", name, String::from_utf8_lossy(value.as_bytes())),
        );
    }
    if !body_bytes.is_empty() {
        text.push_str("\n=== Request Body ===\n");
        text.push_str(&String::from_utf8_lossy(&body_bytes));
        text.push('\n');
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain")
        .body(Body::from(text))
        .expect("infallible"))
}

// ---------------------------------------------------------------------------
// TCP connector for the FastCGI backend
// ---------------------------------------------------------------------------

/// Connector that opens a plain TCP connection to the FastCGI backend.
struct BackendConnector;

impl rama::Service<FastCgiClientRequest> for BackendConnector {
    type Output = EstablishedClientConnection<tokio::net::TcpStream, FastCgiClientRequest>;
    type Error = std::io::Error;

    async fn serve(&self, input: FastCgiClientRequest) -> Result<Self::Output, Self::Error> {
        let conn = tokio::net::TcpStream::connect(BACKEND_ADDR).await?;
        Ok(EstablishedClientConnection { input, conn })
    }
}

// ---------------------------------------------------------------------------
// HTTP reverse proxy service
// ---------------------------------------------------------------------------

/// HTTP service: proxies each HTTP request to the FastCGI backend.
///
/// [`FastCgiHttpClient`] handles all CGI environment construction and CGI stdout
/// parsing automatically — the proxy only needs to handle connection errors.
struct FastCgiProxyService {
    client: FastCgiHttpClient<BackendConnector>,
}

impl FastCgiProxyService {
    fn new() -> Self {
        Self {
            client: FastCgiHttpClient::new(BackendConnector),
        }
    }
}

impl rama::Service<Request> for FastCgiProxyService {
    type Output = Response;
    type Error = std::convert::Infallible;

    async fn serve(&self, req: Request) -> Result<Response, std::convert::Infallible> {
        match self.client.serve(req).await {
            Ok(resp) => Ok(resp),
            Err(e) => {
                tracing::error!("fastcgi backend error: {e}");
                Ok(Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Body::from("FastCGI backend error\n"))
                    .expect("infallible"))
            }
        }
    }
}
