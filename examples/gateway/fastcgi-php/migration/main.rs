//! Step-by-step migration: rama serves two endpoints natively in Rust;
//! everything else falls through to a legacy PHP backend over **FastCGI on a
//! Unix socket**.
//!
//! ```text
//!   curl ──HTTP──► rama router ──┐
//!                                ├─► /api/health, /api/version  (handled in Rust)
//!                                └─► everything else: FastCGI over Unix socket ──► php-fpm ──► app.php
//! ```
//!
//! The PHP backend *also* implements `/api/health` and `/api/version`
//! returning `"source":"php"`. Those handlers are unreachable while the
//! migration is in this state — the test script asserts exactly that.
//!
//! # Run
//!
//! ```sh
//! ./examples/gateway/fastcgi-php/migration/run.sh
//! ```
//!
//! Configuration via environment:
//!
//! - `RAMA_FASTCGI_PHP_LISTEN`           HTTP listen address (default `127.0.0.1:62081`).
//! - `RAMA_FASTCGI_PHP_BACKEND_SOCKET`   Path to the php-fpm Unix socket (required).
//! - `RAMA_FASTCGI_PHP_SCRIPT_FILENAME`  Absolute path of the PHP front controller (required).
//! - `RAMA_FASTCGI_PHP_DOCUMENT_ROOT`    Document root (defaults to the script's parent dir).

#![expect(
    clippy::expect_used,
    reason = "examples: panic-on-error is the standard pattern"
)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rama::{
    Service,
    bytes::Bytes,
    error::{BoxError, ErrorContext as _},
    gateway::fastcgi::{FastCgiClientRequest, FastCgiHttpClient, proto::cgi},
    graceful::Shutdown,
    http::{
        Request, Response, StatusCode,
        layer::trace::TraceLayer,
        server::HttpServer,
        service::web::{
            Router,
            response::{IntoResponse, Json},
        },
    },
    layer::Layer,
    net::{address::SocketAddress, client::EstablishedClientConnection},
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
    unix::{TokioUnixStream, UnixStream},
};

use serde_json::json;

#[tokio::main]
async fn main() {
    tracing::subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let listen: SocketAddress = std::env::var("RAMA_FASTCGI_PHP_LISTEN")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| SocketAddress::local_ipv4(62081));

    let backend_socket = PathBuf::from(
        std::env::var("RAMA_FASTCGI_PHP_BACKEND_SOCKET")
            .expect("RAMA_FASTCGI_PHP_BACKEND_SOCKET must point to the php-fpm Unix socket"),
    );

    let script_filename = std::env::var("RAMA_FASTCGI_PHP_SCRIPT_FILENAME")
        .expect("RAMA_FASTCGI_PHP_SCRIPT_FILENAME must point to the PHP front controller");
    let document_root = std::env::var("RAMA_FASTCGI_PHP_DOCUMENT_ROOT").unwrap_or_else(|_| {
        std::path::Path::new(&script_filename)
            .parent()
            .and_then(|p| p.to_str())
            .unwrap_or(".")
            .to_owned()
    });

    let shutdown = Shutdown::default();
    let exec = Executor::graceful(shutdown.guard());

    // ── FastCGI fallback service: anything we don't yet serve in Rust ────
    let fastcgi_fallback = Arc::new(FastCgiHttpClient::new(PhpUnixBackendConnector {
        socket_path: backend_socket,
        script_filename: Bytes::from(script_filename),
        document_root: Bytes::from(document_root),
    }));

    // ── Router: Rust-native endpoints + FastCGI catch-all ───────────────
    let router: Arc<Router> = Arc::new(
        Router::new()
            .with_get("/api/health", async || {
                Json(json!({ "status": "ok", "source": "rust" }))
            })
            .with_get("/api/version", async || {
                Json(json!({ "version": env!("CARGO_PKG_VERSION"), "source": "rust" }))
            })
            .with_not_found(php_fallback_service(fastcgi_fallback)),
    );

    let http_server =
        HttpServer::auto(exec.clone()).service(TraceLayer::new_for_http().into_layer(router));

    let tcp = TcpListener::bind_address(listen, exec.clone())
        .await
        .expect("bind http listener");
    tracing::info!("rama-fastcgi-php migration listening on http://{listen}");

    shutdown.spawn_task(tcp.serve(http_server));

    shutdown
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}

/// Wrap a `FastCgiHttpClient` in a service that surfaces backend errors as
/// HTTP 502 (so the router's `with_not_found` slot can plug it in directly).
fn php_fallback_service<S>(client: Arc<FastCgiHttpClient<S>>) -> PhpFallback<S> {
    PhpFallback(client)
}

struct PhpFallback<S>(Arc<FastCgiHttpClient<S>>);

impl<S> Clone for PhpFallback<S> {
    #[inline(always)]
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<S> Service<Request> for PhpFallback<S>
where
    S: Service<
            FastCgiClientRequest,
            Output = EstablishedClientConnection<UnixStream, FastCgiClientRequest>,
            Error: Into<BoxError>,
        >,
{
    type Output = Response;
    type Error = std::convert::Infallible;

    async fn serve(&self, req: Request) -> Result<Response, std::convert::Infallible> {
        match self.0.serve(req).await {
            Ok(resp) => Ok(resp),
            Err(err) => {
                tracing::error!(?err, "fastcgi backend error");
                Ok((
                    StatusCode::BAD_GATEWAY,
                    Json(json!({
                        "error": "FastCGI backend unreachable",
                        "source": "rust",
                    })),
                )
                    .into_response())
            }
        }
    }
}

/// Connector that opens a Unix-socket connection to php-fpm and injects the
/// two CGI params php-fpm requires (`SCRIPT_FILENAME`, `DOCUMENT_ROOT`).
struct PhpUnixBackendConnector {
    socket_path: PathBuf,
    script_filename: Bytes,
    document_root: Bytes,
}

impl Service<FastCgiClientRequest> for PhpUnixBackendConnector {
    type Output = EstablishedClientConnection<UnixStream, FastCgiClientRequest>;
    type Error = BoxError;

    async fn serve(&self, mut input: FastCgiClientRequest) -> Result<Self::Output, Self::Error> {
        input
            .push_param(cgi::SCRIPT_FILENAME, self.script_filename.clone())
            .push_param(cgi::DOCUMENT_ROOT, self.document_root.clone());

        let stream = TokioUnixStream::connect(&self.socket_path)
            .await
            .with_context(|| {
                format!(
                    "connect to php-fpm Unix socket: {}",
                    self.socket_path.display()
                )
            })?;
        Ok(EstablishedClientConnection {
            input,
            conn: stream.into(),
        })
    }
}
