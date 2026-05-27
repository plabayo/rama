//! HTTPS reverse proxy that terminates TLS and forwards every request to a
//! PHP-FPM backend over FastCGI (TCP).
//!
//! Layout:
//!
//! ```text
//!   curl ──HTTPS──► rama (this example, self-signed TLS) ──FastCGI/TCP──► php-fpm ──► app.php
//! ```
//!
//! See [`examples/gateway/fastcgi-php/gateway/run.sh`] for a complete
//! end-to-end script that boots php-fpm, runs this binary, and asserts the
//! round-trip with curl + jq.
//!
//! # Run
//!
//! ```sh
//! ./examples/gateway/fastcgi-php/gateway/run.sh
//! ```
//!
//! Configuration is supplied via two environment variables:
//!
//! - `RAMA_FASTCGI_PHP_LISTEN` — the HTTPS listen address (default `127.0.0.1:62443`).
//! - `RAMA_FASTCGI_PHP_BACKEND` — TCP `host:port` of php-fpm (default `127.0.0.1:9000`).
//! - `RAMA_FASTCGI_PHP_SCRIPT_FILENAME` — absolute path of `app.php` (required;
//!   php-fpm refuses without it).
//! - `RAMA_FASTCGI_PHP_DOCUMENT_ROOT` — directory containing the front
//!   controller (defaults to the parent dir of `SCRIPT_FILENAME`).

#![expect(
    clippy::expect_used,
    reason = "examples: panic-on-error is the standard pattern"
)]

use std::sync::Arc;
use std::time::Duration;

use rama::{
    Service,
    error::BoxError,
    gateway::fastcgi::{FastCgiClientRequest, FastCgiHttpClient, FastCgiTcpConnector},
    graceful::Shutdown,
    http::{
        Request, Response, StatusCode, layer::trace::TraceLayer, server::HttpServer,
        service::web::response::IntoResponse,
    },
    layer::Layer,
    net::{
        address::{HostWithPort, SocketAddress},
        client::EstablishedClientConnection,
        tls::server::SelfSignedData,
    },
    rt::Executor,
    tcp::{TcpStream, server::TcpListener},
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
    tls::rustls::server::{TlsAcceptorDataBuilder, TlsAcceptorLayer},
};

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
        .unwrap_or_else(|| SocketAddress::local_ipv4(62443));

    let backend: HostWithPort = std::env::var("RAMA_FASTCGI_PHP_BACKEND")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| HostWithPort::local_ipv4(9000));

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
    let guard = shutdown.guard();
    let exec = Executor::graceful(guard);

    // ── TLS terminator (rustls + self-signed, HTTP/1.1 + HTTP/2) ─────────
    let tls_data = TlsAcceptorDataBuilder::try_new_self_signed(SelfSignedData {
        organisation_name: Some("rama-fastcgi-php example".to_owned()),
        ..Default::default()
    })
    .expect("self-signed acceptor data")
    .with_alpn_protocols_http_auto()
    .build();

    // ── FastCGI client: HTTP → CGI env (+SCRIPT_FILENAME) → php-fpm ──────
    // `FastCgiTcpConnector::php_fpm` opens a TCP connection to the backend
    // and stages the two CGI params php-fpm requires (`SCRIPT_FILENAME` and
    // `DOCUMENT_ROOT`) — no custom connector wrapper needed.
    let connector = FastCgiTcpConnector::php_fpm(backend.clone(), exec.clone(), &script_filename)
        .with_document_root(&document_root);
    let fastcgi_client = Arc::new(FastCgiHttpClient::new(connector));

    let app_service = GatewayService {
        client: fastcgi_client,
    };

    let http_server =
        HttpServer::auto(exec.clone()).service(TraceLayer::new_for_http().into_layer(app_service));

    let tcp = TcpListener::bind_address(listen, exec.clone())
        .await
        .expect("bind https listener");
    tracing::info!(
        backend = %backend,
        "rama-fastcgi-php gateway listening (HTTPS) on https://{listen}"
    );

    shutdown.spawn_task(tcp.serve(TlsAcceptorLayer::new(tls_data).into_layer(http_server)));

    shutdown
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}

/// HTTP service: forward to php-fpm via FastCGI, surfacing protocol-level
/// errors as a 502.
struct GatewayService<S> {
    client: Arc<FastCgiHttpClient<S>>,
}

impl<S> Clone for GatewayService<S> {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
        }
    }
}

impl<S> Service<Request> for GatewayService<S>
where
    S: Service<
            FastCgiClientRequest,
            Output = EstablishedClientConnection<TcpStream, FastCgiClientRequest>,
            Error: Into<BoxError>,
        >,
{
    type Output = Response;
    type Error = std::convert::Infallible;

    async fn serve(&self, req: Request) -> Result<Self::Output, Self::Error> {
        match self.client.serve(req).await {
            Ok(resp) => Ok(resp),
            Err(err) => {
                tracing::error!(?err, "fastcgi backend error");
                Ok((
                    StatusCode::BAD_GATEWAY,
                    "FastCGI backend error\n".to_owned(),
                )
                    .into_response())
            }
        }
    }
}
