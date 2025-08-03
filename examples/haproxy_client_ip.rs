//! An example to showcase how to optionally support HaProxy.
//! which is typically used in case your service is behind a loadbalancer.
//!
//! Our server implementation can handle both v1 and v2 alike.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example haproxy_client_ip --features=haproxy,http-full
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62025`. You can use `curl` to interact with the service:
//!
//! ```sh
//! curl -v http://127.0.0.1:62025
//! ```
//!
//! You should see a response with `HTTP/1.1 200 OK` and the client IP as the body payload.
//! In case you are doing this with HaProxy data at the start of your Tcp stream,
//! you'll see the client IP Address advertised in there, otherwise you'll see
//! the socket peer addr.

use rama::{
    Context, Layer,
    error::ErrorContext,
    http::{
        StatusCode, layer::required_header::AddRequiredResponseHeaders, server::HttpServer,
        service::web::Router,
    },
    net::{forwarded::Forwarded, stream::SocketInfo},
    proxy::haproxy::server::HaProxyLayer,
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing::level_filters::LevelFilter,
};

use std::time::Duration;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .init();

    let graceful = rama::graceful::Shutdown::default();

    graceful.spawn_task_fn(async |guard| {
        let tcp_http_service = HttpServer::auto(Executor::graceful(guard.clone())).service(
            AddRequiredResponseHeaders::new(Router::new().get(
                "/",
                async |ctx: Context<()>| -> Result<String, (StatusCode, String)> {
                    let client_ip = ctx
                        .get::<Forwarded>()
                        .and_then(|f| f.client_ip())
                        .or_else(|| ctx.get::<SocketInfo>().map(|info| info.peer_addr().ip()))
                        .context("failed to fetch client IP")
                        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
                    Ok(client_ip.to_string())
                },
            )),
        );

        TcpListener::bind("127.0.0.1:62025")
            .await
            .expect("bind TCP Listener")
            .serve_graceful(
                guard,
                HaProxyLayer::new()
                    // by default [`HaProxyLayer`] is enforced,
                    // setting peek=true allows you to make it optional,
                    // which is pretty useful to easily run cloud services locally
                    .with_peek(true)
                    .into_layer(tcp_http_service),
            )
            .await;
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}
