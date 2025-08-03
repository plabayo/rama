//! This example demonstrates the use of an infinite
//! resource used as a honeypot for bad bots and other
//! malicious actors.
//!
//! ```sh
//! cargo run --example http_anti_bot_infinite_resource --features=http-full
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62035`. You can use your browser to interact with the service:
//!
//! ```sh
//! open http://127.0.0.1:62035
//! ```
//!
//! Will return a greeting for humans.
//!
//! Here are the other resources:
//!
//! ```sh
//! curl -v http://127.0.0.1:62035/robots.txt  # robots.txt
//! curl -v http://127.0.0.1:62035/internal/clients.csv  # honeypot file
//! curl -v http://127.0.0.1:62035/internal/clients.csv?_test_limit=42  # make it finite (42 bytes, not a hard limit)
//! ```
//!
//! Once you hit the file once you will also be blocked (IP wise).

// rama provides everything out of the box to build a complete web service.
use rama::{
    Context, Layer, Service,
    error::{BoxError, OpaqueError},
    http::{
        InfiniteReader, StatusCode,
        headers::ContentType,
        layer::required_header::AddRequiredResponseHeadersLayer,
        layer::trace::TraceLayer,
        server::HttpServer,
        service::web::{
            Router,
            extract::Query,
            response::{Headers, Html, IntoResponse},
        },
    },
    layer::ConsumeErrLayer,
    net::{address::SocketAddress, stream::SocketInfo},
    rt::Executor,
    tcp::{TcpStream, server::TcpListener},
    telemetry::tracing::{self, level_filters::LevelFilter},
};

/// Everything else we need is provided by the standard library, community crates or tokio.
use serde::Deserialize;
use std::{collections::HashSet, net::IpAddr, sync::Arc, time::Duration};
use tokio::sync::Mutex;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};

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

    let router = Router::new()
        .get("/", Html(r##"<h1>Hello, Human!?</h1>"##.to_owned()))
        .get("/robots.txt", ROBOTS_TXT)
        .get("/internal/clients.csv", infinite_resource);

    let exec = Executor::graceful(graceful.guard());
    let app = HttpServer::auto(exec).service(
        (
            TraceLayer::new_for_http(),
            AddRequiredResponseHeadersLayer::default(),
        )
            .into_layer(router),
    );

    let tcp_svc = (ConsumeErrLayer::default(), IpFirewall).into_layer(app);

    let address = SocketAddress::local_ipv4(62035);
    tracing::info!("running service at: {address}");
    let tcp_server = TcpListener::build_with_state(State::default())
        .bind(address)
        .await
        .expect("bind tcp server");

    graceful.spawn_task_fn(|guard| tcp_server.serve_graceful(guard, tcp_svc));

    graceful
        .shutdown_with_limit(Duration::from_secs(8))
        .await
        .expect("graceful shutdown");
}

#[derive(Debug, Clone, Default)]
struct State {
    block_list: Arc<Mutex<HashSet<IpAddr>>>,
}

const ROBOTS_TXT: &str = r##"User-agent: *
Disallow: /internal/
Disallow: /internal/clients.csv
"##;

#[derive(Debug, Deserialize)]
struct InfiniteResourceParameters {
    _test_limit: Option<usize>,
}

async fn infinite_resource(
    Query(parameters): Query<InfiniteResourceParameters>,
    ctx: Context<State>,
) -> impl IntoResponse {
    let Some(socket_info) = ctx.get::<SocketInfo>() else {
        tracing::error!("failed to fetch IP from SocketInfo; fail request with 500");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let ip_addr = socket_info.peer_addr().ip();
    let mut block_list = ctx.state().block_list.lock().await;
    block_list.insert(ip_addr);
    tracing::info!(
        "blocking bad ip: {ip_addr}; serve content (limit: {:?})",
        parameters._test_limit
    );

    (
        Headers::single(ContentType::csv()),
        [("X-Robots-Tag", "noindex, nofollow")],
        InfiniteReader::new()
            .maybe_with_size_limit(parameters._test_limit)
            .with_throttle(Duration::from_secs(2)),
    )
        .into_response()
}

#[derive(Debug, Clone)]
struct IpFirewall;
#[derive(Debug, Clone)]
struct IpFirewallService<S>(S);

impl<S> Layer<S> for IpFirewall {
    type Service = IpFirewallService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        IpFirewallService(inner)
    }
}

impl<S> Service<State, TcpStream> for IpFirewallService<S>
where
    S: Service<State, TcpStream, Error: Into<BoxError>>,
{
    type Response = S::Response;
    type Error = BoxError;

    async fn serve(
        &self,
        ctx: Context<State>,
        stream: TcpStream,
    ) -> Result<Self::Response, Self::Error> {
        let ip_addr = ctx
            .get::<SocketInfo>()
            .ok_or_else(|| OpaqueError::from_display("no socket info found").into_boxed())?
            .peer_addr()
            .ip();
        let block_list = ctx.state().block_list.lock().await;
        if block_list.contains(&ip_addr) {
            return Err(OpaqueError::from_display(format!(
                "drop connection for blocked ip: {ip_addr}"
            ))
            .into_boxed());
        }
        std::mem::drop(block_list);
        self.0.serve(ctx, stream).await.map_err(Into::into)
    }
}
