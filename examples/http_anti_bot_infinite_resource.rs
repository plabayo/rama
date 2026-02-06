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
//! The server will start and listen on `:62039`. You can use your browser to interact with the service:
//!
//! ```sh
//! open http://127.0.0.1:62039
//! ```
//!
//! Will return a greeting for humans.
//!
//! Here are the other resources:
//!
//! ```sh
//! curl -v http://127.0.0.1:62039/robots.txt  # robots.txt
//! curl -v http://127.0.0.1:62039/internal/clients.csv  # honeypot file
//! curl -v http://127.0.0.1:62039/internal/clients.csv?_test_limit=42  # make it finite (42 bytes, not a hard limit)
//! ```
//!
//! Once you hit the file once you will also be blocked (IP wise).

// rama provides everything out of the box to build a complete web service.
use rama::{
    Layer, Service,
    conversion::FromRef,
    error::{BoxError, ErrorContext as _, ErrorExt},
    extensions::ExtensionsRef,
    http::{
        InfiniteReader,
        headers::ContentType,
        layer::{required_header::AddRequiredResponseHeadersLayer, trace::TraceLayer},
        server::HttpServer,
        service::web::{
            Router,
            extract::{Extension, Query, State},
            response::{Headers, Html, IntoResponse},
        },
    },
    layer::ConsumeErrLayer,
    net::{address::SocketAddress, stream::SocketInfo},
    rt::Executor,
    tcp::{TcpStream, server::TcpListener},
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
    utils::macros::impl_deref,
};

/// Everything else we need is provided by the standard library, community crates or tokio.
use ahash::HashSet;
use serde::Deserialize;
use std::{net::IpAddr, sync::Arc, time::Duration};
use tokio::sync::Mutex;

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

    let state = AppState::default();

    let router = Router::new_with_state(state.clone())
        .with_get("/", Html(r##"<h1>Hello, Human!?</h1>"##.to_owned()))
        .with_get("/robots.txt", ROBOTS_TXT)
        .with_get("/internal/clients.csv", infinite_resource);

    let exec = Executor::graceful(graceful.guard());
    let app = HttpServer::auto(exec).service(Arc::new(
        (
            TraceLayer::new_for_http(),
            AddRequiredResponseHeadersLayer::default(),
        )
            .into_layer(router),
    ));

    let tcp_svc = (
        ConsumeErrLayer::default(),
        IpFirewall::new(state.block_list.clone()),
    )
        .into_layer(app);

    let address = SocketAddress::local_ipv4(62039);
    tracing::info!("running service at: {address}");

    let exec = Executor::graceful(graceful.guard());
    let tcp_server = TcpListener::build(exec)
        .bind(address)
        .await
        .expect("bind tcp server");

    graceful.spawn_task(tcp_server.serve(tcp_svc));

    graceful
        .shutdown_with_limit(Duration::from_secs(8))
        .await
        .expect("graceful shutdown");
}

#[derive(Debug, Clone, Default, FromRef)]
struct AppState {
    block_list: BlockList,
}

#[derive(Clone, Debug, Default)]
struct BlockList(Arc<Mutex<HashSet<IpAddr>>>);

impl_deref!(BlockList: Arc<Mutex<HashSet<IpAddr>>>);

const ROBOTS_TXT: &str = r##"User-agent: *
Disallow: /internal/
Disallow: /internal/clients.csv
"##;

#[derive(Debug, Deserialize)]
struct InfiniteResourceParameters {
    _test_limit: Option<usize>,
}

async fn infinite_resource(
    // We can access global state like this, the easy option for fast prototyping
    State(_global_state): State<AppState>,
    // request will fail with status 500 in case extension is not available,
    // use Option<Extension<_>> in case you deem it an optional value
    Extension(socket_info): Extension<SocketInfo>,
    // But for production usage we should only use the specific state this handler needs by implementing:
    // `FromRef<AppState> for BlockList`. This is considered better practise because
    // handlers only take what they need and never need to know what to GlobalState is.
    State(block_list): State<BlockList>,
    Query(parameters): Query<InfiniteResourceParameters>,
) -> impl IntoResponse {
    let ip_addr = socket_info.peer_addr().ip_addr;
    let mut block_list = block_list.lock().await;
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
struct IpFirewall {
    block_list: BlockList,
}

impl IpFirewall {
    fn new(block_list: BlockList) -> Self {
        Self { block_list }
    }
}

#[derive(Debug, Clone)]
struct IpFirewallService<S> {
    inner: S,
    block_list: BlockList,
}

impl<S> Layer<S> for IpFirewall {
    type Service = IpFirewallService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        IpFirewallService {
            inner,
            block_list: self.block_list.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        IpFirewallService {
            inner,
            block_list: self.block_list,
        }
    }
}

impl<S> Service<TcpStream> for IpFirewallService<S>
where
    S: Service<TcpStream, Error: Into<BoxError>>,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, stream: TcpStream) -> Result<Self::Output, Self::Error> {
        let ip_addr = stream
            .extensions()
            .get::<SocketInfo>()
            .context("no socket info found")?
            .peer_addr()
            .ip_addr;
        let block_list = self.block_list.lock().await;
        if block_list.contains(&ip_addr) {
            return Err(
                BoxError::from("drop connection for blocked ip").context_field("ip_addr", ip_addr)
            );
        }
        std::mem::drop(block_list);
        self.inner.serve(stream).await.into_box_error()
    }
}
