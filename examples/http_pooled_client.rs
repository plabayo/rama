//! This example demonstrates how use a connection pool when working with the httpClient
//!
//! ```sh
//! cargo run --example http_pooled_client --features=http-full
//! ```
//!
//! # Expected output
//!
//! You should see a new connection open for the first request and the request succeeded.
//! Then you should see the second request complete, but without opening a new connection,
//! because we are re-using a connection from the pool. Finally we disable the pool and now
//! we should see the request failing because we open a connection while the server only excepts
//! one connection over it's entire lifespan.

// rama provides everything out of the box to build a complete web service.

use rama::{
    Layer,
    error::OpaqueError,
    http::{
        BodyExtractExt,
        client::EasyHttpWebClient,
        server::HttpServer,
        service::{client::HttpClientExt, web::WebService},
    },
    layer::{
        LimitLayer,
        limit::{Policy, PolicyOutput, policy::PolicyResult},
    },
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing::{self, level_filters::LevelFilter},
};

// Everything else we need is provided by the standard library, community crates or tokio.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::{sync::oneshot::Sender, sync::oneshot::channel};
use tokio_test::assert_err;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};

const ADDRESS: &str = "127.0.0.1:62024";

#[tokio::main]
async fn main() {
    setup_tracing();
    let (ready_tx, ready_rx) = channel();
    tokio::spawn(run_server(ADDRESS, ready_tx));
    ready_rx.await.unwrap();

    let client = EasyHttpWebClient::builder()
        .with_default_transport_connector()
        .without_tls_proxy_support()
        .with_proxy_support()
        .without_tls_support()
        .with_connection_pool(Default::default())
        .expect("connection pool")
        .build();

    let resp = client
        .get(format!("http://{ADDRESS}/"))
        .send()
        .await
        .unwrap();

    let body = resp.try_into_string().await.unwrap();
    tracing::info!("body: {body}");
    assert_eq!(body, "Hello, World!");

    // Server has a limit of one total connection. So this request will work if we reuse
    // an existing connection from the pool, and will fail if we would open a new one
    let _resp = client
        .get(format!("http://{ADDRESS}/"))
        .send()
        .await
        .unwrap();

    // If we dont use a connection pool now we should get an error from the server as we
    // will need to open a new connection
    let client = EasyHttpWebClient::default();
    let result = client.get(format!("http://{ADDRESS}/")).send().await;

    assert_err!(result);
}

fn setup_tracing() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .init();
}

async fn run_server(addr: &str, ready: Sender<()>) {
    tracing::info!("running service at: {addr}");
    let exec = Executor::default();

    let http_service =
        HttpServer::auto(exec).service(WebService::default().get("/", "Hello, World!"));

    let serve = TcpListener::build()
        .bind(addr)
        .await
        .expect("bind TCP Listener")
        .serve(LimitLayer::new(FirstConnOnly::new()).into_layer(http_service));

    ready.send(()).unwrap();
    serve.await;
}

#[derive(Clone)]
/// Policy for limit layer that will only allow the first connection to succeed
struct FirstConnOnly(Arc<AtomicBool>);

impl FirstConnOnly {
    fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }
}

impl<Request> Policy<Request> for FirstConnOnly
where
    Request: Send + 'static,
{
    type Guard = ();

    type Error = OpaqueError;

    async fn check(&self, request: Request) -> PolicyResult<Request, Self::Guard, Self::Error> {
        let output = match !self.0.swap(true, Ordering::AcqRel) {
            true => PolicyOutput::Ready(()),
            false => PolicyOutput::Abort(OpaqueError::from_display(
                "Only first connection is allowed",
            )),
        };
        PolicyResult { request, output }
    }
}
