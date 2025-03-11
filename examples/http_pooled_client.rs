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
    Context, Service,
    error::OpaqueError,
    http::{
        BodyExtractExt,
        client::HttpClient,
        server::HttpServer,
        service::{client::HttpClientExt, web::WebService},
    },
    net::client::Pool,
    rt::Executor,
    tcp::server::TcpListener,
};

// Everything else we need is provided by the standard library, community crates or tokio.

use std::{
    sync::{Arc, atomic::AtomicU16},
    time::Duration,
};
use tokio::time::sleep;
use tokio_test::assert_err;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};

const ADDRESS: &str = "127.0.0.1:62024";

#[tokio::main]
async fn main() {
    setup_tracing();
    tokio::spawn(async move {
        run_server(ADDRESS).await;
    });

    // Give server time to start, we do this instead of retrying as we want all
    // errors to be given back to us and never retried internally.
    sleep(Duration::from_millis(10)).await;

    let client = HttpClient::default().with_connection_pool(Pool::default());

    let resp = client
        .get(format!("http://{ADDRESS}/"))
        .send(Context::default())
        .await
        .unwrap();

    let body = resp.try_into_string().await.unwrap();
    tracing::info!("body: {:?}", body);
    assert_eq!(body, "Hello, World!");

    // Server has a limit of one total connection. So this request will work if we reuse
    // an existing connection from the pool, and will fail if we would open a new one
    let _resp = client
        .get(format!("http://{ADDRESS}/"))
        .send(Context::default())
        .await
        .unwrap();

    // If we dont use a connection pool now we should get an error from the server as we
    // will need to open a new connection
    let client = client.without_connection_pool();
    let result = client
        .get(format!("http://{ADDRESS}/"))
        .send(Context::default())
        .await;

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

async fn run_server(addr: &str) {
    tracing::info!("running service at: {addr}");
    let exec = Executor::default();

    let http_service =
        HttpServer::auto(exec).service(WebService::default().get("/", "Hello, World!"));

    TcpListener::build()
        .bind(addr)
        .await
        .expect("bind TCP Listener")
        .serve(LimitedConnections {
            inner: http_service,
            conns: Default::default(),
            max_conns: 1,
        })
        .await;
}

/// [`LimitedConnections`] will keep track of total connection (not "active" connections) seen
/// by the server and will stop working once conns >= max_conns
struct LimitedConnections<S> {
    inner: S,
    max_conns: u16,
    conns: Arc<AtomicU16>,
}

impl<State, Request, S> Service<State, Request> for LimitedConnections<S>
where
    S: Service<State, Request>,
    State: Clone + Send + Sync + 'static,
    Request: Send + 'static,
{
    type Response = S::Response;

    type Error = OpaqueError;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> Result<Self::Response, Self::Error> {
        let conns = self.conns.load(std::sync::atomic::Ordering::Acquire);
        if conns >= self.max_conns {
            return Err(OpaqueError::from_display("Exceeded max connections"));
        }

        self.conns.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        match self.inner.serve(ctx, req).await {
            Ok(resp) => Ok(resp),
            Err(_) => Err(OpaqueError::from_display("Internal error")),
        }
    }
}
