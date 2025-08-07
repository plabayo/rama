use std::time::Duration;

use http::Version;
use rama::{
    Context, Layer, Service,
    error::ErrorContext,
    http::{
        Body, BodyExtractExt, Request, client::EasyHttpWebClientBuilder, layer::trace::TraceLayer,
        server::HttpServer, service::web::WebService,
    },
    net::address::SocketAddress,
};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};
use turmoil::{Builder, ToSocketAddrs};

use crate::types::TurmoilTcpConnector;

const ADDRESS: SocketAddress = SocketAddress::default_ipv4(62004);

fn setup_tracing() {
    tracing_subscriber::registry()
        .with(fmt::layer().with_test_writer())
        .with(
            EnvFilter::try_from_env("RUST_LOG")
                .unwrap_or_else(|_| EnvFilter::new("turmoil=trace,info")),
        )
        .init();
}

async fn start_server(
    address: impl ToSocketAddrs,
) -> Result<(), Box<dyn std::error::Error + 'static>> {
    let listener = turmoil::net::TcpListener::bind(address).await?;

    let conn_result = tokio::time::timeout(Duration::from_secs(1), listener.accept())
        .await
        .context("accept timeout")?;

    let (conn, _) = conn_result?;

    let server = HttpServer::http1();
    server
        .serve(
            Context::default(),
            conn,
            TraceLayer::new_for_http().into_layer(WebService::default().get("/", "Hello, World")),
        )
        .await
        .expect("serving endpoint");
    Ok(())
}

async fn run_client(address: impl Into<SocketAddress>) -> Result<(), Box<dyn std::error::Error>> {
    let client = TraceLayer::new_for_http().into_layer(
        EasyHttpWebClientBuilder::default()
            .with_custom_transport_connector(TurmoilTcpConnector)
            .without_tls_proxy_support()
            .without_proxy_support()
            .without_tls_support()
            .build(),
    );

    let resp = client
        .serve(
            Context::default(),
            Request::builder()
                .uri(format!("http://{address}/", address = address.into()))
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    assert!(resp.status().is_success());
    assert_eq!(resp.version(), Version::HTTP_11);
    let body = resp.try_into_string().await.unwrap();
    assert_eq!(body, "Hello, World");
    Ok(())
}

#[test]
fn http_1_client_server_it() {
    setup_tracing();

    let mut sim = Builder::new().enable_tokio_io().build();

    sim.host(ADDRESS.ip_addr(), || start_server(ADDRESS.to_string()));

    sim.client("client", run_client(ADDRESS));

    sim.run().expect("Error during simulation");
}
