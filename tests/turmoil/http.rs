use std::time::Duration;

use rama::{
    Layer, Service,
    error::ErrorContext,
    http::{
        Body, BodyExtractExt, Request, Version, client::EasyHttpWebClient,
        layer::trace::TraceLayer, server::HttpServer, service::web::WebService,
    },
    net::address::SocketAddress,
    rt::Executor,
    telemetry::tracing::subscriber::{
        self, EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt,
    },
};

use turmoil::{Builder, ToSocketAddrs};

use crate::{stream::TcpStream, types::TurmoilTcpConnector};

const ADDRESS: SocketAddress = SocketAddress::default_ipv4(62004);

fn setup_tracing() {
    subscriber::registry()
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
    let conn = TcpStream::new(conn);

    let server = HttpServer::http1(Executor::default());
    server
        .serve(
            conn,
            TraceLayer::new_for_http()
                .into_layer(WebService::default().with_get("/", "Hello, World")),
        )
        .await
        .expect("serving endpoint");
    Ok(())
}

async fn run_client(address: impl Into<SocketAddress>) -> Result<(), Box<dyn std::error::Error>> {
    let client = TraceLayer::new_for_http().into_layer(
        EasyHttpWebClient::connector_builder()
            .with_custom_transport_connector(TurmoilTcpConnector)
            .without_tls_proxy_support()
            .without_proxy_support()
            .without_tls_support()
            .with_default_http_connector(Executor::default())
            .build_client(),
    );

    let resp = client
        .serve(
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

    sim.host(ADDRESS.ip_addr, || start_server(ADDRESS.to_string()));

    sim.client("client", run_client(ADDRESS));

    sim.run().expect("Error during simulation");
}
