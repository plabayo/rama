use rama::{
    http::{
        client::EasyHttpWebClient, layer::trace::TraceLayer, server::HttpServer,
        service::web::WebService, Body, BodyExtractExt, Request,
    },
    net::address::SocketAddress,
    Context, Layer, Service,
};
use rama_http_backend::client::EasyHttpWebClientBuilder;
use tracing_subscriber::{
    filter::LevelFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter,
};
use turmoil::Builder;

use crate::types::TurmoilTcpConnector;

const ADDRESS: SocketAddress = SocketAddress::default_ipv4(62004);

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

async fn start_server(
    address: impl Into<SocketAddress>,
) -> Result<(), Box<dyn std::error::Error + 'static>> {
    let s: SocketAddress = address.into();
    let addr = s.to_string();

    let listener = turmoil::net::TcpListener::bind(addr).await?;

    let (conn, _) = listener.accept().await?;

    let server = HttpServer::http1();
    server
        .serve(
            Context::default(),
            conn,
            TraceLayer::new_for_http().into_layer(WebService::default().get("/", "Hello, World")),
        )
        .await
        .unwrap();
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

    //let client = EasyHttpWebClientBuilder::default().with_custom_transport_connector(connector)
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
    let body = resp.try_into_string().await.unwrap();
    assert_eq!(body, "Hello, World");
    Ok(())
}

#[test]
fn http_1_client_server_it() {
    setup_tracing();

    let mut sim = Builder::new().enable_tokio_io().build();

    sim.host(ADDRESS.ip_addr(), || start_server(ADDRESS));

    sim.client("client", run_client(ADDRESS));

    sim.run().expect("Error during simulation");
}
