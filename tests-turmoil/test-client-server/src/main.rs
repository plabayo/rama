use rama::{
    http::{
        client::EasyHttpWebClient, layer::trace::TraceLayer, server::HttpServer,
        service::web::WebService, Body, BodyExtractExt, Request,
    },
    net::address::SocketAddress,
    Context, Layer, Service,
};
use tracing::{info, info_span, Instrument};
use tracing_subscriber::{
    filter::LevelFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter,
};
use turmoil::Builder;

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
    HttpServer::http1()
        .listen(
            address.into(),
            (TraceLayer::new_for_http()).into_layer(WebService::default().get("/", "Hello, World")),
        )
        .await
        .map_err(|e| e as Box<dyn std::error::Error>)
}

async fn run_client(
    address: impl Into<SocketAddress>,
) -> Result<(), Box<dyn std::error::Error + 'static>> {
    let client = (TraceLayer::new_for_http(),).into_layer(EasyHttpWebClient::default());
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

fn main() {
    setup_tracing();
    let mut sim = Builder::new().enable_tokio_io().build();

    sim.host(ADDRESS.ip_addr(), || {
        start_server(ADDRESS).instrument(info_span!("server"))
    });

    sim.client(
        "client",
        run_client(ADDRESS).instrument(info_span!("client")),
    );

    sim.run().expect("Error during simulation");
}
