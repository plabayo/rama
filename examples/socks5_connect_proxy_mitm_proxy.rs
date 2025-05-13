//! An example to showcase how one can build an authenticated socks5 CONNECT proxy server,
//! which is built to MITM http(s) traffic. The MITM part is very similar to
//! the "http_mitm_proxy_boring.rs" example.
//!
//! TODO: change this example to make use of AutoTlsAcceptor logic once possible,
//! as for now that is not a thing that rama offers. Meaning for now it can only do
//! out of the box either always TLS or never tls. You can of course implement your own
//! wrapper service already in case you need it more urgent than we provide it.
//!
//! > Tracked as <https://github.com/plabayo/rama/issues/547>
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example socks5_connect_proxy_mitm_proxy --features=dns,socks5,http-full
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62022`. You can use `curl` to interact with the service:
//!
//! ```sh
//! curl -v -x socks5://127.0.0.1:62022 --proxy-user 'john:secret' http://www.example.com/
//! curl -v -x socks5h://127.0.0.1:62022 --proxy-user 'john:secret' http://www.example.com/
//! ```
//!
//! > NOTE: no tls traffic for now, see _TODO_ above.
//!
//! You should see in all the above examples the responses from the server.

use http::StatusCode;
use rama::{
    Context, Layer, Service,
    http::{
        Body, Request, Response,
        client::EasyHttpWebClient,
        layer::{
            compress_adapter::CompressAdaptLayer,
            map_response_body::MapResponseBodyLayer,
            remove_header::{RemoveRequestHeaderLayer, RemoveResponseHeaderLayer},
            required_header::AddRequiredRequestHeadersLayer,
            trace::TraceLayer,
            traffic_writer::{self, RequestWriterInspector},
        },
        server::HttpServer,
        service::web::response::IntoResponse,
    },
    layer::ConsumeErrLayer,
    proxy::socks5::{Socks5Acceptor, Socks5Auth, server::LazyConnector},
    rt::Executor,
    service::service_fn,
    tcp::server::TcpListener,
};

use std::{convert::Infallible, time::Duration};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let graceful = rama::graceful::Shutdown::default();

    let http_mitm_service = new_http_mitm_proxy();
    let http_service =
        HttpServer::auto(Executor::graceful(graceful.guard())).service(http_mitm_service);

    let tcp_service = TcpListener::bind("127.0.0.1:62022")
        .await
        .expect("bind proxy to 127.0.0.1:62022");
    let socks5_acceptor = Socks5Acceptor::new()
        .with_auth(Socks5Auth::username_password("john", "secret"))
        .with_connector(LazyConnector::new(http_service));
    graceful.spawn_task_fn(|guard| tcp_service.serve_graceful(guard, socks5_acceptor));

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}

fn new_http_mitm_proxy() -> impl Service<(), Request, Response = Response, Error = Infallible> {
    (
        MapResponseBodyLayer::new(Body::new),
        TraceLayer::new_for_http(),
        ConsumeErrLayer::default(),
        RemoveResponseHeaderLayer::hop_by_hop(),
        RemoveRequestHeaderLayer::hop_by_hop(),
        CompressAdaptLayer::default(),
        AddRequiredRequestHeadersLayer::new(),
    )
        .into_layer(service_fn(http_mitm_proxy))
}

async fn http_mitm_proxy(ctx: Context<()>, req: Request) -> Result<Response, Infallible> {
    // This function will receive all requests going through this proxy,
    // be it sent via HTTP or HTTPS, both are equally visible. Hence... MITM

    // NOTE: use a custom connector (layers) in case you wish to add custom features,
    // such as upstream proxies or other configurations
    let client = EasyHttpWebClient::default().with_http_conn_req_inspector((
        // these layers are for example purposes only,
        // best not to print requests like this in production...
        //
        // If you want to see the request that actually is send to the server
        // you also usually do not want it as a layer, but instead plug the inspector
        // directly JIT-style into your http (client) connector.
        RequestWriterInspector::stdout_unbounded(
            ctx.executor(),
            Some(traffic_writer::WriterMode::Headers),
        ),
    ));

    match client.serve(ctx, req).await {
        Ok(resp) => Ok(resp),
        Err(err) => {
            tracing::error!(error = ?err, "error in client request");
            Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
    }
}
