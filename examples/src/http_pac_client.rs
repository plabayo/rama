//! An example to showcase how a client routes its requests through the
//! proxies a PAC script selects — and how to generate that script.
//!
//! Three servers run in-process: one serving a generated PAC script, one
//! standing in for a proxy, and one for the origin. The client fetches the
//! script once, evaluates `FindProxyForURL` per request, and connects
//! through whatever the script returned — including falling back to the
//! next proxy in the list when the first one is unreachable.
//!
//! The stand-in proxy answers requests itself instead of forwarding them,
//! so the response body tells you which path a request took.
//!
//! # Run the example
//!
//! ```sh
//! cargo run -p rama-examples --bin http_pac_client --features=pac
//! ```
//!
//! # Expected output
//!
//! ```text
//! proxied.example  -> from the proxy  (generated route said PROXY)
//! localhost        -> from the origin (generated route said DIRECT)
//! failover.example -> from the proxy  (first proxy down, second answered)
//! ```

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "example: panic-on-error is the standard pattern for demos"
)]

use std::sync::Arc;
use std::time::Duration;

use rama::{
    Layer, Service,
    error::BoxError,
    http::{
        Body, BodyExtractExt, Request, Response, client::EasyHttpWebClient, server::HttpServer,
    },
    js::pac::{
        FetchPacScript, PacDirective, PacDirectives, PacGenerator, PacProxyRoutesLayer,
        PacResolver, PacScript, PacScriptCacheLayer,
    },
    net::{
        address::{Domain, SocketAddress},
        uri::Uri,
    },
    rt::Executor,
    service::service_fn,
    tcp::server::TcpListener,
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
};

const PAC_ADDRESS: SocketAddress = SocketAddress::local_ipv4(63030);
const PROXY_ADDRESS: SocketAddress = SocketAddress::local_ipv4(63031);
const ORIGIN_ADDRESS: SocketAddress = SocketAddress::local_ipv4(63032);
/// nothing listens here, so the first choice has to fail over
const DEAD_ADDRESS: SocketAddress = SocketAddress::local_ipv4(63033);

const FROM_PROXY: &str = "from the proxy";
const FROM_ORIGIN: &str = "from the origin";

#[tokio::main]
async fn main() {
    tracing::subscriber::registry()
        .with(fmt::layer())
        .with(LevelFilter::INFO)
        .init();

    tokio::spawn(serve_body(ORIGIN_ADDRESS, FROM_ORIGIN));
    tokio::spawn(serve_body(PROXY_ADDRESS, FROM_PROXY));
    tokio::spawn(serve_pac_script(PAC_ADDRESS));
    tokio::time::sleep(Duration::from_millis(250)).await;

    let client = pac_client().await.unwrap();

    for (host, expected, note) in [
        ("proxied.example", FROM_PROXY, "generated route said PROXY"),
        // a DIRECT route is dialled locally, so this host must resolve
        ("localhost", FROM_ORIGIN, "generated route said DIRECT"),
        (
            "failover.example",
            FROM_PROXY,
            "first proxy down, second answered",
        ),
    ] {
        // a proxied host is never resolved locally (the proxy is dialled
        // instead), so the body proves which path the request took
        let uri = format!("http://{host}:{}/", ORIGIN_ADDRESS.port);
        let body = client
            .serve(Request::get(uri).body(Body::empty()).unwrap())
            .await
            .unwrap()
            .try_into_string()
            .await
            .unwrap();

        tracing::info!("{host:<17}-> {body:<16}({note})");
        assert_eq!(body, expected, "{host}");
    }
}

/// The client: PAC picks the routes, the connector tries them in order.
async fn pac_client() -> Result<impl Service<Request, Output = Response, Error = BoxError>, BoxError>
{
    let provider =
        PacScriptCacheLayer::new().into_layer(FetchPacScript::new(EasyHttpWebClient::default()));
    let script_uri: Uri = format!("http://{PAC_ADDRESS}/proxy.pac").parse()?;
    let resolver = Arc::new(PacResolver::builder().build(provider, script_uri)?);

    // the default client already carries a `ProxyRoutesConnector`, so the
    // routes this layer inserts are honoured without further wiring
    Ok(PacProxyRoutesLayer::new(resolver).into_layer(EasyHttpWebClient::default()))
}

/// The routing policy, expressed in typed rules rather than javascript.
fn pac_script() -> PacScript {
    let proxy = PacDirective::proxy(PROXY_ADDRESS);
    let dead = PacDirective::proxy(DEAD_ADDRESS);

    PacGenerator::new()
        .with_route(PacDirectives::direct(), [Domain::from_static("localhost")])
        // the dead proxy is tried first, so the connector has to fail over
        .with_route(
            PacDirectives::new([dead, proxy.clone()]),
            [Domain::from_static("failover.example")],
        )
        .with_default_route(PacDirectives::new([proxy, PacDirective::Direct]))
        .generate()
}

async fn serve_pac_script(address: SocketAddress) {
    let script = pac_script();
    tracing::info!("generated pac script:\n{}", script.as_str());

    serve(
        address,
        service_fn(move |_req: Request| {
            let script = script.as_str().to_owned();
            async move { Ok::<_, std::convert::Infallible>(Response::new(Body::from(script))) }
        }),
    )
    .await;
}

/// A server answering every request with the same body, whichever
/// request-target form it arrives in.
async fn serve_body(address: SocketAddress, body: &'static str) {
    serve(
        address,
        service_fn(move |_req: Request| async move {
            Ok::<_, std::convert::Infallible>(Response::new(Body::from(body)))
        }),
    )
    .await;
}

async fn serve<S>(address: SocketAddress, service: S)
where
    S: Service<Request, Output = Response, Error = std::convert::Infallible> + Clone,
{
    TcpListener::build(Executor::default())
        .bind_address(address)
        .await
        .expect("bind TCP listener")
        .serve(HttpServer::default().service(service))
        .await;
}
