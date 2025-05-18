//! An example to showcase how one can build an authenticated socks5 CONNECT proxy server,
//! which is built to MITM http(s) traffic. The MITM part is very similar to
//! the "http_mitm_proxy_boring.rs" example.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example socks5_connect_proxy_mitm_proxy --features=dns,socks5,boring,http-full
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62022`. You can use `curl` to interact with the service:
//!
//! ```sh
//! curl -v -x socks5://127.0.0.1:62022 --proxy-user 'john:secret' http://www.example.com/
//! curl -v -x socks5h://127.0.0.1:62022 --proxy-user 'john:secret' http://www.example.com/
//! curl -k -v -x socks5://127.0.0.1:62022 --proxy-user 'john:secret' https://www.example.com/
//! curl -k -v -x socks5h://127.0.0.1:62022 --proxy-user 'john:secret' https://www.example.com/
//! ```
//!
//! You should see in all the above examples the responses from the server.

use rama::{
    Layer, Service,
    error::{ErrorContext, OpaqueError},
    http::{
        Body, Request, Response, StatusCode,
        client::{EasyHttpWebClient, TlsConnectorConfig},
        layer::{
            compress_adapter::CompressAdaptLayer,
            map_response_body::MapResponseBodyLayer,
            remove_header::{RemoveRequestHeaderLayer, RemoveResponseHeaderLayer},
            required_header::AddRequiredRequestHeadersLayer,
            trace::TraceLayer,
            traffic_writer::{self, RequestWriterInspector},
        },
        server::HttpServer,
    },
    layer::ConsumeErrLayer,
    net::tls::{
        ApplicationProtocol, SecureTransport,
        client::{
            ClientConfig, ClientHelloExtension, ServerVerifyMode, extract_client_config_from_ctx,
        },
        server::{SelfSignedData, ServerAuth, ServerConfig, TlsPeekRouter},
    },
    proxy::socks5::{Socks5Acceptor, Socks5Auth, server::LazyConnector},
    rt::Executor,
    service::service_fn,
    tcp::server::TcpListener,
    tls::boring::server::{TlsAcceptorData, TlsAcceptorLayer},
};

use std::{convert::Infallible, time::Duration};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

type State = ();
type Context = rama::Context<State>;

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

    let mitm_tls_service_data =
        new_mitm_tls_service_data().expect("generate self-signed mitm tls cert");

    let graceful = rama::graceful::Shutdown::default();

    let http_mitm_service = new_http_mitm_proxy();
    let http_service =
        HttpServer::auto(Executor::graceful(graceful.guard())).service(http_mitm_service);
    let https_service = TlsAcceptorLayer::new(mitm_tls_service_data)
        .with_store_client_hello(true)
        .into_layer(http_service.clone());

    let auto_https_service = TlsPeekRouter::new(https_service).with_fallback(http_service);

    let tcp_service = TcpListener::bind("127.0.0.1:62022")
        .await
        .expect("bind proxy to 127.0.0.1:62022");
    let socks5_acceptor = Socks5Acceptor::new()
        .with_auth(Socks5Auth::username_password("john", "secret"))
        .with_connector(LazyConnector::new(auto_https_service));
    graceful.spawn_task_fn(|guard| tcp_service.serve_graceful(guard, socks5_acceptor));

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}

fn new_http_mitm_proxy() -> impl Service<State, Request, Response = Response, Error = Infallible> {
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

async fn http_mitm_proxy(ctx: Context, req: Request) -> Result<Response, Infallible> {
    // This function will receive all requests going through this proxy,
    // be it sent via HTTP or HTTPS, both are equally visible. Hence... MITM

    // NOTE: use a custom connector (layers) in case you wish to add custom features,
    // such as upstream proxies or other configurations
    let mut client = EasyHttpWebClient::default().with_http_conn_req_inspector(
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
    );

    let mut base_tls_cfg = ctx
        .get::<SecureTransport>()
        .and_then(|st| st.client_hello())
        .cloned()
        .map(Into::into)
        .unwrap_or_else(|| ClientConfig {
            extensions: Some(vec![
                ClientHelloExtension::ApplicationLayerProtocolNegotiation(vec![
                    ApplicationProtocol::HTTP_2,
                    ApplicationProtocol::HTTP_11,
                ]),
            ]),
            ..Default::default()
        });
    base_tls_cfg.server_verify_mode = Some(ServerVerifyMode::Disable);

    // TODO: this tls stack API needs to be easier and more performant; but especially less messy

    let tls_client_config = match extract_client_config_from_ctx(&ctx) {
        Some(chain) => {
            let mut cfg = base_tls_cfg;
            for other_cfg in chain.iter() {
                cfg.merge(other_cfg.clone());
            }
            cfg
        }
        None => base_tls_cfg,
    };

    client.set_tls_connector_config(TlsConnectorConfig::Boring(Some(tls_client_config)));

    match client.serve(ctx, req).await {
        Ok(resp) => Ok(resp),
        Err(err) => {
            tracing::error!(error = ?err, "error in client request");
            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .unwrap())
        }
    }
}

// NOTE: for a production service you ideally use
// an issued TLS cert (if possible via ACME). Or at the very least
// load it in from memory/file, so that your clients can install the certificate for trust.
fn new_mitm_tls_service_data() -> Result<TlsAcceptorData, OpaqueError> {
    let tls_server_config = ServerConfig {
        application_layer_protocol_negotiation: Some(vec![
            ApplicationProtocol::HTTP_2,
            ApplicationProtocol::HTTP_11,
        ]),
        ..ServerConfig::new(ServerAuth::SelfSigned(SelfSignedData {
            organisation_name: Some("Example Server Acceptor".to_owned()),
            ..Default::default()
        }))
    };
    tls_server_config
        .try_into()
        .context("create tls server config")
}
