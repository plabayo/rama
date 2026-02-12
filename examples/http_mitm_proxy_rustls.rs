//! This example shows how one can begin with creating a MITM proxy.
//!
//! Note that this MITM proxy is not production ready, and is only meant
//! to show you how one might start. You might want to address the following:
//!
//! - Load in your tls mitm cert/key pair from file or ACME
//! - Make sure your clients trust the MITM cert
//! - Do not enforce the Application protocol and instead convert requests when needed,
//!   e.g. in this example we _always_ map the protocol between two ends,
//!   even though it might be better to be able to map bidirectionaly between http versions
//! - ... and much more
//!
//! That said for basic usage it does work and should at least give you an idea on how to get started.
//!
//! It combines concepts that can seen in action separately in the following examples:
//!
//! - [`http_connect_proxy`](./http_connect_proxy.rs);
//! - [`tls_rustls_termination`](./tls_rustls_termination.rs);
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example http_mitm_proxy_rustls --features=http-full,rustls
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62019`. You can use `curl` to interact with the service:
//!
//! ```sh
//! curl -v -x http://127.0.0.1:62019 --proxy-user 'john:secret' http://www.example.com/
//! curl -k -v -x http://127.0.0.1:62019 --proxy-user 'john:secret' https://www.example.com/
//! ```

use rama::{
    Layer, Service,
    error::{BoxError, ErrorContext},
    extensions::{ExtensionsMut, ExtensionsRef},
    http::{
        Body, Request, Response, StatusCode, Version,
        client::EasyHttpWebClient,
        layer::{
            compression::CompressionLayer,
            decompression::DecompressionLayer,
            map_response_body::MapResponseBodyLayer,
            proxy_auth::ProxyAuthLayer,
            remove_header::{RemoveRequestHeaderLayer, RemoveResponseHeaderLayer},
            required_header::AddRequiredRequestHeadersLayer,
            trace::TraceLayer,
            upgrade::{UpgradeLayer, Upgraded},
        },
        matcher::MethodMatcher,
        server::HttpServer,
        service::web::response::IntoResponse,
    },
    layer::{AddInputExtensionLayer, ConsumeErrLayer},
    net::{
        http::RequestContext, proxy::ProxyTarget, stream::layer::http::BodyLimitLayer,
        tls::server::SelfSignedData, user::credentials::basic,
    },
    rt::Executor,
    service::service_fn,
    tcp::server::TcpListener,
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
    tls::rustls::{
        client::TlsConnectorDataBuilder,
        server::{TlsAcceptorData, TlsAcceptorDataBuilder, TlsAcceptorLayer},
    },
};

use std::{convert::Infallible, sync::Arc, time::Duration};

#[derive(Debug, Clone)]
struct State {
    mitm_tls_service_data: TlsAcceptorData,
    exec: Executor,
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    tracing::subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let mitm_tls_service_data =
        try_new_mitm_tls_service_data().context("generate self-signed mitm tls cert")?;

    let graceful = rama::graceful::Shutdown::default();

    let exec = Executor::graceful(graceful.guard());
    let state = State {
        mitm_tls_service_data,
        exec: exec.clone(),
    };

    graceful.spawn_task(async {
        let tcp_service = TcpListener::build(exec.clone())
            .bind("127.0.0.1:62019")
            .await
            .expect("bind tcp proxy to 127.0.0.1:62019");

        let http_mitm_service = new_http_mitm_proxy();
        let http_service = HttpServer::auto(exec.clone()).service(Arc::new(
            (
                TraceLayer::new_for_http(),
                ConsumeErrLayer::default(),
                // See [`ProxyAuthLayer::with_labels`] for more information,
                // e.g. can also be used to extract upstream proxy filters
                ProxyAuthLayer::new(basic!("john", "secret")),
                UpgradeLayer::new(
                    exec,
                    MethodMatcher::CONNECT,
                    service_fn(http_connect_accept),
                    service_fn(http_connect_proxy),
                ),
            )
                .into_layer(http_mitm_service),
        ));

        tcp_service
            .serve(
                (
                    AddInputExtensionLayer::new(state),
                    // protect the http proxy from too large bodies, both from request and response end
                    BodyLimitLayer::symmetric(2 * 1024 * 1024),
                )
                    .into_layer(http_service),
            )
            .await;
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .context("graceful shutdown")?;

    Ok(())
}

async fn http_connect_accept(mut req: Request) -> Result<(Response, Request), Response> {
    match RequestContext::try_from(&req).map(|ctx| ctx.host_with_port()) {
        Ok(authority) => {
            tracing::info!(
                server.address = %authority.host,
                server.port = authority.port,
                "accept CONNECT (lazy): insert proxy target into context",
            );
            req.extensions_mut().insert(ProxyTarget(authority));
        }
        Err(err) => {
            tracing::error!("error extracting authority: {err:?}");
            return Err(StatusCode::BAD_REQUEST.into_response());
        }
    }

    Ok((StatusCode::OK.into_response(), req))
}

async fn http_connect_proxy(upgraded: Upgraded) -> Result<(), Infallible> {
    // In the past we deleted the request context here, as such:
    // ```
    // ctx.remove::<RequestContext>();
    // ```
    // This is however not correct, as the request context remains true.
    // The user proxies here with a target as aim. This target, incoming version
    // and so on does not change. This initial context remains true
    // and should be preserved. This is especially important,
    // as we otherwise might not be able to define the scheme/authority
    // for upstream http requests.

    let http_service = new_http_mitm_proxy();

    let state = upgraded.extensions().get::<State>().unwrap();

    let executor = state.exec.clone();
    let http_transport_service = HttpServer::auto(executor).service(http_service);

    let https_service = TlsAcceptorLayer::new(state.mitm_tls_service_data.clone())
        .with_store_client_hello(true)
        .into_layer(http_transport_service);

    https_service.serve(upgraded).await.expect("infallible");

    Ok(())
}

fn new_http_mitm_proxy() -> impl Service<Request, Output = Response, Error = Infallible> + Clone {
    Arc::new(
        (
            MapResponseBodyLayer::new_boxed_streaming_body(),
            TraceLayer::new_for_http(),
            ConsumeErrLayer::default(),
            RemoveResponseHeaderLayer::hop_by_hop(),
            RemoveRequestHeaderLayer::hop_by_hop(),
            CompressionLayer::new(),
            AddRequiredRequestHeadersLayer::new(),
        )
            .into_layer(service_fn(http_mitm_proxy)),
    )
}

async fn http_mitm_proxy(req: Request) -> Result<Response, Infallible> {
    // This function will receive all requests going through this proxy,
    // be it sent via HTTP or HTTPS, both are equally visible. Hence... MITM

    // NOTE: use a custom connector (layers) in case you wish to add custom features,
    // such as upstream proxies or other configurations
    let tls_config = TlsConnectorDataBuilder::new()
        .with_alpn_protocols_http_auto()
        .try_with_env_key_logger()
        .expect("with env keylogger")
        .with_no_cert_verifier()
        .build();

    let state = req.extensions().get::<State>().unwrap();
    let executor = state.exec.clone();

    let client = EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .with_tls_proxy_support_using_rustls()
        .with_proxy_support()
        .with_tls_support_using_rustls_and_default_http_version(Some(tls_config), Version::HTTP_11)
        .with_default_http_connector(executor)
        .build_client();

    let client = (
        MapResponseBodyLayer::new_boxed_streaming_body(),
        DecompressionLayer::new(),
    )
        .into_layer(client);

    match client.serve(req).await {
        Ok(resp) => Ok(resp),
        Err(err) => {
            tracing::error!("error in client request: {err:?}");
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
fn try_new_mitm_tls_service_data() -> Result<TlsAcceptorData, BoxError> {
    let data = TlsAcceptorDataBuilder::try_new_self_signed(SelfSignedData {
        organisation_name: Some("Example Server Acceptor".to_owned()),
        ..Default::default()
    })
    .context("self signed builder")?
    .with_alpn_protocols_http_auto()
    .try_with_env_key_logger()
    .context("with env key logger")?
    .build();

    Ok(data)
}
