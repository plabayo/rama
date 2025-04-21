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
    error::{BoxError, ErrorContext, OpaqueError},
    http::layer::compress_adapter::CompressAdaptLayer,
    http::{
        Body, IntoResponse, Request, Response, StatusCode,
        client::{EasyHttpWebClient, TlsConnectorConfig},
        layer::{
            map_response_body::MapResponseBodyLayer,
            proxy_auth::ProxyAuthLayer,
            remove_header::{RemoveRequestHeaderLayer, RemoveResponseHeaderLayer},
            required_header::AddRequiredRequestHeadersLayer,
            trace::TraceLayer,
            upgrade::{UpgradeLayer, Upgraded},
        },
        matcher::MethodMatcher,
        server::HttpServer,
    },
    layer::ConsumeErrLayer,
    net::{
        http::RequestContext, stream::layer::http::BodyLimitLayer, tls::server::SelfSignedData,
        user::Basic,
    },
    rt::Executor,
    service::service_fn,
    tcp::server::TcpListener,
    tls::rustls::{
        client::TlsConnectorDataBuilder,
        server::{TlsAcceptorData, TlsAcceptorDataBuilder, TlsAcceptorLayer},
    },
};

use std::{convert::Infallible, time::Duration};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug, Clone)]
struct State {
    mitm_tls_service_data: TlsAcceptorData,
}

type Context = rama::Context<State>;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let mitm_tls_service_data =
        new_mitm_tls_service_data().context("generate self-signed mitm tls cert")?;

    let state = State {
        mitm_tls_service_data,
    };

    let graceful = rama::graceful::Shutdown::default();

    graceful.spawn_task_fn(async |guard| {
        let tcp_service = TcpListener::build_with_state(state)
            .bind("127.0.0.1:62019")
            .await
            .expect("bind tcp proxy to 127.0.0.1:62019");

        let exec = Executor::graceful(guard.clone());
        let http_mitm_service = new_http_mitm_proxy();
        let http_service = HttpServer::auto(exec).service(
            (
                TraceLayer::new_for_http(),
                // See [`ProxyAuthLayer::with_labels`] for more information,
                // e.g. can also be used to extract upstream proxy filters
                ProxyAuthLayer::new(Basic::new("john", "secret")),
                UpgradeLayer::new(
                    MethodMatcher::CONNECT,
                    service_fn(http_connect_accept),
                    service_fn(http_connect_proxy),
                ),
            )
                .into_layer(http_mitm_service),
        );

        tcp_service
            .serve_graceful(
                guard,
                (
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

async fn http_connect_accept(
    mut ctx: Context,
    req: Request,
) -> Result<(Response, Context, Request), Response> {
    match ctx.get_or_try_insert_with_ctx::<RequestContext, _>(|ctx| (ctx, &req).try_into()) {
        Ok(request_ctx) => {
            tracing::info!("accept CONNECT to {}", request_ctx.authority);
        }
        Err(err) => {
            tracing::error!(err = %err, "error extracting authority");
            return Err(StatusCode::BAD_REQUEST.into_response());
        }
    }

    Ok((StatusCode::OK.into_response(), ctx, req))
}

async fn http_connect_proxy(ctx: Context, upgraded: Upgraded) -> Result<(), Infallible> {
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

    let http_transport_service = HttpServer::auto(ctx.executor().clone()).service(http_service);

    let https_service = TlsAcceptorLayer::new(ctx.state().mitm_tls_service_data.clone())
        .with_store_client_hello(true)
        .into_layer(http_transport_service);

    https_service
        .serve(ctx, upgraded)
        .await
        .expect("infallible");

    Ok(())
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
    let mut client = EasyHttpWebClient::default();

    let data = TlsConnectorDataBuilder::new()
        .with_no_cert_verifier()
        .with_alpn_protocols_http_auto()
        .with_env_key_logger()
        .expect("with env key logger")
        .build();

    client.set_tls_connector_config(TlsConnectorConfig::Rustls(Some(data)));

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
    let data = TlsAcceptorDataBuilder::new_self_signed(SelfSignedData {
        organisation_name: Some("Example Server Acceptor".to_owned()),
        ..Default::default()
    })
    .context("self signed builder")?
    .with_alpn_protocols_http_auto()
    .with_env_key_logger()
    .context("with env key logger")?
    .build();

    Ok(data)
}
