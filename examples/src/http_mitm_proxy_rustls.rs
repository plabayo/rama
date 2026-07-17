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
//! cargo run -p rama-examples --bin http_mitm_proxy_rustls --features=http-full,rustls,aws-lc
//! ```
//!
//! or if you prefer ring instead:
//!
//! ```sh
//! cargo run -p rama-examples --bin http_mitm_proxy_rustls --features=http-full,rustls,ring
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

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "example/test/bench: panic-on-error and print-for-output are the standard patterns for demos and harnesses"
)]

use rama::{
    Layer, Service,
    error::{BoxError, ErrorContext},
    extensions::{Extension, ExtensionsRef},
    http::{
        Body, BodyLimitLayer, Request, Response, StatusCode, Version,
        client::EasyHttpWebClient,
        layer::{
            compression::{CompressionLayer, MirrorDecompressed},
            decompression::DecompressionLayer,
            map_response_body::MapResponseBodyLayer,
            proxy_auth::ProxyAuthLayer,
            remove_header::{RemoveRequestHeaderLayer, RemoveResponseHeaderLayer},
            required_header::AddRequiredRequestHeadersLayer,
            trace::TraceLayer,
            upgrade::{DefaultHttpProxyConnectReplyService, UpgradeLayer, Upgraded},
        },
        matcher::MethodMatcher,
        server::HttpServer,
    },
    layer::{AddInputExtensionLayer, ConsumeErrLayer},
    net::user::credentials::basic,
    rt::Executor,
    service::service_fn,
    tcp::server::TcpListener,
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
    tls::KeyLogIntent,
    tls::client::{ServerVerifyMode, TlsClientConfig},
    tls::rustls::server::TlsAcceptorLayer,
    tls::server::{SelfSignedData, TlsServerConfig},
    utils::octets::mib,
};

use std::{convert::Infallible, sync::Arc, time::Duration};

#[derive(Debug, Clone, Extension)]
struct State {
    mitm_tls_service_data: TlsServerConfig,
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

    let mitm_tls_service_data = new_mitm_tls_service_data();

    let graceful = rama::graceful::Shutdown::default();

    let exec = Executor::graceful(graceful.guard());
    let state = State {
        mitm_tls_service_data,
        exec: exec.clone(),
    };

    graceful.spawn_task(async {
        let tcp_service = TcpListener::build(exec.clone())
            .bind_address("127.0.0.1:62019")
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
                    DefaultHttpProxyConnectReplyService::new(),
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
                    BodyLimitLayer::symmetric(mib(2)),
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

async fn http_connect_proxy(upgraded: Upgraded) -> Result<(), BoxError> {
    let http_service = new_http_mitm_proxy();

    let state = upgraded.extensions().get_ref::<State>().unwrap();

    let executor = state.exec.clone();
    let http_transport_service = HttpServer::auto(executor).service(http_service);

    let https_service = TlsAcceptorLayer::new(state.mitm_tls_service_data.clone())
        .with_store_client_hello(true)
        .into_layer(http_transport_service);

    // The upgrade handler may return an error: it is routed to the
    // `UpgradeLayer`'s error sink (tracing at DEBUG by default) instead of
    // being coerced to `Infallible` with `.expect(..)`.
    https_service.serve(upgraded).await?;

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
            // A MITM proxy relays whatever `Accept-Encoding` the client sends; it must not turn an
            // unsatisfiable negotiation into its own 406, so opt out of that enforcement.
            CompressionLayer::new()
                .with_compress_predicate(MirrorDecompressed::new())
                .with_enforce_not_acceptable(false),
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
    let tls_config = TlsClientConfig::default_http().with_server_verify(ServerVerifyMode::Disable);

    let state = req.extensions().get_ref::<State>().unwrap();
    let executor = state.exec.clone();

    let client = EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .with_default_dns_connector()
        .with_tls_proxy_support_using_rustls()
        .with_proxy_support()
        .with_tls_support_using_rustls_and_default_http_version(tls_config, Version::HTTP_11)
        .with_default_http_connector(executor)
        .build_client();

    let client = (
        MapResponseBodyLayer::new_boxed_streaming_body(),
        // A MITM proxy decodes the upstream body to (potentially) inspect/rewrite it; a truncated
        // upstream response should end the client stream cleanly rather than surface a decode error.
        DecompressionLayer::new()
            .with_insert_accept_encoding_header(false)
            .with_tolerate_decode_errors(true),
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
fn new_mitm_tls_service_data() -> TlsServerConfig {
    TlsServerConfig::new()
        .try_with_self_signed(SelfSignedData {
            organisation_name: Some("Example Server Acceptor".to_owned()),
            ..Default::default()
        })
        .expect("self-signed")
        .with_alpn_http_auto()
        .with_keylog(KeyLogIntent::Environment)
}
