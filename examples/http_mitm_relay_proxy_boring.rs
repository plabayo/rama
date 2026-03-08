//! This example shows how one can begin with creating a MITM proxy,
//! using a relay approach. This in contrast to `http_mitm_proxy_boring`,
//! where the flow is rather linear, here the approach is to handshake more like a dance.
//!
//! It is as such a more complex flow, but the advantage is that your proxy's
//! TLS acceptor will mimic the certificate and server (TLS) settings from
//! the target and the http client (egress) will nicely be 1:1 tied
//! the ingress traffic and mirror it.
//!
//! Note that this proxy is not production ready, and is only meant
//! to show you how one might start.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example http_mitm_relay_proxy_boring --features=http-full,boring
//! ```
//!
//! ## Expected output
//!
//! The server will start and listen on `:62049`. You can use `curl` to interact with the service:
//!
//! ```sh
//! curl -v -x http://127.0.0.1:62049 --proxy-user 'john:secret' http://www.example.com/
//! curl -k -v -x http://127.0.0.1:62049 --proxy-user 'john:secret' https://www.example.com/
//! ```

use rama::{
    Layer, Service,
    error::{BoxError, ErrorContext},
    extensions::ExtensionsMut,
    http::{
        HeaderName, HeaderValue, Request, Response, StatusCode,
        client::EasyHttpWebClient,
        layer::{
            map_response_body::MapResponseBodyLayer,
            proxy_auth::ProxyAuthLayer,
            set_header::{SetRequestHeaderLayer, SetResponseHeaderLayer},
            trace::TraceLayer,
            upgrade::UpgradeLayer,
        },
        matcher::MethodMatcher,
        proxy::mitm::{DefaultErrorResponse, HttpMitmRelay},
        server::HttpServer,
        service::web::response::IntoResponse,
    },
    io::Io,
    layer::{ArcLayer, ConsumeErrLayer},
    net::{
        http::{RequestContext, server::HttpPeekRouter},
        proxy::{ProxyTarget, StreamForwardService},
        stream::layer::http::BodyLimitLayer,
        tls::server::{PeekTlsClientHelloService, SelfSignedData},
        user::credentials::basic,
    },
    rt::Executor,
    service::service_fn,
    tcp::{proxy::IoToProxyBridgeIoLayer, server::TcpListener},
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
    tls::boring::proxy::TlsMitmRelay,
};

use std::{convert::Infallible, sync::Arc, time::Duration};

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

    let graceful = rama::graceful::Shutdown::default();
    let exec = Executor::graceful(graceful.guard());

    let mitm_svc = new_mitm_svc(exec.clone()).context("build MITM service")?;

    graceful.spawn_task_fn(async move |guard| {
        let tcp_service = TcpListener::build(Executor::graceful(guard.clone()))
            .bind("127.0.0.1:62049")
            .await
            .expect("bind tcp proxy to 127.0.0.1:62049");

        let http_service = HttpServer::auto(exec).service(Arc::new(
            (
                TraceLayer::new_for_http(),
                ConsumeErrLayer::default(),
                // See [`ProxyAuthLayer::with_labels`] for more information,
                // e.g. can also be used to extract upstream proxy filters
                ProxyAuthLayer::new(basic!("john", "secret")),
                UpgradeLayer::new(
                    Executor::graceful(guard.clone()),
                    MethodMatcher::CONNECT,
                    service_fn(http_connect_accept),
                    mitm_svc,
                ),
                (
                    SetRequestHeaderLayer::overriding(
                        HeaderName::from_static("x-observed"),
                        HeaderValue::from_static("1"),
                    ),
                    SetResponseHeaderLayer::overriding(
                        HeaderName::from_static("x-proxy"),
                        HeaderValue::from_static(rama::utils::info::NAME),
                    ),
                    SetResponseHeaderLayer::overriding(
                        HeaderName::from_static("x-proxy-version"),
                        HeaderValue::from_static(rama::utils::info::VERSION),
                    ),
                ),
            )
                .into_layer(EasyHttpWebClient::default_with_executor(
                    Executor::graceful(guard),
                )),
        ));

        tcp_service
            .serve(BodyLimitLayer::symmetric(2 * 1024 * 1024).into_layer(http_service))
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

fn new_mitm_svc<Ingress: Io + Unpin + ExtensionsMut>(
    exec: Executor,
) -> Result<impl Service<Ingress, Output = (), Error = Infallible> + Clone, BoxError> {
    let http_mitm_relay = HttpMitmRelay::new(exec.clone()).with_http_middleware((
        ConsumeErrLayer::trace_as_debug().with_response(DefaultErrorResponse::new()),
        MapResponseBodyLayer::new_boxed_streaming_body(),
        TraceLayer::new_for_http(),
        SetRequestHeaderLayer::overriding(
            HeaderName::from_static("x-observed"),
            HeaderValue::from_static("1"),
        ),
        SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-proxy"),
            HeaderValue::from_static(rama::utils::info::NAME),
        ),
        SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-proxy-version"),
            HeaderValue::from_static(rama::utils::info::VERSION),
        ),
        ArcLayer::new(),
    ));
    let maybe_http_relay =
        HttpPeekRouter::new(http_mitm_relay).with_fallback(StreamForwardService::new());

    let tls_mitm_relay = TlsMitmRelay::try_new_with_cached_self_signed_issuer(&SelfSignedData {
        organisation_name: Some("HTTP MITM Relay Proxy Boring Example".to_owned()),
        ..Default::default()
    })
    .context("build TLS mitm relay")?;

    let app_mitm_layer =
        PeekTlsClientHelloService::new(tls_mitm_relay.into_layer(maybe_http_relay.clone()))
            .with_fallback(maybe_http_relay);

    Ok(Arc::new(
        (
            ConsumeErrLayer::trace_as_debug(),
            IoToProxyBridgeIoLayer::extension_proxy_target(exec),
        )
            .into_layer(app_mitm_layer),
    ))
}
