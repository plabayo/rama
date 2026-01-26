//! Http Test service for various purposes

use rama::{
    Service,
    combinators::Either,
    error::{BoxError, ErrorContext, OpaqueError},
    graceful::ShutdownGuard,
    http::{
        HeaderName, HeaderValue, Request,
        headers::exotic::XClacksOverhead,
        layer::{
            catch_panic::CatchPanicLayer, required_header::AddRequiredResponseHeadersLayer,
            set_header::SetResponseHeaderLayer, trace::TraceLayer,
        },
        matcher::HttpMatcher,
        server::HttpServer,
        service::web::{Router, response::IntoResponse},
    },
    layer::{
        ConsumeErrLayer, Layer, LimitLayer, TimeoutLayer,
        limit::policy::{ConcurrentPolicy, UnlimitedPolicy},
    },
    net::{socket::Interface, stream::layer::http::BodyLimitLayer, tls::ApplicationProtocol},
    rt::Executor,
    tcp::server::TcpListener,
    telemetry::tracing,
    tls::boring::server::TlsAcceptorLayer,
    utils::backoff::ExponentialBackoff,
};

use clap::Args;
use std::{convert::Infallible, sync::Arc, time::Duration};

use crate::utils::{http::HttpVersion, tls::try_new_server_config};

mod endpoint;

#[derive(Debug, Args)]
/// rama http test service
pub struct CliCommandHttpTest {
    /// the interface to bind to
    #[arg(long, default_value = "127.0.0.1:8080")]
    bind: Interface,

    #[arg(short = 'c', long, default_value_t = 0)]
    /// the number of concurrent connections to allow
    ///
    /// (0 = no limit)
    concurrent: usize,

    /// http version to serve FP Service from
    #[arg(long, default_value = "auto")]
    http_version: HttpVersion,

    #[arg(short = 't', long, default_value_t = 60.)]
    /// the timeout in seconds for each connection
    ///
    /// (<= 0.0 = no timeout)
    timeout: f64,

    #[arg(long, short = 's')]
    /// run service in secure mode (enable TLS)
    secure: bool,
}

/// run the rama http test service
pub async fn run(graceful: ShutdownGuard, cfg: CliCommandHttpTest) -> Result<(), BoxError> {
    let middlewares = (
        TraceLayer::new_for_http(),
        CatchPanicLayer::new(),
        SetResponseHeaderLayer::<XClacksOverhead>::if_not_present_default_typed(),
        AddRequiredResponseHeadersLayer::default(),
        SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-sponsored-by"),
            HeaderValue::from_static("fly.io"),
        ),
        ConsumeErrLayer::trace(tracing::Level::WARN),
    );

    let router = Router::new()
        .with_get("/", endpoint::index::service())
        .with_match_route(
            "/method",
            HttpMatcher::custom(true),
            endpoint::method::handler,
        )
        .with_sub_service(
            "/request-compression",
            endpoint::request_compression::service(),
        )
        .with_get(
            "/response-compression",
            endpoint::response_compression::service(),
        )
        .with_get("/response-stream", endpoint::response_stream::service())
        .with_get(
            "/response-stream-compression",
            endpoint::response_stream_compression::service(),
        )
        .with_get("/sse", endpoint::sse::service());

    let http_service = Arc::new(middlewares.into_layer(router));

    serve_http(graceful, cfg, http_service).await
}

async fn serve_http<Response>(
    graceful: ShutdownGuard,
    cfg: CliCommandHttpTest,
    http_service: impl Service<Request, Output = Response, Error = Infallible> + Clone,
) -> Result<(), BoxError>
where
    Response: IntoResponse + Send + 'static,
{
    let exec = Executor::graceful(graceful);
    let maybe_tls_server_config = cfg
        .secure
        .then(|| {
            try_new_server_config(
                Some(match cfg.http_version {
                    HttpVersion::Auto => vec![
                        ApplicationProtocol::HTTP_2,
                        ApplicationProtocol::HTTP_11,
                        ApplicationProtocol::HTTP_10,
                        ApplicationProtocol::HTTP_09,
                    ],
                    HttpVersion::H1 => vec![
                        ApplicationProtocol::HTTP_11,
                        ApplicationProtocol::HTTP_10,
                        ApplicationProtocol::HTTP_09,
                    ],
                    HttpVersion::H2 => vec![ApplicationProtocol::HTTP_2],
                }),
                exec.clone(),
            )
        })
        .transpose()?;

    let tls_acceptor_data = match maybe_tls_server_config {
        None => None,
        Some(cfg) => Some(cfg.try_into()?),
    };

    let tcp_listener = TcpListener::build(exec.clone())
        .bind(cfg.bind.clone())
        .await
        .map_err(OpaqueError::from_boxed)
        .context("bind http test service")?;

    let bind_address = tcp_listener
        .local_addr()
        .context("get local addr of tcp listener")?;

    let tcp_service_builder = (
        ConsumeErrLayer::trace(tracing::Level::WARN),
        if cfg.timeout > 0. {
            TimeoutLayer::new(Duration::from_secs_f64(cfg.timeout))
        } else {
            TimeoutLayer::never()
        },
        LimitLayer::new(if cfg.concurrent > 0 {
            Either::A(ConcurrentPolicy::max_with_backoff(
                cfg.concurrent,
                ExponentialBackoff::default(),
            ))
        } else {
            Either::B(UnlimitedPolicy::new())
        }),
        // Limit the body size to 1MB for both request and response
        BodyLimitLayer::symmetric(1024 * 1024),
        tls_acceptor_data.map(|data| TlsAcceptorLayer::new(data).with_store_client_hello(true)),
    );

    exec.clone().into_spawn_task(async move {
        match cfg.http_version {
            HttpVersion::Auto => {
                tracing::info!(
                    network.local.address = %bind_address.ip(),
                    network.local.port = %bind_address.port(),
                    "HTTP Test Service (auto) listening: bind interface = {}", cfg.bind,
                );
                tcp_listener
                    .serve(
                        tcp_service_builder
                            .into_layer(HttpServer::auto(exec).service(http_service)),
                    )
                    .await;
            }
            HttpVersion::H1 => {
                tracing::info!(
                    network.local.address = %bind_address.ip(),
                    network.local.port = %bind_address.port(),
                    "HTTP Test Service (<= HTTP/1.1) listening: bind interface = {}", cfg.bind,
                );
                tcp_listener
                    .serve(
                        tcp_service_builder
                            .into_layer(HttpServer::http1(exec).service(http_service)),
                    )
                    .await;
            }
            HttpVersion::H2 => {
                tracing::info!(
                    network.local.address = %bind_address.ip(),
                    network.local.port = %bind_address.port(),
                    "HTTP Test Service (h2) listening: bind interface = {}", cfg.bind,
                );
                tcp_listener
                    .serve(
                        tcp_service_builder.into_layer(HttpServer::h2(exec).service(http_service)),
                    )
                    .await;
            }
        }
    });

    Ok(())
}
