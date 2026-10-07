//! Http Test service for various purposes

use std::{convert::Infallible, sync::Arc, time::Duration};

use clap::Args;
use rama::{
    Service,
    combinators::Either,
    error::{BoxError, ErrorContext},
    graceful::ShutdownGuard,
    http::{
        BodyLimitLayer, HeaderName, HeaderValue, Request,
        headers::exotic::XClacksOverhead,
        layer::{
            catch_panic::CatchPanicLayer, error_handling::ErrorHandlerLayer,
            required_header::AddRequiredResponseHeadersLayer, set_header::SetResponseHeaderLayer,
            trace::TraceLayer,
        },
        matcher::HttpMatcher,
        server::HttpServer,
        service::web::{Router, response::IntoResponse},
    },
    layer::{
        ConsumeErrLayer, Layer, LimitLayer, TimeoutLayer,
        limit::policy::{ConcurrentPolicy, RateLimitReached, RatePolicy, UnlimitedPolicy},
    },
    net::{
        address::SocketAddress,
        stream::layer::{ThrottleLayer, ThrottleMode},
        tls::ApplicationProtocol,
    },
    rt::Executor,
    telemetry::tracing,
    tls::{boring::server::TlsAcceptorLayer, server::TlsServerConfig},
    utils::{backoff::ExponentialBackoff, octets::mib},
};

use crate::utils::{
    http::{HttpVersions, TcpHttpVersion},
    http3::{Http3Args, Http3Endpoints, HttpListeners},
    rate::opt_per_sec,
    tls::try_new_server_config,
};

mod endpoint;

#[derive(Debug, Args)]
/// rama http test service
pub struct CliCommandHttpTest {
    /// the address to bind to
    #[arg(long, default_value_t = SocketAddress::local_ipv4(8080))]
    bind: SocketAddress,

    #[arg(short = 'c', long, default_value_t = 0)]
    /// the number of concurrent connections to allow
    ///
    /// (0 = no limit)
    concurrent: usize,

    /// http versions to serve: `auto` or a comma separated list of h1, h2 and h3
    ///
    /// `auto` serves HTTP/1.1 and h2 over TCP and, in secure mode, HTTP/3 over QUIC.
    #[arg(long, default_value = "auto")]
    http_version: HttpVersions,

    #[command(flatten)]
    http3: Http3Args,

    #[arg(short = 't', long, default_value_t = 60.)]
    /// the timeout in seconds for each connection
    ///
    /// (<= 0.0 = no timeout)
    timeout: f64,

    #[arg(long, default_value_t = 0)]
    /// rate limit the service in requests per second
    ///
    /// (0 = no limit)
    rate: u64,

    #[arg(long, default_value_t = 0)]
    /// throttle each connection at the given byte rate
    /// (bytes per second, both directions)
    ///
    /// (0 = no throttling)
    throttle: u64,

    #[arg(long, short = 's')]
    /// run service in secure mode (enable TLS)
    secure: bool,
}

/// run the rama http test service
pub async fn run(
    graceful: ShutdownGuard,
    http3_endpoints: Http3Endpoints,
    cfg: CliCommandHttpTest,
) -> Result<(), BoxError> {
    let exec = Executor::graceful(graceful);
    let tcp_version = cfg.http_version.tcp();
    let maybe_tls_server_config = cfg
        .secure
        .then(|| {
            try_new_server_config(
                Some(match tcp_version {
                    Some(TcpHttpVersion::Auto) | None => vec![
                        ApplicationProtocol::HTTP_2,
                        ApplicationProtocol::HTTP_11,
                        ApplicationProtocol::HTTP_10,
                        ApplicationProtocol::HTTP_09,
                    ],
                    Some(TcpHttpVersion::H1) => vec![
                        ApplicationProtocol::HTTP_11,
                        ApplicationProtocol::HTTP_10,
                        ApplicationProtocol::HTTP_09,
                    ],
                    Some(TcpHttpVersion::H2) => vec![ApplicationProtocol::HTTP_2],
                }),
                exec.clone(),
            )
        })
        .transpose()?;
    let listeners = HttpListeners::bind(
        exec.clone(),
        cfg.bind,
        cfg.http_version,
        maybe_tls_server_config.as_ref(),
        &cfg.http3,
    )
    .await
    .context("bind http test service")?;

    // Defence-in-depth response headers. The HTML index page now serves
    // its CSS from `/style/index.css`, the test endpoints emit either
    // streamed HTML with no scripts or JSON / octet-stream bodies, and
    // none of them open WebSockets — so the strict-self baseline (with
    // the rama-banner image host whitelisted) covers every shape.
    let (csp_layer, nosniff_layer, referrer_layer, frame_layer) =
        rama::cli::service::http_security::defence_in_depth_layer(
            rama::cli::service::http_security::rama_html_csp(),
        );

    let middlewares = (
        TraceLayer::new_for_http(),
        opt_per_sec(Some(cfg.rate)).map(|rate| {
            LimitLayer::new(RatePolicy::abort(rate)).with_error_into_response_fn(
                |err: RateLimitReached| Ok::<_, Infallible>(err.into_response()),
            )
        }),
        CatchPanicLayer::new(),
        SetResponseHeaderLayer::<XClacksOverhead>::if_not_present_default_typed(),
        listeners
            .alt_svc()?
            .map(SetResponseHeaderLayer::if_not_present_typed),
        AddRequiredResponseHeadersLayer::default(),
        SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-sponsored-by"),
            HeaderValue::from_static("fly.io"),
        ),
        csp_layer,
        nosniff_layer,
        referrer_layer,
        frame_layer,
        ConsumeErrLayer::trace_as(tracing::Level::WARN),
        ErrorHandlerLayer::new(),
    );

    let router = Router::new()
        .with_get("/", endpoint::index::service())
        .with_get("/style/index.css", endpoint::index::STYLE_CSS)
        .with_get("/bytes", endpoint::bytes::service())
        .with_match_route(
            "/method",
            HttpMatcher::custom(true),
            endpoint::method::handler,
        )
        .with_endpoint_service(
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
        .with_get("/sse", endpoint::sse::service())
        .with_get("/style/sse.css", endpoint::sse::STYLE_CSS)
        .with_get("/script/sse.js", endpoint::sse::SCRIPT_JS)
        .with_get("/multipart", endpoint::multipart::get_form)
        .with_post("/multipart", endpoint::multipart::post_service())
        .with_post("/octet-stream", endpoint::octet_stream::service())
        .with_post("/sink", endpoint::sink::service());

    let http_service = Arc::new(middlewares.into_layer(router));

    serve_http(
        exec,
        &http3_endpoints,
        &cfg,
        listeners,
        maybe_tls_server_config,
        http_service,
    )
}

fn serve_http<Response>(
    exec: Executor,
    http3_endpoints: &Http3Endpoints,
    cfg: &CliCommandHttpTest,
    listeners: HttpListeners,
    maybe_tls_server_config: Option<TlsServerConfig>,
    http_service: impl Service<Request, Output = Response, Error = Infallible> + Clone,
) -> Result<(), BoxError>
where
    Response: IntoResponse + Send + 'static,
{
    let connection_timeout = if cfg.timeout > 0. {
        TimeoutLayer::new(Duration::from_secs_f64(cfg.timeout))
    } else {
        TimeoutLayer::never()
    };
    let connection_limit = LimitLayer::new(if cfg.concurrent > 0 {
        Either::A(ConcurrentPolicy::max_with_backoff(
            cfg.concurrent,
            ExponentialBackoff::default(),
        ))
    } else {
        Either::B(UnlimitedPolicy::new())
    });
    // Keep a public-service-wide cap while still allowing the
    // stress endpoints (`/bytes`, `/octet-stream`) to exercise
    // multi-megabyte bodies without third-party infrastructure.
    let body_limit = BodyLimitLayer::symmetric(mib(32));
    // One layer for both: QUIC paces all streams of a connection against one budget.
    let throttle = opt_per_sec(Some(cfg.throttle))
        .map(|rate| ThrottleLayer::symmetric(ThrottleMode::per_conn(rate)));

    if let Some(endpoint) = listeners.http3 {
        let http3_service = (
            ConsumeErrLayer::trace_as(tracing::Level::WARN),
            connection_timeout.clone(),
            connection_limit.clone(),
            throttle.clone(),
            body_limit.clone(),
        )
            .into_layer(HttpServer::new_http3(exec.clone()).service(http_service.clone()));
        http3_endpoints.serve(&exec, "HTTP Test", endpoint, Arc::new(http3_service));
    }

    let Some((tcp_listener, tcp_version)) = listeners.tcp.zip(cfg.http_version.tcp()) else {
        return Ok(());
    };
    let bind_address = tcp_listener
        .local_addr()
        .context("get local addr of tcp listener")?;

    let tcp_service_builder = (
        ConsumeErrLayer::trace_as(tracing::Level::WARN),
        connection_timeout,
        connection_limit,
        throttle,
        body_limit,
        maybe_tls_server_config.map(|cfg| TlsAcceptorLayer::new(cfg).with_store_client_hello(true)),
    );

    let bind = cfg.bind;
    exec.clone().into_spawn_task(async move {
        match tcp_version {
            TcpHttpVersion::Auto => {
                tracing::info!(
                    network.local.address = %bind_address.ip(),
                    network.local.port = %bind_address.port(),
                    "HTTP Test Service (auto) listening: bind interface = {}", bind,
                );
                tcp_listener
                    .serve(
                        tcp_service_builder
                            .into_layer(HttpServer::auto(exec).service(http_service)),
                    )
                    .await;
            }
            TcpHttpVersion::H1 => {
                tracing::info!(
                    network.local.address = %bind_address.ip(),
                    network.local.port = %bind_address.port(),
                    "HTTP Test Service (<= HTTP/1.1) listening: bind interface = {}", bind,
                );
                tcp_listener
                    .serve(
                        tcp_service_builder
                            .into_layer(HttpServer::new_http1(exec).service(http_service)),
                    )
                    .await;
            }
            TcpHttpVersion::H2 => {
                tracing::info!(
                    network.local.address = %bind_address.ip(),
                    network.local.port = %bind_address.port(),
                    "HTTP Test Service (h2) listening: bind interface = {}", bind,
                );
                tcp_listener
                    .serve(
                        tcp_service_builder
                            .into_layer(HttpServer::new_h2(exec).service(http_service)),
                    )
                    .await;
            }
        }
    });

    Ok(())
}
