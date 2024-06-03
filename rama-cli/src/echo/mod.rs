//! Echo service that echos the http request and tls client config

use clap::Args;
use rama::{
    error::BoxError,
    http::{
        dep::http_body_util::BodyExt,
        layer::{required_header::AddRequiredResponseHeadersLayer, trace::TraceLayer},
        response::Json,
        server::HttpServer,
        IntoResponse, Request, RequestContext, Response,
    },
    proxy::pp::server::HaProxyLayer,
    rt::Executor,
    service::{
        layer::{limit::policy::ConcurrentPolicy, LimitLayer, TimeoutLayer},
        Context, ServiceBuilder,
    },
    stream::{layer::http::BodyLimitLayer, SocketInfo},
    tcp::server::TcpListener,
    tls::rustls::server::IncomingClientHello,
    ua::{UserAgent, UserAgentClassifierLayer},
};
use serde_json::json;
use std::{convert::Infallible, time::Duration};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Debug, Args)]
/// rama echo service (echos the http request and tls client config)
pub struct CliCommandEcho {
    #[arg(short = 'p', long, default_value_t = 8080)]
    /// the port to listen on
    port: u16,

    #[arg(short = 'i', long, default_value = "127.0.0.1")]
    /// the interface to listen on
    interface: String,

    #[arg(short = 'c', long, default_value_t = 0)]
    /// the number of concurrent connections to allow (0 = no limit)
    concurrent: usize,

    #[arg(short = 't', long, default_value_t = 8)]
    /// the timeout in seconds for each connection (0 = no timeout)
    timeout: u64,

    #[arg(short = 'a', long)]
    /// enable HaProxy PROXY Protocol
    ha_proxy: bool,
}

/// run the rama echo service
pub async fn run(cfg: CliCommandEcho) -> Result<(), BoxError> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let graceful = rama::utils::graceful::Shutdown::default();

    let address = format!("{}:{}", cfg.interface, cfg.port);
    tracing::info!("starting echo service on: {}", address);

    graceful.spawn_task_fn(move |guard| async move {
        let tcp_listener = TcpListener::build()
            .bind(address)
            .await
            .expect("bind echo service to 127.0.0.1:62001");

        let tcp_service_builder = ServiceBuilder::new()
            .layer(
                (cfg.concurrent > 0)
                    .then(|| LimitLayer::new(ConcurrentPolicy::max(cfg.concurrent))),
            )
            .layer((cfg.timeout > 0).then(|| TimeoutLayer::new(Duration::from_secs(cfg.timeout))))
            .layer((cfg.ha_proxy).then(HaProxyLayer::default))
            // Limit the body size to 1MB for requests
            .layer(BodyLimitLayer::request_only(1024 * 1024));

        // TODO: support opt-in TLS

        // TODO document how one would force IPv4 or IPv6

        let http_service = ServiceBuilder::new()
            .layer(TraceLayer::new_for_http())
            .layer(AddRequiredResponseHeadersLayer::default())
            .layer(UserAgentClassifierLayer::new())
            .service_fn(echo);

        let tcp_service = tcp_service_builder
            .service(HttpServer::auto(Executor::graceful(guard.clone())).service(http_service));

        tracing::info!("echo service ready");

        tcp_listener.serve_graceful(guard, tcp_service).await;
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await?;

    Ok(())
}

async fn echo<State>(ctx: Context<State>, req: Request) -> Result<Response, Infallible> {
    let user_agent_info = ctx
        .get()
        .map(|ua: &UserAgent| {
            json!({
                "user_agent": ua.header_str().to_owned(),
                "kind": ua.info().map(|info| info.kind.to_string()),
                "version": ua.info().and_then(|info| info.version),
                "platform": ua.platform().map(|v| v.to_string()),
            })
        })
        .unwrap_or_default();

    let authority = ctx
        .get::<RequestContext>()
        .and_then(RequestContext::authority);

    // TODO: get in correct order
    // TODO: get in correct case
    // TODO: get also pseudo headers (or separate?!)

    let headers: Vec<_> = req
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                value.to_str().map(|v| v.to_owned()).unwrap_or_default(),
            )
        })
        .collect();

    let (parts, body) = req.into_parts();

    let body = body.collect().await.unwrap().to_bytes();
    let body = hex::encode(body.as_ref());

    let tls_client_hello = ctx.get::<IncomingClientHello>().map(|hello| {
        json!({
            "server_name": hello.server_name.clone(),
            "signature_schemes": hello
                .signature_schemes
                .iter()
                .map(|v| format!("{:?}", v))
                .collect::<Vec<_>>(),
            "alpn": hello.alpn.clone(),
            "cipher_suites": hello
                .cipher_suites
                .iter()
                .map(|v| format!("{:?}", v))
                .collect::<Vec<_>>(),
        })
    });

    Ok(Json(json!({
        "ua": user_agent_info,
        "http": {
            "version": format!("{:?}", parts.version),
            "scheme": parts.uri
            .scheme_str()
            .map(|v| v.to_owned())
            .unwrap_or_else(|| {
                if ctx.get::<IncomingClientHello>().is_some() {
                    "https"
                } else {
                    "http"
                }
                .to_owned()
            }),
            "method": format!("{:?}", parts.method),
            "authority": authority,
            "path": parts.uri.path().to_owned(),
            "query": parts.uri.query().map(str::to_owned),
            "headers": headers,
            "payload": body,
        },
        "tls": tls_client_hello,
        "ip": ctx.get::<SocketInfo>().map(|v| v.peer_addr().to_string()),
    }))
    .into_response())
}
