use argh::FromArgs;
use rama::{
    error::BoxError,
    http::{
        headers::Server,
        layer::{set_header::SetResponseHeaderLayer, trace::TraceLayer},
        server::HttpServer,
        IntoResponse, Request, Response, StatusCode,
    },
    proxy::pp::server::HaProxyLayer,
    rt::Executor,
    service::{
        layer::{limit::policy::ConcurrentPolicy, LimitLayer, TimeoutLayer},
        Context, ServiceBuilder,
    },
    stream::{layer::http::BodyLimitLayer, SocketInfo},
    tcp::server::TcpListener,
};
use std::{convert::Infallible, time::Duration};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(FromArgs, PartialEq, Debug)]
/// rama ip service (returns the ip address of the client)
#[argh(subcommand, name = "ip")]
pub struct CliCommandIp {
    #[argh(option, short = 'p', default = "8080")]
    /// the port to listen on
    port: u16,

    #[argh(option, short = 'i', default = "String::from(\"127.0.0.1\")")]
    /// the interface to listen on
    interface: String,

    #[argh(option, short = 'c', default = "0")]
    /// the number of concurrent connections to allow (0 = no limit)
    concurrent: usize,

    #[argh(option, short = 't', default = "8")]
    /// the timeout in seconds for each connection (0 = no timeout)
    timeout: u64,

    #[argh(switch, short = 'a')]
    /// enable HaProxy PROXY Protocol
    ha_proxy: bool,
}

pub async fn run(cfg: CliCommandIp) -> Result<(), BoxError> {
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
    tracing::info!("starting ip service on: {}", address);

    graceful.spawn_task_fn(move |guard| async move {
        let tcp_listener = TcpListener::build()
            .bind(address)
            .await
            .expect("bind tcp proxy to 127.0.0.1:62001");

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
            .layer(SetResponseHeaderLayer::overriding_typed(
                format!("{}/{}", rama::utils::info::NAME, rama::utils::info::VERSION)
                    .parse::<Server>()
                    .unwrap(),
            ))
            .service_fn(ip);

        let tcp_service = tcp_service_builder
            .service(HttpServer::auto(Executor::graceful(guard.clone())).service(http_service));

        tcp_listener.serve_graceful(guard, tcp_service).await;
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await?;

    Ok(())
}

pub async fn ip<State>(ctx: Context<State>, _: Request) -> Result<Response, Infallible> {
    Ok(
        match ctx.get::<SocketInfo>().map(|v| v.peer_addr().to_string()) {
            Some(ip) => ip.into_response(),
            None => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        },
    )
}
