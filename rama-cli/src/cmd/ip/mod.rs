//! rama ip service

use clap::Args;
use rama::{
    error::BoxError,
    http::{
        layer::{required_header::AddRequiredResponseHeadersLayer, trace::TraceLayer},
        server::HttpServer,
        IntoResponse, Request, Response, StatusCode,
    },
    net::stream::{layer::http::BodyLimitLayer, SocketInfo, Stream},
    proxy::pp::server::HaProxyLayer,
    rt::Executor,
    service::{
        layer::{
            limit::policy::{ConcurrentPolicy, UnlimitedPolicy},
            LimitLayer, TimeoutLayer,
        },
        util::combinators::Either,
        Context, ServiceBuilder,
    },
    tcp::server::TcpListener,
};
use std::{convert::Infallible, time::Duration};
use tokio::io::AsyncWriteExt;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Debug, Args)]
/// rama ip service (returns the ip address of the client)
pub struct CliCommandIp {
    #[arg(long, short = 'p', default_value_t = 8080)]
    /// the port to listen on
    port: u16,

    #[arg(long, short = 'i', default_value = "127.0.0.1")]
    /// the interface to listen on
    interface: String,

    #[arg(long, short = 'c', default_value_t = 0)]
    /// the number of concurrent connections to allow (0 = no limit)
    concurrent: usize,

    #[arg(long, short = 't', default_value = "8")]
    /// the timeout in seconds for each connection (0 = default timeout of 30s)
    timeout: u64,

    #[arg(long, short = 'a')]
    /// enable HaProxy PROXY Protocol
    ha_proxy: bool,

    #[arg(long, short = 'T')]
    /// operate the IP service on transport layer (tcp)
    transport: bool,
}

/// run the rama ip service
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
            .expect("bind ip service to 127.0.0.1:62001");

        let tcp_service_builder = ServiceBuilder::new()
            .layer(LimitLayer::new(if cfg.concurrent > 0 {
                Either::A(ConcurrentPolicy::max(cfg.concurrent))
            } else {
                Either::B(UnlimitedPolicy::default())
            }))
            .layer(TimeoutLayer::new(if cfg.timeout > 0 {
                Duration::from_secs(cfg.timeout)
            } else {
                Duration::from_secs(30)
            }))
            .layer((cfg.ha_proxy).then(HaProxyLayer::default));

        // TODO document how one would force IPv4 or IPv6

        // TODO: support opt-in TLS

        if cfg.transport {
            let tcp_service = tcp_service_builder.service(IpTransportEchoService);

            tracing::info!("ip service ready");

            tcp_listener.serve_graceful(guard, tcp_service).await;
        } else {
            let http_service = ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(AddRequiredResponseHeadersLayer::default())
                .service_fn(ip);

            let tcp_service = tcp_service_builder
                // Limit the body size to 1MB for requests
                .layer(BodyLimitLayer::request_only(1024 * 1024))
                .service(HttpServer::auto(Executor::graceful(guard.clone())).service(http_service));

            tracing::info!("ip service ready");

            tcp_listener.serve_graceful(guard, tcp_service).await;
        }
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await?;

    Ok(())
}

async fn ip<State>(ctx: Context<State>, _: Request) -> Result<Response, Infallible>
where
    State: Send + Sync + 'static,
{
    Ok(
        match ctx.get::<SocketInfo>().map(|v| v.peer_addr().to_string()) {
            Some(ip) => ip.into_response(),
            None => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        },
    )
}

#[derive(Debug, Clone)]
struct IpTransportEchoService;

impl<State, Input> rama::service::Service<State, Input> for IpTransportEchoService
where
    State: Send + Sync + 'static,
    Input: Stream,
{
    type Response = ();
    type Error = BoxError;

    async fn serve(
        &self,
        ctx: rama::service::Context<State>,
        stream: Input,
    ) -> Result<Self::Response, Self::Error> {
        let socket_info = match ctx.get::<SocketInfo>() {
            Some(socket_info) => socket_info,
            None => {
                tracing::error!("missing socket info");
                return Ok(());
            }
        };

        let mut stream = std::pin::pin!(stream);

        match socket_info.peer_addr().ip() {
            std::net::IpAddr::V4(ip) => {
                if let Err(err) = stream.write_all(&ip.octets()).await {
                    tracing::error!("error writing IPv4 of peer to peer: {}", err);
                }
            }
            std::net::IpAddr::V6(ip) => {
                if let Err(err) = stream.write_all(&ip.octets()).await {
                    tracing::error!("error writing IPv6 of peer to peer: {}", err);
                }
            }
        };

        Ok(())
    }
}
