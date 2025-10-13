//! rama proxy service

use clap::Args;
use rama::{
    Layer, Service,
    error::{BoxError, ErrorContext, OpaqueError},
    extensions::ExtensionsMut,
    http::{
        Body, Request, Response, StatusCode,
        client::EasyHttpWebClient,
        layer::{
            remove_header::{RemoveRequestHeaderLayer, RemoveResponseHeaderLayer},
            trace::TraceLayer,
            upgrade::UpgradeLayer,
        },
        matcher::MethodMatcher,
        server::HttpServer,
        service::web::response::IntoResponse,
    },
    layer::{ConsumeErrLayer, LimitLayer, TimeoutLayer, limit::policy::ConcurrentPolicy},
    net::{
        http::RequestContext, proxy::ProxyTarget, socket::Interface,
        stream::layer::http::BodyLimitLayer,
    },
    rt::Executor,
    service::service_fn,
    tcp::{client::service::Forwarder, server::TcpListener},
    telemetry::tracing::{self, level_filters::LevelFilter},
};
use std::{convert::Infallible, time::Duration};

#[derive(Debug, Args)]
/// rama proxy server
pub struct CliCommandProxy {
    /// the interface to bind to
    #[arg(long, default_value = "127.0.0.1:8080")]
    bind: Interface,

    #[arg(long, short = 'c', default_value_t = 0)]
    /// the number of concurrent connections to allow (0 = no limit)
    concurrent: usize,

    #[arg(long, short = 't', default_value_t = 8)]
    /// the timeout in seconds for each connection (0 = no timeout)
    timeout: u64,
}

/// run the rama proxy service
pub async fn run(cfg: CliCommandProxy) -> Result<(), BoxError> {
    crate::trace::init_tracing(LevelFilter::INFO);

    let graceful = rama::graceful::Shutdown::default();

    tracing::info!("starting proxy on: bind interface = {}", cfg.bind);

    let tcp_service = TcpListener::build()
        .bind(cfg.bind.clone())
        .await
        .map_err(OpaqueError::from_boxed)
        .context("bind proxy service")?;

    let bind_address = tcp_service
        .local_addr()
        .context("get local addr of tcp listener")?;

    graceful.spawn_task_fn(async move |guard| {
        let exec = Executor::graceful(guard.clone());
        let http_service = HttpServer::auto(exec).service(
            (
                TraceLayer::new_for_http(),
                UpgradeLayer::new(
                    MethodMatcher::CONNECT,
                    service_fn(http_connect_accept),
                    ConsumeErrLayer::default().into_layer(Forwarder::ctx()),
                ),
                RemoveResponseHeaderLayer::hop_by_hop(),
                RemoveRequestHeaderLayer::hop_by_hop(),
            )
                .into_layer(service_fn(http_plain_proxy)),
        );

        let tcp_service_builder = (
            // protect the http proxy from too large bodies, both from request and response end
            BodyLimitLayer::symmetric(2 * 1024 * 1024),
            (cfg.concurrent > 0).then(|| LimitLayer::new(ConcurrentPolicy::max(cfg.concurrent))),
            (cfg.timeout > 0).then(|| TimeoutLayer::new(Duration::from_secs(cfg.timeout))),
        );

        tracing::info!(
            network.local.address = %bind_address.ip(),
            network.local.port = %bind_address.port(),
            "proxy ready: bind interface = {}", cfg.bind,
        );

        tcp_service
            .serve_graceful(guard, tcp_service_builder.into_layer(http_service))
            .await;
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await?;

    Ok(())
}

async fn http_connect_accept(mut req: Request) -> Result<(Response, Request), Response> {
    match RequestContext::try_from(&req).map(|ctx| ctx.authority) {
        Ok(authority) => {
            tracing::info!(
                server.address = %authority.host(),
                server.port = %authority.port(),
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

async fn http_plain_proxy(req: Request) -> Result<Response, Infallible> {
    let client = EasyHttpWebClient::default();
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
