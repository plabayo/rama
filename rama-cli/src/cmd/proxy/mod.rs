//! rama proxy service

use clap::Args;
use rama::{
    Context, Layer, Service,
    error::{BoxError, ErrorContext, OpaqueError},
    http::{
        Body, IntoResponse, Request, Response, StatusCode,
        client::EasyHttpWebClient,
        layer::{
            remove_header::{RemoveRequestHeaderLayer, RemoveResponseHeaderLayer},
            trace::TraceLayer,
            upgrade::{UpgradeLayer, Upgraded},
        },
        matcher::MethodMatcher,
        server::HttpServer,
    },
    layer::{LimitLayer, TimeoutLayer, limit::policy::ConcurrentPolicy},
    net::{
        conn::is_connection_error, http::RequestContext, socket::Interface,
        stream::layer::http::BodyLimitLayer,
    },
    rt::Executor,
    service::service_fn,
    tcp::{client::default_tcp_connect, server::TcpListener},
};
use std::{convert::Infallible, time::Duration};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

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
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let graceful = rama::graceful::Shutdown::default();

    tracing::info!(
        bind = %cfg.bind,
        "starting proxy on",
    );

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
                    service_fn(http_connect_proxy),
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
            bind = %cfg.bind,
            %bind_address,
            "proxy ready",
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

async fn http_connect_accept<S>(
    mut ctx: Context<S>,
    req: Request,
) -> Result<(Response, Context<S>, Request), Response>
where
    S: Clone + Send + Sync + 'static,
{
    match ctx.get_or_try_insert_with_ctx::<RequestContext, _>(|ctx| (ctx, &req).try_into()) {
        Ok(request_ctx) => tracing::info!("accept CONNECT to {}", request_ctx.authority),
        Err(err) => {
            tracing::error!(err = %err, "error extracting authority");
            return Err(StatusCode::BAD_REQUEST.into_response());
        }
    }

    Ok((StatusCode::OK.into_response(), ctx, req))
}

async fn http_connect_proxy<S>(ctx: Context<S>, mut upgraded: Upgraded) -> Result<(), Infallible>
where
    S: Clone + Send + Sync + 'static,
{
    let authority = ctx // assumption validated by `http_connect_accept`
        .get::<RequestContext>()
        .unwrap()
        .authority
        .clone();
    tracing::info!("CONNECT to {authority}");
    let (mut stream, _) = match default_tcp_connect(&ctx, authority).await {
        Ok(stream) => stream,
        Err(err) => {
            tracing::error!(error = %err, "error connecting to host");
            return Ok(());
        }
    };
    if let Err(err) = tokio::io::copy_bidirectional(&mut upgraded, &mut stream).await {
        if !is_connection_error(&err) {
            tracing::error!(error = %err, "error copying data");
        }
    }
    Ok(())
}

async fn http_plain_proxy<S>(ctx: Context<S>, req: Request) -> Result<Response, Infallible>
where
    S: Clone + Send + Sync + 'static,
{
    let client = EasyHttpWebClient::default();
    match client.serve(ctx, req).await {
        Ok(resp) => Ok(resp),
        Err(err) => {
            tracing::error!(error = %err, "error in client request");
            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .unwrap())
        }
    }
}
