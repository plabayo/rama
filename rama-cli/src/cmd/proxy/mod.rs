//! rama proxy service

use clap::Args;
use rama::{
    error::BoxError,
    http::{
        client::HttpClient,
        get_request_context,
        layer::{
            remove_header::{RemoveRequestHeaderLayer, RemoveResponseHeaderLayer},
            trace::TraceLayer,
            upgrade::{UpgradeLayer, Upgraded},
        },
        matcher::MethodMatcher,
        server::HttpServer,
        Body, IntoResponse, Request, RequestContext, Response, StatusCode,
    },
    net::stream::layer::http::BodyLimitLayer,
    rt::Executor,
    service::{
        layer::{limit::policy::ConcurrentPolicy, LimitLayer, TimeoutLayer},
        service_fn, Context, Service, ServiceBuilder,
    },
    tcp::{server::TcpListener, utils::is_connection_error},
};
use std::{convert::Infallible, time::Duration};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Debug, Args)]
/// rama proxy runner
pub struct CliCommandProxy {
    #[arg(long, short = 'p', default_value_t = 8080)]
    /// the port to listen on
    port: u16,

    #[arg(long, short = 'i', default_value = "127.0.0.1")]
    /// the interface to listen on
    interface: String,

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

    let graceful = rama::utils::graceful::Shutdown::default();

    let address = format!("{}:{}", cfg.interface, cfg.port);
    tracing::info!("starting proxy on: {}", address);

    graceful.spawn_task_fn(move |guard| async move {
        let tcp_service = TcpListener::build()
            .bind(address)
            .await
            .expect("bind proxy to 127.0.0.1:62001");

        let exec = Executor::graceful(guard.clone());
        let http_service = HttpServer::auto(exec).service(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(UpgradeLayer::new(
                    MethodMatcher::CONNECT,
                    service_fn(http_connect_accept),
                    service_fn(http_connect_proxy),
                ))
                .service(
                    ServiceBuilder::new()
                        .layer(RemoveResponseHeaderLayer::hop_by_hop())
                        .layer(RemoveRequestHeaderLayer::hop_by_hop())
                        .service_fn(http_plain_proxy),
                ),
        );

        let tcp_service_builder = ServiceBuilder::new()
            // protect the http proxy from too large bodies, both from request and response end
            .layer(BodyLimitLayer::symmetric(2 * 1024 * 1024))
            .layer(
                (cfg.concurrent > 0)
                    .then(|| LimitLayer::new(ConcurrentPolicy::max(cfg.concurrent))),
            )
            .layer((cfg.timeout > 0).then(|| TimeoutLayer::new(Duration::from_secs(cfg.timeout))));

        tcp_service
            .serve_graceful(guard, tcp_service_builder.service(http_service))
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
    S: Send + Sync + 'static,
{
    let request_ctx = get_request_context!(ctx, req);
    match &request_ctx.authority {
        Some(authority) => tracing::info!("accept CONNECT to {authority}"),
        None => {
            tracing::error!("error extracting host");
            return Err(StatusCode::BAD_REQUEST.into_response());
        }
    }

    Ok((StatusCode::OK.into_response(), ctx, req))
}

async fn http_connect_proxy<S>(ctx: Context<S>, mut upgraded: Upgraded) -> Result<(), Infallible>
where
    S: Send + Sync + 'static,
{
    let authority = ctx // assumption validated by `http_connect_accept`
        .get::<RequestContext>()
        .unwrap()
        .authority
        .as_ref()
        .unwrap()
        .to_string();
    tracing::info!("CONNECT to {}", authority);
    let mut stream = match tokio::net::TcpStream::connect(authority).await {
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
    S: Send + Sync + 'static,
{
    let client = HttpClient::default();
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
