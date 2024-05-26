use argh::FromArgs;
use rama::{
    error::BoxError,
    http::{
        client::HttpClient,
        layer::{
            remove_header::{RemoveRequestHeaderLayer, RemoveResponseHeaderLayer},
            trace::TraceLayer,
            upgrade::{UpgradeLayer, Upgraded},
        },
        matcher::MethodMatcher,
        server::HttpServer,
        Body, IntoResponse, Request, RequestContext, Response, StatusCode,
    },
    rt::Executor,
    service::{
        layer::{limit::policy::ConcurrentPolicy, Identity, LimitLayer, TimeoutLayer},
        service_fn,
        util::combinators::Either,
        Context, Service, ServiceBuilder,
    },
    stream::layer::http::BodyLimitLayer,
    tcp::{server::TcpListener, utils::is_connection_error},
};
use std::{convert::Infallible, time::Duration};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(FromArgs, PartialEq, Debug)]
/// rama proxy runner
#[argh(subcommand, name = "proxy")]
pub struct CliCommandProxy {
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
}

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
            .expect("bind tcp proxy to 127.0.0.1:62001");

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
            .layer(BodyLimitLayer::symmetric(2 * 1024 * 1024));

        let tcp_service_builder = if cfg.concurrent > 0 {
            tcp_service_builder.layer(Either::A(LimitLayer::new(ConcurrentPolicy::max(
                cfg.concurrent,
            ))))
        } else {
            tcp_service_builder.layer(Either::B(Identity::new()))
        };

        let tcp_service_builder = if cfg.timeout > 0 {
            tcp_service_builder.layer(Either::A(TimeoutLayer::new(Duration::from_secs(
                cfg.timeout,
            ))))
        } else {
            tcp_service_builder.layer(Either::B(Identity::new()))
        };

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
    match ctx
        .get_or_insert_with::<RequestContext>(|| RequestContext::from(&req))
        .host
        .as_ref()
    {
        Some(host) => tracing::info!("accept CONNECT to {host}"),
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
    let host = ctx
        .get::<RequestContext>()
        .unwrap()
        .host
        .as_ref()
        .unwrap()
        .clone();
    tracing::info!("CONNECT to {}", host);
    let mut stream = match tokio::net::TcpStream::connect(&host).await {
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
